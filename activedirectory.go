package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// ExportADJoinPoints fills the bundle with Active Directory join points.
func ExportADJoinPoints(c *Client, b *Bundle, families []string, log func(string, ...any)) error {
	if !slices.Contains(families, familyADJoinPoints) {
		return nil
	}

	log("Listing Active Directory join points…")
	stubs, err := c.ersList(pathActiveDirectory)
	if err != nil {
		return fmt.Errorf("listing Active Directory join points: %w", err)
	}

	log("Found %d Active Directory join points; reading them…", len(stubs))
	joinPoints, err := c.ersGetAll(pathActiveDirectory, rootActiveDirectory, stubs)
	if err != nil {
		return fmt.Errorf("reading Active Directory join points: %w", err)
	}

	out := make([]map[string]any, 0, len(joinPoints))
	for _, jp := range joinPoints {
		out = append(out, stripLocal(jp))
	}

	log("Captured %d Active Directory join points.", len(out))
	b.Objects[familyADJoinPoints] = out
	return nil
}

// preflightADJoinPoints resolves every Active Directory join point against the
// target and reports what would happen. It is called before preflightPolicyElements
// so a join point created in this run counts as an identity source for policy.
func preflightADJoinPoints(c *Client, b *Bundle, r *PreflightReport) {
	items := b.Objects[familyADJoinPoints]
	if len(items) == 0 {
		return
	}

	// Read target's join points
	targetStubs, err := c.ersList(pathActiveDirectory)
	if err != nil {
		// Log and continue; join points are optional
		return
	}

	// Build maps for lookup and read full details
	targetByName := map[string]map[string]any{}
	targetByDomain := map[string]string{} // domain -> name

	if targetDetail, err := c.ersGetAll(pathActiveDirectory, rootActiveDirectory, targetStubs); err == nil {
		for _, detail := range targetDetail {
			name := str(detail, "name")
			domain := str(detail, "domain")
			targetByName[name] = detail
			if domain != "" {
				targetByDomain[domain] = name
			}
		}
	}

	// Helper to extract SIDs from an adgroups block
	extractSIDs := func(adgroupsObj any) map[string]bool {
		sids := make(map[string]bool)
		if adgroupsObj == nil {
			return sids
		}
		adgroupsMap, ok := adgroupsObj.(map[string]any)
		if !ok {
			return sids
		}
		groupsObj, ok := adgroupsMap["groups"].([]any)
		if !ok {
			return sids
		}
		for _, g := range groupsObj {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			sid := str(gm, "sid")
			if sid != "" {
				sids[sid] = true
			}
		}
		return sids
	}

	// Process bundle join points
	for _, bundleItem := range items {
		bundleName := str(bundleItem, "name")
		bundleDomain := str(bundleItem, "domain")

		it := PreflightItem{
			Family: familyADJoinPoints,
			Name:   bundleName,
			obj:    bundleItem,
		}

		if bundleName == "" {
			it.Action, it.Reason = actionBlocked, "join point has no name"
			r.add(it)
			continue
		}

		if bundleDomain == "" {
			it.Action, it.Reason = actionBlocked, "join point has no domain"
			r.add(it)
			continue
		}

		// Check if target already has a join point with the same name
		if targetJP := targetByName[bundleName]; targetJP != nil {
			it.Action, it.Reason = actionSkip, "already exists on the target"
			r.add(it)

			// Add a second item for groups: check if we need to load them
			bundleGroupSIDs := extractSIDs(bundleItem["adgroups"])
			targetGroupSIDs := extractSIDs(targetJP["adgroups"])

			groupCount := len(bundleGroupSIDs)
			groupsItem := PreflightItem{
				Family: familyADJoinPoints,
				Name:   fmt.Sprintf("%s — %d AD groups", bundleName, groupCount),
			}

			// Check if target holds all the bundle's groups
			hasAllGroups := len(bundleGroupSIDs) > 0 && len(targetGroupSIDs) > 0
			if hasAllGroups {
				for sid := range bundleGroupSIDs {
					if !targetGroupSIDs[sid] {
						hasAllGroups = false
						break
					}
				}
			}

			if len(targetGroupSIDs) == 0 && len(bundleGroupSIDs) > 0 {
				// Target has no groups but bundle has them
				groupsItem.Action = actionCreate
				groupsItem.Reason = "the target join point has no groups loaded; will load them from the bundle"
			} else if hasAllGroups {
				// Target already has all the bundle's groups
				groupsItem.Action = actionSkip
				groupsItem.Reason = "already loaded on the target"
			} else if len(bundleGroupSIDs) > 0 {
				// Target has some but not all groups
				groupsItem.Action = actionCreate
				groupsItem.Reason = "the target join point is missing some groups; will load all groups from the bundle"
			} else {
				// Bundle has no groups
				groupsItem.Action = actionSkip
				groupsItem.Reason = "no groups to load"
			}

			r.add(groupsItem)
			continue
		}

		// Check if target has a join point for the same domain but different name
		if targetName, exists := targetByDomain[bundleDomain]; exists && targetName != bundleName {
			it.Action, it.Reason = actionBlocked,
				fmt.Sprintf("the target has a join point %q for domain %q; the bundle names it %q. Rename one or repoint the migrated rules.",
					targetName, bundleDomain, bundleName)
			r.add(it)
			continue
		}

		// Create new join point
		it.Action = actionCreate
		it.Reason = "will be created (not joined); the operator must join the domain in the ISE GUI, then run the import again to load its groups"
		r.add(it)
	}
}

// applyADJoinPoints creates join points and loads their groups.
func applyADJoinPoints(c *Client, r *PreflightReport, res *ImportResult, log func(string, ...any)) error {
	items := r.Items

	// Count creations and group loads separately
	var createCount, groupLoadCount int
	for _, it := range items {
		if it.Family != familyADJoinPoints {
			continue
		}
		if strings.HasSuffix(it.Name, " AD groups") {
			if it.Action == actionCreate {
				groupLoadCount++
			}
		} else if it.Action == actionCreate {
			createCount++
		}
	}

	// Create join points first (without groups)
	if createCount > 0 {
		log("Creating %d Active Directory join points…", createCount)
		for _, it := range items {
			if it.Family != familyADJoinPoints || it.Action != actionCreate || strings.HasSuffix(it.Name, " AD groups") {
				continue
			}

			obj := maps.Clone(it.obj)
			// Remove adgroups from the create payload — a join point cannot carry
			// groups before the domain is joined
			delete(obj, "adgroups")

			if err := c.ersCreate(pathActiveDirectory, rootActiveDirectory, obj); err != nil {
				if isDuplicate(err) {
					res.Skipped++
					log("Active Directory join point %q already exists; skipped.", it.Name)
				} else {
					res.Failed++
					res.Errors = append(res.Errors, fmt.Sprintf("Active Directory join point %q: %v", it.Name, err))
					log("FAILED Active Directory join point %q: %v", it.Name, err)
				}
				continue
			}
			res.Created++
			log("Created Active Directory join point %q.", it.Name)
		}
	}

	// Load groups into existing or newly created join points
	if groupLoadCount > 0 {
		log("Loading Active Directory groups…")

		// Read target join points to get their IDs
		targetStubs, err := c.ersList(pathActiveDirectory)
		if err != nil {
			log("Could not read target join points to load groups: %v", err)
			return nil
		}

		targetByName := map[string]string{} // name -> id
		for _, stub := range targetStubs {
			targetByName[stub.Name] = stub.ID
		}

		for _, it := range items {
			if it.Family != familyADJoinPoints || !strings.HasSuffix(it.Name, " AD groups") {
				continue
			}

			// Extract the join point name from the groups item name
			// Format: "name — N AD groups"
			jpName := it.Name
			if i := strings.Index(jpName, " — "); i >= 0 {
				jpName = jpName[:i]
			}

			if it.Action != actionCreate {
				if it.Action == actionSkip {
					res.Skipped++
				} else {
					res.Blocked++
				}
				continue
			}

			// Get the target join point's ID
			targetID := targetByName[jpName]
			if targetID == "" {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("Active Directory groups for %q: target join point not found", jpName))
				log("FAILED Active Directory groups for %q: target join point not found", jpName)
				continue
			}

			// Find the corresponding bundle object to get the groups
			var bundleObj map[string]any
			for _, bundleItem := range r.Items {
				if bundleItem.Family == familyADJoinPoints && !strings.HasSuffix(bundleItem.Name, " AD groups") && bundleItem.Name == jpName {
					bundleObj = bundleItem.obj
					break
				}
			}

			if bundleObj == nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("Active Directory groups for %q: bundle object not found", jpName))
				log("FAILED Active Directory groups for %q: bundle object not found", jpName)
				continue
			}

			// Build the addGroups payload: only name, description, domain, and adgroups
			payload := map[string]any{
				"name":     str(bundleObj, "name"),
				"domain":   str(bundleObj, "domain"),
				"adgroups": bundleObj["adgroups"],
			}
			if desc := str(bundleObj, "description"); desc != "" {
				payload["description"] = desc
			}

			if err := c.ersPut(pathActiveDirectory+"/"+targetID+"/addGroups", rootActiveDirectory, payload); err != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("Active Directory groups for %q: %v. Join the domain in the ISE GUI and run the import again.", jpName, err))
				log("FAILED Active Directory groups for %q: %v. Join the domain in the ISE GUI and run the import again.", jpName, err)
				continue
			}

			res.Created++
			log("Loaded Active Directory groups for %q.", jpName)
		}
	}

	return nil
}

// joinPointsAfterThisRun names the AD join points the target will have once this
// import finishes: the ones it already has, plus the ones pre-flight decided to
// create. preflightADJoinPoints runs before the policy families, so its verdicts
// are already in the report by the time they ask.
//
// Only the join point itself counts. Its dictionary and its groups appear when
// the domain is joined, which is a manual step between two runs, so anything
// needing those still blocks on the first pass.
func joinPointsAfterThisRun(c *Client, r *PreflightReport) map[string]bool {
	names := map[string]bool{}
	stubs, _ := c.ersList(pathActiveDirectory)
	for _, s := range stubs {
		names[s.Name] = true
	}
	for _, it := range r.Items {
		if it.Family == familyADJoinPoints && it.Action == actionCreate {
			if name := str(it.obj, "name"); name != "" {
				names[name] = true
			}
		}
	}
	return names
}
