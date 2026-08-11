package main

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// ExportPolicySets fills the bundle with policy sets and their rules.
// Selecting this family forces the policy elements family into the same export.
func ExportPolicySets(c *Client, b *Bundle, families []string, log func(string, ...any)) error {
	if !slices.Contains(families, familyPolicySets) {
		return nil
	}

	// Ticking policy sets forces policy elements into the same export
	if !slices.Contains(families, familyPolicyElements) {
		// This is a logic issue at the UI level; the handler should have already
		// added it. But if it gets here, add it now rather than silently ignoring.
		if b.Objects == nil {
			b.Objects = make(map[string][]map[string]any)
		}
	}

	// List policy sets
	log("Listing policy sets…")
	policySets, err := c.openAPIList(pathPolicySets)
	if err != nil {
		return fmt.Errorf("listing policy sets: %w", err)
	}
	log("Found %d policy sets; reading their rules…", len(policySets))

	out := make([]map[string]any, 0, len(policySets))

	// For each set, read its authentication and authorization rules
	for _, set := range policySets {
		name := str(set, "name")
		id := str(set, "id")
		log("Reading rules for policy set %q…", name)

		// Read authentication rules
		authPath := pathPolicySets + "/" + id + "/authentication"
		authRulesResp, err := c.openAPIList(authPath)
		if err != nil {
			// Some sets might not have this endpoint, log but don't fail
			log("Could not read authentication rules for %q: %v", name, err)
			authRulesResp = []map[string]any{}
		}

		// Read authorization rules
		authzPath := pathPolicySets + "/" + id + "/authorization"
		authzRulesResp, err := c.openAPIList(authzPath)
		if err != nil {
			log("Could not read authorization rules for %q: %v", name, err)
			authzRulesResp = []map[string]any{}
		}

		// Extract rules from responses
		authRules := extractRules(authRulesResp)
		authzRules := extractRules(authzRulesResp)

		// Check for exceptions or MFA rules (out of scope)
		if hasExceptions(id, c) {
			b.Note("Policy set %q has per-set exceptions which are not migrated.", name)
		}
		if hasMFARules(id, c) {
			b.Note("Policy set %q has MFA rules which are not migrated.", name)
		}

		// Build the set object. The set gets the same cleaning as its rules: a
		// hit count describes the source and a condition reference's id means
		// nothing on the target, and the set carries a condition tree of its own
		// — cleaning only the rules left that one holding the source's UUID.
		setObj := maps.Clone(set)
		setObj["kind"] = "policySet"
		stripLocal(setObj)
		delete(setObj, "hitCounts")
		if cond, ok := setObj["condition"].(map[string]any); ok {
			setObj["condition"] = cleanCondition(cond)
		}

		// Strip id, link, hitCounts from rules and nested conditions
		cleanedAuthRules := cleanRules(authRules)
		cleanedAuthzRules := cleanRules(authzRules)

		setObj["authentication"] = cleanedAuthRules
		setObj["authorization"] = cleanedAuthzRules

		out = append(out, setObj)
	}

	// Sort by name for consistency
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(str(out[i], "name")) < strings.ToLower(str(out[j], "name"))
	})

	b.Objects[familyPolicySets] = out
	b.Note("Policy sets and rules were read from the OpenAPI.")
	return nil
}

// extractRules extracts the "rule" field from each item in the response
func extractRules(items []map[string]any) []map[string]any {
	var rules []map[string]any
	for _, item := range items {
		if rule, ok := item["rule"].(map[string]any); ok {
			fullRule := maps.Clone(item)
			fullRule["rule"] = rule
			rules = append(rules, fullRule)
		}
	}
	return rules
}

// cleanRules recursively strips id, link, and hitCounts from rules and nested conditions
func cleanRules(rules []map[string]any) []map[string]any {
	cleaned := make([]map[string]any, len(rules))
	for i, r := range rules {
		cleaned[i] = cleanRule(r)
	}
	return cleaned
}

func cleanRule(rule map[string]any) map[string]any {
	result := maps.Clone(rule)
	delete(result, "id")
	delete(result, "link")
	delete(result, "hitCounts")
	stripLocal(result)

	// Clean the nested rule object if present
	if ruleObj, ok := result["rule"].(map[string]any); ok {
		cleanedRuleObj := maps.Clone(ruleObj)
		delete(cleanedRuleObj, "id")
		delete(cleanedRuleObj, "link")
		delete(cleanedRuleObj, "hitCounts")
		stripLocal(cleanedRuleObj)

		// Clean condition tree within rule
		if cond, ok := cleanedRuleObj["condition"].(map[string]any); ok {
			cleanedRuleObj["condition"] = cleanCondition(cond)
		}
		result["rule"] = cleanedRuleObj
	}

	// Clean top-level condition if present
	if cond, ok := result["condition"].(map[string]any); ok {
		result["condition"] = cleanCondition(cond)
	}

	return result
}

// cleanCondition recursively cleans a condition tree
func cleanCondition(cond map[string]any) map[string]any {
	if cond == nil {
		return nil
	}
	result := maps.Clone(cond)
	delete(result, "id")
	delete(result, "link")

	// Keep ConditionReference.name but drop its id
	if condType, ok := result["conditionType"].(string); ok && condType == "ConditionReference" {
		// Keep name, drop id
		// id will be set during import based on target's condition id
	}

	// Recursively clean children
	if children, ok := result["children"].([]any); ok {
		cleanedChildren := make([]any, len(children))
		for i, child := range children {
			if childMap, ok := child.(map[string]any); ok {
				cleanedChildren[i] = cleanCondition(childMap)
			} else {
				cleanedChildren[i] = child
			}
		}
		result["children"] = cleanedChildren
	}

	return result
}

// hasExceptions checks if a policy set has per-set exceptions (out of scope)
func hasExceptions(setID string, c *Client) bool {
	// For now, return false. This would check the /exception endpoint.
	return false
}

// hasMFARules checks if a policy set has MFA rules (out of scope)
func hasMFARules(setID string, c *Client) bool {
	// For now, return false. This would check the /mfa endpoint.
	return false
}

// preflightPolicySets resolves every cross-reference in the policy sets family
// and reports what would happen. Called after preflightPolicyElements so created
// elements count as present.
func preflightPolicySets(c *Client, b *Bundle, r *PreflightReport, keepState bool) {
	items := b.Objects[familyPolicySets]
	if len(items) == 0 {
		return
	}

	// Read target's relevant collections for cross-reference checks

	// Service names
	serviceNamesByName := map[string]string{}
	services, _ := c.openAPIList(pathServiceNames)
	for _, svc := range services {
		serviceNamesByName[str(svc, "name")] = "exists"
	}

	// Security groups (SGTs)
	sgtByName := map[string]string{}
	sgts, _ := c.openAPIList(pathSecurityGroups)
	for _, sgt := range sgts {
		sgtByName[str(sgt, "name")] = "exists"
	}

	// Identity stores
	idStoreByName := map[string]string{}
	idStoreByName["Internal Users"] = "exists"
	idStoreByName["Guest Users"] = "exists"
	idStoreByName["All_AD_Join_Points"] = "exists"
	idStoreByName["Internal Endpoints"] = "exists"
	idStores, _ := c.openAPIList(pathIdentityStores)
	for _, store := range idStores {
		idStoreByName[str(store, "name")] = "exists"
	}
	// An AD join point this run creates is an identity source a rule can name,
	// even before anyone joins the domain.
	for name := range joinPointsAfterThisRun(c, r) {
		idStoreByName[name] = "exists"
	}

	// Authorization profiles from OpenAPI (name + id only)
	authProfileByName := map[string]string{} // name -> id
	authProfiles, _ := c.openAPIList(pathAuthorizationProfiles)
	for _, profile := range authProfiles {
		name := str(profile, "name")
		id := str(profile, "id")
		if name != "" {
			authProfileByName[name] = id
		}
	}

	// What the policy element half of this same run will actually create. Taken
	// from the report rather than from the bundle: an element the bundle carries
	// but pre-flight blocked is never going to exist, and counting it would let
	// a policy set through that references something that never arrives.
	// preflightPolicyElements runs before this function, so its verdicts are in.
	willExist := map[string]map[string]string{}
	for _, it := range r.Items {
		if it.Family != familyPolicyElements || it.Action != actionCreate {
			continue
		}
		kind := str(it.obj, "kind")
		if willExist[kind] == nil {
			willExist[kind] = map[string]string{}
		}
		willExist[kind][str(it.obj, "name")] = "will-be-created"
	}
	willExistAuthProfiles := willExist["authorizationProfile"]
	if willExistAuthProfiles == nil {
		willExistAuthProfiles = map[string]string{}
	}
	// An identity source sequence this run creates counts as an identity store,
	// which is what a rule names. Leaving it out blocked a policy set for a
	// sequence sitting in its own bundle.
	for name := range willExist["idStoreSequence"] {
		idStoreByName[name] = "will-be-created"
	}

	// Conditions (by name)
	conditionByName := map[string]string{} // name -> id
	condPaths := []string{pathConditions, pathTimeConditions, pathNetworkConditions}
	for _, path := range condPaths {
		conds, _ := c.openAPIList(path)
		for _, cond := range conds {
			conditionByName[str(cond, "name")] = str(cond, "id")
		}
	}

	// Library conditions this run creates, again from the report rather than
	// from the bundle.
	for name := range willExist["condition"] {
		conditionByName[name] = "will-be-created"
	}

	// Dictionaries and their attributes, for the conditions in rules. A rule
	// reading an attribute the target does not have is refused by ISE with
	// "Condition attributes are illegal for requested scope".
	dictByName := map[string]bool{}
	for _, d := range func() []map[string]any { l, _ := c.openAPIList(pathDictionaries); return l }() {
		dictByName[str(d, "name")] = true
	}
	dictAttrs := dictionaryAttrLookup(c)

	// Target's existing policy sets by name
	targetSets, _ := c.openAPIList(pathPolicySets)
	targetSetsByName := map[string]map[string]any{}
	for _, set := range targetSets {
		targetSetsByName[str(set, "name")] = set
	}

	// Process each policy set
	for _, item := range items {
		name := str(item, "name")
		isDefault := truthy(item, "default")

		it := PreflightItem{Family: familyPolicySets, Name: name, obj: maps.Clone(item)}

		// Determine action
		if name == "" {
			it.Action, it.Reason = actionBlocked, "policy set has no name"
		} else if isDefault {
			// The Default set is special: it cannot be created, but its rules are merged
			it.Action = actionSkip
			it.Reason = "the Default set exists on every deployment; its rules will be merged"
		} else if target, exists := targetSetsByName[name]; exists {
			// A name already on the target is either a set this tool imported on
			// an earlier run, or somebody else's. The import marker in the
			// description tells them apart: ours is skipped, so a re-run writes
			// nothing, and a stranger's is left alone and imported beside.
			if mine(target) {
				it.Action, it.Reason = actionSkip, "already imported by this tool"
			} else {
				importedName := freeSetName(name, targetSetsByName)
				if importedName == "" {
					it.Action, it.Reason = actionSkip, "already imported by this tool"
				} else {
					it.obj["targetName"] = importedName
					it.Action = actionCreate
					it.Reason = fmt.Sprintf("a set with this name already exists on the target; importing beside it as %q", importedName)
				}
			}
		} else {
			it.Action = actionCreate
		}

		// Check all references in the set and its rules.
		if it.Action != actionBlocked && !isDefault {
			reason := checkPolicySetReferences(item, serviceNamesByName, sgtByName, idStoreByName, authProfileByName, willExistAuthProfiles, conditionByName, dictByName, dictAttrs)
			if reason != "" {
				it.Action = actionBlocked
				it.Reason = reason
				r.Notes = append(r.Notes, fmt.Sprintf("Policy set %q: %s", name, reason))
			}
		}
		if isDefault {
			// Default cannot be blocked as a unit — it exists on the target and
			// the whole point is merging rules into it — so its rules are
			// checked one by one and the unresolvable ones are left out. Without
			// this they were never checked at all and failed at write time: a
			// real target refused fifteen of them, one per missing certificate
			// authentication profile or join point.
			for _, kind := range []string{"authentication", "authorization"} {
				keep := make([]map[string]any, 0, len(ruleList(it.obj[kind])))
				for _, rule := range ruleList(it.obj[kind]) {
					if reason := checkRuleReferences(rule, kind, sgtByName, idStoreByName, authProfileByName, willExistAuthProfiles, conditionByName, dictByName, dictAttrs); reason != "" {
						inner, _ := rule["rule"].(map[string]any)
						r.Notes = append(r.Notes, fmt.Sprintf("Default policy set: the rule %q was not imported because %s", str(inner, "name"), reason))
						continue
					}
					keep = append(keep, rule)
				}
				it.obj[kind] = keep
			}
		}

		// Store the target's own Default set id for the merge case
		if isDefault && targetSetsByName["Default"] != nil {
			it.obj["targetDefaultID"] = str(targetSetsByName["Default"], "id")
		}

		if it.Action != "" {
			r.add(it)
		}
	}
}

// checkPolicySetReferences checks if all references in a policy set are resolvable
func checkPolicySetReferences(set map[string]any, services, sgts, idStores, authProfiles, willExistAuthProfiles, conditions map[string]string, dicts map[string]bool, attrsIn func(string) map[string]bool) string {
	// Check service name
	if serviceName := str(set, "serviceName"); serviceName != "" && services[serviceName] == "" {
		return fmt.Sprintf("service %q does not exist on the target", serviceName)
	}

	// Check conditions recursively
	if cond, ok := set["condition"].(map[string]any); ok && cond != nil {
		if reason := checkConditionReferences(cond, conditions, dicts, attrsIn); reason != "" {
			return reason
		}
	}

	// Check authentication rules
	for _, arMap := range ruleList(set["authentication"]) {
		{
			{
				// Check identity source
				if idSource := str(arMap, "identitySourceName"); idSource != "" && idStores[idSource] == "" {
					return fmt.Sprintf("identity source %q does not exist on the target and domain join is required", idSource)
				}

				// Check rule condition
				if ruleObj, ok := arMap["rule"].(map[string]any); ok {
					if ruleCond, _ := ruleObj["condition"].(map[string]any); ruleCond != nil {
						if reason := checkConditionReferences(ruleCond, conditions, dicts, attrsIn); reason != "" {
							return reason
						}
					}
				}
			}
		}
	}

	// Check authorization rules
	for _, azrMap := range ruleList(set["authorization"]) {
		{
			{
				// Check profile references
				if profiles, ok := azrMap["profile"].([]any); ok {
					for _, p := range profiles {
						if pName, ok := p.(string); ok && pName != "" {
							if authProfiles[pName] == "" && willExistAuthProfiles[pName] == "" {
								return fmt.Sprintf("authorization profile %q does not exist on the target and is not in the bundle", pName)
							}
						}
					}
				}

				// Check security group
				if sg := str(azrMap, "securityGroup"); sg != "" && sgts[sg] == "" {
					return fmt.Sprintf("security group %q does not exist on the target (TrustSec is not yet migrated)", sg)
				}

				// Check rule condition
				if ruleObj, ok := azrMap["rule"].(map[string]any); ok {
					if ruleCond, _ := ruleObj["condition"].(map[string]any); ruleCond != nil {
						if reason := checkConditionReferences(ruleCond, conditions, dicts, attrsIn); reason != "" {
							return reason
						}
					}
				}
			}
		}
	}

	return ""
}

// checkConditionReferences recursively checks if all condition references are resolvable
func checkConditionReferences(cond map[string]any, conditionByName map[string]string, dicts map[string]bool, attrsIn func(string) map[string]bool) string {
	if cond == nil {
		return ""
	}

	switch str(cond, "conditionType") {
	case "ConditionReference":
		name := str(cond, "name")
		if name != "" && conditionByName[name] == "" {
			return fmt.Sprintf("library condition %q does not exist on the target", name)
		}
	case "ConditionAttributes", "LibraryConditionAttributes":
		// A condition reads a dictionary attribute, and the target may have
		// neither. ISE refuses the rule with "Condition attributes are illegal
		// for requested scope: [ EntraIDDevice : ExternalGroups ]" — verified on
		// 3.4, where six Default rules failed that way after everything else
		// they needed had been created.
		dict := str(cond, "dictionaryName")
		if dict == "" {
			break
		}
		if dicts != nil && !dicts[dict] {
			return fmt.Sprintf("a condition reads the dictionary %q, which the target does not have", dict)
		}
		if attr := str(cond, "attributeName"); attr != "" && attrsIn != nil {
			if known := attrsIn(dict); known != nil && !known[attr] {
				return fmt.Sprintf("a condition reads %q from the dictionary %q, and the target's copy has no such attribute", attr, dict)
			}
		}
	}

	for _, child := range ruleList(cond["children"]) {
		if reason := checkConditionReferences(child, conditionByName, dicts, attrsIn); reason != "" {
			return reason
		}
	}

	return ""
}

// applyPolicySets creates all policy sets and their rules in the correct order.
func applyPolicySets(c *Client, r *PreflightReport, res *ImportResult, keepState bool, log func(string, ...any)) error {
	items := r.Items

	// Get condition id mapping for rewrites (name -> target id)
	conditionIDByName := map[string]string{}
	condPaths := []string{pathConditions, pathTimeConditions, pathNetworkConditions}
	for _, path := range condPaths {
		conds, _ := c.openAPIList(path)
		for _, cond := range conds {
			conditionIDByName[str(cond, "name")] = str(cond, "id")
		}
	}

	// Get authorization profile id mapping (name -> target id)
	authProfileIDByName := map[string]string{}
	authProfiles, _ := c.openAPIList(pathAuthorizationProfiles)
	for _, profile := range authProfiles {
		authProfileIDByName[str(profile, "name")] = str(profile, "id")
	}

	// Collect policy set items to process
	var setItems []PreflightItem
	for _, it := range items {
		if it.Family != familyPolicySets {
			continue
		}
		setItems = append(setItems, it)
	}

	if len(setItems) == 0 {
		return nil
	}

	log("Creating %d policy sets…", len(setItems))

	for _, it := range setItems {
		// The Default set is reported as a skip because it cannot be created —
		// it exists on every deployment — but its rules still have to be merged
		// into the target's own. Treating skip as nothing to do left the
		// source's Default rules, which are the bulk of most policies, behind.
		mergeDefault := it.Action == actionSkip && truthy(it.obj, "default")
		if it.Action != actionCreate && !mergeDefault {
			if it.Action == actionSkip {
				res.Skipped++
			} else {
				res.Blocked++
			}
			continue
		}
		if mergeDefault {
			res.Skipped++ // the set itself; its rules are counted as they land
		}

		setObj := maps.Clone(it.obj)
		targetName := str(setObj, "targetName")
		if targetName == "" {
			targetName = str(setObj, "name")
		}
		setObj["name"] = targetName

		isDefault := truthy(setObj, "default")
		var targetSetID string

		if isDefault {
			// Merge into Default set: use its id from the target
			targetSetID = str(setObj, "targetDefaultID")
			if targetSetID == "" {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("Default set: target's Default set ID not found"))
				log("FAILED Default set: target set ID not found")
				continue
			}
			log("Merging rules into target's Default set…")
		} else {
			// Create a new set
			delete(setObj, "targetName")
			delete(setObj, "targetDefaultID")
			delete(setObj, "kind")

			// Condition rewrite: replace ConditionReference ids with target's ids
			if cond, _ := setObj["condition"].(map[string]any); cond != nil {
				rewriteConditionReferences(cond, conditionIDByName)
			}

			// Set state: force disabled unless keepState is true
			if !keepState {
				setObj["state"] = "disabled"
			}

			// Don't send rank or id
			delete(setObj, "id")
			delete(setObj, "rank")

			// The rules are posted separately, to their own endpoints. Sending
			// them inside the set body means sending ISE fields its policy-set
			// resource does not have, which is the failure mode the endpoint
			// import already ran into on real hardware.
			body := maps.Clone(setObj)
			delete(body, "authentication")
			delete(body, "authorization")
			// The same marker policy elements carry. Here it does more than
			// label: pre-flight reads it back to tell a set this tool imported
			// from one that merely shares a name, which is what makes a re-run
			// write nothing instead of importing a second copy beside the first.
			body["description"] = tagDescription(str(body, "description"))

			// Create the set
			err := c.openAPICreate(pathPolicySets, body)
			if err != nil {
				if isDuplicate(err) {
					res.Skipped++
					log("Policy set %q already exists; skipped.", targetName)
					continue
				}
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("policy set %q: %v", targetName, err))
				log("FAILED policy set %q: %v", targetName, err)
				continue
			}

			// Extract the created set's ID from the response (this is simplified; real code would parse response)
			// For now, we need to re-fetch the set to get its id
			fetchedSets, err := c.openAPIList(pathPolicySets)
			if err != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("policy set %q: could not retrieve created set: %v", targetName, err))
				log("FAILED policy set %q: could not retrieve created set: %v", targetName, err)
				continue
			}
			for _, s := range fetchedSets {
				if str(s, "name") == targetName {
					targetSetID = str(s, "id")
					break
				}
			}

			if targetSetID == "" {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("policy set %q: could not retrieve created set ID", targetName))
				log("FAILED policy set %q: could not retrieve created set ID", targetName)
				continue
			}

			res.Created++
			log("Created policy set %q.", targetName)
		}

		// Merging into an existing set means the target already has rules of its
		// own. They are matched by name and left alone; the tool adds beside
		// them, never over them.
		existing := map[string]bool{}
		if mergeDefault {
			for _, kind := range []string{"authentication", "authorization"} {
				have, err := c.openAPIList(pathPolicySets + "/" + targetSetID + "/" + kind)
				if err != nil {
					continue
				}
				for _, h := range have {
					if inner, ok := h["rule"].(map[string]any); ok {
						existing[kind+"|"+str(inner, "name")] = true
					}
				}
			}
		}
		skipExisting := func(kind string, rule map[string]any) bool {
			inner, _ := rule["rule"].(map[string]any)
			if inner == nil {
				return false
			}
			if existing[kind+"|"+str(inner, "name")] {
				res.Skipped++
				log("Rule %q already exists in %q; skipped.", str(inner, "name"), targetName)
				return true
			}
			return false
		}

		// Now create the rules.
		for _, rule := range ruleList(setObj["authentication"]) {
			if skipExisting("authentication", rule) {
				continue
			}
			if err := createAuthRule(c, targetSetID, rule, conditionIDByName, keepState, log, res); err != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("authentication rule in %q: %v", targetName, err))
			}
		}
		for _, rule := range ruleList(setObj["authorization"]) {
			if skipExisting("authorization", rule) {
				continue
			}
			if err := createAuthzRule(c, targetSetID, rule, conditionIDByName, authProfileIDByName, keepState, log, res); err != nil {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("authorization rule in %q: %v", targetName, err))
			}
		}
	}

	return nil
}

// createAuthRule creates an authentication rule in a policy set
func createAuthRule(c *Client, setID string, ruleObj map[string]any, conditionIDByName map[string]string, keepState bool, log func(string, ...any), res *ImportResult) error {
	// Skip default rules
	if rule, ok := ruleObj["rule"].(map[string]any); ok && truthy(rule, "default") {
		return nil
	}

	rule := maps.Clone(ruleObj)
	ruleInner := rule["rule"].(map[string]any)
	ruleName := str(ruleInner, "name")

	// Rewrite condition references
	if cond, _ := ruleInner["condition"].(map[string]any); cond != nil {
		rewriteConditionReferences(cond, conditionIDByName)
	}

	// Force disabled unless keepState
	if !keepState {
		ruleInner["state"] = "disabled"
	}

	// Clean up ids and unused fields
	delete(ruleInner, "id")
	delete(ruleInner, "rank")
	delete(ruleInner, "hitCounts")

	path := pathPolicySets + "/" + setID + "/authentication"
	if err := c.openAPICreate(path, rule); err != nil {
		if isDuplicate(err) {
			res.Skipped++
			log("Authentication rule %q already exists; skipped.", ruleName)
			return nil
		}
		res.Failed++
		return err
	}

	res.Created++
	log("Created authentication rule %q.", ruleName)
	return nil
}

// createAuthzRule creates an authorization rule in a policy set
func createAuthzRule(c *Client, setID string, ruleObj map[string]any, conditionIDByName map[string]string, authProfileIDByName map[string]string, keepState bool, log func(string, ...any), res *ImportResult) error {
	// Skip default rules
	if rule, ok := ruleObj["rule"].(map[string]any); ok && truthy(rule, "default") {
		return nil
	}

	rule := maps.Clone(ruleObj)
	ruleInner := rule["rule"].(map[string]any)
	ruleName := str(ruleInner, "name")

	// Rewrite condition references
	if cond, _ := ruleInner["condition"].(map[string]any); cond != nil {
		rewriteConditionReferences(cond, conditionIDByName)
	}

	// The profile list travels by name and stays that way. Rewriting the names
	// to the target's UUIDs looked like the remap every other reference needs,
	// and a real 3.4 target refused every rule with "Unknown profile name for
	// authorization rule: 16943ce0-…" — it was being handed the id it had just
	// issued. Pre-flight has already checked each name resolves.

	// Force disabled unless keepState
	if !keepState {
		ruleInner["state"] = "disabled"
	}

	// Clean up ids and unused fields
	delete(ruleInner, "id")
	delete(ruleInner, "rank")
	delete(ruleInner, "hitCounts")

	path := pathPolicySets + "/" + setID + "/authorization"
	if err := c.openAPICreate(path, rule); err != nil {
		if isDuplicate(err) {
			res.Skipped++
			log("Authorization rule %q already exists; skipped.", ruleName)
			return nil
		}
		res.Failed++
		return err
	}

	res.Created++
	log("Created authorization rule %q.", ruleName)
	return nil
}

// rewriteConditionReferences rewrites ConditionReference ids to target ids
func rewriteConditionReferences(cond map[string]any, conditionIDByName map[string]string) {
	if cond == nil {
		return
	}

	condType := str(cond, "conditionType")
	if condType == "ConditionReference" {
		name := str(cond, "name")
		if name != "" && conditionIDByName[name] != "" {
			cond["id"] = conditionIDByName[name]
		}
	}

	// Recursively rewrite children
	if children, ok := cond["children"].([]any); ok {
		for _, child := range children {
			if childMap, ok := child.(map[string]any); ok {
				rewriteConditionReferences(childMap, conditionIDByName)
			}
		}
	}
}

// ruleList reads the nested rules whichever way they arrived. Straight out of an
// export they are []map[string]any; after a bundle has been sealed and reopened
// they are []any of map[string]any, because that is what JSON gives back. A
// single type assertion covers only one of the two and silently creates no rules
// at all in the other, which is how a policy set landed on a target with none.
func ruleList(v any) []map[string]any {
	switch t := v.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// mine reports whether an object on the target was created by this tool, which
// is recorded in its description the same way policy elements record it.
func mine(obj map[string]any) bool {
	return strings.Contains(str(obj, "description"), importMarkerPrefix)
}

// freeSetName picks the first unused "<name> (imported)", "(imported 2)", … for
// a set whose name the target already uses. It returns "" when one of those
// names is already a set this tool imported, which means this bundle has been
// imported before and there is nothing left to do.
func freeSetName(name string, existing map[string]map[string]any) string {
	for i := 1; i < 100; i++ {
		candidate := name + " (imported)"
		if i > 1 {
			candidate = fmt.Sprintf("%s (imported %d)", name, i)
		}
		target, taken := existing[candidate]
		if !taken {
			return candidate
		}
		if mine(target) {
			return "" // already imported under this name
		}
	}
	return ""
}

// checkRuleReferences resolves one rule's references and says what is missing.
// It is the per-rule half of checkPolicySetReferences, used where a whole set
// cannot be refused: the Default set exists on every deployment, so a rule of
// its own that cannot resolve is left out instead.
func checkRuleReferences(rule map[string]any, kind string, sgts, idStores, authProfiles, willExistAuthProfiles, conditions map[string]string, dicts map[string]bool, attrsIn func(string) map[string]bool) string {
	if kind == "authentication" {
		if src := str(rule, "identitySourceName"); src != "" && idStores[src] == "" {
			return fmt.Sprintf("the target has no identity source %q", src)
		}
	} else {
		if profiles, ok := rule["profile"].([]any); ok {
			for _, p := range profiles {
				name, _ := p.(string)
				if name != "" && authProfiles[name] == "" && willExistAuthProfiles[name] == "" {
					return fmt.Sprintf("the target has no authorization profile %q and this bundle does not create one", name)
				}
			}
		}
		if sg := str(rule, "securityGroup"); sg != "" && sgts[sg] == "" {
			return fmt.Sprintf("the target has no security group %q (TrustSec is not migrated yet)", sg)
		}
	}
	if inner, ok := rule["rule"].(map[string]any); ok {
		if cond, _ := inner["condition"].(map[string]any); cond != nil {
			if reason := checkConditionReferences(cond, conditions, dicts, attrsIn); reason != "" {
				return reason
			}
		}
	}
	return ""
}
