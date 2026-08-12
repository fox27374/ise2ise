package main

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// ExportIdentitySources fills the bundle with identity sources: REST ID stores
// and certificate authentication profiles.
func ExportIdentitySources(c *Client, b *Bundle, families []string, log func(string, ...any)) error {
	if !slices.Contains(families, familyIdentitySources) {
		return nil
	}

	out := make([]map[string]any, 0, 32)

	// Export REST ID stores
	log("Listing REST ID stores…")
	restStubs, err := c.ersList(pathRestIDStore)
	if err != nil {
		return fmt.Errorf("listing REST ID stores: %w", err)
	}

	log("Found %d REST ID stores; reading them…", len(restStubs))
	restStores, err := c.ersGetAll(pathRestIDStore, rootRestIDStore, restStubs)
	if err != nil {
		return fmt.Errorf("reading REST ID stores: %w", err)
	}

	for _, store := range restStores {
		store["kind"] = "restIDStore"
		out = append(out, stripLocal(store))

		// Warn if this store carries a clientSecret
		attrs, _ := store["ersRestIDStoreAttributes"].(map[string]any)
		if headers := extractHeaders(attrs); len(headers) > 0 {
			for _, header := range headers {
				if str(header, "key") == "clientSecret" && str(header, "value") != "" {
					name := str(store, "name")
					b.Note("REST identity store %q carries an application secret and travels in the bundle; the file is credential material.", name)
					break
				}
			}
		}
	}

	log("Captured %d REST ID stores.", len(restStores))

	// Export certificate authentication profiles
	log("Listing certificate authentication profiles…")
	certStubs, err := c.ersList(pathCertificateProfile)
	if err != nil {
		return fmt.Errorf("listing certificate authentication profiles: %w", err)
	}

	log("Found %d certificate authentication profiles; reading them…", len(certStubs))
	certProfiles, err := c.ersGetAll(pathCertificateProfile, rootCertificateProfile, certStubs)
	if err != nil {
		return fmt.Errorf("reading certificate authentication profiles: %w", err)
	}

	for _, profile := range certProfiles {
		profile["kind"] = "certificateProfile"
		out = append(out, stripLocal(profile))
	}

	log("Captured %d certificate authentication profiles.", len(certProfiles))

	// Sort by kind then name for consistency
	sort.Slice(out, func(i, j int) bool {
		ki := str(out[i], "kind")
		kj := str(out[j], "kind")
		if ki != kj {
			return ki < kj
		}
		return strings.ToLower(str(out[i], "name")) < strings.ToLower(str(out[j], "name"))
	})

	b.Objects[familyIdentitySources] = out
	return nil
}

// preflightIdentitySources resolves every identity source against the target
// and reports what would happen. It is called after preflightADJoinPoints so
// that join points created in this run count as identity sources for the policy
// families checked afterwards.
func preflightIdentitySources(c *Client, b *Bundle, r *PreflightReport) {
	items := b.Objects[familyIdentitySources]
	if len(items) == 0 {
		return
	}

	// Read target's REST ID stores and certificate profiles
	targetByName := map[string]map[string]any{} // "kind\x00name" -> target object
	targetRestStores := map[string]bool{}       // name -> exists
	targetCertProfiles := map[string]bool{}     // name -> exists

	restStubs, _ := c.ersList(pathRestIDStore)
	for _, stub := range restStubs {
		targetRestStores[stub.Name] = true
	}

	if restDetails, err := c.ersGetAll(pathRestIDStore, rootRestIDStore, restStubs); err == nil {
		for _, detail := range restDetails {
			name := str(detail, "name")
			targetByName["restIDStore\x00"+name] = detail
		}
	}

	certStubs, _ := c.ersList(pathCertificateProfile)
	for _, stub := range certStubs {
		targetCertProfiles[stub.Name] = true
	}

	if certDetails, err := c.ersGetAll(pathCertificateProfile, rootCertificateProfile, certStubs); err == nil {
		for _, detail := range certDetails {
			name := str(detail, "name")
			targetByName["certificateProfile\x00"+name] = detail
		}
	}

	// Process each item
	for _, item := range items {
		kind := str(item, "kind")
		name := str(item, "name")
		it := PreflightItem{Family: familyIdentitySources, Name: name, obj: maps.Clone(item)}

		// ERS refuses a name with anything but letters, digits and underscore:
		// "name field may contain only alphanumeric and _ characters". The GUI
		// is more permissive, so a source can hold a name ERS will not accept.
		if kind == "restIDStore" && !ersSafeName(name) {
			it.Action, it.Reason = actionBlocked,
				"ERS refuses this name on create — a REST identity store name may contain only letters, digits and underscores. Rename it on the source, or create it by hand on the target."
			r.add(it)
			continue
		}

		if kind == "restIDStore" {
			noteRestStoreGaps(item, r)
		}

		// Determine if target has this object
		exists := false
		if kind == "restIDStore" {
			exists = targetRestStores[name]
		} else if kind == "certificateProfile" {
			exists = targetCertProfiles[name]
		}

		switch {
		case name == "":
			it.Action, it.Reason = actionBlocked, fmt.Sprintf("the bundle holds a %s with no name", kind)

		case kind != "restIDStore" && kind != "certificateProfile":
			it.Action, it.Reason = actionBlocked, fmt.Sprintf("unknown object kind %q", kind)

		case kind == "certificateProfile" && name == "Preloaded_Certificate_Profile":
			// Skip the factory certificate profile
			it.Action, it.Reason = actionSkip, "factory certificate profile"

		case exists:
			it.Action = actionSkip
			it.Reason = "already exists on the target"
			// Report differences, redacting secrets
			targetObj := targetByName[kind+"\x00"+name]
			if targetObj != nil {
				if fields := driftFieldsIdentitySource(item, targetObj, kind); len(fields) > 0 {
					it.Reason = fmt.Sprintf("already exists on the target and DIFFERS from the source in %s; not changed — edit it on the target if the source's version is the one you want", strings.Join(fields, ", "))
				}
			}

		default:
			it.Action = actionCreate
		}

		if it.Action != "" {
			r.add(it)
		}
	}
}

// applyIdentitySources creates all identity sources.
func applyIdentitySources(c *Client, r *PreflightReport, res *ImportResult, log func(string, ...any)) error {
	items := r.Items

	// Count creations by kind
	var createCount int
	for _, it := range items {
		if it.Family == familyIdentitySources && it.Action == actionCreate {
			createCount++
		}
	}

	if createCount > 0 {
		log("Creating %d identity sources…", createCount)
		for _, it := range items {
			if it.Family != familyIdentitySources {
				continue
			}

			if it.Action == actionSkip {
				res.Skipped++
				continue
			}

			if it.Action != actionCreate {
				res.Blocked++
				continue
			}

			kind := str(it.obj, "kind")
			name := it.Name

			obj := maps.Clone(it.obj)
			delete(obj, "kind")

			var path, root string
			if kind == "restIDStore" {
				path = pathRestIDStore
				root = rootRestIDStore
				// ERS refuses a REST ID store create carrying either of these,
				// and refuses a PUT adding them afterwards — both answer
				// "Resource Initialization Failed due to JSON invalidity"
				// naming the block. They are GUI-only. Verified on 3.4 by
				// bisecting the payload: attributes plus user attributes is
				// accepted (201), either of these two turns it into a 400, and
				// user attributes are required rather than optional.
				delete(obj, "ersRestIDStoreDeviceAttributes")
				delete(obj, "ersRestIDStoreAdvanceSettings")
			} else if kind == "certificateProfile" {
				path = pathCertificateProfile
				root = rootCertificateProfile
			} else {
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s %q: unknown kind %q", kind, name, kind))
				continue
			}

			if err := c.ersCreate(path, root, obj); err != nil {
				if isDuplicate(err) {
					res.Skipped++
					log("%s %q already exists; skipped.", kind, name)
				} else {
					res.Failed++
					// If error text might contain a secret, don't include the request body
					errMsg := fmt.Sprintf("%s %q: %v", kind, name, err)
					res.Errors = append(res.Errors, errMsg)
					log("FAILED %s", errMsg)
				}
				continue
			}

			res.Created++
			log("Created %s %q.", kind, name)
		}
	}

	return nil
}

// identitySourcesAfterThisRun returns the identity source names (both REST ID
// stores and certificate profiles) that will exist after this import, including
// the named REST ID stores from this bundle plus any that will be created.
func identitySourcesAfterThisRun(c *Client, r *PreflightReport) map[string]bool {
	names := map[string]bool{}

	// Add existing REST ID stores
	stubs, _ := c.ersList(pathRestIDStore)
	for _, s := range stubs {
		names[s.Name] = true
	}

	// Add existing certificate profiles
	stubs, _ = c.ersList(pathCertificateProfile)
	for _, s := range stubs {
		names[s.Name] = true
	}

	// Add those created in this run
	for _, it := range r.Items {
		if it.Family == familyIdentitySources && it.Action == actionCreate {
			if name := str(it.obj, "name"); name != "" {
				names[name] = true
			}
		}
	}

	return names
}

// driftFieldsIdentitySource names the fields in which the bundle's object and
// the target's own copy disagree, redacting secret values.
func driftFieldsIdentitySource(mine, theirs map[string]any, kind string) []string {
	if theirs == nil {
		return nil
	}
	ignore := map[string]bool{"id": true, "link": true, "kind": true}
	seen := map[string]bool{}
	var fields []string

	for _, m := range []map[string]any{mine, theirs} {
		for k := range m {
			if ignore[k] || seen[k] {
				continue
			}
			seen[k] = true

			a, b := mine[k], theirs[k]

			// For REST ID stores, check attributes without comparing secret values
			if kind == "restIDStore" && k == "ersRestIDStoreAttributes" {
				aAttrs, aOk := a.(map[string]any)
				bAttrs, bOk := b.(map[string]any)
				if !aOk || !bOk {
					if !mapsEqual(a, b) {
						fields = append(fields, k)
					}
					continue
				}

				// Check if attributes differ, with special handling for headers
				differs := attributesDiffer(aAttrs, bAttrs)
				if differs {
					fields = append(fields, "clientSecret")
				}
				continue
			}

			if !mapsEqual(a, b) {
				fields = append(fields, k)
			}
		}
	}
	sort.Strings(fields)
	return fields
}

// attributesDiffer checks if two attribute blocks differ, treating header values as secrets
func attributesDiffer(a, b map[string]any) bool {
	// Check structural properties
	aHeaders := extractHeaders(a)
	bHeaders := extractHeaders(b)

	// Different number of headers means they differ
	if len(aHeaders) != len(bHeaders) {
		return true
	}

	// Compare all keys in both maps except for specific handling of headers
	seen := make(map[string]bool)
	for k := range a {
		seen[k] = true
		if k == "headers" {
			// For headers, only compare keys, not values (values are secrets)
			aKeys := make(map[string]bool)
			for _, h := range aHeaders {
				aKeys[str(h, "key")] = true
			}
			bKeys := make(map[string]bool)
			for _, h := range bHeaders {
				bKeys[str(h, "key")] = true
			}
			if !mapsEqual(aKeys, bKeys) {
				return true
			}
			// Keys match but values might differ - be conservative and report as differing
			// since we can't check the values (they're secrets)
			if len(aHeaders) > 0 {
				return true // Headers might have changed values, report as different
			}
		} else if !mapsEqual(a[k], b[k]) {
			return true
		}
	}

	// Check keys only in b
	for k := range b {
		if !seen[k] && k != "headers" {
			if !mapsEqual(a[k], b[k]) {
				return true
			}
		}
	}

	return false
}

// extractHeaders extracts the headers array from a REST ID store attributes block.
func extractHeaders(attrsObj any) []map[string]any {
	if attrsObj == nil {
		return nil
	}
	attrsMap, ok := attrsObj.(map[string]any)
	if !ok {
		return nil
	}
	headersObj, ok := attrsMap["headers"].([]any)
	if !ok {
		return nil
	}
	var result []map[string]any
	for _, h := range headersObj {
		if hm, ok := h.(map[string]any); ok {
			result = append(result, hm)
		}
	}
	return result
}

// mapsEqual compares two maps of strings.
func mapsEqual(a, b any) bool {
	// Simple comparison that doesn't recurse into complex structures
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	return aStr == bStr
}

// ersSafeName reports whether ERS will accept a REST identity store name.
// Verified on 3.4: "name field may contain only alphanumeric and _ characters".
func ersSafeName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// noteRestStoreGaps names the parts of a REST identity store that cannot travel.
// ERS accepts neither on a create nor on a PUT afterwards, so the operator sets
// them in the GUI or the store behaves differently from the source's.
func noteRestStoreGaps(item map[string]any, r *PreflightReport) {
	name := str(item, "name")
	var missing []string
	if _, ok := item["ersRestIDStoreDeviceAttributes"]; ok {
		missing = append(missing, "its device attributes")
	}
	if _, ok := item["ersRestIDStoreAdvanceSettings"]; ok {
		missing = append(missing, "its advanced settings")
	}
	if len(missing) == 0 {
		return
	}
	r.Notes = append(r.Notes, fmt.Sprintf(
		"REST identity store %q: %s cannot be carried — ERS refuses both on a create and on an update, so set them in the ISE GUI after the import.",
		name, strings.Join(missing, " and ")))
}
