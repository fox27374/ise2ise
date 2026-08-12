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
		// The application secret does not travel. The tool cannot create a REST
		// identity store at all — see below — so carrying the secret would put a
		// credential in a file to no purpose. Everything else is kept, because
		// the report uses it to tell the operator what to build by hand.
		dropClientSecret(store)
		out = append(out, stripLocal(store))
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

		// A REST identity store is never created. ISE cannot make a usable one
		// over its API: the device attributes and device query settings cannot
		// be written, and a store without them cannot be saved in the GUI
		// either, because the tabs that would supply them are not shown. It is
		// reported with what the operator needs to build it by hand.
		if kind == "restIDStore" && !targetRestStores[name] {
			it.Action, it.Reason = actionBlocked, restStoreManualSteps(item)
			r.add(it)
			continue
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
	ignore := map[string]bool{
		// Neither can be written by any API, so the bundle carrying a copy the
		// target lacks is expected, not drift.
		"ersRestIDStoreDeviceAttributes": true,
		"ersRestIDStoreAdvanceSettings":  true,
		"id":                             true, "link": true, "kind": true}
	seen := map[string]bool{}
	var fields []string

	for _, m := range []map[string]any{mine, theirs} {
		for k := range m {
			if ignore[k] || seen[k] {
				continue
			}
			seen[k] = true

			a, b := mine[k], theirs[k]

			// A REST identity store's attributes are compared without the client
			// secret on either side: the bundle deliberately does not carry one,
			// so comparing it would report every store as differing in the one
			// field the tool has decided not to migrate.
			if kind == "restIDStore" && k == "ersRestIDStoreAttributes" {
				aAttrs, aOk := a.(map[string]any)
				bAttrs, bOk := b.(map[string]any)
				if !aOk || !bOk {
					if !mapsEqual(a, b) {
						fields = append(fields, k)
					}
					continue
				}
				aCopy, bCopy := maps.Clone(aAttrs), maps.Clone(bAttrs)
				dropClientSecret(map[string]any{"ersRestIDStoreAttributes": aCopy})
				dropClientSecret(map[string]any{"ersRestIDStoreAttributes": bCopy})
				if attributesDiffer(aCopy, bCopy) {
					fields = append(fields, "connection settings")
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
// attributesDiffer compares two REST identity store attribute blocks.
//
// The client secret has already been removed from both sides by the caller, so
// what is left — rootUrl, the username suffix, the provider, the client and
// tenant ids — is ordinary configuration and is compared as such. An earlier
// version returned true whenever any header existed, on the grounds that a
// secret cannot be compared; that reported every store as drifting in the one
// field this tool has decided not to migrate.
func attributesDiffer(a, b map[string]any) bool {
	headerMap := func(m map[string]any) map[string]any {
		out := map[string]any{}
		for _, h := range extractHeaders(m) {
			out[str(h, "key")] = str(h, "value")
		}
		return out
	}
	if !mapsEqual(headerMap(a), headerMap(b)) {
		return true
	}
	seen := map[string]bool{}
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if k == "headers" || seen[k] {
				continue
			}
			seen[k] = true
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

// dropClientSecret removes the application secret from a REST identity store,
// in place, before it reaches the bundle. Every other header is kept: the client
// and tenant ids are what the operator needs to rebuild the store by hand, and
// neither is a credential on its own.
func dropClientSecret(store map[string]any) {
	attrs, _ := store["ersRestIDStoreAttributes"].(map[string]any)
	if attrs == nil {
		return
	}
	kept := []any{}
	for _, h := range ruleList(attrs["headers"]) {
		if str(h, "key") == "clientSecret" {
			continue
		}
		kept = append(kept, h)
	}
	attrs["headers"] = kept
}

// restStoreManualSteps is what the report tells the operator to build by hand.
// ISE cannot create one of these over its API: the device attributes and device
// query settings cannot be written, and a store missing them cannot be saved in
// the GUI either — its Device Attributes and Device Query tabs are not shown, so
// the required settings can never be supplied. Verified on 3.4 by creating one,
// failing to complete it every way the API allows, and watching the GUI refuse
// to save it.
func restStoreManualSteps(item map[string]any) string {
	attrs, _ := item["ersRestIDStoreAttributes"].(map[string]any)
	var b strings.Builder
	b.WriteString("a REST identity store cannot be created over ISE's API: its device attributes and device query settings cannot be written, and a store without them cannot be saved in the GUI either. Create it by hand under Administration > Identity Management > External Identity Sources > REST (ROPC)")
	if attrs != nil {
		fmt.Fprintf(&b, " — provider %q, rootUrl %q, username suffix %q",
			str(attrs, "predefined"), str(attrs, "rootUrl"), str(attrs, "usernameSuffix"))
		for _, h := range ruleList(attrs["headers"]) {
			if k := str(h, "key"); k == "clientID" || k == "tenantID" {
				fmt.Fprintf(&b, ", %s %q", k, str(h, "value"))
			}
		}
	}
	b.WriteString(". The client secret is deliberately not carried in the bundle; take it from your own records.")
	return b.String()
}
