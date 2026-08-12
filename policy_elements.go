package main

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
)

// ExportPolicyElements fills the bundle with policy elements: network device
// groups, dACLs, authorization profiles, identity source sequences, and
// conditions. All five families are selected together.
func ExportPolicyElements(c *Client, b *Bundle, families []string, log func(string, ...any)) error {
	if !slices.Contains(families, familyPolicyElements) {
		return nil
	}

	// The five families are stored under one key with a kind field per object.
	out := make([]map[string]any, 0, 128)

	// 1. Network device groups (ERS)
	log("Listing network device groups…")
	ndgStubs, err := c.ersList(pathNetworkDeviceGroups)
	if err != nil {
		return fmt.Errorf("listing network device groups: %w", err)
	}
	log("Found %d network device groups; reading them…", len(ndgStubs))
	ndgs, err := c.ersGetAll(pathNetworkDeviceGroups, rootNetworkDeviceGroup, ndgStubs)
	if err != nil {
		return fmt.Errorf("reading network device groups: %w", err)
	}
	for _, g := range ndgs {
		g["kind"] = "networkDeviceGroup"
		out = append(out, stripLocal(g))
	}
	log("Captured %d network device groups.", len(ndgs))

	// 2. dACLs (ERS)
	log("Listing dACLs…")
	daclStubs, err := c.ersList(pathDownloadableACLs)
	if err != nil {
		return fmt.Errorf("listing dACLs: %w", err)
	}
	log("Found %d dACLs; reading them…", len(daclStubs))
	dacls, err := c.ersGetAll(pathDownloadableACLs, rootDownloadableACL, daclStubs)
	if err != nil {
		return fmt.Errorf("reading dACLs: %w", err)
	}
	for _, a := range dacls {
		a["kind"] = "dacl"
		out = append(out, stripLocal(a))
	}
	log("Captured %d dACLs.", len(dacls))

	// 3. Authorization profiles (OpenAPI stubs + ERS detail)
	log("Listing authorization profiles…")
	authProfiles, err := c.openAPIList(pathAuthProfilesAPI)
	if err != nil {
		return fmt.Errorf("listing authorization profiles from OpenAPI: %w", err)
	}
	log("Found %d authorization profile stubs; reading details…", len(authProfiles))

	// The collection read is unusable on 3.4 — it answers 500 with a conversion
	// exception on cisco-av-pair — so the stubs come from the OpenAPI, which
	// carries a name and an id and nothing else, and the detail comes per id.
	captured := 0
	for _, stub := range authProfiles {
		id := str(stub, "id")
		if id == "" {
			continue
		}
		detail, err := c.ersGetByID(pathAuthProfiles, id, rootAuthProfile)
		if err != nil {
			// ISE cannot deserialise some of its own profiles — a web redirection
			// is the case seen on 3.4. The stub is a name and an id, so carrying
			// it would put an empty profile on the target that looks migrated and
			// authorises nothing. Name it instead and carry the rest.
			b.Note("Authorization profile %q could not be read by the source's own ERS API and was not exported: %v. Recreate this profile by hand on the target.", str(stub, "name"), err)
			continue
		}
		detail["kind"] = "authorizationProfile"
		out = append(out, stripLocal(detail))
		captured++
	}
	log("Captured %d of %d authorization profiles.", captured, len(authProfiles))

	// 4. Identity source sequences (ERS)
	log("Listing identity source sequences…")
	issStubs, err := c.ersList(pathIdStoreSequences)
	if err != nil {
		return fmt.Errorf("listing identity source sequences: %w", err)
	}
	log("Found %d identity source sequences; reading them…", len(issStubs))
	isss, err := c.ersGetAll(pathIdStoreSequences, rootIdStoreSequence, issStubs)
	if err != nil {
		return fmt.Errorf("reading identity source sequences: %w", err)
	}
	for _, s := range isss {
		s["kind"] = "idStoreSequence"
		out = append(out, stripLocal(s))
	}
	log("Captured %d identity source sequences.", len(isss))

	// 5. Conditions (OpenAPI - three types)
	log("Reading conditions…")
	conditions := []map[string]any{}
	for _, path := range []string{pathConditions, pathTimeConditions, pathNetworkConditions} {
		conds, err := c.openAPIList(path)
		if err != nil {
			// Log but don't fail; empty collections are normal
			log("Could not read %s: %v", path, err)
			continue
		}
		for _, cond := range conds {
			cond["kind"] = "condition"
			// Which of the three collections it belongs to, so the import puts it
			// back where it came from rather than into the library.
			cond["conditionPath"] = path
			conditions = append(conditions, stripLocal(cond))
		}
	}
	log("Captured %d conditions.", len(conditions))
	out = append(out, conditions...)

	// Sort by kind then name for consistency
	sort.Slice(out, func(i, j int) bool {
		ki := str(out[i], "kind")
		kj := str(out[j], "kind")
		if ki != kj {
			return ki < kj
		}
		return strings.ToLower(str(out[i], "name")) < strings.ToLower(str(out[j], "name"))
	})

	b.Objects[familyPolicyElements] = out
	b.Note("Policy elements were read from ERS and OpenAPI.")
	return nil
}

// preflightPolicyElements resolves every cross-reference in the policy
// elements family and reports what would happen.
func preflightPolicyElements(c *Client, b *Bundle, r *PreflightReport) {
	items := b.Objects[familyPolicyElements]
	if len(items) == 0 {
		return
	}

	// Read target's relevant collections for cross-reference checks

	// The target's own objects, kept whole where they can be read, because a skip
	// is only half the answer: the operator also needs to know when the target's
	// copy differs from the source's.
	targetDetail := map[string]map[string]any{} // "kind\x00name" -> the target's object
	uncomparable := map[string]string{}         // "kind\x00name" -> why it could not be read
	key := func(kind, name string) string { return kind + "\x00" + name }

	// Network device groups by name
	ndgIDByName := map[string]bool{}
	ndgStubs, _ := c.ersList(pathNetworkDeviceGroups)
	for _, stub := range ndgStubs {
		ndgIDByName[stub.Name] = true
	}
	if objs, err := c.ersGetAll(pathNetworkDeviceGroups, rootNetworkDeviceGroup, ndgStubs); err == nil {
		for _, o := range objs {
			targetDetail[key("networkDeviceGroup", str(o, "name"))] = o
		}
	}

	// dACLs by name
	daclIDByName := map[string]bool{}
	daclStubs, _ := c.ersList(pathDownloadableACLs)
	for _, stub := range daclStubs {
		daclIDByName[stub.Name] = true
	}
	if objs, err := c.ersGetAll(pathDownloadableACLs, rootDownloadableACL, daclStubs); err == nil {
		for _, o := range objs {
			targetDetail[key("dacl", str(o, "name"))] = o
		}
	}

	// Authorization profiles from OpenAPI stubs, detail per id — the collection
	// read is the one that answers 500.
	authProfileIDByName := map[string]bool{}
	authProfiles, _ := c.openAPIList(pathAuthProfilesAPI)
	for _, p := range authProfiles {
		name := str(p, "name")
		authProfileIDByName[name] = true
		detail, err := c.ersGetByID(pathAuthProfiles, str(p, "id"), rootAuthProfile)
		if err != nil {
			uncomparable[key("authorizationProfile", name)] = err.Error()
			continue
		}
		targetDetail[key("authorizationProfile", name)] = detail
	}

	// Dictionaries
	// Attributes inside a dictionary, read once per dictionary and only for the
	// ones a profile actually names.
	attrCache := map[string]map[string]bool{}
	dictAttrs := func(dict string) map[string]bool {
		if known, ok := attrCache[dict]; ok {
			return known
		}
		attrs, err := c.openAPIListOnce(pathDictionaries + "/" + dict + "/attribute")
		if err != nil {
			attrCache[dict] = nil // unknown is not the same as absent; do not block on it
			return nil
		}
		known := map[string]bool{}
		for _, a := range attrs {
			known[str(a, "name")] = true
		}
		attrCache[dict] = known
		return known
	}

	dictionaryByName := map[string]bool{}
	dicts, _ := c.openAPIList(pathDictionaries)
	for _, d := range dicts {
		dictionaryByName[str(d, "name")] = true
	}

	// AD join points, the target's own plus any this run will create. An
	// unjoined join point still exists as an identity source, so a sequence
	// naming it resolves — which is what lets a first migration carry the join
	// point and the sequences that depend on it in one pass. Its dictionary and
	// its groups are deliberately not counted: those appear only once someone
	// joins the domain.
	adJoinPointByName := joinPointsAfterThisRun(c, r)

	// Identity source sequences. The built-in store names are always present on
	// any deployment; everything else has to be read.
	idSourceByName := map[string]bool{}
	idSourceByName["Internal Users"] = true
	idSourceByName["Guest Users"] = true
	idSourceByName["All_AD_Join_Points"] = true
	idSourceByName["Internal Endpoints"] = true
	issStubs, _ := c.ersList(pathIdStoreSequences)
	for _, stub := range issStubs {
		idSourceByName[stub.Name] = true
	}
	issByName := map[string]bool{}
	for _, stub := range issStubs {
		issByName[stub.Name] = true
	}
	if objs, err := c.ersGetAll(pathIdStoreSequences, rootIdStoreSequence, issStubs); err == nil {
		for _, o := range objs {
			targetDetail[key("idStoreSequence", str(o, "name"))] = o
		}
	}

	// Conditions, whole objects straight off the list.
	conditionByName := map[string]bool{}
	for _, path := range []string{pathConditions, pathTimeConditions, pathNetworkConditions} {
		objs, err := c.openAPIList(path)
		if err != nil {
			r.Notes = append(r.Notes, fmt.Sprintf("Policy elements: the target's conditions at %s could not be read, so they were not deduplicated: %v", path, err))
			continue
		}
		for _, o := range objs {
			name := str(o, "name")
			conditionByName[name] = true
			targetDetail[key("condition", name)] = o
		}
	}

	// Certificate profiles and REST ID stores: get the target's copies plus any
	// created in this run so a sequence naming them resolves.
	certProfileByName := map[string]bool{}
	certStubs, _ := c.ersList(pathCertificateProfile)
	for _, stub := range certStubs {
		certProfileByName[stub.Name] = true
	}

	// Add identity sources created in this run
	idSourcesThisRun := identitySourcesAfterThisRun(c, r)
	for name := range idSourcesThisRun {
		idSourceByName[name] = true
		// If it's a cert profile created this run, also add to certProfileByName
		// Note: we need to check if it's a cert profile by looking at the items
		for _, it := range r.Items {
			if it.Family == familyIdentitySources && it.Action == actionCreate &&
				str(it.obj, "name") == name && str(it.obj, "kind") == "certificateProfile" {
				certProfileByName[name] = true
			}
		}
	}

	// willExist tracks what will exist after this import (bundles created in same run)
	willExist := map[string]map[string]bool{
		"networkDeviceGroup": maps.Clone(ndgIDByName),
		"dacl":               maps.Clone(daclIDByName),
	}

	// Process network device groups first; ancestors may need to be pulled in
	ndgsByName := map[string]map[string]any{}
	for _, item := range items {
		if str(item, "kind") == "networkDeviceGroup" {
			name := str(item, "name")
			ndgsByName[name] = item
		}
	}

	// Pull in ancestors for selected groups
	selectedNDGs := []string{}
	for name := range ndgsByName {
		selectedNDGs = append(selectedNDGs, name)
		// Parents are nested in the name (e.g., "Device Type#All Device Types#Router")
		ancestors := extractAncestors(name)
		for _, ancestor := range ancestors {
			if !ndgIDByName[ancestor] && !willExist["networkDeviceGroup"][ancestor] {
				// Create a synthetic ancestor for pre-flight reporting
				// othername is the group type — the first segment of the path —
				// and ERS refuses a device group without it.
				root, _, _ := strings.Cut(ancestor, "#")
				ancestorItem := map[string]any{
					"name":      ancestor,
					"kind":      "networkDeviceGroup",
					"othername": root,
				}
				willExist["networkDeviceGroup"][ancestor] = true
				it := PreflightItem{
					Family: familyPolicyElements,
					Name:   ancestor,
					Action: actionCreate,
					Reason: fmt.Sprintf("created because %q needs it", name),
					obj:    ancestorItem,
				}
				r.add(it)
			}
		}
	}

	// Now process all items
	for _, item := range items {
		kind := str(item, "kind")
		name := str(item, "name")
		it := PreflightItem{Family: familyPolicyElements, Name: name, obj: maps.Clone(item)}

		// One rule for all five families: a name the target already has is
		// skipped and never written, factory or not. What differs between the
		// two copies is reported instead, because a customised factory object
		// left at the target's version is the failure this reporting exists to
		// catch — and the tool still writes nothing.
		exists := map[string]bool{
			"networkDeviceGroup":   ndgIDByName[name],
			"dacl":                 daclIDByName[name],
			"authorizationProfile": authProfileIDByName[name],
			"idStoreSequence":      issByName[name],
			"condition":            conditionByName[name],
		}[kind]

		switch {
		case name == "":
			it.Action, it.Reason = actionBlocked, fmt.Sprintf("the bundle holds a %s with no name", kind)
		case kind != "networkDeviceGroup" && kind != "dacl" && kind != "authorizationProfile" &&
			kind != "idStoreSequence" && kind != "condition":
			it.Action, it.Reason = actionBlocked, fmt.Sprintf("unknown object kind %q", kind)
		case exists:
			it.Action, it.Reason = actionSkip, "already exists on the target"
			if why, ok := uncomparable[key(kind, name)]; ok {
				it.Reason = "already exists on the target; its content could not be compared: " + why
			} else if fields := driftFields(item, targetDetail[key(kind, name)]); len(fields) > 0 {
				it.Reason = fmt.Sprintf("already exists on the target and DIFFERS from the source in %s; not changed — edit it on the target if the source's version is the one you want", strings.Join(fields, ", "))
			}
		case kind == "authorizationProfile":
			if reason := checkAuthProfileRefs(item, willExist["dacl"], daclIDByName, dictionaryByName, dictAttrs); reason != "" {
				it.Action, it.Reason = actionBlocked, reason
			} else {
				it.Action = actionCreate
			}
		case kind == "idStoreSequence":
			if reason := checkIdStoreSequenceRefs(item, adJoinPointByName, idSourceByName, certProfileByName); reason != "" {
				it.Action, it.Reason = actionBlocked, reason
			} else {
				it.Action = actionCreate
			}
		default:
			it.Action = actionCreate
			if kind == "networkDeviceGroup" || kind == "dacl" {
				willExist[kind][name] = true
			}
		}

		if it.Action != "" {
			r.add(it)
		}
	}
}

// extractAncestors returns all ancestors of a hierarchical name.
// E.g., "Device Type#All Device Types#Router" -> ["Device Type", "Device Type#All Device Types"]
// extractAncestors returns the groups a hierarchical name depends on.
//
// The first segment is the group *type* ("Device Type", "Location"), not a
// group: the topmost object is "Device Type#All Device Types". Treating that
// first segment as an ancestor made the import try to create "Device Type",
// which a real 3.4 target refused with "Mandatory fields missing: [othername]",
// five times in one run.
func extractAncestors(name string) []string {
	parts := strings.Split(name, "#")
	if len(parts) <= 2 {
		return nil
	}
	var ancestors []string
	for i := 2; i < len(parts); i++ {
		ancestors = append(ancestors, strings.Join(parts[:i], "#"))
	}
	return ancestors
}

// Policy elements have no enabled/disabled state — ISE offers one on policy sets
// and rules, and on nothing this family carries — so an object created by this
// tool is marked in its description instead. That is the only field every one of
// the five families has, and it is visible in the ISE list views without opening
// anything.
const importMarkerPrefix = "[ise2ise "

// ISE truncates or refuses an over-long description; 256 is the shortest limit
// seen across these resources, and losing the tail of a description is better
// than losing the object.
const maxDescription = 256

// importMarker is regenerated per call so a run started before midnight and
// finishing after it stays self-consistent within one object.
func importMarker(when time.Time) string {
	return importMarkerPrefix + when.Format("2006-01-02") + "]"
}

// tagDescription appends the marker, leaving an already-marked description
// alone so a re-created object does not collect two of them.
func tagDescription(desc string) string {
	marker := importMarker(time.Now())
	if strings.Contains(desc, importMarkerPrefix) {
		return desc
	}
	out := marker
	if desc != "" {
		out = desc + " " + marker
	}
	if len(out) > maxDescription {
		cut := maxDescription - len(marker) - 1
		if cut < 0 {
			return marker
		}
		out = strings.TrimSpace(desc[:cut]) + " " + marker
	}
	return out
}

// stripImportMarker removes the marker for comparison. Without this every object
// the tool created would report as drifted against its own source on the next
// run, which would make the drift report worthless exactly where it matters.
func stripImportMarker(desc string) string {
	i := strings.Index(desc, importMarkerPrefix)
	if i < 0 {
		return desc
	}
	end := strings.Index(desc[i:], "]")
	if end < 0 {
		return strings.TrimSpace(desc[:i])
	}
	return strings.TrimSpace(desc[:i] + desc[i+end+1:])
}

// driftFields names the fields in which the bundle's object and the target's own
// copy disagree. Deployment-local bookkeeping is ignored: an id and a link differ
// between any two deployments and say nothing, and kind is this tool's own.
//
// It is only ever used to explain a skip. Nothing here writes to the target.
func driftFields(mine, theirs map[string]any) []string {
	if theirs == nil {
		return nil
	}
	ignore := map[string]bool{"id": true, "link": true, "kind": true, "conditionPath": true}
	seen := map[string]bool{}
	var fields []string
	for _, m := range []map[string]any{mine, theirs} {
		for k := range m {
			if ignore[k] || seen[k] {
				continue
			}
			seen[k] = true
			a, bb := mine[k], theirs[k]
			if k == "description" {
				// The marker this tool adds is not drift.
				a, bb = stripImportMarker(str(mine, k)), stripImportMarker(str(theirs, k))
			}
			if !reflect.DeepEqual(a, bb) {
				fields = append(fields, k)
			}
		}
	}
	sort.Strings(fields)
	return fields
}

// checkAuthProfileRefs checks if an authorization profile's references are resolvable
func checkAuthProfileRefs(obj map[string]any, willExistDacl, existingDacl, existingDict map[string]bool, attrsIn func(string) map[string]bool) string {
	// Check dACL reference
	if daclName := str(obj, "daclName"); daclName != "" {
		if !existingDacl[daclName] && !willExistDacl[daclName] {
			return fmt.Sprintf("dACL %q does not exist on the target and is not in the bundle", daclName)
		}
	}

	// Check advancedAttributes for dictionary references, on both sides.
	//
	// The right-hand side can itself be a dictionary attribute rather than a
	// literal — an AD join point's dictionary, typically — and checking only the
	// left let such a profile through. A real 3.4 target answered the create
	// with HTTP 500 and an empty body, which is unusually unhelpful even for
	// this resource: the same profile with that one attribute removed creates
	// fine. Verified by bisecting the payload on 2026-08-10.
	for _, attr := range ruleList(obj["advancedAttributes"]) {
		for _, side := range []string{"leftHandSideDictionaryAttribue", "rightHandSideAttribueValue"} {
			s, ok := attr[side].(map[string]any)
			if !ok {
				continue
			}
			// A literal value carries no dictionary and needs no check.
			if str(s, "AdvancedAttributeValueType") != "AdvancedDictionaryAttribute" {
				continue
			}
			dictName := str(s, "dictionaryName")
			if dictName == "" {
				continue
			}
			if !existingDict[dictName] {
				return fmt.Sprintf("dictionary %q does not exist on the target", dictName)
			}
			// The dictionary can be present while the attribute inside it is
			// not: a custom endpoint attribute lives in the stock EndPoints
			// dictionary, and referencing one the target has never had earns the
			// same empty-bodied HTTP 500. Verified on 3.4, where the source's
			// EndPoints held 23 attributes and the target's 12.
			if attrName := str(s, "attributeName"); attrName != "" && attrsIn != nil {
				if known := attrsIn(dictName); known != nil && !known[attrName] {
					return fmt.Sprintf("the dictionary %q on the target has no attribute %q; it is a custom attribute and has to be created there first", dictName, attrName)
				}
			}
		}
	}

	return ""
}

// checkIdStoreSequenceRefs checks if an identity source sequence's references are resolvable
func checkIdStoreSequenceRefs(obj map[string]any, adJoins, idSources, certProfiles map[string]bool) string {
	// Check idSeqItem stores
	if items, ok := obj["idSeqItem"].([]any); ok {
		for _, item := range items {
			if itemMap, ok := item.(map[string]any); ok {
				if storeName := str(itemMap, "idstore"); storeName != "" {
					if !idSources[storeName] && !adJoins[storeName] {
						return fmt.Sprintf("identity source %q does not exist on the target and domain is not joined", storeName)
					}
				}
			}
		}
	}

	// Check certificate authentication profile
	if certProf := str(obj, "certificateAuthenticationProfile"); certProf != "" {
		if !certProfiles[certProf] {
			// This is not a hard block; certificate profiles are out of scope for now
			// Log but don't block
		}
	}

	return ""
}

// applyPolicyElements creates all policy elements in the correct order.
func applyPolicyElements(c *Client, r *PreflightReport, res *ImportResult, log func(string, ...any)) error {
	items := r.Items

	// Group items by kind and sort by action
	byKind := make(map[string][]PreflightItem)
	for _, it := range items {
		if it.Family != familyPolicyElements {
			continue
		}
		kind := str(it.obj, "kind")
		byKind[kind] = append(byKind[kind], it)
	}

	// Order: networkDeviceGroup, dacl, authorizationProfile, idStoreSequence, condition
	order := []string{"networkDeviceGroup", "dacl", "authorizationProfile", "idStoreSequence", "condition"}

	for _, kind := range order {
		items := byKind[kind]
		if len(items) == 0 {
			continue
		}

		log("Processing %d %s objects…", len(items), kind)

		for _, it := range items {
			if it.Action != actionCreate {
				if it.Action == actionSkip {
					res.Skipped++
				} else {
					res.Blocked++
				}
				continue
			}

			obj := maps.Clone(it.obj)
			delete(obj, "kind") // Remove synthetic kind field
			obj["description"] = tagDescription(str(obj, "description"))

			var err error
			switch kind {
			case "networkDeviceGroup":
				err = c.ersCreate(pathNetworkDeviceGroups, rootNetworkDeviceGroup, obj)
				if err == nil {
					res.Created++
					log("Created network device group %q.", it.Name)
				}

			case "dacl":
				err = c.ersCreate(pathDownloadableACLs, rootDownloadableACL, obj)
				if err == nil {
					res.Created++
					log("Created dACL %q.", it.Name)
				}

			case "authorizationProfile":
				// Handle web redirect retry: if it fails with portal error, retry without redirect
				err = c.ersCreate(pathAuthProfiles, rootAuthProfile, obj)
				if err != nil {
					// Check if this is a web redirect issue
					var ae *APIError
					if errors.As(err, &ae) && (strings.Contains(strings.ToLower(ae.Body), "portal") || strings.Contains(strings.ToLower(ae.Body), "webr")) {
						// Retry without web redirect
						log("Authorization profile %q: web redirect rejected (%v); retrying without redirect.", it.Name, err)
						objNoRedir := maps.Clone(obj)
						delete(objNoRedir, "webRedirection")
						err = c.ersCreate(pathAuthProfiles, rootAuthProfile, objNoRedir)
						if err == nil {
							res.Created++
							log("Created authorization profile %q (web redirect could not be set).", it.Name)
							res.Errors = append(res.Errors, fmt.Sprintf("authorization profile %q: web redirect could not be set; configure the portal manually", it.Name))
							continue
						}
					}
				}
				if err == nil {
					res.Created++
					log("Created authorization profile %q.", it.Name)
				}

			case "idStoreSequence":
				err = c.ersCreate(pathIdStoreSequences, rootIdStoreSequence, obj)
				if err == nil {
					res.Created++
					log("Created identity source sequence %q.", it.Name)
				}

			case "condition":
				// A condition goes back to the collection it came from: the
				// library, time or network endpoint. They are three different
				// object types sharing a shape.
				path := str(obj, "conditionPath")
				if path == "" {
					path = pathConditions
				}
				delete(obj, "conditionPath")
				err = c.openAPICreate(path, obj)
				if err == nil {
					res.Created++
					log("Created condition %q.", it.Name)
				}
			}

			if err != nil {
				if isDuplicate(err) {
					res.Skipped++
					log("%s %q already exists; skipped.", kind, it.Name)
					continue
				}
				res.Failed++
				res.Errors = append(res.Errors, fmt.Sprintf("%s %q: %v", kind, it.Name, err))
				log("FAILED %s %q: %v", kind, it.Name, err)
			}
		}
	}

	return nil
}

// dictionaryAttrLookup answers which attributes a dictionary on this deployment
// has, reading each dictionary once and only when something asks. The attribute
// endpoint ignores paging, so it is read with a single request.
func dictionaryAttrLookup(c *Client) func(string) map[string]bool {
	cache := map[string]map[string]bool{}
	return func(dict string) map[string]bool {
		if known, ok := cache[dict]; ok {
			return known
		}
		attrs, err := c.openAPIListOnce(pathDictionaries + "/" + dict + "/attribute")
		if err != nil {
			cache[dict] = nil // unknown is not absent; never block on it
			return nil
		}
		known := map[string]bool{}
		for _, a := range attrs {
			known[str(a, "name")] = true
		}
		cache[dict] = known
		return known
	}
}
