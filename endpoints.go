package main

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

// Object families carried by a bundle. One string per family, used as the
// bundle key, the UI checkbox value and the pre-flight report's grouping.
const (
	familyEndpointGroups = "endpointGroups"
	familyEndpoints      = "endpoints"
	familyTrustedCerts   = "trustedCertificates"
)

// ISE paths and their ERS root keys.
const (
	pathEndpointGroups = "/ers/config/endpointgroup"
	rootEndpointGroup  = "EndPointGroup"
	pathEndpoints      = "/ers/config/endpoint"
	rootEndpoint       = "ERSEndPoint"
	pathProfiles       = "/ers/config/profilerprofile"
	pathEndpointsAPI   = "/api/v1/endpoint"
)

// openAPIOnlyEndpointFields are fields the OpenAPI endpoint resource returns and
// the ERS endpoint resource does not know. ERS answers a create carrying any of
// them with HTTP 400 "Resource Initialization Failed due to JSON invalidity",
// naming every property in the payload rather than the offending one — so this
// list is what a real 3.4 box actually rejected, not a guess at its schema.
//
// Nulls are already stripped at ersCreate, which hid this for every endpoint ISE
// had never learned an IP or an asset attribute for. A DHCP-learned ipAddress is
// a non-null value and failed the create outright. All of it is runtime state
// the target relearns, so dropping it loses nothing.
var openAPIOnlyEndpointFields = []string{
	"ipAddress", "vendor", "productId", "serialNumber", "deviceType",
	"softwareRevision", "hardwareRevision", "protocol",
	"assetId", "assetName", "assetIpAddress", "assetVendor", "assetProductId",
	"assetSerialNumber", "assetDeviceType", "assetSwRevision",
	"assetHwRevision", "assetProtocol", "assetConnectedLinks",
}

// --- cross-reference remapping ----------------------------------------------
//
// Every reference between ISE objects is a UUID that only means something in
// the deployment that minted it. The whole tool depends on one rule: a
// reference travels by *name*, never by UUID. On export the UUID is resolved to
// the referenced object's name and the UUID field is dropped; on import the
// name is resolved against the target and the target's UUID is written back.
// A name that does not resolve is a pre-flight failure, never a dangling
// reference written into the target.

// refToName replaces obj[idField] with obj[nameField], looked up in names
// (source UUID -> name). Returns false with a reason when the UUID is unknown.
func refToName(obj map[string]any, idField, nameField, kind string, names map[string]string) (bool, string) {
	id, _ := obj[idField].(string)
	if id == "" {
		delete(obj, idField)
		return true, ""
	}
	name, ok := names[id]
	if !ok {
		return false, fmt.Sprintf("%s %q does not match any %s on the source deployment", idField, id, kind)
	}
	delete(obj, idField)
	obj[nameField] = name
	return true, ""
}

// nameToRef is the import half: obj[nameField] -> obj[idField] using the
// target's name -> UUID map.
func nameToRef(obj map[string]any, nameField, idField, kind string, ids map[string]string) (bool, string) {
	name, _ := obj[nameField].(string)
	if name == "" {
		delete(obj, nameField)
		return true, ""
	}
	id, ok := ids[name]
	if !ok {
		return false, fmt.Sprintf("the target has no %s named %q", kind, name)
	}
	delete(obj, nameField)
	obj[idField] = id
	return true, ""
}

// stripLocal removes deployment-local identity: the object's own id and every
// "link" self-reference, at any depth. What is left is portable.
func stripLocal(obj map[string]any) map[string]any {
	delete(obj, "id")
	stripLinks(obj)
	return obj
}

func stripLinks(v any) {
	switch t := v.(type) {
	case map[string]any:
		delete(t, "link")
		for _, sub := range t {
			stripLinks(sub)
		}
	case []any:
		for _, sub := range t {
			stripLinks(sub)
		}
	}
}

func str(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

func truthy(obj map[string]any, key string) bool {
	switch v := obj[key].(type) {
	case bool:
		return v
	case string: // ISE has been seen to return "true" as a string
		return strings.EqualFold(v, "true")
	}
	return false
}

// isStatic keeps only endpoints the operator actually decided something about.
// Everything else is profiler output, which the new deployment regenerates by
// itself the first time the endpoint shows up; carrying it is pointless churn.
func isStatic(ep map[string]any) bool {
	return truthy(ep, "staticGroupAssignment") || truthy(ep, "staticProfileAssignment")
}

// endpointMAC finds the MAC. OpenAPI and ERS both use "mac"; ERS list stubs use
// the MAC as the object name, so "name" is the fallback.
func endpointMAC(ep map[string]any) string {
	if m := str(ep, "mac"); m != "" {
		return normMAC(m)
	}
	return normMAC(str(ep, "name"))
}

// normMAC makes MACs comparable: ISE returns them upper-case colon-separated,
// but a bundle may have travelled through something less tidy.
func normMAC(m string) string {
	return strings.ToUpper(strings.TrimSpace(m))
}

// --- export ------------------------------------------------------------------

// ExportEndpoints fills the bundle with endpoint identity groups and, for the
// groups the operator selected, their statically assigned endpoints.
// groupNames empty means "no endpoints, groups only" - but if either family is
// selected and groupNames is empty, an error is returned.
func ExportEndpoints(c *Client, b *Bundle, families []string, groupNames []string, log func(string, ...any)) error {
	wantGroups := slices.Contains(families, familyEndpointGroups)
	wantEndpoints := slices.Contains(families, familyEndpoints)
	if !wantGroups && !wantEndpoints {
		return nil
	}

	// Validate: if either family is selected and no groups are selected, error
	if (wantGroups || wantEndpoints) && len(groupNames) == 0 {
		return fmt.Errorf("select at least one endpoint identity group, or untick both Endpoint identity groups and Static endpoints")
	}

	// Endpoint groups are needed either way: they are both an object family and
	// the lookup table that turns an endpoint's groupId into a name.
	log("Listing endpoint identity groups…")
	stubs, err := c.ersList(pathEndpointGroups)
	if err != nil {
		return fmt.Errorf("listing endpoint identity groups: %w", err)
	}
	log("Found %d endpoint identity groups; reading them…", len(stubs))
	groups, err := c.ersGetAll(pathEndpointGroups, rootEndpointGroup, stubs)
	if err != nil {
		return fmt.Errorf("reading endpoint identity groups: %w", err)
	}

	groupNameByID := map[string]string{}
	allGroupNames := []string{}
	for _, g := range groups {
		if id := str(g, "id"); id != "" {
			name := str(g, "name")
			groupNameByID[id] = name
			allGroupNames = append(allGroupNames, name)
		}
	}

	if wantGroups {
		// Only export the selected groups
		selectedSet := map[string]bool{}
		for _, want := range groupNames {
			selectedSet[want] = true
		}

		out := make([]map[string]any, 0, len(groups))
		var leftBehind []string

		for _, g := range groups {
			name := str(g, "name")
			if !selectedSet[name] {
				leftBehind = append(leftBehind, name)
				continue // Skip unselected groups
			}

			// A nested group would need its parent to exist first, and the
			// parent UUID means nothing on the target. Say so rather than
			// writing a broken reference.
			if p := str(g, "parentId"); p != "" {
				b.Note("Endpoint identity group %q is nested under %q on the source; nesting is not carried, the group is created at the top level.", name, groupNameByID[p])
				delete(g, "parentId")
			}
			out = append(out, stripLocal(g))
		}

		// Report the left-behind groups
		if len(leftBehind) > 0 {
			sort.Strings(leftBehind)
			b.Note("%d of %d endpoint identity groups on the source were not selected and were not exported: %s", len(leftBehind), len(allGroupNames), strings.Join(leftBehind, ", "))
		}

		b.Objects[familyEndpointGroups] = out
		log("Captured %d endpoint identity groups.", len(out))
	}

	if !wantEndpoints {
		return nil
	}

	// Selected group names -> source UUIDs, so endpoints can be filtered by
	// membership before anything else is done with them.
	selected := map[string]bool{}
	for _, want := range groupNames {
		found := false
		for id, name := range groupNameByID {
			if name == want {
				selected[id] = true
				found = true
			}
		}
		if !found {
			b.Note("Selected endpoint identity group %q no longer exists on the source; skipped.", want)
		}
	}

	log("Reading profiler profiles (to resolve static profile assignments)…")
	profileNameByID := map[string]string{}
	profStubs, err := c.ersList(pathProfiles)
	if err != nil {
		b.Note("Could not read the profiler profile list (%v); endpoints with a static profile assignment cannot be carried and are skipped.", err)
	} else {
		for _, p := range profStubs {
			profileNameByID[p.ID] = p.Name
		}
	}

	eps, source, err := fetchEndpoints(c, log)
	if err != nil {
		return err
	}
	log("Read %d endpoints from %s; filtering…", len(eps), source)
	b.Note("Endpoints were read from %s.", source)

	out := make([]map[string]any, 0, 64)
	var skippedDynamic, skippedOtherGroup int
	for _, ep := range eps {
		if !selected[str(ep, "groupId")] {
			skippedOtherGroup++
			continue
		}
		if !isStatic(ep) {
			skippedDynamic++
			continue
		}
		mac := endpointMAC(ep)
		if mac == "" {
			b.Note("An endpoint in the export has no MAC address; skipped. Received: %v", ep)
			continue
		}
		ok, why := refToName(ep, "groupId", "groupName", "endpoint identity group", groupNameByID)
		if !ok {
			b.Note("Endpoint %s skipped: %s", mac, why)
			continue
		}
		if truthy(ep, "staticProfileAssignment") {
			ok, why := refToName(ep, "profileId", "profileName", "profiler profile", profileNameByID)
			if !ok {
				b.Note("Endpoint %s skipped: %s", mac, why)
				continue
			}
		} else {
			// Profiler-assigned: the target regenerates it, and the UUID is
			// meaningless there.
			delete(ep, "profileId")
			delete(ep, "profile")
		}
		ep["mac"] = mac
		out = append(out, stripLocal(ep))
	}
	sort.Slice(out, func(i, j int) bool { return endpointMAC(out[i]) < endpointMAC(out[j]) })
	b.Objects[familyEndpoints] = out

	log("Captured %d statically assigned endpoints (%d dynamic skipped, %d outside the selected groups).",
		len(out), skippedDynamic, skippedOtherGroup)
	if skippedDynamic > 0 {
		b.Note("%d endpoints in the selected groups are profiler-assigned, not static, and were not carried; the target regenerates them.", skippedDynamic)
	}
	return nil
}

// scanPolicyUsage counts, per endpoint identity group, how many policy rules and
// library conditions reference it. It is advisory: the operator uses it to tell a
// group that is genuinely dead from one a rule still points at.
//
// It returns the counts and, when anything could not be read, a sentence naming
// what. A caller must show that sentence: a scan that failed and a deployment
// whose policy references no groups both produce zeros, and presenting the first
// as the second is what would make an operator drop a group a rule depends on.
// Never fatal — a failed scan costs the badge, not the migration.
func scanPolicyUsage(c *Client, groupNames []string) (map[string]int, string) {
	if len(groupNames) == 0 {
		return map[string]int{}, ""
	}

	usageMap := make(map[string]int)
	var scanErrors []string
	scanned := 0

	// Device admin policy is scanned but never migrated: a group used only by
	// TACACS rules is still in use, and reporting it as unused is the failure
	// this whole feature exists to prevent.
	paths := []string{
		"/api/v1/policy/network-access/policy-set",
		"/api/v1/policy/device-admin/policy-set",
		"/api/v1/policy/network-access/condition",
		"/api/v1/policy/device-admin/condition",
	}

	// scan reads one document and walks it. Each rule set is independent, so one
	// refusal costs that document's references and nothing else.
	scan := func(path string) []map[string]any {
		items, err := c.openAPIList(path)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		scanned++
		for _, item := range items {
			walkForGroupRefs(item, usageMap)
		}
		return items
	}

	for _, path := range paths {
		items := scan(path)
		if !strings.HasSuffix(path, "/policy-set") {
			continue
		}
		// A policy set's rules hang off it and hold the references; the set
		// itself carries almost none.
		for _, set := range items {
			id := str(set, "id")
			if id == "" {
				continue
			}
			// Both rule sets are read even when the first refuses: an
			// authentication rule that cannot be read says nothing about the
			// authorization rules next to it.
			scan(path + "/" + id + "/authentication")
			scan(path + "/" + id + "/authorization")
		}
	}

	var errMsg string
	switch {
	case scanned == 0:
		errMsg = "Policy usage could not be determined — nothing was read: " + strings.Join(scanErrors, "; ")
	case len(scanErrors) > 0:
		errMsg = "Policy usage may be incomplete; some rules could not be read: " + strings.Join(scanErrors, "; ")
	}

	return usageMap, errMsg
}

// walkForGroupRefs walks a decoded rule document and counts every endpoint
// identity group reference in it. The rule schema is deliberately not modelled:
// conditions nest inside conditions to arbitrary depth and the shapes are not
// otherwise needed here, so a generic walk cannot miss one by getting the
// structure wrong.
func walkForGroupRefs(v any, usageMap map[string]int) {
	switch t := v.(type) {
	case map[string]any:
		if isGroupReference(t) {
			if name := extractGroupName(str(t, "attributeValue")); name != "" {
				usageMap[name]++
			}
		}
		for _, sub := range t {
			walkForGroupRefs(sub, usageMap)
		}
	case []any:
		for _, item := range t {
			walkForGroupRefs(item, usageMap)
		}
	}
}

// isGroupReference recognises the shape a real ISE 3.4 returns for a rule that
// matches on an endpoint identity group: dictionary IdentityGroup, attribute
// Name, and a value carrying the group's path. Matching is by name, not UUID,
// which is why this survives a migration at all.
func isGroupReference(obj map[string]any) bool {
	return str(obj, "dictionaryName") == "IdentityGroup" &&
		str(obj, "attributeName") == "Name" &&
		strings.HasPrefix(str(obj, "attributeValue"), groupRefPrefix)
}

// groupRefPrefix is how ISE writes an endpoint identity group in a rule
// condition, verified against 3.4: "Endpoint Identity Groups:Production:Siemens".
const groupRefPrefix = "Endpoint Identity Groups:"

// extractGroupName takes the leaf of a reference value: the value carries the
// group's nesting path, "Endpoint Identity Groups:Production:Siemens", and the
// group is the last segment. Endpoint identity group names are unique in ISE —
// the import's own duplicate check already relies on it — so the leaf identifies
// the group without the path.
func extractGroupName(attrValue string) string {
	if !strings.HasPrefix(attrValue, groupRefPrefix) {
		return ""
	}
	parts := strings.Split(attrValue, ":")
	return strings.TrimSpace(parts[len(parts)-1])
}

// fetchEndpoints prefers OpenAPI, which returns whole objects in one list call.
// ERS needs a GET per MAC, which on a real deployment is thousands of requests.
func fetchEndpoints(c *Client, log func(string, ...any)) ([]map[string]any, string, error) {
	log("Reading endpoints from the OpenAPI…")
	eps, err := c.openAPIList(pathEndpointsAPI)
	if err == nil {
		return eps, "OpenAPI " + pathEndpointsAPI, nil
	}
	log("OpenAPI endpoint list unavailable (%v); falling back to ERS.", err)

	stubs, ersErr := c.ersList(pathEndpoints)
	if ersErr != nil {
		return nil, "", fmt.Errorf("could not read endpoints from either API. OpenAPI: %v. ERS: %w", err, ersErr)
	}
	log("Found %d endpoints in ERS; reading them one by one…", len(stubs))
	eps, ersErr = c.ersGetAll(pathEndpoints, rootEndpoint, stubs)
	if ersErr != nil {
		return nil, "", fmt.Errorf("reading endpoints from ERS: %w", ersErr)
	}
	return eps, "ERS " + pathEndpoints, nil
}

// EndpointGroup is a group with its system-defined flag and policy usage count.
type EndpointGroup struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	SystemDefined bool   `json:"systemDefined"`
	UsedBy        int    `json:"usedBy"`
}

// ListEndpointGroups is what the picker shows. The group selection now decides
// what is created on the target, not just which endpoints are read, so the two
// things an operator needs to choose well travel with each name: whether ISE
// defined the group itself, and how many policy rules point at it.
//
// systemDefined is only on the detail object, so every group is read; the export
// makes the same read.
//
// The second return is a sentence to show the operator when the policy scan
// could not complete. Empty means the counts are trustworthy.
func ListEndpointGroups(c *Client) ([]EndpointGroup, string, error) {
	stubs, err := c.ersList(pathEndpointGroups)
	if err != nil {
		return nil, "", err
	}
	groups, err := c.ersGetAll(pathEndpointGroups, rootEndpointGroup, stubs)
	if err != nil {
		return nil, "", err
	}

	names := make([]string, len(groups))
	for i, g := range groups {
		names[i] = str(g, "name")
	}
	usage, scanNote := scanPolicyUsage(c, names)

	out := make([]EndpointGroup, 0, len(groups))
	for _, g := range groups {
		name := str(g, "name")
		out = append(out, EndpointGroup{
			ID:            str(g, "id"),
			Name:          name,
			SystemDefined: truthy(g, "systemDefined"),
			UsedBy:        usage[name],
		})
	}

	// ISE's own groups sort last: they exist on every target already, so the
	// operator's own groups are what the picker should open on.
	sort.Slice(out, func(i, j int) bool {
		if out[i].SystemDefined == out[j].SystemDefined {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return !out[i].SystemDefined
	})
	return out, scanNote, nil
}

// --- pre-flight and import ---------------------------------------------------

// Pre-flight actions.
const (
	actionCreate  = "create"
	actionSkip    = "skip"    // already on the target
	actionBlocked = "blocked" // a reference does not resolve; never attempted
)

// PreflightItem is one object's verdict. This shape is deliberately generic:
// every later object family lands in the same report and the same gate.
type PreflightItem struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`

	obj map[string]any // the object to create; not serialised to the UI
}

type PreflightReport struct {
	Source  BundleSource    `json:"source"`
	Items   []PreflightItem `json:"items"`
	Create  int             `json:"create"`
	Skip    int             `json:"skip"`
	Blocked int             `json:"blocked"`
	Notes   []string        `json:"notes"`
}

func (r *PreflightReport) add(it PreflightItem) {
	switch it.Action {
	case actionCreate:
		r.Create++
	case actionSkip:
		r.Skip++
	case actionBlocked:
		r.Blocked++
	}
	r.Items = append(r.Items, it)
}

// Preflight resolves every cross-reference in the bundle against the target and
// reports what would happen. It writes nothing. Import is not allowed to touch
// the target until an operator has seen this and confirmed.
func Preflight(c *Client, b *Bundle) (*PreflightReport, error) {
	r := &PreflightReport{Source: b.Source, Items: []PreflightItem{}, Notes: append([]string{}, b.Notes...)}

	preflightTrustedCerts(c, b, r)

	groupIDByName, err := stubsByName(c, pathEndpointGroups)
	if err != nil {
		return nil, fmt.Errorf("reading the target's endpoint identity groups: %w", err)
	}

	// Groups first, and a group created in this run counts as resolvable for
	// the endpoints that reference it.
	willExist := map[string]bool{}
	for name := range groupIDByName {
		willExist[name] = true
	}
	for _, g := range b.Objects[familyEndpointGroups] {
		name := str(g, "name")
		it := PreflightItem{Family: familyEndpointGroups, Name: name, obj: g}
		switch {
		case name == "":
			it.Action, it.Reason = actionBlocked, "the bundle contains an endpoint identity group with no name"
		case groupIDByName[name] != "":
			it.Action, it.Reason = actionSkip, "already exists on the target"
		default:
			it.Action = actionCreate
			willExist[name] = true
		}
		r.add(it)
	}

	eps := b.Objects[familyEndpoints]
	if len(eps) == 0 {
		return r, nil
	}

	profileIDByName, err := stubsByName(c, pathProfiles)
	if err != nil {
		return nil, fmt.Errorf("reading the target's profiler profiles: %w", err)
	}
	existingMAC, err := targetMACs(c)
	if err != nil {
		return nil, fmt.Errorf("reading the target's endpoints: %w", err)
	}

	for _, ep := range eps {
		mac := endpointMAC(ep)
		it := PreflightItem{Family: familyEndpoints, Name: mac, obj: ep}
		gname := str(ep, "groupName")
		pname := str(ep, "profileName")
		switch {
		case mac == "":
			it.Action, it.Reason = actionBlocked, "endpoint has no MAC address"
		case existingMAC[mac]:
			it.Action, it.Reason = actionSkip, "already exists on the target"
		case gname != "" && !willExist[gname]:
			it.Action, it.Reason = actionBlocked, fmt.Sprintf("the target has no endpoint identity group named %q and the bundle does not create one", gname)
		case pname != "" && profileIDByName[pname] == "":
			it.Action, it.Reason = actionBlocked, fmt.Sprintf("the target has no profiler profile named %q", pname)
		default:
			it.Action = actionCreate
		}
		r.add(it)
	}

	return r, nil
}

// preflightTrustedCerts resolves the trusted certificate family. It runs before
// the endpoint families and in its own function because the endpoint section
// returns early when the bundle carries no endpoints, and certificates travel
// independently of them.
func preflightTrustedCerts(c *Client, b *Bundle, r *PreflightReport) {
	certs := b.Objects[familyTrustedCerts]
	if len(certs) > 0 {
		// Read target's trusted certificates from OpenAPI.
		targetCerts, err := fetchTrustedCertsOpenAPI(c)
		if err != nil {
			// The only create path is OpenAPI, so one blocked item stands for the
			// whole family rather than one per certificate.
			it := PreflightItem{Family: familyTrustedCerts, Name: "trusted certificates", Action: actionBlocked, Reason: "the import path POST /api/v1/certs/trusted-certificate/import is OpenAPI-only and the target's OpenAPI is not answering: " + err.Error()}
			r.add(it)
			return
		}

		// Fingerprint -> the name the target knows that certificate by. The same
		// trust often sits in two stores under two friendly names, so the
		// target's name is worth reporting: "already exists" under a name the
		// operator does not recognise is the one skip worth looking at.
		targetByFingerprint := map[string]string{}
		targetByName := map[string]bool{}
		fingerprints := 0

		for _, cert := range targetCerts {
			if fp := str(cert, "sha256Fingerprint"); fp != "" {
				// Normalize: lowercase, strip whitespace and colons.
				fp = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fp, ":", ""), " ", ""))
				targetByFingerprint[fp] = str(cert, "friendlyName")
				fingerprints++
			}
			if friendlyName := str(cert, "friendlyName"); friendlyName != "" {
				targetByName[friendlyName] = true
			}
		}

		// If no usable fingerprints, emit exactly one note.
		if fingerprints == 0 && len(targetByName) > 0 {
			r.Notes = append(r.Notes, "Trusted certificates: the target's objects do not expose a sha256Fingerprint field; using name-based deduplication instead")
		}

		for _, certObj := range certs {
			name := str(certObj, "name")
			pemData := str(certObj, "pem")
			notAfter := str(certObj, "notAfter")
			fp := str(certObj, "fingerprint")

			it := PreflightItem{Family: familyTrustedCerts, Name: name, obj: certObj}

			// Expired certificates are never attempted. The date is parsed, not
			// string-compared: a fresh deployment does not need dead trust, and
			// ISE would refuse it anyway without allowOutOfDateCert.
			if notAfter != "" {
				exp, err := time.Parse(time.RFC3339, notAfter)
				switch {
				case err != nil:
					it.Action, it.Reason = actionBlocked, fmt.Sprintf("certificate expiry %q is not a date this build understands", notAfter)
					r.add(it)
					continue
				case exp.Before(time.Now()):
					it.Action, it.Reason = actionBlocked, fmt.Sprintf("certificate expired on %s", exp.Format(time.RFC3339))
					r.add(it)
					continue
				}
			}

			// Check PEM.
			if pemData == "" {
				it.Action, it.Reason = actionBlocked, "certificate has no PEM data"
				r.add(it)
				continue
			}

			// Dedup by fingerprint if available, else by name.
			if fingerprints > 0 && fp != "" {
				fpNorm := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fp, ":", ""), " ", ""))
				if targetName, ok := targetByFingerprint[fpNorm]; ok {
					it.Action, it.Reason = actionSkip, "already exists on the target"
					// Matched by content, not by name: the target holds this
					// exact certificate under a name of its own, and the
					// operator cannot tell that from the skip alone.
					if targetName != "" && targetName != name {
						it.Reason = fmt.Sprintf("already exists on the target as %q (same certificate, different name)", targetName)
					}
					r.add(it)
					continue
				}
			} else if targetByName[name] {
				it.Action, it.Reason = actionSkip, "already exists on the target"
				r.add(it)
				continue
			}

			it.Action = actionCreate
			r.add(it)
		}
	}
}

func stubsByName(c *Client, path string) (map[string]string, error) {
	stubs, err := c.ersList(path)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(stubs))
	for _, s := range stubs {
		m[s.Name] = s.ID
	}
	return m, nil
}

// targetMACs lists the MACs already on the target. ERS list stubs name an
// endpoint by its MAC, so the cheap stub listing is enough - no detail reads.
func targetMACs(c *Client) (map[string]bool, error) {
	stubs, err := c.ersList(pathEndpoints)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(stubs))
	for _, s := range stubs {
		m[normMAC(s.Name)] = true
	}
	return m, nil
}

// ImportResult is the after-the-fact counterpart of the pre-flight report.
type ImportResult struct {
	Created int      `json:"created"`
	Skipped int      `json:"skipped"`
	Blocked int      `json:"blocked"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors"`
}

// ApplyImport writes the objects the pre-flight report marked as creatable, in
// dependency order: trusted certificates first, then groups, then endpoints.
// Nothing else is touched; existing objects are never overwritten.
func ApplyImport(c *Client, r *PreflightReport, log func(string, ...any)) (*ImportResult, error) {
	res := &ImportResult{Errors: []string{}}

	// Trusted certificates.
	var certCount int
	for _, it := range r.Items {
		if it.Family == familyTrustedCerts && it.Action == actionCreate {
			certCount++
		}
	}
	if certCount > 0 {
		log("Creating %d trusted certificates…", certCount)
		for _, it := range r.Items {
			if it.Family != familyTrustedCerts || it.Action != actionCreate {
				continue
			}

			obj := maps.Clone(it.obj)
			name := str(obj, "name")
			pemData := str(obj, "pem")
			crlSettings := obj["crl"]
			description := str(obj, "description")

			// Remove fields not in the import payload.
			delete(obj, "fingerprint")
			delete(obj, "notAfter")
			delete(obj, "subject")
			delete(obj, "issuer")
			delete(obj, "crl")
			delete(obj, "pem")
			delete(obj, "friendlyName")

			// Build the import payload with plain-text PEM data (not base64-encoded).
			payload := map[string]any{
				"name":                        name,
				"data":                        pemData,
				"allowOutOfDateCert":          false,
				"allowSHA1Certificates":       false,
				"allowBasicConstraintCAFalse": false,
			}

			// Add optional fields from the bundle.
			for _, flag := range []string{"trustForIseAuth", "trustForClientAuth", "trustForCertificateBasedAdminAuth", "trustForCiscoServicesAuth", "allowBasicConstraintCAFalse", "allowOutOfDateCert", "allowSHA1Certificates", "validateCertificateExtensions"} {
				if v, ok := obj[flag]; ok {
					payload[flag] = v
				}
			}

			// POST the import. If description contains a comma, the import will fail with
			// "Security Check Failed". Retry without the description on that specific error.
			if description != "" {
				payload["description"] = description
			}

			if err := c.openAPICreate(pathTrustedCertsAPI+"/import", payload); err != nil {
				// Check if this is the "Security Check Failed" + comma-in-description case.
				var ae *APIError
				if errors.As(err, &ae) && ae.Status == http.StatusBadRequest && strings.Contains(strings.ToLower(ae.Body), "security check failed") && strings.Contains(description, ",") {
					// Retry without the description.
					log("Trusted certificate %q: description contains a comma and was rejected; retrying without description.", name)
					delete(payload, "description")
					if retryErr := c.openAPICreate(pathTrustedCertsAPI+"/import", payload); retryErr != nil {
						if isDuplicate(retryErr) {
							res.Skipped++
							log("Trusted certificate %q already exists; skipped.", name)
							continue
						}
						res.Failed++
						res.Errors = append(res.Errors, fmt.Sprintf("trusted certificate %q: %v", name, retryErr))
						log("FAILED trusted certificate %q: %v", name, retryErr)
						continue
					}
					// Created without description; record that the description was not set.
					res.Created++
					log("Created trusted certificate %q (description could not be set).", name)
					res.Errors = append(res.Errors, fmt.Sprintf("trusted certificate %q: description %q contains a comma and could not be set; please enter it manually in the GUI", name, description))
				} else if isDuplicate(err) {
					res.Skipped++
					log("Trusted certificate %q already exists; skipped.", name)
					continue
				} else {
					res.Failed++
					res.Errors = append(res.Errors, fmt.Sprintf("trusted certificate %q: %v", name, err))
					log("FAILED trusted certificate %q: %v", name, err)
					continue
				}
			} else {
				res.Created++
				log("Created trusted certificate %q.", name)
			}

			// If there are CRL settings, look up the cert and update via OpenAPI PUT.
			if crlSettings != nil {
				// The bundle is operator-supplied data: a shape that is not an
				// object is reported, never asserted.
				crlMap, ok := crlSettings.(map[string]any)
				if !ok {
					res.Errors = append(res.Errors, fmt.Sprintf("trusted certificate %q: the bundle's CRL settings are %T, not an object; they were not applied", name, crlSettings))
					continue
				}

				// Re-read the target's certs to find the new one by friendlyName.
				targetCerts, err := fetchTrustedCertsOpenAPI(c)
				if err != nil {
					// Can't look it up; record the error but don't fail the whole import.
					errMsg := fmt.Sprintf("trusted certificate %q: CRL settings could not be applied (could not read target certs): %v", name, err)
					res.Errors = append(res.Errors, errMsg)
					log("WARNING: %s; these settings must be entered manually.", errMsg)
					continue
				}

				var targetID string
				for _, cert := range targetCerts {
					if str(cert, "friendlyName") == name {
						targetID = str(cert, "id")
						break
					}
				}
				if targetID == "" {
					errMsg := fmt.Sprintf("trusted certificate %q: CRL settings could not be applied (certificate not found on target after creation)", name)
					res.Errors = append(res.Errors, errMsg)
					log("WARNING: %s; these settings must be entered manually.", errMsg)
					continue
				}

				// Build the CRL PUT payload. The bundle has booleans and integers;
				// the API PUT expects the same types.
				crlUpdate := map[string]any{"name": name}
				for k, v := range crlMap {
					if k != "selectedOCSPService" {
						crlUpdate[k] = v
					}
				}
				// ISE 3.4 rejects the whole PUT with "can only be set true if
				// downloadCRL parameter is set to be true" when any of these is
				// true while CRL download is off. They are inert in that state
				// anyway, so they are forced false rather than losing the rest of
				// the settings to a 400.
				if dl, _ := crlUpdate["downloadCRL"].(bool); !dl {
					for _, dependent := range crlDownloadDependentFields {
						if b, _ := crlUpdate[dependent].(bool); b {
							crlUpdate[dependent] = false
						}
					}
				}
				if description != "" && !strings.Contains(description, ",") {
					crlUpdate["description"] = description
				}
				// The PUT replaces the object rather than patching it: a trust
				// flag left out of the body comes back false, and the certificate
				// ends up trusted for nothing ("trustedFor": "Unknown") despite
				// the import having set it correctly. Carry them again. Verified
				// on 3.4.
				for _, flag := range trustFlagFields {
					if v, ok := obj[flag]; ok {
						crlUpdate[flag] = v
					}
				}

				// PUT the CRL settings via OpenAPI.
				if err := c.openAPIPut(pathTrustedCertsAPI+"/"+targetID, crlUpdate); err != nil {
					errMsg := fmt.Sprintf("trusted certificate %q: CRL settings could not be applied: %v", name, err)
					res.Errors = append(res.Errors, errMsg)
					log("WARNING: %s; these settings must be entered manually.", errMsg)
					// Don't fail the whole import; the cert was created successfully.
				}
			}
		}
		if certCount > 0 {
			log("Completed %d trusted certificates.", certCount)
		}
	}

	var createdGroups int
	for _, it := range r.Items {
		if it.Family != familyEndpointGroups || it.Action != actionCreate {
			continue
		}
		obj := maps.Clone(it.obj)
		if err := c.ersCreate(pathEndpointGroups, rootEndpointGroup, obj); err != nil {
			if isDuplicate(err) {
				res.Skipped++
				log("Endpoint identity group %q already exists; skipped.", it.Name)
				continue
			}
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("endpoint identity group %q: %v", it.Name, err))
			log("FAILED endpoint identity group %q: %v", it.Name, err)
			continue
		}
		res.Created++
		createdGroups++
		log("Created endpoint identity group %q.", it.Name)
	}
	if createdGroups > 0 {
		log("Created %d endpoint identity groups.", createdGroups)
	}

	endpoints := 0
	for _, it := range r.Items {
		if it.Family == familyEndpoints && it.Action == actionCreate {
			endpoints++
		}
	}
	if endpoints == 0 {
		return res, nil
	}

	// Groups just created have brand-new target UUIDs, so the name -> UUID map
	// has to be read back after the group pass.
	groupIDByName, err := stubsByName(c, pathEndpointGroups)
	if err != nil {
		return res, fmt.Errorf("re-reading the target's endpoint identity groups: %w", err)
	}
	profileIDByName, err := stubsByName(c, pathProfiles)
	if err != nil {
		return res, fmt.Errorf("re-reading the target's profiler profiles: %w", err)
	}

	done := 0
	for _, it := range r.Items {
		if it.Family != familyEndpoints || it.Action != actionCreate {
			continue
		}
		done++
		obj := maps.Clone(it.obj)
		// Stripped here rather than on export so a bundle written before this
		// was known imports too.
		for _, f := range openAPIOnlyEndpointFields {
			delete(obj, f)
		}
		if ok, why := nameToRef(obj, "groupName", "groupId", "endpoint identity group", groupIDByName); !ok {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("endpoint %s: %s", it.Name, why))
			continue
		}
		if ok, why := nameToRef(obj, "profileName", "profileId", "profiler profile", profileIDByName); !ok {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("endpoint %s: %s", it.Name, why))
			continue
		}
		if err := c.ersCreate(pathEndpoints, rootEndpoint, obj); err != nil {
			if isDuplicate(err) {
				res.Skipped++
				continue
			}
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("endpoint %s: %v", it.Name, err))
			continue
		}
		res.Created++
		if done%25 == 0 || done == endpoints {
			log("Endpoints: %d/%d processed.", done, endpoints)
		}
	}
	return res, nil
}
