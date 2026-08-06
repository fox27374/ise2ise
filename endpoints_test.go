package main

import (
	"strings"
	"testing"
)

func TestRefRemapRoundTrip(t *testing.T) {
	// Export: the source UUID becomes a name.
	ep := map[string]any{"mac": "AA:BB:CC:DD:EE:01", "groupId": "src-uuid-1"}
	if ok, why := refToName(ep, "groupId", "groupName", "endpoint identity group", map[string]string{"src-uuid-1": "Printers"}); !ok {
		t.Fatalf("refToName failed: %s", why)
	}
	if _, still := ep["groupId"]; still {
		t.Error("the source UUID must not survive into the bundle")
	}
	if ep["groupName"] != "Printers" {
		t.Fatalf("groupName = %v", ep["groupName"])
	}

	// Import: the name becomes the target's own UUID.
	if ok, why := nameToRef(ep, "groupName", "groupId", "endpoint identity group", map[string]string{"Printers": "tgt-uuid-9"}); !ok {
		t.Fatalf("nameToRef failed: %s", why)
	}
	if ep["groupId"] != "tgt-uuid-9" {
		t.Fatalf("groupId = %v, want the target UUID", ep["groupId"])
	}
	if _, still := ep["groupName"]; still {
		t.Error("groupName must be replaced, not kept alongside the UUID")
	}
}

func TestRefRemapUnresolvable(t *testing.T) {
	ep := map[string]any{"profileId": "ghost"}
	ok, why := refToName(ep, "profileId", "profileName", "profiler profile", map[string]string{"p1": "Cisco-Device"})
	if ok {
		t.Fatal("an unknown source UUID must not resolve")
	}
	if !strings.Contains(why, "ghost") || !strings.Contains(why, "profiler profile") {
		t.Errorf("reason should name the id and the kind: %q", why)
	}

	ep2 := map[string]any{"profileName": "Apple-Device"}
	ok, why = nameToRef(ep2, "profileName", "profileId", "profiler profile", map[string]string{"Cisco-Device": "x"})
	if ok {
		t.Fatal("a name the target does not have must not resolve")
	}
	if !strings.Contains(why, "Apple-Device") {
		t.Errorf("reason should name the missing object: %q", why)
	}
	if _, wrote := ep2["profileId"]; wrote {
		t.Error("a failed resolve must not write a dangling reference")
	}
}

func TestStripLocalRemovesIDAndNestedLinks(t *testing.T) {
	o := map[string]any{
		"id": "abc", "name": "Printers",
		"link":       map[string]any{"href": "https://src/ers/x"},
		"customAttr": map[string]any{"link": map[string]any{"href": "https://src/y"}, "keep": "yes"},
		"list":       []any{map[string]any{"link": "x", "keep": 1}},
	}
	stripLocal(o)
	if _, ok := o["id"]; ok {
		t.Error("id survived")
	}
	if _, ok := o["link"]; ok {
		t.Error("top-level link survived")
	}
	if _, ok := o["customAttr"].(map[string]any)["link"]; ok {
		t.Error("nested link survived")
	}
	if _, ok := o["list"].([]any)[0].(map[string]any)["link"]; ok {
		t.Error("link inside a list survived")
	}
	if o["customAttr"].(map[string]any)["keep"] != "yes" {
		t.Error("stripLocal removed real data")
	}
}

func TestIsStatic(t *testing.T) {
	cases := []struct {
		ep   map[string]any
		want bool
	}{
		{map[string]any{"staticGroupAssignment": true}, true},
		{map[string]any{"staticProfileAssignment": true}, true},
		{map[string]any{"staticGroupAssignment": "true"}, true}, // ISE has returned strings here
		{map[string]any{"staticGroupAssignment": false, "staticProfileAssignment": false}, false},
		{map[string]any{}, false},
	}
	for _, c := range cases {
		if got := isStatic(c.ep); got != c.want {
			t.Errorf("isStatic(%v) = %v, want %v", c.ep, got, c.want)
		}
	}
}

// sourceISE is the export-side fixture: three groups, two profiles and a mix of
// static, dynamic and unresolvable endpoints.
func sourceISE(t *testing.T) *fakeISE {
	f := newFakeISE(t)
	f.addGroup("g1", "Printers")
	f.addGroup("g2", "Cameras")
	f.addProfile("p1", "Cisco-Device")
	f.addProfile("p2", "Apple-Device")
	f.addEndpoint("AA:BB:CC:DD:EE:01", "g1", true, "")     // static group
	f.addEndpoint("AA:BB:CC:DD:EE:02", "g1", false, "")    // profiler output
	f.addEndpoint("AA:BB:CC:DD:EE:03", "g2", true, "")     // group not selected
	f.addEndpoint("AA:BB:CC:DD:EE:04", "g1", false, "p1")  // static profile only
	f.addEndpoint("AA:BB:CC:DD:EE:05", "g1", true, "gone") // profile UUID resolves to nothing
	return f
}

func TestExportKeepsOnlyStaticEndpointsOfSelectedGroups(t *testing.T) {
	f := sourceISE(t)
	b := NewBundle(&Probe{Host: "src"})
	err := ExportEndpoints(f.client(), b, []string{familyEndpointGroups, familyEndpoints}, []string{"Printers"}, quiet)
	if err != nil {
		t.Fatalf("ExportEndpoints: %v", err)
	}

	if got := len(b.Objects[familyEndpointGroups]); got != 2 {
		t.Fatalf("groups exported = %d, want 2 (all groups travel, endpoints are filtered)", got)
	}
	eps := b.Objects[familyEndpoints]
	macs := map[string]map[string]any{}
	for _, e := range eps {
		macs[endpointMAC(e)] = e
	}
	if len(eps) != 2 {
		t.Fatalf("endpoints exported = %d (%v), want 01 and 04 only", len(eps), macs)
	}
	for _, unwanted := range []string{"AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:05"} {
		if _, ok := macs[unwanted]; ok {
			t.Errorf("%s should not have been exported", unwanted)
		}
	}

	e1 := macs["AA:BB:CC:DD:EE:01"]
	if e1["groupName"] != "Printers" {
		t.Errorf("groupId was not resolved to a name: %v", e1)
	}
	for _, local := range []string{"id", "link", "groupId", "profileId"} {
		if _, ok := e1[local]; ok {
			t.Errorf("deployment-local field %q survived export: %v", local, e1)
		}
	}
	e4 := macs["AA:BB:CC:DD:EE:04"]
	if e4["profileName"] != "Cisco-Device" {
		t.Errorf("profileId was not resolved to a name: %v", e4)
	}

	notes := strings.Join(b.Notes, "\n")
	if !strings.Contains(notes, "AA:BB:CC:DD:EE:05") {
		t.Errorf("the endpoint with an unresolvable profile must be reported, notes were:\n%s", notes)
	}
	if !strings.Contains(notes, "profiler-assigned") {
		t.Errorf("the dynamic endpoints that were dropped must be reported, notes were:\n%s", notes)
	}
	if !strings.Contains(notes, "OpenAPI") {
		t.Errorf("the bundle should record which API the endpoints came from:\n%s", notes)
	}
	// Groups must be portable too.
	for _, g := range b.Objects[familyEndpointGroups] {
		if _, ok := g["id"]; ok {
			t.Errorf("group kept its source id: %v", g)
		}
		if _, ok := g["link"]; ok {
			t.Errorf("group kept its link: %v", g)
		}
	}
}

func TestExportFallsBackToERSWhenOpenAPIIsOff(t *testing.T) {
	f := sourceISE(t)
	f.apiUnauthorized = true

	b := NewBundle(&Probe{Host: "src"})
	if err := ExportEndpoints(f.client(), b, []string{familyEndpoints}, []string{"Printers"}, quiet); err != nil {
		t.Fatalf("ExportEndpoints: %v", err)
	}
	if got := len(b.Objects[familyEndpoints]); got != 2 {
		t.Fatalf("endpoints exported = %d, want 2 via the ERS fallback", got)
	}
	if !strings.Contains(strings.Join(b.Notes, "\n"), "ERS /ers/config/endpoint") {
		t.Errorf("the fallback must be recorded in the bundle notes: %v", b.Notes)
	}
	if f.pagesServed["endpoint"] == 0 {
		t.Error("the ERS endpoint collection was never listed")
	}
}

func TestExportGroupsOnly(t *testing.T) {
	f := sourceISE(t)
	b := NewBundle(&Probe{Host: "src"})
	if err := ExportEndpoints(f.client(), b, []string{familyEndpointGroups}, nil, quiet); err != nil {
		t.Fatalf("ExportEndpoints: %v", err)
	}
	if _, ok := b.Objects[familyEndpoints]; ok {
		t.Error("endpoints were exported although the family was not selected")
	}
	if len(b.Objects[familyEndpointGroups]) != 2 {
		t.Errorf("groups = %v", b.Objects[familyEndpointGroups])
	}
}

// exportedBundle runs a real export against the source fixture so the import
// tests consume exactly what the export produces.
func exportedBundle(t *testing.T) *Bundle {
	t.Helper()
	f := sourceISE(t)
	b := NewBundle(&Probe{Host: "src", Version: "3.3.0.430", Nodes: []string{"ise-src-1"}})
	if err := ExportEndpoints(f.client(), b, []string{familyEndpointGroups, familyEndpoints}, []string{"Printers", "Cameras"}, quiet); err != nil {
		t.Fatalf("ExportEndpoints: %v", err)
	}
	return b
}

func TestPreflightClassifiesAndWritesNothing(t *testing.T) {
	b := exportedBundle(t)

	tgt := newFakeISE(t)
	tgt.addGroup("t1", "Printers")                       // already there
	tgt.addProfile("tp1", "Cisco-Device")                // resolvable
	tgt.addEndpoint("AA:BB:CC:DD:EE:01", "t1", true, "") // already there
	// No "Apple-Device" profile on the target on purpose.
	b.Objects[familyEndpoints] = append(b.Objects[familyEndpoints], map[string]any{
		"mac": "AA:BB:CC:DD:EE:09", "name": "AA:BB:CC:DD:EE:09",
		"groupName": "Printers", "profileName": "Apple-Device",
		"staticProfileAssignment": true,
	})

	before := len(tgt.groups) + len(tgt.endpoints)
	rep, err := Preflight(tgt.client(), b)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if len(tgt.groups)+len(tgt.endpoints) != before || len(tgt.created) != 0 {
		t.Fatal("pre-flight wrote to the target")
	}

	byName := map[string]PreflightItem{}
	for _, it := range rep.Items {
		byName[it.Name] = it
	}
	if got := byName["Printers"].Action; got != actionSkip {
		t.Errorf("existing group: action = %q, want skip", got)
	}
	if got := byName["Cameras"].Action; got != actionCreate {
		t.Errorf("new group: action = %q, want create", got)
	}
	if got := byName["AA:BB:CC:DD:EE:01"].Action; got != actionSkip {
		t.Errorf("existing endpoint: action = %q, want skip", got)
	}
	if got := byName["AA:BB:CC:DD:EE:03"].Action; got != actionCreate {
		t.Errorf("endpoint in a group created by this run: action = %q (%s), want create",
			got, byName["AA:BB:CC:DD:EE:03"].Reason)
	}
	blocked := byName["AA:BB:CC:DD:EE:09"]
	if blocked.Action != actionBlocked || !strings.Contains(blocked.Reason, "Apple-Device") {
		t.Errorf("endpoint with an unresolvable profile: %+v", blocked)
	}
	if rep.Blocked != 1 || rep.Skip != 2 {
		t.Errorf("counts wrong: create=%d skip=%d blocked=%d", rep.Create, rep.Skip, rep.Blocked)
	}
}

func TestApplyCreatesOnlyWhatPreflightAllowed(t *testing.T) {
	b := exportedBundle(t)

	tgt := newFakeISE(t)
	tgt.addGroup("t1", "Printers")
	tgt.addProfile("tp1", "Cisco-Device")
	tgt.addEndpoint("AA:BB:CC:DD:EE:01", "t1", true, "")

	c := tgt.client()
	rep, err := Preflight(c, b)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	res, err := ApplyImport(c, rep, quiet)
	if err != nil {
		t.Fatalf("ApplyImport: %v", err)
	}
	if res.Failed != 0 {
		t.Fatalf("failures: %v", res.Errors)
	}
	// Cameras + endpoints 03 and 04 (01 already exists, 02/05 never exported).
	if res.Created != 3 {
		t.Errorf("created = %d, want 3 (%v)", res.Created, tgt.created)
	}
	if len(tgt.created["endpointgroup"]) != 1 || tgt.created["endpointgroup"][0]["name"] != "Cameras" {
		t.Fatalf("group creates = %v", tgt.created["endpointgroup"])
	}

	var camera map[string]any
	for _, e := range tgt.created["endpoint"] {
		if e["mac"] == "AA:BB:CC:DD:EE:03" {
			camera = e
		}
	}
	if camera == nil {
		t.Fatalf("endpoint 03 was not created: %v", tgt.created["endpoint"])
	}
	// It must point at the group the *target* just minted, not the source UUID.
	var camerasID any
	for _, g := range tgt.groups {
		if g["name"] == "Cameras" {
			camerasID = g["id"]
		}
	}
	if camerasID == nil || camera["groupId"] != camerasID {
		t.Errorf("groupId = %v, want the newly created target group's id %v", camera["groupId"], camerasID)
	}
	if _, ok := camera["groupName"]; ok {
		t.Error("groupName must not be sent to ISE")
	}

	// Running it again must create nothing: create-only, never overwrite.
	rep2, err := Preflight(c, b)
	if err != nil {
		t.Fatalf("Preflight (second run): %v", err)
	}
	if rep2.Create != 0 {
		t.Errorf("second run wants to create %d objects; everything already exists", rep2.Create)
	}
	res2, err := ApplyImport(c, rep2, quiet)
	if err != nil {
		t.Fatalf("ApplyImport (second run): %v", err)
	}
	if res2.Created != 0 || res2.Failed != 0 {
		t.Errorf("second run: created=%d failed=%d %v", res2.Created, res2.Failed, res2.Errors)
	}
}

func TestApplyReportsISEErrorText(t *testing.T) {
	b := NewBundle(nil)
	b.Objects[familyEndpointGroups] = []map[string]any{{"name": "Printers"}}

	tgt := newFakeISE(t)
	c := tgt.client()
	rep, err := Preflight(c, b)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	// Someone else created the group between the gate and the write.
	tgt.addGroup("t9", "Printers")

	res, err := ApplyImport(c, rep, quiet)
	if err != nil {
		t.Fatalf("ApplyImport: %v", err)
	}
	if res.Skipped != 1 || res.Created != 0 || res.Failed != 0 {
		t.Errorf("a race with an existing object is a skip, not a failure: %+v", res)
	}
}
