package main

import (
	"strings"
	"testing"
	"time"
)

// TestExportPolicyElements verifies that policy elements are exported correctly.
func TestExportPolicyElements(t *testing.T) {
	f := newFakeISE(t)

	// Add some policy elements to the fake ISE
	f.addNetworkDeviceGroup("ndg1", "Device Type#Switches", "Switch devices")
	f.addDACL("dacl1", "PERMIT_ALL", "permit ip any any")
	f.addAuthProfile("ap1", "DefaultProfile", "")
	f.addIdStoreSequence("iss1", "Default_Sequence", "")
	f.addCondition("cond1", "MyCondition", "LibraryConditionAttributes")

	c := f.client()
	b := NewBundle(&Probe{Host: "src"})
	err := ExportPolicyElements(c, b, []string{familyPolicyElements}, quiet)
	if err != nil {
		t.Fatalf("ExportPolicyElements: %v", err)
	}

	items := b.Objects[familyPolicyElements]
	if len(items) != 5 {
		t.Fatalf("exported items = %d, want 5", len(items))
	}

	// Verify each kind is present
	kinds := make(map[string]int)
	for _, item := range items {
		kind := str(item, "kind")
		kinds[kind]++
		// Verify id and link are stripped
		if _, ok := item["id"]; ok {
			t.Errorf("item has id: %v", item)
		}
		if _, ok := item["link"]; ok {
			t.Errorf("item has link: %v", item)
		}
	}

	if kinds["networkDeviceGroup"] != 1 {
		t.Errorf("networkDeviceGroup count = %d, want 1", kinds["networkDeviceGroup"])
	}
	if kinds["dacl"] != 1 {
		t.Errorf("dacl count = %d, want 1", kinds["dacl"])
	}
	if kinds["authorizationProfile"] != 1 {
		t.Errorf("authorizationProfile count = %d, want 1", kinds["authorizationProfile"])
	}
	if kinds["idStoreSequence"] != 1 {
		t.Errorf("idStoreSequence count = %d, want 1", kinds["idStoreSequence"])
	}
	if kinds["condition"] != 1 {
		t.Errorf("condition count = %d, want 1", kinds["condition"])
	}
}

// TestPreflightPolicyElements verifies pre-flight resolution of policy elements.
func TestPreflightPolicyElements(t *testing.T) {
	// Source ISE
	f := newFakeISE(t)
	f.addNetworkDeviceGroup("ndg1", "Device Type#Switches", "")
	f.addDACL("dacl1", "PERMIT_ALL", "permit ip any any")
	f.addAuthProfile("ap1", "DefaultProfile", "")
	f.addIdStoreSequence("iss1", "Default_Sequence", "")
	f.addCondition("cond1", "MyCondition", "LibraryConditionAttributes")

	// Target ISE (empty)
	t2 := newFakeISE(t)

	// Export from source
	c := f.client()
	b := NewBundle(&Probe{Host: "src"})
	err := ExportPolicyElements(c, b, []string{familyPolicyElements}, quiet)
	if err != nil {
		t.Fatalf("ExportPolicyElements: %v", err)
	}

	// Check what was exported
	items := b.Objects[familyPolicyElements]
	if len(items) == 0 {
		t.Fatalf("bundle has no policy elements")
	}

	// Run pre-flight against the target (empty)
	ct := t2.client()
	r, err := Preflight(ct, b, []string{}, false)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	// Count items by action
	creates := 0
	skips := 0
	for _, it := range r.Items {
		if it.Family == familyPolicyElements {
			if it.Action == actionCreate {
				creates++
			} else if it.Action == actionSkip {
				skips++
			}
		}
	}
	// Against an empty target everything is created: the five objects plus the
	// "Device Type" ancestor the group needs. Nothing is skipped for being
	// factory-named — a name that looks like ISE's own is still missing on a
	// target that does not have it, and dropping it would lose the operator's
	// own device types.
	// Five objects. "Device Type#Switches" needs no ancestor: its first segment
	// is the group type, which is not an object.
	if creates != 5 {
		t.Logf("got %d creates, %d skips: %+v", creates, skips, r.Items)
		t.Fatalf("pre-flight creates = %d, want 5", creates)
	}
	if skips != 0 {
		t.Fatalf("pre-flight skips = %d, want 0 against an empty target", skips)
	}
}

// A factory object the target already has is skipped and never written — but if
// its content differs from the source's, the operator is told, because a
// customised factory object silently left at the target's version is the whole
// reason this comparison exists.
func TestPreflightReportsContentDriftOnSkip(t *testing.T) {
	src := newFakeISE(t)
	src.addDACL("dacl1", "PERMIT_ALL_IPV4_TRAFFIC", "permit ip any any")

	tgt := newFakeISE(t)
	tgt.addDACL("dacl9", "PERMIT_ALL_IPV4_TRAFFIC", "deny ip any any")

	b := NewBundle(&Probe{Host: "src"})
	if err := ExportPolicyElements(src.client(), b, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export: %v", err)
	}
	r, err := Preflight(tgt.client(), b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}

	var found bool
	for _, it := range r.Items {
		if it.Family != familyPolicyElements || it.Name != "PERMIT_ALL_IPV4_TRAFFIC" {
			continue
		}
		found = true
		if it.Action != actionSkip {
			t.Fatalf("action = %q, want skip: the tool never overwrites what it did not create", it.Action)
		}
		if !strings.Contains(it.Reason, "DIFFERS") || !strings.Contains(it.Reason, "dacl") {
			t.Errorf("reason should name the field that drifted, got %q", it.Reason)
		}
	}
	if !found {
		t.Fatal("the dACL never appeared in the report")
	}

	// Identical content on both sides is a plain skip with nothing alarming said.
	tgt2 := newFakeISE(t)
	tgt2.addDACL("dacl9", "PERMIT_ALL_IPV4_TRAFFIC", "permit ip any any")
	r2, err := Preflight(tgt2.client(), b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	for _, it := range r2.Items {
		if it.Name == "PERMIT_ALL_IPV4_TRAFFIC" && strings.Contains(it.Reason, "DIFFERS") {
			t.Errorf("identical content reported as drift: %q", it.Reason)
		}
	}
}

// TestAuthProfileDACLReference verifies that authorization profiles block on missing dACLs.
func TestAuthProfileDACLReference(t *testing.T) {
	f := newFakeISE(t)
	// Don't add the dACL, just the profile
	f.addDACL("dacl1", "PERMIT_ALL", "permit ip any any")

	c := f.client()
	b := NewBundle(&Probe{Host: "src"})
	ExportPolicyElements(c, b, []string{familyPolicyElements}, quiet)

	// Remove the dACL from the export, leaving only the profile
	// This simulates a case where the dACL was deleted on the source but the profile still references it
	filtered := []map[string]any{}
	for _, item := range b.Objects[familyPolicyElements] {
		if str(item, "kind") != "dacl" {
			filtered = append(filtered, item)
		}
	}
	b.Objects[familyPolicyElements] = filtered

	// Add the dACL back with a reference from the profile
	prof := map[string]any{
		"kind":     "authorizationProfile",
		"name":     "ProfileWithDACL",
		"daclName": "MISSING_DACL",
	}
	b.Objects[familyPolicyElements] = append(b.Objects[familyPolicyElements], prof)

	// Pre-flight should block this profile
	r, err := Preflight(c, b, []string{}, false)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	blocked := 0
	for _, it := range r.Items {
		if it.Family == familyPolicyElements && it.Action == actionBlocked && strings.Contains(it.Reason, "MISSING_DACL") {
			blocked++
		}
	}
	if blocked != 1 {
		t.Fatalf("blocked items with missing dACL = %d, want 1", blocked)
	}
}

// TestNetworkDeviceGroupAncestors verifies that ancestors are pulled in automatically.
func TestNetworkDeviceGroupAncestors(t *testing.T) {
	f := newFakeISE(t)
	// Add a nested group without its parents
	f.addNetworkDeviceGroup("ndg1", "Location#EMEA#Ireland", "Ireland office")

	c := f.client()
	b := NewBundle(&Probe{Host: "src"})
	ExportPolicyElements(c, b, []string{familyPolicyElements}, quiet)

	// The export should have the child group
	items := b.Objects[familyPolicyElements]
	if len(items) != 1 {
		t.Fatalf("exported items = %d, want 1", len(items))
	}

	// Pre-flight should create ancestors
	r, err := Preflight(c, b, []string{}, false)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	// Count creates
	creates := 0
	ancestorCreates := 0
	for _, it := range r.Items {
		if it.Family == familyPolicyElements && it.Action == actionCreate {
			creates++
			if strings.Contains(it.Reason, "created because") {
				ancestorCreates++
			}
		}
	}
	// "Location#EMEA#Ireland" depends on one group, "Location#EMEA". The first
	// segment is the group type, not a group: ISE refuses a create for it.
	if creates != 1 {
		t.Fatalf("creates = %d, want 1 (the one real ancestor)", creates)
	}
	if ancestorCreates != 1 {
		t.Fatalf("ancestor creates = %d, want 1", ancestorCreates)
	}
}

// TestIdStoreSequenceReferences verifies that missing identity stores block the sequence.
func TestIdStoreSequenceReferences(t *testing.T) {
	f := newFakeISE(t)
	// Don't add any AD join points

	c := f.client()
	b := NewBundle(&Probe{Host: "src"})

	// Manually add an identity source sequence that references a missing store
	iss := map[string]any{
		"kind": "idStoreSequence",
		"name": "Custom_Sequence",
		"idSeqItem": []any{
			map[string]any{"idstore": "MissingADJoinPoint", "order": 1},
		},
	}
	b.Objects[familyPolicyElements] = []map[string]any{iss}

	// Pre-flight should block this
	r, err := Preflight(c, b, []string{}, false)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}

	blocked := 0
	for _, it := range r.Items {
		if it.Family == familyPolicyElements && it.Action == actionBlocked && strings.Contains(it.Reason, "MissingADJoinPoint") {
			blocked++
		}
	}
	if blocked != 1 {
		t.Fatalf("blocked items with missing store = %d, want 1", blocked)
	}
}

/* Helper methods for fakeISE */

func (f *fakeISE) addNetworkDeviceGroup(id, name, desc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := map[string]any{
		"id":          id,
		"name":        name,
		"description": desc,
	}
	f.networkDeviceGroups = append(f.networkDeviceGroups, obj)
}

func (f *fakeISE) addDACL(id, name, acl string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := map[string]any{
		"id":       id,
		"name":     name,
		"dacl":     acl,
		"daclType": "IPV4",
	}
	f.dacls = append(f.dacls, obj)
}

func (f *fakeISE) addAuthProfile(id, name, desc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := map[string]any{
		"id":          id,
		"name":        name,
		"description": desc,
	}
	f.authProfiles = append(f.authProfiles, obj)
}

func (f *fakeISE) addIdStoreSequence(id, name, desc string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := map[string]any{
		"id":          id,
		"name":        name,
		"description": desc,
		"idSeqItem": []any{
			map[string]any{"idstore": "Internal Users", "order": 1},
		},
	}
	f.idStoreSequences = append(f.idStoreSequences, obj)
}

func (f *fakeISE) addCondition(id, name, condType string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := map[string]any{
		"id":            id,
		"name":          name,
		"conditionType": condType,
		"isNegate":      false,
	}
	f.conditions = append(f.conditions, obj)
}

// ISE 3.4 cannot deserialise an authorization profile holding a web redirection:
// the collection read answers 500, and so does that one profile's own id. The
// export must carry the readable ones and name the one it could not read —
// never put the OpenAPI stub in the bundle, which is a name and an id and would
// land on the target as a profile that authorises nothing.
func TestExportSkipsUnreadableAuthProfileAndNamesIt(t *testing.T) {
	f := newFakeISE(t)
	f.authProfileListFails = true
	f.authProfileDetailFails = map[string]bool{"ap-guest": true}
	f.addAuthProfile("ap-ok", "Allow_Corp", "readable")
	f.addAuthProfile("ap-guest", "ACME-Guest_Profile", "web redirect")

	b := NewBundle(&Probe{Host: "src"})
	if err := ExportPolicyElements(f.client(), b, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export must survive a profile ISE cannot read: %v", err)
	}

	var names []string
	for _, o := range b.Objects[familyPolicyElements] {
		if str(o, "kind") == "authorizationProfile" {
			names = append(names, str(o, "name"))
		}
	}
	if len(names) != 1 || names[0] != "Allow_Corp" {
		t.Fatalf("exported profiles = %v, want only the readable one", names)
	}

	var noted bool
	for _, n := range b.Notes {
		if strings.Contains(n, "ACME-Guest_Profile") && strings.Contains(n, "WebRedirection") && strings.Contains(n, "by hand") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("the unreadable profile must be named with ISE's own error and what to do; notes were %v", b.Notes)
	}
}

// The same failure on the target side must not take the family down with it: the
// profile is still skipped as existing, and the report says the content could
// not be compared rather than claiming the two copies match.
func TestPreflightReportsUncomparableProfile(t *testing.T) {
	src := newFakeISE(t)
	src.addAuthProfile("ap1", "Allow_Corp", "source version")

	tgt := newFakeISE(t)
	tgt.addAuthProfile("ap9", "Allow_Corp", "target version")
	tgt.authProfileDetailFails = map[string]bool{"ap9": true}

	b := NewBundle(&Probe{Host: "src"})
	if err := ExportPolicyElements(src.client(), b, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export: %v", err)
	}
	r, err := Preflight(tgt.client(), b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	for _, it := range r.Items {
		if it.Name != "Allow_Corp" {
			continue
		}
		if it.Action != actionSkip {
			t.Fatalf("action = %q, want skip", it.Action)
		}
		if !strings.Contains(it.Reason, "could not be compared") {
			t.Errorf("reason = %q, want it to admit the comparison failed", it.Reason)
		}
		return
	}
	t.Fatal("the profile never appeared in the report")
}

// Portals cannot be listed on 3.4 — GET /ers/config/portal answers 500 — so a
// profile's web redirection cannot be checked in advance. It is attempted, and
// if the target refuses it the profile is created without the redirect and the
// operator is told what to set by hand. Losing the whole profile over a portal
// this tool never migrates would be worse.
func TestWebRedirectionRetriedWithoutTheRedirect(t *testing.T) {
	src := newFakeISE(t)
	src.addAuthProfile("ap1", "Guest_Profile", "")
	src.mu.Lock()
	src.authProfiles[len(src.authProfiles)-1]["webRedirection"] = map[string]any{
		"WebRedirectionType": "CentralizedWebAuth",
		"acl":                "ACL_WEBAUTH_REDIRECT",
		"portalName":         "ibk-lab-guest",
	}
	src.mu.Unlock()

	b := NewBundle(&Probe{Host: "src"})
	if err := ExportPolicyElements(src.client(), b, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export: %v", err)
	}

	tgt := newFakeISE(t)
	tgt.rejectWebRedirection = true
	ct := tgt.client()
	rep, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	res, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, false, quiet)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Created < 1 {
		t.Fatalf("the profile should have been created without its redirect, got %+v", res)
	}

	tgt.mu.Lock()
	defer tgt.mu.Unlock()
	var landed map[string]any
	for _, p := range tgt.authProfiles {
		if str(p, "name") == "Guest_Profile" {
			landed = p
		}
	}
	if landed == nil {
		t.Fatal("the profile never reached the target")
	}
	if landed["webRedirection"] != nil {
		t.Error("the redirect was kept; the target refused it, so it must have been dropped")
	}
	var told bool
	for _, e := range res.Errors {
		if strings.Contains(e, "Guest_Profile") && strings.Contains(strings.ToLower(e), "redirect") {
			told = true
		}
	}
	if !told {
		t.Errorf("the report must say the redirect was dropped, got %v", res.Errors)
	}
}

// Re-running a completed import writes nothing: everything is skipped by name.
func TestPolicyElementsReRunCreatesNothing(t *testing.T) {
	src := newFakeISE(t)
	src.addNetworkDeviceGroup("ndg1", "Device Type#All Device Types#Router", "")
	src.addDACL("dacl1", "PERMIT_ALL_IPV4_TRAFFIC", "permit ip any any")
	src.addAuthProfile("ap1", "Allow_Corp", "")
	src.addIdStoreSequence("iss1", "Corp_Sequence", "")
	src.addCondition("cond1", "Wired_802.1X", "LibraryConditionAttributes")

	b := NewBundle(&Probe{Host: "src"})
	if err := ExportPolicyElements(src.client(), b, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export: %v", err)
	}

	tgt := newFakeISE(t)
	ct := tgt.client()
	rep, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	first, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, false, quiet)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if first.Created == 0 || first.Failed != 0 {
		t.Fatalf("first run should create everything and fail nothing, got %+v", first)
	}

	rep2, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("second preflight: %v", err)
	}
	second, err := ApplyImport(ct, rep2, "test-passphrase-1234567890", "", nil, false, false, quiet)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if second.Created != 0 || second.Failed != 0 {
		t.Fatalf("a re-run must write nothing, got %+v (preflight said %d create)", second, rep2.Create)
	}
}

// Policy elements carry no enabled/disabled state — ISE has one on policy sets
// and on nothing here — so what the tool created is marked in the description,
// which is the one field all five families share.
func TestImportMarksWhatItCreated(t *testing.T) {
	src := newFakeISE(t)
	src.addDACL("dacl1", "CORP_QUARANTINE", "permit ip any any")
	src.addNetworkDeviceGroup("ndg1", "Device Type#Switches", "")
	src.mu.Lock()
	src.dacls[0]["description"] = "Quarantine ACL"
	src.mu.Unlock()

	b := NewBundle(&Probe{Host: "src"})
	if err := ExportPolicyElements(src.client(), b, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export: %v", err)
	}

	tgt := newFakeISE(t)
	ct := tgt.client()
	rep, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if _, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, false, quiet); err != nil {
		t.Fatalf("apply: %v", err)
	}

	tgt.mu.Lock()
	defer tgt.mu.Unlock()
	for _, d := range tgt.dacls {
		if str(d, "name") != "CORP_QUARANTINE" {
			continue
		}
		desc := str(d, "description")
		if !strings.Contains(desc, importMarkerPrefix) {
			t.Fatalf("description = %q, want the import marker", desc)
		}
		if !strings.HasPrefix(desc, "Quarantine ACL") {
			t.Errorf("the source's own description was lost: %q", desc)
		}
		return
	}
	t.Fatal("the dACL never reached the target")
}

// The marker must not read as drift on the next run, or every object the tool
// created would report as differing from its own source.
func TestImportMarkerIsNotDrift(t *testing.T) {
	mine := map[string]any{"name": "X", "description": "Quarantine ACL", "dacl": "deny ip any any"}
	theirs := map[string]any{"name": "X", "description": "Quarantine ACL [ise2ise 2026-08-10]", "dacl": "deny ip any any"}
	if got := driftFields(mine, theirs); len(got) != 0 {
		t.Errorf("driftFields = %v, want none: the marker is this tool's own", got)
	}

	theirs["dacl"] = "permit ip any any"
	if got := driftFields(mine, theirs); len(got) != 1 || got[0] != "dacl" {
		t.Errorf("driftFields = %v, want exactly [dacl]: real drift must still be caught", got)
	}
}

func TestTagDescription(t *testing.T) {
	marker := importMarker(time.Now())

	if got := tagDescription(""); got != marker {
		t.Errorf("empty description = %q, want just the marker", got)
	}
	if got := tagDescription("Guest ACL"); got != "Guest ACL "+marker {
		t.Errorf("got %q", got)
	}
	// Marking twice must not stack: an object recreated after a manual delete
	// would otherwise collect a marker per run.
	once := tagDescription("Guest ACL")
	if twice := tagDescription(once); twice != once {
		t.Errorf("second tag changed it: %q -> %q", once, twice)
	}
	// An over-long description loses its tail, not the marker.
	long := tagDescription(strings.Repeat("x", 400))
	if len(long) > maxDescription {
		t.Errorf("length %d exceeds ISE's limit", len(long))
	}
	if !strings.HasSuffix(long, marker) {
		t.Errorf("the marker was truncated away: %q", long[len(long)-40:])
	}
}
