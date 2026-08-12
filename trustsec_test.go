package main

import (
	"slices"
	"strings"
	"testing"
)

// The ANY security group's real id on 3.4, kept because the tests lean on ISE
// hiding exactly this object from its own list.
const anySGTID = "92bb1950-8c01-11e6-996c-525400b48521"

func sgtObj(id, name string, value float64) map[string]any {
	return map[string]any{
		"id": id, "name": name, "value": value, "description": "",
		"generationId": "1", "propogateToApic": false,
		"link": map[string]any{"rel": "self"},
	}
}

func sgaclObj(id, name, content string) map[string]any {
	return map[string]any{
		"id": id, "name": name, "description": "", "generationId": "3",
		"ipVersion": "IPV4", "sgAclType": "TRUSTSEC", "validateAclContent": false,
		"aclcontent": content, "link": map[string]any{"rel": "self"},
	}
}

func cellObj(id, name, srcID, dstID, rule string, sgaclIDs ...string) map[string]any {
	ids := make([]any, 0, len(sgaclIDs))
	for _, s := range sgaclIDs {
		ids = append(ids, s)
	}
	return map[string]any{
		"id": id, "name": name, "sourceSgtId": srcID, "destinationSgtId": dstID,
		"matrixCellStatus": "ENABLED", "defaultRule": rule, "sgacls": ids,
		"matrixId": "9fa3a33a-329e-43cb-a4cf-7bd38df16e7b",
		"link":     map[string]any{"rel": "self"},
	}
}

// exported returns the bundle item of the given kind and name.
func exported(t *testing.T, b *Bundle, kind, name string) map[string]any {
	t.Helper()
	for _, item := range b.Objects[familyTrustSec] {
		if str(item, "kind") == kind && str(item, "name") == name {
			return item
		}
	}
	t.Fatalf("bundle has no %s named %q", kind, name)
	return nil
}

func itemNamed(t *testing.T, r *PreflightReport, name string) PreflightItem {
	t.Helper()
	for _, it := range r.Items {
		if it.Family == familyTrustSec && it.Name == name {
			return it
		}
	}
	t.Fatalf("pre-flight has no TrustSec item named %q", name)
	return PreflightItem{}
}

func TestTrustSecExport(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("sgt-prod", "Production", 24))
	f.sgacls = append(f.sgacls, sgaclObj("acl-1", "IpYesICMPno", "deny icmp\npermit ip"))
	f.egressCells = append(f.egressCells, cellObj("cell-1", "Production-Production", "sgt-prod", "sgt-prod", "NONE", "acl-1"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	if err := ExportTrustSec(f.client(), b, []string{familyTrustSec}, t.Logf); err != nil {
		t.Fatalf("ExportTrustSec: %v", err)
	}

	items := b.Objects[familyTrustSec]
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
	// An SGT has to be decided before the cell that names it, so the family is
	// ordered by kind and never alphabetically.
	if got := []string{str(items[0], "kind"), str(items[1], "kind"), str(items[2], "kind")}; !slices.Equal(got, trustSecKinds) {
		t.Errorf("bundle order is %v, want %v", got, trustSecKinds)
	}

	cell := exported(t, b, kindEgressCell, "Production-Production")
	if str(cell, "sourceSgtName") != "Production" || str(cell, "destinationSgtName") != "Production" {
		t.Errorf("SGT references did not become names: %v", cell)
	}
	if got := nameList(cell, "sgaclNames"); !slices.Equal(got, []string{"IpYesICMPno"}) {
		t.Errorf("sgaclNames = %v, want [IpYesICMPno]", got)
	}
	for _, gone := range []string{"sourceSgtId", "destinationSgtId", "sgacls", "id", "link", "matrixId", "generationId"} {
		if _, ok := cell[gone]; ok {
			t.Errorf("cell still carries %q, which belongs to the source deployment", gone)
		}
	}
	sgt := exported(t, b, kindSGT, "Production")
	if _, ok := sgt["generationId"]; ok {
		t.Error("SGT still carries generationId")
	}
	if sgt["value"] != 24.0 {
		t.Errorf("SGT value = %v, want 24", sgt["value"])
	}
	if len(b.Notes) == 0 || !containsNote(b.Notes, "not pushed to network devices") {
		t.Errorf("bundle does not say TrustSec is not deployed to devices: %v", b.Notes)
	}
}

// ISE leaves the ANY security group out of /ers/config/sgt but answers a GET on
// its id. Every default egress cell points at it, so export has to follow the
// reference the list cannot satisfy.
func TestTrustSecExportResolvesSGTHiddenFromTheList(t *testing.T) {
	f := newFakeISE(t)
	f.hiddenFromList = map[string]bool{anySGTID: true}
	f.sgts = append(f.sgts, sgtObj(anySGTID, "ANY", 65535), sgtObj("sgt-prod", "Production", 24))
	f.sgacls = append(f.sgacls, sgaclObj("acl-permit", "Permit IP", "permit ip"))
	f.egressCells = append(f.egressCells, cellObj("cell-any", "ANY-ANY", anySGTID, anySGTID, "PERMIT_IP", "acl-permit"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	if err := ExportTrustSec(f.client(), b, []string{familyTrustSec}, t.Logf); err != nil {
		t.Fatalf("ExportTrustSec: %v", err)
	}

	// The hidden SGT is not in the family - it was never listed - but the cell
	// still names it.
	cell := exported(t, b, kindEgressCell, "ANY-ANY")
	if str(cell, "sourceSgtName") != "ANY" || str(cell, "destinationSgtName") != "ANY" {
		t.Fatalf("hidden SGT was not resolved by a direct GET: %v", cell)
	}
	for _, n := range b.Notes {
		if strings.Contains(n, "would not return") {
			t.Errorf("resolution succeeded but was reported as a failure: %s", n)
		}
	}
}

// A reference ISE will not resolve at all is carried as the id and reported, so
// the cell blocks on import instead of being written against nothing.
func TestTrustSecExportReportsUnresolvableReference(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("sgt-prod", "Production", 24))
	f.egressCells = append(f.egressCells, cellObj("cell-1", "Production-Gone", "sgt-prod", "sgt-vanished", "NONE"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	if err := ExportTrustSec(f.client(), b, []string{familyTrustSec}, t.Logf); err != nil {
		t.Fatalf("ExportTrustSec: %v", err)
	}
	cell := exported(t, b, kindEgressCell, "Production-Gone")
	if str(cell, "destinationSgtName") != "sgt-vanished" {
		t.Errorf("unresolvable reference was not kept as its id: %v", cell["destinationSgtName"])
	}
	if !containsNote(b.Notes, "sgt-vanished") {
		t.Errorf("nothing in the notes names the reference that could not be followed: %v", b.Notes)
	}
}

// A tag value is what a switch puts on the wire, so an SGT whose value the
// target has given to another name is left out and the holder is named.
func TestTrustSecTagCollisionBlocks(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-1", "VLAN_175", 16))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		{"kind": kindSGT, "name": "TestSGT", "value": 16.0, "description": ""},
	}

	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(f.client(), b, r)

	it := itemNamed(t, r, "TestSGT")
	if it.Action != actionSkip {
		t.Errorf("action = %q, want %q", it.Action, actionSkip)
	}
	if !strings.Contains(it.Reason, "VLAN_175") || !strings.Contains(it.Reason, "16") {
		t.Errorf("reason does not name the holder and the value: %s", it.Reason)
	}
}

// The same name with the same value is not a collision with itself.
func TestTrustSecSameNameSameValueIsDriftNotCollision(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-1", "Auditors", 9))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		{"kind": kindSGT, "name": "Auditors", "value": 9.0, "description": "Auditor Security Group"},
	}

	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(f.client(), b, r)

	it := itemNamed(t, r, "Auditors")
	if it.Action != actionSkip {
		t.Fatalf("action = %q, want %q", it.Action, actionSkip)
	}
	if !strings.Contains(it.Reason, "already exists") || !strings.Contains(it.Reason, "description") {
		t.Errorf("reason should report the description drift, got: %s", it.Reason)
	}
}

// One build answers with a property, another leaves it out, and the object is
// the same object. The lab pair does exactly this with validateAclContent.
func TestTrustSecAbsentPropertyIsNotDrift(t *testing.T) {
	f := newFakeISE(t)
	target := sgaclObj("tgt-1", "Permit IP", "permit ip")
	delete(target, "validateAclContent")
	f.sgacls = append(f.sgacls, target)

	mine := portableTrustSec(sgaclObj("src-1", "Permit IP", "permit ip"))
	mine["kind"] = kindSGACL
	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{mine}

	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(f.client(), b, r)

	if it := itemNamed(t, r, "Permit IP"); strings.Contains(it.Reason, "validateAclContent") {
		t.Errorf("a property one build omits was reported as drift: %s", it.Reason)
	}

	// A property the target actually sets differently is still drift.
	f2 := newFakeISE(t)
	other := sgaclObj("tgt-2", "Permit IP", "permit ip")
	other["validateAclContent"] = true
	f2.sgacls = append(f2.sgacls, other)
	r2 := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(f2.client(), b, r2)
	if it := itemNamed(t, r2, "Permit IP"); !strings.Contains(it.Reason, "validateAclContent") {
		t.Errorf("a property the target sets differently was not reported: %s", it.Reason)
	}
}

func TestTrustSecIdenticalObjectIsReportedAsIdentical(t *testing.T) {
	f := newFakeISE(t)
	f.sgacls = append(f.sgacls, sgaclObj("tgt-1", "Permit IP", "permit ip"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		portableTrustSec(sgaclObj("src-1", "Permit IP", "permit ip")),
	}
	b.Objects[familyTrustSec][0]["kind"] = kindSGACL

	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(f.client(), b, r)

	it := itemNamed(t, r, "Permit IP")
	if it.Action != actionSkip || !strings.Contains(it.Reason, "identical") {
		t.Errorf("action=%q reason=%q, want a skip reported as identical", it.Action, it.Reason)
	}
}

// A cell is written whole or not at all: one missing SGACL and the whole cell
// stays out, because a cell short of a rule permits or denies the wrong traffic.
func TestTrustSecCellBlockedWholeByMissingSGACL(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-prod", "Production", 24))
	// The target has one of the cell's two SGACLs, which is the case a partial
	// write would slip through.
	f.sgacls = append(f.sgacls, sgaclObj("tgt-permit", "Permit IP", "permit ip"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		{"kind": kindEgressCell, "name": "Production-Production",
			"sourceSgtName": "Production", "destinationSgtName": "Production",
			"defaultRule": "NONE", "matrixCellStatus": "ENABLED",
			"sgaclNames": []any{"Permit IP", "IpYesICMPno"}},
	}

	c := f.client()
	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(c, b, r)

	it := itemNamed(t, r, "Production-Production")
	if it.Action != actionSkip {
		t.Fatalf("action = %q, want %q", it.Action, actionSkip)
	}
	if !strings.Contains(it.Reason, "IpYesICMPno") {
		t.Errorf("reason does not name the missing SGACL: %s", it.Reason)
	}

	res := &ImportResult{}
	if err := applyTrustSec(c, r, res, t.Logf); err != nil {
		t.Fatalf("applyTrustSec: %v", err)
	}
	if len(f.egressCells) != 0 {
		t.Errorf("a blocked cell was written anyway: %v", f.egressCells)
	}
}

// An SGT blocked by a tag collision takes the cells that name it with it.
func TestTrustSecCellBlockedByCollidingSGT(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-1", "VLAN_175", 16))
	f.sgacls = append(f.sgacls, sgaclObj("tgt-acl", "Permit IP", "permit ip"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		{"kind": kindSGT, "name": "TestSGT", "value": 16.0},
		{"kind": kindEgressCell, "name": "TestSGT-TestSGT",
			"sourceSgtName": "TestSGT", "destinationSgtName": "TestSGT",
			"defaultRule": "NONE", "sgaclNames": []any{"Permit IP"}},
	}

	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(f.client(), b, r)

	it := itemNamed(t, r, "TestSGT-TestSGT")
	if it.Action != actionSkip || !strings.Contains(it.Reason, "TestSGT") {
		t.Errorf("action=%q reason=%q, want the cell blocked on its security group", it.Action, it.Reason)
	}
}

// The default cell decides every pair with no cell of its own. It is described
// and never written, and the description has to name both sides for real.
func TestTrustSecDefaultCellIsReportedNeverWritten(t *testing.T) {
	f := newFakeISE(t)
	f.hiddenFromList = map[string]bool{anySGTID: true}
	f.sgts = append(f.sgts, sgtObj(anySGTID, "ANY", 65535))
	f.sgacls = append(f.sgacls, sgaclObj("tgt-permit", "Permit IP", "permit ip"))
	f.egressCells = append(f.egressCells, cellObj("tgt-any", "ANY-ANY", anySGTID, anySGTID, "PERMIT_IP", "tgt-permit"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		{"kind": kindEgressCell, "name": "ANY-ANY",
			"sourceSgtName": "ANY", "destinationSgtName": "ANY",
			"defaultRule": "DENY_IP", "matrixCellStatus": "ENABLED",
			"sgaclNames": []any{"Deny IP"}},
	}

	c := f.client()
	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(c, b, r)

	it := itemNamed(t, r, "ANY-ANY")
	if it.Action != actionSkip {
		t.Fatalf("action = %q, want %q", it.Action, actionSkip)
	}
	for _, want := range []string{"DENY_IP", "Deny IP", "PERMIT_IP", "Permit IP"} {
		if !strings.Contains(it.Reason, want) {
			t.Errorf("reason %q does not mention %q; both sides have to be named", it.Reason, want)
		}
	}

	res := &ImportResult{}
	if err := applyTrustSec(c, r, res, t.Logf); err != nil {
		t.Fatalf("applyTrustSec: %v", err)
	}
	if len(f.egressCells) != 1 {
		t.Errorf("the default cell was written: %d cells on the target", len(f.egressCells))
	}
}

// A cell holding a catch-all rule and an SGACL at once is what ISE refused on
// the lab. It is still attempted, and the operator is told why it may fail.
func TestTrustSecCatchAllPlusSGACLIsNoted(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-aud", "Auditors", 9))
	f.sgacls = append(f.sgacls, sgaclObj("tgt-deny", "Deny IP", "deny ip"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		{"kind": kindEgressCell, "name": "Auditors-Auditors",
			"sourceSgtName": "Auditors", "destinationSgtName": "Auditors",
			"defaultRule": "DENY_IP", "matrixCellStatus": "ENABLED",
			"sgaclNames": []any{"Deny IP"}},
	}

	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(f.client(), b, r)

	if it := itemNamed(t, r, "Auditors-Auditors"); it.Action != actionCreate {
		t.Errorf("action = %q, want the cell attempted", it.Action)
	}
	if !containsNote(r.Notes, "Multiple SGACLs per cell") {
		t.Errorf("nothing warns about the setting that decides this: %v", r.Notes)
	}
}

// The whole slice end to end: what the target lacks is created, in an order
// that lets the cell resolve the SGT and SGACL created moments earlier.
func TestTrustSecImportCreatesInDependencyOrder(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-prod", "Production", 24))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	b.Objects[familyTrustSec] = []map[string]any{
		{"kind": kindSGT, "name": "Guests", "value": 6.0, "description": "Guest Security Group"},
		{"kind": kindSGACL, "name": "IpYesICMPno", "aclcontent": "deny icmp\npermit ip", "ipVersion": "IPV4", "sgAclType": "TRUSTSEC"},
		{"kind": kindEgressCell, "name": "Production-Guests",
			"sourceSgtName": "Production", "destinationSgtName": "Guests",
			"defaultRule": "NONE", "matrixCellStatus": "ENABLED",
			"sgaclNames": []any{"IpYesICMPno"}},
	}

	c := f.client()
	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(c, b, r)
	for _, name := range []string{"Guests", "IpYesICMPno", "Production-Guests"} {
		if it := itemNamed(t, r, name); it.Action != actionCreate {
			t.Errorf("%s: action=%q reason=%q, want create", name, it.Action, it.Reason)
		}
	}

	res := &ImportResult{}
	if err := applyTrustSec(c, r, res, t.Logf); err != nil {
		t.Fatalf("applyTrustSec: %v", err)
	}
	if res.Created != 3 || res.Failed != 0 {
		t.Fatalf("created=%d failed=%d errors=%v, want 3 created", res.Created, res.Failed, res.Errors)
	}

	if len(f.egressCells) != 1 {
		t.Fatalf("expected one cell on the target, got %d", len(f.egressCells))
	}
	cell := f.egressCells[0]
	// The cell has to carry the target's own UUIDs, not the source's names.
	if _, ok := cell["sourceSgtName"]; ok {
		t.Error("the cell was written with a name where ISE wants a UUID")
	}
	sgtIDs, _ := stubsByName(c, pathSGT)
	sgaclIDs, _ := stubsByName(c, pathSGACL)
	if cell["sourceSgtId"] != sgtIDs["Production"] || cell["destinationSgtId"] != sgtIDs["Guests"] {
		t.Errorf("cell SGT references = %v/%v, want %v/%v",
			cell["sourceSgtId"], cell["destinationSgtId"], sgtIDs["Production"], sgtIDs["Guests"])
	}
	if ids, ok := cell["sgacls"].([]any); !ok || len(ids) != 1 || ids[0] != sgaclIDs["IpYesICMPno"] {
		t.Errorf("cell SGACL references = %v, want [%v]", cell["sgacls"], sgaclIDs["IpYesICMPno"])
	}
}

// The second run over an already-migrated target writes nothing.
func TestTrustSecRerunCreatesNothing(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-prod", "Production", 24))
	f.sgacls = append(f.sgacls, sgaclObj("tgt-acl", "Permit IP", "permit ip"))
	f.egressCells = append(f.egressCells, cellObj("tgt-cell", "Production-Production", "tgt-prod", "tgt-prod", "NONE", "tgt-acl"))

	// The bundle is what an export of that same target would produce.
	src := newFakeISE(t)
	src.sgts = append(src.sgts, sgtObj("src-prod", "Production", 24))
	src.sgacls = append(src.sgacls, sgaclObj("src-acl", "Permit IP", "permit ip"))
	src.egressCells = append(src.egressCells, cellObj("src-cell", "Production-Production", "src-prod", "src-prod", "NONE", "src-acl"))

	b := NewBundle(&Probe{Version: "3.4.0.608"})
	if err := ExportTrustSec(src.client(), b, []string{familyTrustSec}, t.Logf); err != nil {
		t.Fatalf("ExportTrustSec: %v", err)
	}

	c := f.client()
	r := &PreflightReport{Items: []PreflightItem{}}
	preflightTrustSec(c, b, r)

	res := &ImportResult{}
	if err := applyTrustSec(c, r, res, t.Logf); err != nil {
		t.Fatalf("applyTrustSec: %v", err)
	}
	if res.Created != 0 {
		t.Errorf("created %d on a re-run, want 0", res.Created)
	}
	if res.Skipped != 3 {
		t.Errorf("skipped %d, want 3", res.Skipped)
	}
	if len(f.sgts) != 1 || len(f.sgacls) != 1 || len(f.egressCells) != 1 {
		t.Errorf("the target grew on a re-run: %d SGTs, %d SGACLs, %d cells", len(f.sgts), len(f.sgacls), len(f.egressCells))
	}
}

// A security group this run creates is one a policy set is allowed to name.
func TestTrustSecSGTNamesAfterThisRun(t *testing.T) {
	f := newFakeISE(t)
	f.sgts = append(f.sgts, sgtObj("tgt-prod", "Production", 24))

	r := &PreflightReport{Items: []PreflightItem{
		{Family: familyTrustSec, Name: "Guests", Action: actionCreate,
			obj: map[string]any{"kind": kindSGT, "name": "Guests", "value": 6.0}},
		{Family: familyTrustSec, Name: "TestSGT", Action: actionSkip,
			obj: map[string]any{"kind": kindSGT, "name": "TestSGT", "value": 16.0}},
	}}

	names := sgtNamesAfterThisRun(f.client(), r)
	if !names["Production"] || !names["Guests"] {
		t.Errorf("names = %v, want the target's own and the created one", names)
	}
	if names["TestSGT"] {
		t.Error("a security group that was blocked must not count as existing")
	}
}

func containsNote(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}
