package main

import (
	"strings"
	"testing"
)

// srcWithPolicySets builds a source deployment holding one custom set and the
// Default set, each with an authentication and an authorization rule, plus the
// objects those rules point at.
func srcWithPolicySets(t *testing.T) *fakeISE {
	t.Helper()
	f := newFakeISE(t)
	f.addNamedList("service", "Default Network Access", "svc-1")
	f.addNamedList("store", "Internal Users", "store-1")
	f.addNamedList("sgt", "BYOD", "sgt-1")
	f.addAuthProfile("ap1", "CLIENTS-88", "")
	f.addCondition("cond1", "Wired_802.1X", "LibraryConditionAttributes")

	ref := map[string]any{
		"conditionType": "ConditionReference",
		"isNegate":      false,
		"name":          "Wired_802.1X",
		"id":            "src-cond-uuid",
		"link":          map[string]any{"rel": "self"},
	}
	f.addPolicySetNA("src-set-1", "KOF - EntraID", 0, "enabled", "Default Network Access", false, ref)
	f.addRule("src-set-1", "authentication", "TEAP", false,
		map[string]any{"identitySourceName": "Internal Users", "ifAuthFail": "REJECT"}, ref)
	f.addRule("src-set-1", "authorization", "Machine Auth", false,
		map[string]any{"profile": []any{"CLIENTS-88"}, "securityGroup": nil}, ref)

	f.addPolicySetNA("src-default", "Default", 9, "enabled", "Default Network Access", true, nil)
	f.addRule("src-default", "authorization", "EntraID_User", false,
		map[string]any{"profile": []any{"CLIENTS-88"}}, nil)
	f.addRule("src-default", "authorization", "Default", true,
		map[string]any{"profile": []any{"DenyAccess"}}, nil)
	return f
}

// tgtForPolicySets is a target holding everything the source's rules reference,
// plus its own Default set.
func tgtForPolicySets(t *testing.T) *fakeISE {
	t.Helper()
	f := newFakeISE(t)
	f.addNamedList("service", "Default Network Access", "tgt-svc-1")
	f.addNamedList("store", "Internal Users", "tgt-store-1")
	f.addNamedList("sgt", "BYOD", "tgt-sgt-1")
	f.addAuthProfile("tgt-ap1", "CLIENTS-88", "")
	f.addAuthProfile("tgt-ap2", "DenyAccess", "")
	f.addCondition("tgt-cond1", "Wired_802.1X", "LibraryConditionAttributes")
	f.addPolicySetNA("tgt-default", "Default", 0, "enabled", "Default Network Access", true, nil)
	f.addRule("tgt-default", "authorization", "Default", true,
		map[string]any{"profile": []any{"DenyAccess"}}, nil)
	return f
}

func exportSets(t *testing.T, f *fakeISE) *Bundle {
	t.Helper()
	b := NewBundle(&Probe{Host: "src"})
	if err := ExportPolicySets(f.client(), b, []string{familyPolicySets}, quiet); err != nil {
		t.Fatalf("export: %v", err)
	}
	return b
}

// The bundle must carry the rules nested under their set, and nothing
// deployment-local: an id, a link or a hit count that travelled would either be
// rejected by the target or describe the source.
func TestExportNestsRulesAndStripsLocalIdentity(t *testing.T) {
	b := exportSets(t, srcWithPolicySets(t))
	sets := b.Objects[familyPolicySets]
	if len(sets) != 2 {
		t.Fatalf("exported %d sets, want 2", len(sets))
	}

	var custom map[string]any
	for _, s := range sets {
		if str(s, "name") == "KOF - EntraID" {
			custom = s
		}
	}
	if custom == nil {
		t.Fatal("the custom set is missing from the bundle")
	}
	for _, key := range []string{"id", "link", "hitCounts"} {
		if _, ok := custom[key]; ok {
			t.Errorf("set carries %q, which means nothing on the target", key)
		}
	}
	authn, _ := custom["authentication"].([]map[string]any)
	authz, _ := custom["authorization"].([]map[string]any)
	if len(authn) != 1 || len(authz) != 1 {
		t.Fatalf("rules did not nest: %d authentication, %d authorization", len(authn), len(authz))
	}
	inner, _ := authz[0]["rule"].(map[string]any)
	if inner == nil {
		t.Fatalf("authorization rule lost its rule wrapper: %+v", authz[0])
	}
	for _, key := range []string{"id", "hitCounts"} {
		if _, ok := inner[key]; ok {
			t.Errorf("rule carries %q", key)
		}
	}
	// The condition reference keeps its name and loses the source's UUID.
	cond, _ := inner["condition"].(map[string]any)
	if cond == nil || str(cond, "name") != "Wired_802.1X" {
		t.Fatalf("condition reference lost its name: %+v", cond)
	}
	if _, ok := cond["id"]; ok {
		t.Error("condition reference kept the source's UUID; it means nothing on the target")
	}
}

// Everything imported arrives disabled unless the operator asks otherwise: an
// import must not change how the target treats traffic until a human enables it.
func TestImportedSetsArriveDisabled(t *testing.T) {
	for _, tc := range []struct {
		keepState bool
		want      string
	}{
		{false, "disabled"},
		{true, "enabled"},
	} {
		b := exportSets(t, srcWithPolicySets(t))
		tgt := tgtForPolicySets(t)
		ct := tgt.client()
		rep, err := Preflight(ct, b, nil, tc.keepState)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if _, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, tc.keepState, quiet); err != nil {
			t.Fatalf("apply: %v", err)
		}

		tgt.mu.Lock()
		var landed map[string]any
		for _, s := range tgt.policySets {
			if str(s, "name") == "KOF - EntraID" {
				landed = s
			}
		}
		tgt.mu.Unlock()
		if landed == nil {
			t.Fatalf("keepState=%v: the set never reached the target", tc.keepState)
		}
		if got := str(landed, "state"); got != tc.want {
			t.Errorf("keepState=%v: set state = %q, want %q", tc.keepState, got, tc.want)
		}
	}
}

// A rule's condition reference has to point at the target's own condition, not
// the source's UUID, or the rule matches nothing.
func TestConditionReferenceRewrittenToTargetID(t *testing.T) {
	b := exportSets(t, srcWithPolicySets(t))
	tgt := tgtForPolicySets(t)
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
	var found bool
	for key, rules := range tgt.policySetRules {
		if !strings.HasSuffix(key, "|authorization") || strings.HasPrefix(key, "tgt-default|") {
			continue
		}
		for _, r := range rules {
			inner, _ := r["rule"].(map[string]any)
			if inner == nil {
				continue
			}
			cond, _ := inner["condition"].(map[string]any)
			if cond == nil || str(cond, "conditionType") != "ConditionReference" {
				continue
			}
			found = true
			if id := str(cond, "id"); id != "tgt-cond1" {
				t.Errorf("condition reference id = %q, want the target's own tgt-cond1", id)
			}
			if str(cond, "name") != "Wired_802.1X" {
				t.Errorf("condition reference lost its name: %+v", cond)
			}
		}
	}
	if !found {
		t.Fatal("no imported rule carried a condition reference")
	}
}

// The Default set exists on every deployment, so it is never created; its rules
// are added beside the target's own, and a rule the target already has is left
// alone.
func TestDefaultSetRulesAreMergedNotCreated(t *testing.T) {
	b := exportSets(t, srcWithPolicySets(t))
	tgt := tgtForPolicySets(t)
	ct := tgt.client()
	rep, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	for _, it := range rep.Items {
		if it.Family == familyPolicySets && it.Name == "Default" && it.Action == actionCreate {
			t.Fatal("the Default set must never be created; it exists on every deployment")
		}
	}
	if _, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, false, quiet); err != nil {
		t.Fatalf("apply: %v", err)
	}

	tgt.mu.Lock()
	defer tgt.mu.Unlock()
	var defaults int
	for _, s := range tgt.policySets {
		if str(s, "name") == "Default" {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("the target has %d sets named Default, want exactly its own", defaults)
	}
	names := map[string]bool{}
	for _, r := range tgt.policySetRules["tgt-default|authorization"] {
		inner, _ := r["rule"].(map[string]any)
		names[str(inner, "name")] = true
	}
	if !names["EntraID_User"] {
		t.Error("the source's Default rule was not merged into the target's Default set")
	}
	// The target's own catch-all must not have been duplicated, and a rule with
	// default:true is ISE's own and is never posted.
	var catchAlls int
	for _, r := range tgt.policySetRules["tgt-default|authorization"] {
		inner, _ := r["rule"].(map[string]any)
		if truthy(inner, "default") {
			catchAlls++
		}
	}
	if catchAlls != 1 {
		t.Errorf("catch-all rules = %d, want the target's own only", catchAlls)
	}
}

// A set whose name the target already uses is imported beside it, and the
// target's own set is never touched.
func TestNameClashImportsBesideTheTargetsSet(t *testing.T) {
	b := exportSets(t, srcWithPolicySets(t))
	tgt := tgtForPolicySets(t)
	tgt.addPolicySetNA("tgt-existing", "KOF - EntraID", 1, "enabled", "Default Network Access", false, nil)
	ct := tgt.client()

	rep, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if _, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, false, quiet); err != nil {
		t.Fatalf("apply: %v", err)
	}

	tgt.mu.Lock()
	names := map[string]int{}
	for _, s := range tgt.policySets {
		names[str(s, "name")]++
	}
	tgt.mu.Unlock()
	if names["KOF - EntraID"] != 1 {
		t.Errorf("the target's own set was touched: %d copies of the original name", names["KOF - EntraID"])
	}
	if names["KOF - EntraID (imported)"] != 1 {
		t.Fatalf("want one \"KOF - EntraID (imported)\", got %d: %+v", names["KOF - EntraID (imported)"], names)
	}
}

// A reference nothing can supply blocks the whole set: a set that lands without
// one of its rules still matches the traffic and then treats it differently.
func TestUnresolvedReferenceBlocksTheWholeSet(t *testing.T) {
	src := srcWithPolicySets(t)
	// A rule pointing at an SGT the target will not have. TrustSec is a later
	// slice, so nothing can create it.
	src.addRule("src-set-1", "authorization", "Quarantine", false,
		map[string]any{"profile": []any{"CLIENTS-88"}, "securityGroup": "Quarantine_SGT"}, nil)

	b := exportSets(t, src)
	tgt := tgtForPolicySets(t)
	ct := tgt.client()
	rep, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}

	var blocked bool
	for _, it := range rep.Items {
		if it.Family == familyPolicySets && strings.Contains(it.Name, "KOF") {
			if it.Action != actionBlocked {
				t.Fatalf("action = %q, want blocked: one rule cannot resolve", it.Action)
			}
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("the set was not reported at all")
	}
	var named bool
	for _, n := range rep.Notes {
		if strings.Contains(n, "Quarantine_SGT") {
			named = true
		}
	}
	if !named {
		t.Errorf("the notes must name the missing object; got %v", rep.Notes)
	}

	if _, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, false, quiet); err != nil {
		t.Fatalf("apply: %v", err)
	}
	tgt.mu.Lock()
	defer tgt.mu.Unlock()
	for _, s := range tgt.policySets {
		if strings.Contains(str(s, "name"), "KOF") {
			t.Error("a blocked set was written to the target")
		}
	}
}

// Running a completed import again writes nothing.
func TestPolicySetsReRunCreatesNothing(t *testing.T) {
	b := exportSets(t, srcWithPolicySets(t))
	tgt := tgtForPolicySets(t)
	ct := tgt.client()

	rep, err := Preflight(ct, b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	first, err := ApplyImport(ct, rep, "test-passphrase-1234567890", "", nil, false, false, quiet)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if first.Created == 0 {
		t.Fatalf("first run created nothing: %+v", first)
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
		t.Fatalf("a re-run must write nothing, got %+v", second)
	}
}

// A policy set must not be blocked for an object the same run is about to
// create — and must still be blocked when that object is itself blocked. The
// distinction is what the report says, not what the bundle happens to contain.
func TestSetCountsOnlyElementsThatWillReallyBeCreated(t *testing.T) {
	src := srcWithPolicySets(t)
	// The rule names an identity source sequence the bundle also carries.
	src.addIdStoreSequence("iss-corp", "Corp_Sequence", "")
	src.addRule("src-set-1", "authentication", "Corp", false,
		map[string]any{"identitySourceName": "Corp_Sequence", "ifAuthFail": "REJECT"}, nil)

	b := exportSets(t, src)
	if err := ExportPolicyElements(src.client(), b, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export elements: %v", err)
	}

	tgt := tgtForPolicySets(t)
	rep, err := Preflight(tgt.client(), b, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	for _, it := range rep.Items {
		if it.Family == familyPolicySets && strings.Contains(it.Name, "KOF") {
			if it.Action == actionBlocked && strings.Contains(it.Reason, "Corp_Sequence") {
				t.Fatalf("blocked for a sequence this same run creates: %q", it.Reason)
			}
		}
	}

	// Now make that sequence unresolvable, so the element half blocks it. The
	// set must block too: what is never created cannot be referenced.
	src2 := srcWithPolicySets(t)
	src2.addIdStoreSequence("iss-ad", "AD_Sequence", "")
	src2.mu.Lock()
	for _, s := range src2.idStoreSequences {
		if str(s, "name") == "AD_Sequence" {
			s["idSeqItem"] = []any{map[string]any{"idstore": "some.domain.example", "order": 1}}
		}
	}
	src2.mu.Unlock()
	src2.addRule("src-set-1", "authentication", "AD", false,
		map[string]any{"identitySourceName": "AD_Sequence", "ifAuthFail": "REJECT"}, nil)

	b2 := exportSets(t, src2)
	if err := ExportPolicyElements(src2.client(), b2, []string{familyPolicyElements}, quiet); err != nil {
		t.Fatalf("export elements: %v", err)
	}
	rep2, err := Preflight(tgtForPolicySets(t).client(), b2, nil, false)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	var blocked bool
	for _, it := range rep2.Items {
		if it.Family == familyPolicySets && strings.Contains(it.Name, "KOF") && it.Action == actionBlocked {
			blocked = true
		}
	}
	if !blocked {
		t.Error("the set was allowed through on a sequence whose own creation is blocked")
	}
}

// ISE takes an authorization rule's profiles by name. Rewriting them to the
// target's UUIDs — which looks like the remap every other reference needs — made
// a real 3.4 target refuse every rule with "Unknown profile name for
// authorization rule: <the id it had just issued>".
func TestAuthorizationRuleKeepsProfileNames(t *testing.T) {
	b := exportSets(t, srcWithPolicySets(t))
	tgt := tgtForPolicySets(t)
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
	var seen bool
	for key, rules := range tgt.policySetRules {
		if !strings.HasSuffix(key, "|authorization") {
			continue
		}
		for _, r := range rules {
			profiles, _ := r["profile"].([]any)
			for _, p := range profiles {
				name, _ := p.(string)
				if name == "" {
					continue
				}
				seen = true
				if !strings.Contains(name, "-") || name == "CLIENTS-88" {
					continue
				}
				t.Errorf("profile went across as %q, which is not the name the source used", name)
			}
		}
	}
	if !seen {
		t.Fatal("no imported authorization rule carried a profile")
	}
}
