package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestERSListPages(t *testing.T) {
	f := newFakeISE(t)
	const total = 250 // > 2 pages at size=100
	for i := 0; i < total; i++ {
		f.addGroup(fmt.Sprintf("g%03d", i), fmt.Sprintf("Group %03d", i))
	}
	stubs, err := f.client().ersList(pathEndpointGroups)
	if err != nil {
		t.Fatalf("ersList: %v", err)
	}
	if len(stubs) != total {
		t.Fatalf("got %d stubs, want %d", len(stubs), total)
	}
	if got := f.pagesServed["endpointgroup"]; got != 3 {
		t.Errorf("served %d pages, want 3 (100+100+50)", got)
	}
	if stubs[0].Name != "Group 000" || stubs[249].ID != "g249" {
		t.Errorf("stub contents wrong: %+v / %+v", stubs[0], stubs[249])
	}
}

func TestERSListExactMultipleOfPageSize(t *testing.T) {
	f := newFakeISE(t)
	for i := 0; i < pageSize; i++ {
		f.addGroup(fmt.Sprintf("g%03d", i), fmt.Sprintf("Group %03d", i))
	}
	stubs, err := f.client().ersList(pathEndpointGroups)
	if err != nil {
		t.Fatalf("ersList: %v", err)
	}
	if len(stubs) != pageSize {
		t.Fatalf("got %d stubs, want %d", len(stubs), pageSize)
	}
}

func TestERSStubThenDetail(t *testing.T) {
	f := newFakeISE(t)
	for i := 0; i < 30; i++ {
		f.addGroup(fmt.Sprintf("g%02d", i), fmt.Sprintf("Group %02d", i))
	}
	c := f.client()
	stubs, err := c.ersList(pathEndpointGroups)
	if err != nil {
		t.Fatalf("ersList: %v", err)
	}
	objs, err := c.ersGetAll(pathEndpointGroups, rootEndpointGroup, stubs)
	if err != nil {
		t.Fatalf("ersGetAll: %v", err)
	}
	if len(objs) != 30 {
		t.Fatalf("got %d objects, want 30", len(objs))
	}
	// The worker pool must not reorder results.
	for i, o := range objs {
		if o["name"] != fmt.Sprintf("Group %02d", i) {
			t.Fatalf("object %d is %v; the worker pool reordered results", i, o["name"])
		}
		if o["description"] == nil {
			t.Fatalf("object %d has no detail fields; the stub was returned instead of the object", i)
		}
	}
}

func TestERSListWrongShapeReportsWhatArrived(t *testing.T) {
	f := newFakeISE(t)
	c := f.client()
	// /ers/config/node exists; an unknown collection returns an ISE error body.
	_, err := c.ersList("/ers/config/nosuchthing")
	if err == nil {
		t.Fatal("expected an error for an unknown collection")
	}
	if !strings.Contains(err.Error(), "Resource not found") {
		t.Errorf("ISE's own error text was lost: %v", err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 {
		t.Errorf("expected an APIError with status 404, got %#v", err)
	}
}

func TestUnwrapWrongRootKey(t *testing.T) {
	_, err := unwrap([]byte(`{"SomethingElse":{"name":"x"}}`), rootEndpointGroup, "http://x/y")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "EndPointGroup") || !strings.Contains(err.Error(), "SomethingElse") {
		t.Errorf("error should name both the expected and the received keys: %v", err)
	}
}

func TestDecodeListShapes(t *testing.T) {
	bare, err := decodeList([]byte(`[{"mac":"AA"},{"mac":"BB"}]`))
	if err != nil || len(bare) != 2 {
		t.Fatalf("bare array: %v %v", bare, err)
	}
	wrapped, err := decodeList([]byte(`{"response":[{"mac":"AA"}],"version":"1.0"}`))
	if err != nil || len(wrapped) != 1 {
		t.Fatalf("wrapped: %v %v", wrapped, err)
	}
	empty, err := decodeList([]byte(`{"response":[]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty response: %v %v", empty, err)
	}
	if _, err := decodeList([]byte(`{"ERSResponse":{"messages":[{"title":"boom"}]}}`)); err == nil {
		t.Error("expected an error for an unexpected shape")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Errorf("the received body should be quoted back: %v", err)
	}
}

func TestOpenAPIListBothShapes(t *testing.T) {
	for _, bare := range []bool{false, true} {
		f := newFakeISE(t)
		f.apiBareArray = bare
		for i := 0; i < 120; i++ { // forces a second page
			f.addEndpoint(fmt.Sprintf("AA:BB:CC:00:%02X:%02X", i/256, i%256), "g1", true, "")
		}
		got, err := f.client().openAPIList(pathEndpointsAPI)
		if err != nil {
			t.Fatalf("bare=%v: %v", bare, err)
		}
		if len(got) != 120 {
			t.Fatalf("bare=%v: got %d endpoints, want 120", bare, len(got))
		}
	}
}

func TestAPIErrorCarriesStatusAndBody(t *testing.T) {
	f := newFakeISE(t)
	f.ersUnauthorized = true
	_, err := f.client().iseVersion()
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("expected an APIError, got %#v", err)
	}
	if ae.Status != 401 {
		t.Errorf("status = %d, want 401", ae.Status)
	}
	if !strings.Contains(ae.Body, "Authentication failed") {
		t.Errorf("body was discarded: %q", ae.Body)
	}
	if !strings.Contains(ae.Error(), "401") || !strings.Contains(ae.Error(), "Authentication failed") {
		t.Errorf("Error() must show status and ISE's text: %v", ae)
	}
}

func TestProbeERSOnlyExplainsWhichAPIIsOff(t *testing.T) {
	f := newFakeISE(t)
	f.nodes = []string{"ise-pan-1", "ise-psn-2"}
	f.apiUnauthorized = true // OpenAPI not enabled; ERS is

	p := f.client().ProbeDeployment()
	if !p.Reachable || !p.ERS || p.OpenAPI {
		t.Fatalf("probe = %+v, want reachable ERS-only", p)
	}
	if p.Version != "3.3.0.430" {
		t.Errorf("version = %q", p.Version)
	}
	if len(p.Nodes) != 2 || p.Nodes[0] != "ise-pan-1" {
		t.Errorf("nodes = %v", p.Nodes)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "OpenAPI") {
		t.Fatalf("expected one note about the OpenAPI, got %v", p.Notes)
	}
	// The whole point: a bare 401 is useless, this must say the credentials
	// were fine elsewhere and name the setting to switch on.
	if !strings.Contains(p.Notes[0], "accepted by the other API") || !strings.Contains(p.Notes[0], "API Settings") {
		t.Errorf("note does not distinguish 'API off' from 'bad password': %q", p.Notes[0])
	}
}

func TestProbeBadCredentials(t *testing.T) {
	f := newFakeISE(t)
	c := f.client()
	c.Pass = "wrong"

	p := c.ProbeDeployment()
	if p.ERS || p.OpenAPI {
		t.Fatalf("probe = %+v, want no capabilities", p)
	}
	if !p.Reachable {
		t.Error("both APIs answered with 401, so the host is reachable")
	}
	if len(p.Notes) != 2 {
		t.Fatalf("want a note per API, got %v", p.Notes)
	}
	for _, n := range p.Notes {
		if !strings.Contains(n, "username/password") {
			t.Errorf("with both APIs rejecting, the note must point at the credentials: %q", n)
		}
	}
}

func TestProbeUnreachable(t *testing.T) {
	f := newFakeISE(t)
	c := f.client()
	c.ersBase = "http://127.0.0.1:1" // nothing listens here
	c.apiBase = "http://127.0.0.1:1"

	p := c.ProbeDeployment()
	if p.Reachable {
		t.Fatal("nothing answered; Reachable must be false")
	}
	joined := strings.Join(p.Notes, " ")
	if !strings.Contains(joined, "could not connect") || !strings.Contains(joined, "ports 443 and 9060") {
		t.Errorf("notes should say what to check: %v", p.Notes)
	}
}

// A mistyped address is not a refused connection: the SYN is dropped and nothing
// answers, so the client waits for a timeout rather than an RST. With only the
// request timeout that was two minutes per API, and the probe checks two, so the
// UI sat on "Connecting…" for four minutes before saying anything.
//
// 192.0.2.1 is TEST-NET-1 (RFC 5737) and is not routable. The assertion is an
// upper bound: an environment that answers instantly still passes.
func TestProbeGivesUpQuicklyOnAnUnroutableAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("makes a real connection attempt")
	}
	c := NewClient("192.0.2.1", "admin", "irrelevant", false)

	start := time.Now()
	p := c.ProbeDeployment()
	took := time.Since(start)

	if p.Reachable {
		t.Fatal("TEST-NET-1 must not be reachable")
	}
	// Both checks run together, so one connect timeout covers both, with room
	// for a slow machine.
	if limit := 3 * connectTimeout; took > limit {
		t.Errorf("probe took %s, want under %s — the operator is staring at a spinner for that long", took, limit)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"ise.example.net":            "ise.example.net",
		"https://ise.example.net":    "ise.example.net",
		"https://ise.example.net/":   "ise.example.net",
		"http://ise.example.net:443": "ise.example.net",
		"ise.example.net:9060":       "ise.example.net",
		"  10.1.1.5  ":               "10.1.1.5",
		"https://10.1.1.5/admin":     "10.1.1.5",
	} {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsDuplicate(t *testing.T) {
	dup := &APIError{Status: 400, Body: `{"ERSResponse":{"messages":[{"title":"Endpoint or group already exists: x"}]}}`}
	if !isDuplicate(dup) {
		t.Error("ISE's 'already exists' 400 must count as a duplicate, not a failure")
	}
	if isDuplicate(&APIError{Status: 400, Body: "Invalid MAC address"}) {
		t.Error("a genuine 400 must not be swallowed as a duplicate")
	}
	if isDuplicate(errors.New("connection refused")) {
		t.Error("a transport error is not a duplicate")
	}
}
