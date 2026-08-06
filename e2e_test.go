package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The whole operator path through the real HTTP handlers: probe, group list,
// streamed export, encrypted bundle, uploaded again for pre-flight, then apply.
// It needs a TLS listener on the real ERS port, because that port is not
// configurable - the client builds https://<host>:9060 from the hostname the
// operator types, and that is deliberate.
func TestEndToEndExportThenImport(t *testing.T) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ersPort))
	if err != nil {
		t.Skipf("port %d is not free here (%v); the ERS port is fixed, so this end-to-end check cannot run", ersPort, err)
	}

	src := sourceISE(t)
	ers := httptest.NewUnstartedServer(http.HandlerFunc(src.serveERS))
	ers.Listener.Close()
	ers.Listener = ln
	ers.StartTLS() // self-signed, exactly like a real ISE; verifyTLS is false
	defer ers.Close()

	ui := httptest.NewServer(newMux())
	defer ui.Close()

	// 1. Probe. The OpenAPI (port 443) is not there, which is what a locked
	// down deployment looks like; ERS alone must be enough.
	var probe Probe
	postJSONTest(t, ui.URL+"/api/probe", map[string]any{"host": "127.0.0.1", "user": src.user, "pass": src.pass}, &probe)
	if !probe.ERS {
		t.Fatalf("probe did not find ERS: %+v", probe)
	}
	if probe.Version != src.version {
		t.Errorf("version = %q, want %q", probe.Version, src.version)
	}

	// 2. Group list for the picker.
	var groups struct {
		Groups []Stub `json:"groups"`
	}
	postJSONTest(t, ui.URL+"/api/endpoint-groups", map[string]any{"host": "127.0.0.1", "user": src.user, "pass": src.pass}, &groups)
	if len(groups.Groups) != 2 {
		t.Fatalf("groups = %+v", groups.Groups)
	}

	// 3. Streamed export.
	const passphrase = "a long enough passphrase"
	body, _ := json.Marshal(map[string]any{
		"host": "127.0.0.1", "user": src.user, "pass": src.pass,
		"families": []string{familyEndpointGroups, familyEndpoints},
		"groups":   []string{"Printers", "Cameras"}, "passphrase": passphrase,
	})
	res, err := http.Post(ui.URL+"/api/export", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	msgs := readNDJSON(t, res)
	done := msgs[len(msgs)-1]
	if done["type"] != "done" {
		t.Fatalf("export did not finish: %+v", msgs)
	}
	if len(msgs) < 3 {
		t.Errorf("expected progress lines before the result, got %d messages", len(msgs))
	}
	sealed, err := base64.StdEncoding.DecodeString(done["bundle"].(string))
	if err != nil {
		t.Fatalf("bundle is not base64: %v", err)
	}
	if bytes.Contains(sealed, []byte(src.pass)) || bytes.Contains(sealed, []byte(src.user)) {
		t.Fatal("credentials leaked into the bundle")
	}
	if _, err := OpenBundle(sealed, passphrase); err != nil {
		t.Fatalf("exported bundle does not open: %v", err)
	}

	// 4. Point the same handlers at a fresh target on the same port.
	ers.Close()
	tgt := newFakeISE(t)
	tgt.addProfile("tp1", "Cisco-Device")
	ln2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ersPort))
	if err != nil {
		t.Skipf("could not rebind the ERS port for the import half: %v", err)
	}
	tgtSrv := httptest.NewUnstartedServer(http.HandlerFunc(tgt.serveERS))
	tgtSrv.Listener.Close()
	tgtSrv.Listener = ln2
	tgtSrv.StartTLS()
	defer tgtSrv.Close()

	// 5. Pre-flight. Nothing may be written.
	var pre struct {
		Preflight PreflightReport `json:"preflight"`
	}
	postMultipart(t, ui.URL+"/api/import/preflight", sealed, passphrase, "", &pre)
	if pre.Preflight.Create != 5 { // 2 groups + the 3 static endpoints in them
		t.Errorf("pre-flight wants to create %d objects, want 5: %+v", pre.Preflight.Create, pre.Preflight.Items)
	}
	if len(tgt.created) != 0 {
		t.Fatal("pre-flight wrote to the target")
	}

	// 6. Apply.
	res2 := postMultipartRaw(t, ui.URL+"/api/import/apply", sealed, passphrase, "yes")
	msgs2 := readNDJSON(t, res2)
	last := msgs2[len(msgs2)-1]
	if last["type"] != "done" {
		t.Fatalf("import did not finish: %+v", msgs2)
	}
	result := last["result"].(map[string]any)
	if result["created"].(float64) != 5 || result["failed"].(float64) != 0 {
		t.Fatalf("import result = %+v", result)
	}
	if len(tgt.created["endpointgroup"]) != 2 || len(tgt.created["endpoint"]) != 3 {
		t.Fatalf("target got %v", tgt.created)
	}
	for _, e := range tgt.created["endpoint"] {
		if _, ok := e["groupName"]; ok {
			t.Errorf("a name field was sent to ISE instead of a UUID: %v", e)
		}
		if id, _ := e["groupId"].(string); !strings.HasPrefix(id, "tgt-") {
			t.Errorf("endpoint points at a non-target group id %q", id)
		}
	}
}

func postJSONTest(t *testing.T, url string, body any, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	res, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		t.Fatalf("POST %s: HTTP %d: %s", url, res.StatusCode, msg)
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func readNDJSON(t *testing.T, res *http.Response) []map[string]any {
	t.Helper()
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("HTTP %d: %s", res.StatusCode, b)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q", ct)
	}
	var out []map[string]any
	dec := json.NewDecoder(res.Body)
	for {
		var m map[string]any
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("bad NDJSON: %v", err)
		}
		if m["type"] == "error" {
			t.Fatalf("stream reported an error: %v", m["msg"])
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		t.Fatal("no messages")
	}
	return out
}

func importBody(t *testing.T, sealed []byte, passphrase, confirm string) (string, io.Reader) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	for k, v := range map[string]string{"host": "127.0.0.1", "user": "ersadmin", "pass": "s3cret", "passphrase": passphrase} {
		mw.WriteField(k, v)
	}
	if confirm != "" {
		mw.WriteField("confirm", confirm)
	}
	f, _ := mw.CreateFormFile("bundle", bundleFileName)
	f.Write(sealed)
	mw.Close()
	return mw.FormDataContentType(), buf
}

func postMultipart(t *testing.T, url string, sealed []byte, passphrase, confirm string, out any) {
	t.Helper()
	ct, body := importBody(t, sealed, passphrase, confirm)
	res, err := http.Post(url, ct, body)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("POST %s: HTTP %d: %s", url, res.StatusCode, b)
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

func postMultipartRaw(t *testing.T, url string, sealed []byte, passphrase, confirm string) *http.Response {
	t.Helper()
	ct, body := importBody(t, sealed, passphrase, confirm)
	res, err := http.Post(url, ct, body)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
