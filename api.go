package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
)

// HTTP handlers for the API-driven half of the tool. Credentials arrive in the
// request body, are used for that request only, and are never stored, cached or
// logged: there is no session, the browser holds them in a JS variable and
// sends them again with the next call.

type creds struct {
	Host string `json:"host"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (c creds) client() (*Client, error) {
	if normalizeHost(c.Host) == "" {
		return nil, fmt.Errorf("give the ISE hostname or IP address")
	}
	if c.User == "" || c.Pass == "" {
		return nil, fmt.Errorf("give the API username and password")
	}
	return NewClient(c.Host, c.User, c.Pass, verifyTLS), nil
}

func decodeBody(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"verifyTls": verifyTLS})
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var in creds
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the request: "+err.Error())
		return
	}
	c, err := in.client()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := c.ProbeDeployment()
	p.VerifyTLS = verifyTLS
	writeJSON(w, http.StatusOK, p)
}

func handleEndpointGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var in creds
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the request: "+err.Error())
		return
	}
	c, err := in.client()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	groups, note, err := ListEndpointGroups(c)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	// note is set when the policy usage scan could not complete. The groups are
	// still returned: the badge is advisory, and a migration must not stop
	// because a rule could not be read.
	writeJSON(w, http.StatusOK, map[string]any{"groups": groups, "note": note})
}

func handleTrustedCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var in creds
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the request: "+err.Error())
		return
	}
	c, err := in.client()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	certs, err := ListTrustedCerts(c)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certs": certs})
}

// --- newline-delimited JSON progress ----------------------------------------

// stream writes one JSON object per line and flushes each one, so the browser
// can show progress while a long export or import is still running.
type stream struct {
	w   http.ResponseWriter
	f   http.Flusher
	enc *json.Encoder
}

func newStream(w http.ResponseWriter) *stream {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	s := &stream{w: w, enc: json.NewEncoder(w)}
	if f, ok := w.(http.Flusher); ok {
		s.f = f
		f.Flush()
	}
	return s
}

func (s *stream) send(v any) {
	s.enc.Encode(v)
	if s.f != nil {
		s.f.Flush()
	}
}

func (s *stream) log(format string, a ...any) {
	s.send(map[string]any{"type": "log", "msg": fmt.Sprintf(format, a...)})
}

func (s *stream) fail(format string, a ...any) {
	s.send(map[string]any{"type": "error", "msg": fmt.Sprintf(format, a...)})
}

// --- export ------------------------------------------------------------------

type exportReq struct {
	creds
	Families   []string `json:"families"`
	Groups     []string `json:"groups"`
	Certs      []string `json:"certs"`
	Passphrase string   `json:"passphrase"`
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var in exportReq
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the request: "+err.Error())
		return
	}
	c, err := in.client()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len([]rune(in.Passphrase)) < minPassphrase {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("the bundle passphrase must be at least %d characters", minPassphrase))
		return
	}
	if len(in.Families) == 0 {
		writeErr(w, http.StatusBadRequest, "select at least one object family to export")
		return
	}
	// Checked here as well as in ExportEndpoints so a request that cannot
	// succeed never reaches the deployment with credentials attached.
	if len(in.Groups) == 0 && (slices.Contains(in.Families, familyEndpointGroups) || slices.Contains(in.Families, familyEndpoints)) {
		writeErr(w, http.StatusBadRequest, "select at least one endpoint identity group, or untick both Endpoint identity groups and Static endpoints")
		return
	}

	s := newStream(w)
	s.log("Connecting to %s…", c.Host)
	probe := c.ProbeDeployment()
	probe.VerifyTLS = verifyTLS
	if !probe.ERS {
		s.fail("The ERS API is required for an export and is not usable: %s", firstNote(probe))
		return
	}
	s.log("ISE %s, nodes: %v", probe.Version, probe.Nodes)

	b := NewBundle(probe)
	if err := ExportEndpoints(c, b, in.Families, in.Groups, s.log); err != nil {
		s.fail("%v", err)
		return
	}
	if err := ExportTrustedCerts(c, b, in.Families, in.Certs, s.log); err != nil {
		s.fail("%v", err)
		return
	}

	sealed, err := SealBundle(b, in.Passphrase)
	if err != nil {
		s.fail("encrypting the bundle: %v", err)
		return
	}
	counts := map[string]int{}
	for family, objs := range b.Objects {
		counts[family] = len(objs)
	}
	s.log("Bundle encrypted: %d KB.", (len(sealed)+1023)/1024)
	s.send(map[string]any{
		"type":     "done",
		"filename": bundleFileName,
		"bundle":   base64.StdEncoding.EncodeToString(sealed),
		"counts":   counts,
		"notes":    b.Notes,
		"source":   b.Source,
	})
}

func firstNote(p *Probe) string {
	if len(p.Notes) > 0 {
		return p.Notes[0]
	}
	return "no reason reported"
}

// --- import ------------------------------------------------------------------

// importInput is the multipart form both import steps take: the target's
// credentials, the bundle file and its passphrase.
type importInput struct {
	client *Client
	bundle *Bundle
}

func readImport(w http.ResponseWriter, r *http.Request) (*importInput, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	// maxMemory == the whole cap, so multipart never spills a decryptable
	// bundle to a temp file.
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		return nil, fmt.Errorf("could not read the upload (max 64 MB): %w", err)
	}
	in := creds{Host: r.FormValue("host"), User: r.FormValue("user"), Pass: r.FormValue("pass")}
	c, err := in.client()
	if err != nil {
		return nil, err
	}
	f, _, err := r.FormFile("bundle")
	if err != nil {
		return nil, fmt.Errorf("choose the encrypted bundle file")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUpload))
	if err != nil {
		return nil, fmt.Errorf("reading the bundle: %w", err)
	}
	pass := r.FormValue("passphrase")
	if pass == "" {
		return nil, fmt.Errorf("give the bundle passphrase")
	}
	b, err := OpenBundle(data, pass)
	if err != nil {
		return nil, err
	}
	return &importInput{client: c, bundle: b}, nil
}

func handlePreflight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	in, err := readImport(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	probe := in.client.ProbeDeployment()
	probe.VerifyTLS = verifyTLS
	if !probe.ERS {
		writeErr(w, http.StatusBadGateway, "The ERS API is required for an import and is not usable: "+firstNote(probe))
		return
	}
	rep, err := Preflight(in.client, in.bundle)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"probe":      probe,
		"preflight":  rep,
		"exportedAt": in.bundle.ExportedAt,
	})
}

// handleApply writes to the target. It re-runs the pre-flight itself rather
// than trusting a report the browser sends back: the gate is on the server, and
// the target may have changed since the operator looked at it.
func handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	in, err := readImport(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()
	if r.FormValue("confirm") != "yes" {
		writeErr(w, http.StatusBadRequest, "import was not confirmed")
		return
	}

	s := newStream(w)
	s.log("Re-checking the target before writing…")
	rep, err := Preflight(in.client, in.bundle)
	if err != nil {
		s.fail("%v", err)
		return
	}
	s.log("%d to create, %d already present, %d blocked.", rep.Create, rep.Skip, rep.Blocked)
	if rep.Create == 0 {
		// Nothing to write, but the operator still needs the counts: a re-run of
		// a completed import must report "45 already present", not four zeros.
		s.send(map[string]any{"type": "done", "preflight": rep, "result": &ImportResult{
			Skipped: rep.Skip, Blocked: rep.Blocked, Errors: []string{},
		}})
		return
	}
	res, err := ApplyImport(in.client, rep, s.log)
	if err != nil {
		s.fail("%v", err)
		s.send(map[string]any{"type": "done", "result": res, "preflight": rep})
		return
	}
	res.Skipped += rep.Skip
	res.Blocked = rep.Blocked
	s.send(map[string]any{"type": "done", "result": res, "preflight": rep})
}
