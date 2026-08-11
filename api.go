package main

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
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

func handleSystemCerts(w http.ResponseWriter, r *http.Request) {
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
	certs, err := ListSystemCerts(c)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certs": certs})
}

func handleSystemCertZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("could not read the upload: %v", err))
		return
	}

	var results []UploadedZip
	for _, fileHeader := range r.MultipartForm.File["files"] {
		f, err := fileHeader.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(f, maxUpload))
		f.Close()

		// Parse ZIP and extract certificate
		zipData := data
		if !bytes.HasPrefix(zipData, []byte("PK")) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q is not a ZIP file", fileHeader.Filename))
			return
		}

		zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q is not a valid ZIP: %v", fileHeader.Filename, err))
			return
		}

		var pemData, keyBlobData string
		for _, f := range zr.File {
			rc, _ := f.Open()
			entryBody, _ := io.ReadAll(rc)
			rc.Close()

			if bytes.HasPrefix(entryBody, []byte("-----BEGIN")) {
				block, _ := pem.Decode(entryBody)
				if block != nil && block.Type == "CERTIFICATE" {
					pemData = string(entryBody)
					continue
				}
			}
			if strings.Contains(string(entryBody), "ENCRYPTED PRIVATE KEY") {
				keyBlobData = string(entryBody)
			}
		}

		if pemData == "" {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q: entry cert.pem parsed; no private key entry in the ZIP", fileHeader.Filename))
			return
		}
		if keyBlobData == "" {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q: entry cert.pem parsed; no private key entry in the ZIP", fileHeader.Filename))
			return
		}

		// Parse certificate to extract metadata
		block, _ := pem.Decode([]byte(pemData))
		var cert *x509.Certificate
		var subject, cn string
		var sans []string
		var keySize int
		var selfSigned bool
		var expiresAt string

		if block != nil {
			if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
				cert = parsedCert
				subject = parsedCert.Subject.String()
				cn = parsedCert.Subject.CommonName
				for _, dns := range parsedCert.DNSNames {
					sans = append(sans, dns)
				}
				for _, ip := range parsedCert.IPAddresses {
					sans = append(sans, ip.String())
				}
				keySize = 2048 // Placeholder; would need to examine public key
				selfSigned = cert.Subject.String() == cert.Issuer.String()
				expiresAt = cert.NotAfter.Format(time.RFC3339)
			}
		}

		if cn == "" {
			cn = fileHeader.Filename
		}

		fp := fmt.Sprintf("%x", sha256.Sum256(block.Bytes))
		results = append(results, UploadedZip{
			Filename:    fileHeader.Filename,
			Name:        cn,
			Subject:     subject,
			SANs:        sans,
			KeySize:     keySize,
			ExpiresAt:   expiresAt,
			HasKey:      keyBlobData != "",
			Fingerprint: fp,
			SelfSigned:  selfSigned,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"zips": results})
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
	Families    []string `json:"families"`
	Groups      []string `json:"groups"`
	Certs       []string `json:"certs"`
	Passphrase  string   `json:"passphrase"`
	SystemCerts []string `json:"systemCerts"`

	// One entry per attached GUI-exported ZIP: the name it should carry on the
	// target and the roles the operator ticked, since the file itself says
	// nothing about either.
	SystemCertZips []systemCertZipSpec `json:"systemCertZips"`
}

type systemCertZipSpec struct {
	Filename string   `json:"filename"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
}

// UploadedZip carries metadata about a system certificate uploaded as a ZIP from the 3.2 GUI.
type UploadedZip struct {
	Filename    string   `json:"filename"`
	Name        string   `json:"name"`
	Subject     string   `json:"subject"`
	SANs        []string `json:"sans"`
	KeySize     int      `json:"keySize"`
	ExpiresAt   string   `json:"expiresAt"`
	HasKey      bool     `json:"hasKey"`
	Fingerprint string   `json:"fingerprint"`
	SelfSigned  bool     `json:"selfSigned"`
	EAP         bool     `json:"eap"`
	RADIUS      bool     `json:"radius"`
	TACACS      bool     `json:"tacacs"`
	PxGrid      bool     `json:"pxgrid"`
	IMS         bool     `json:"ims"`
	SAML        bool     `json:"saml"`
	Portal      bool     `json:"portal"`
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	// Parse the request: JSON in the body, files as multipart if present
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	contentType := r.Header.Get("Content-Type")

	var in exportReq
	var systemCertZips []map[string]any
	var zipPassword string

	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Parse multipart form
		if err := r.ParseMultipartForm(maxUpload); err != nil {
			writeErr(w, http.StatusBadRequest, "could not read the upload: "+err.Error())
			return
		}
		defer r.MultipartForm.RemoveAll()

		// Read JSON from form field "req"
		reqJSON := r.FormValue("req")
		if reqJSON == "" {
			writeErr(w, http.StatusBadRequest, "missing req field in multipart form")
			return
		}
		if err := json.Unmarshal([]byte(reqJSON), &in); err != nil {
			writeErr(w, http.StatusBadRequest, "could not parse request JSON: "+err.Error())
			return
		}

		zipPassword = r.FormValue("zipPassword")

		// Process uploaded ZIP files
		for _, fileHeader := range r.MultipartForm.File["zips"] {
			f, err := fileHeader.Open()
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(f, maxUpload))
			f.Close()

			// Parse ZIP and extract certificate metadata
			zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q is not a valid ZIP: %v", fileHeader.Filename, err))
				return
			}

			var pemData, keyBlobData string
			for _, zf := range zr.File {
				rc, _ := zf.Open()
				entryBody, _ := io.ReadAll(rc)
				rc.Close()

				if bytes.HasPrefix(entryBody, []byte("-----BEGIN")) {
					block, _ := pem.Decode(entryBody)
					if block != nil && block.Type == "CERTIFICATE" {
						pemData = string(entryBody)
						continue
					}
				}
				if strings.Contains(string(entryBody), "ENCRYPTED PRIVATE KEY") {
					keyBlobData = string(entryBody)
				}
			}

			if pemData == "" {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q: no .pem entry", fileHeader.Filename))
				return
			}
			if keyBlobData == "" {
				writeErr(w, http.StatusBadRequest, fmt.Sprintf("%q: no private key entry", fileHeader.Filename))
				return
			}

			// Parse certificate to extract metadata
			block, _ := pem.Decode([]byte(pemData))
			var cn string
			var sans []string
			var keySize int
			var selfSigned bool
			var expiresAt string
			var subject string

			if block != nil {
				if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					cn = parsedCert.Subject.CommonName
					subject = parsedCert.Subject.String()
					for _, dns := range parsedCert.DNSNames {
						sans = append(sans, dns)
					}
					for _, ip := range parsedCert.IPAddresses {
						sans = append(sans, ip.String())
					}
					// Extract key size from public key
					switch pk := parsedCert.PublicKey.(type) {
					case *rsa.PublicKey:
						keySize = pk.N.BitLen()
					}
					selfSigned = parsedCert.Subject.String() == parsedCert.Issuer.String()
					expiresAt = parsedCert.NotAfter.Format(time.RFC3339)
				}
			}

			if cn == "" {
				cn = fileHeader.Filename
			}

			fpBytes := sha256.Sum256(block.Bytes)
			fp := fmt.Sprintf("%x", fpBytes)

			zipInfo := map[string]any{
				"filename":    fileHeader.Filename,
				"name":        cn,
				"subject":     subject,
				"sans":        sans,
				"keySize":     keySize,
				"expiresAt":   expiresAt,
				"hasKey":      keyBlobData != "",
				"fingerprint": fp,
				"selfSigned":  selfSigned,
				"pem":         pemData,
				"keyBlob":     keyBlobData,
			}
			// The file says nothing about what the certificate should be called
			// or what it is for; the operator does, in the request beside it.
			for _, spec := range in.SystemCertZips {
				if spec.Filename != fileHeader.Filename {
					continue
				}
				if spec.Name != "" {
					zipInfo["name"] = spec.Name
				}
				for _, role := range spec.Roles {
					zipInfo[role] = true
				}
			}
			systemCertZips = append(systemCertZips, zipInfo)
		}
	} else {
		// JSON-only path (existing behavior)
		if err := decodeBody(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, "could not read the request: "+err.Error())
			return
		}
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

	// Ticking policy sets forces policy elements and AD join points into the same export
	if slices.Contains(in.Families, familyPolicySets) {
		if !slices.Contains(in.Families, familyPolicyElements) {
			in.Families = append(in.Families, familyPolicyElements)
		}
		if !slices.Contains(in.Families, familyADJoinPoints) {
			in.Families = append(in.Families, familyADJoinPoints)
		}
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
	if err := ExportSystemCerts(c, b, in.Families, in.SystemCerts, in.Passphrase, systemCertZips, zipPassword, s.log); err != nil {
		s.fail("%v", err)
		return
	}
	if err := ExportADJoinPoints(c, b, in.Families, s.log); err != nil {
		s.fail("%v", err)
		return
	}
	if err := ExportPolicyElements(c, b, in.Families, s.log); err != nil {
		s.fail("%v", err)
		return
	}
	if err := ExportPolicySets(c, b, in.Families, s.log); err != nil {
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
	client     *Client
	bundle     *Bundle
	passphrase string

	// System certificates only: which target nodes to write to, whether the
	// admin role may be taken, and the password for any certificate that came
	// from a GUI-exported ZIP. None of these are stored anywhere.
	nodes       []string
	adminRole   bool
	zipPassword string

	// Policy sets only: whether to import sets and rules in their source state
	// or force them disabled.
	keepState bool
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
	in2 := &importInput{
		client: c, bundle: b, passphrase: pass,
		adminRole:   yes(r.FormValue("adminRole")),
		zipPassword: r.FormValue("zipPassword"),
		keepState:   yes(r.FormValue("keepState")),
	}
	// The node picker posts a JSON array of hostnames; absent means the
	// pre-flight default, which is every eligible node.
	if raw := r.FormValue("selectedNodes"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &in2.nodes); err != nil {
			return nil, fmt.Errorf("could not read the target node selection: %w", err)
		}
	}
	return in2, nil
}

// yes accepts either spelling the UI has used for a checkbox.
func yes(v string) bool { return v == "yes" || v == "true" }

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
	rep, err := Preflight(in.client, in.bundle, in.nodes, in.keepState)
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
	rep, err := Preflight(in.client, in.bundle, in.nodes, in.keepState)
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

	// The pre-flight above already resolved the operator's node selection, so
	// apply follows the report rather than re-reading the form.
	selectedTargetNodes := map[string]bool{}
	for _, tn := range rep.TargetNodes {
		if tn.Selected {
			selectedTargetNodes[tn.Hostname] = true
		}
	}

	res, err := ApplyImport(in.client, rep, in.passphrase, in.zipPassword, selectedTargetNodes, in.adminRole, in.keepState, s.log)
	if err != nil {
		s.fail("%v", err)
		s.send(map[string]any{"type": "done", "result": res, "preflight": rep})
		return
	}
	res.Skipped += rep.Skip
	res.Blocked = rep.Blocked
	s.send(map[string]any{"type": "done", "result": res, "preflight": rep})
}
