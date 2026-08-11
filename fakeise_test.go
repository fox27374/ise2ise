package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeISE is a stand-in for a real deployment: no ISE is reachable from the
// build environment, and the response shapes here are the ones the client code
// is written against. Two servers, because ISE really does split ERS (9060)
// from the OpenAPI (443) and they fail independently.
type fakeISE struct {
	t *testing.T

	ers *httptest.Server
	api *httptest.Server

	user, pass string

	mu          sync.Mutex
	groups      []map[string]any
	endpoints   []map[string]any
	profiles    []map[string]any
	nodes       []string
	certs       []map[string]any
	certExports map[string][]byte           // cert id -> export body
	policies    map[string][]map[string]any // policy path -> list of policy objects

	systemCerts       map[string][]map[string]any // hostname -> list of system certs
	systemCertImports []map[string]any            // import payloads, in arrival order
	systemCertPEM     map[string][]byte           // cert id -> the PEM its export ZIP carries
	systemCertExports map[string][]byte           // cert id -> export body
	systemCertCreated map[string][]map[string]any // hostname -> created payloads
	deploymentNodes   []map[string]any

	// Policy elements
	rejectWebRedirection   bool            // an authorization profile naming a portal is refused, as a target without it does
	authProfileListFails   bool            // GET /ers/config/authorizationprofile answers 500, as 3.4 does
	authProfileDetailFails map[string]bool // profile id -> its own detail read answers 500 too
	networkDeviceGroups    []map[string]any
	dacls                  []map[string]any
	authProfiles           []map[string]any
	idStoreSequences       []map[string]any
	conditions             []map[string]any
	dictionaries           []map[string]any
	adJoinPoints           []map[string]any
	certProfiles           []map[string]any

	policyForbidden bool // the policy API answers 403, as a locked-down box does

	// Policy sets
	policySets     []map[string]any
	policySetRules map[string][]map[string]any // policy set id -> rules
	serviceNames   []map[string]any
	securityGroups []map[string]any
	identityStores []map[string]any

	csrfRequired bool   // ERS demands a CSRF nonce on writes, as a real 3.4 does
	csrfToken    string // the nonce currently issued
	csrfIssued   int    // how many nonces were handed out

	ersUnauthorized bool // ERS answers 401 (disabled, or wrong credentials)
	apiUnauthorized bool // OpenAPI answers 401
	apiBareArray    bool // OpenAPI returns a bare array instead of {"response":[]}
	version         string

	pagesServed map[string]int // path -> number of list pages requested
	created     map[string][]map[string]any
}

func newFakeISE(t *testing.T) *fakeISE {
	f := &fakeISE{
		t: t, user: "ersadmin", pass: "s3cret", version: "3.3.0.430",
		nodes:             []string{"ise-src-1"},
		pagesServed:       map[string]int{},
		created:           map[string][]map[string]any{},
		policies:          map[string][]map[string]any{},
		policySetRules:    map[string][]map[string]any{},
		systemCerts:       map[string][]map[string]any{},
		systemCertPEM:     map[string][]byte{},
		systemCertExports: map[string][]byte{},
		systemCertCreated: map[string][]map[string]any{},
		deploymentNodes:   []map[string]any{},
	}
	// Initialize deployment nodes
	f.deploymentNodes = []map[string]any{
		{
			"hostname":   "ise-src-1",
			"ipAddress":  "10.0.0.1",
			"nodeStatus": "Connected",
			"roles":      []string{"Admin", "PAN", "MnT"},
		},
	}
	f.systemCerts["ise-src-1"] = []map[string]any{}
	f.systemCertCreated["ise-src-1"] = []map[string]any{}

	f.ers = httptest.NewServer(http.HandlerFunc(f.serveERS))
	f.api = httptest.NewServer(http.HandlerFunc(f.serveAPI))
	t.Cleanup(f.ers.Close)
	t.Cleanup(f.api.Close)
	return f
}

func (f *fakeISE) client() *Client {
	hc := f.ers.Client()
	// NewClient gives the real client a cookie jar because the ERS CSRF nonce
	// is only accepted alongside the session cookie issued with it. The fake's
	// client has to match, or it cannot exercise that path.
	jar, err := cookiejar.New(nil)
	if err != nil {
		f.t.Fatalf("cookie jar: %v", err)
	}
	hc.Jar = jar
	return &Client{
		Host: "fake-ise", User: f.user, Pass: f.pass,
		ersBase: f.ers.URL, apiBase: f.api.URL,
		hc: hc,
	}
}

// iseError is the shape ISE returns for a rejected call. Its text is the only
// useful diagnostic, which is why the client keeps it.
func iseError(w http.ResponseWriter, code int, title string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"ERSResponse": map[string]any{
			"operation": "test",
			"messages":  []any{map[string]any{"title": title, "type": "ERROR", "code": "CRUD operation exception"}},
		},
	})
}

func (f *fakeISE) auth(w http.ResponseWriter, r *http.Request, unauthorized bool) bool {
	u, p, ok := r.BasicAuth()
	if unauthorized || !ok || u != f.user || p != f.pass {
		iseError(w, http.StatusUnauthorized, "Authentication failed or the API is disabled")
		return false
	}
	return true
}

func (f *fakeISE) serveERS(w http.ResponseWriter, r *http.Request) {
	if !f.auth(w, r, f.ersUnauthorized) {
		return
	}

	// Real ISE refuses ERS writes with "CSRF nonce validation failed" unless the
	// client has fetched a nonce and sends it back with the session cookie.
	// Observed on 3.4 with the CSRF check enabled.
	if f.csrfRequired {
		if r.Header.Get("X-CSRF-TOKEN") == "fetch" {
			f.mu.Lock()
			f.csrfIssued++
			tok := fmt.Sprintf("nonce-%d", f.csrfIssued)
			f.csrfToken = tok
			f.mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "APPSESSIONID", Value: "fake-session", Path: "/"})
			w.Header().Set("X-CSRF-Token", tok)
			// ISE answers the fetch with 415, not 200.
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if r.Method != http.MethodGet {
			f.mu.Lock()
			want, cookieOK := f.csrfToken, false
			for _, ck := range r.Cookies() {
				if ck.Name == "APPSESSIONID" {
					cookieOK = true
				}
			}
			f.mu.Unlock()
			if want == "" || r.Header.Get("X-CSRF-TOKEN") != want || !cookieOK {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "<html><body>CSRF nonce validation failed</body></html>")
				return
			}
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path

	if path == "/ers/config/op/systemconfig/iseversion" {
		writeJSONRaw(w, map[string]any{"OperationResult": map[string]any{
			"resultValue": []any{
				map[string]any{"name": "version", "value": f.version},
				map[string]any{"name": "patch information", "value": "3"},
			}}})
		return
	}

	coll, id := splitERSPath(path)

	// A profile carrying a web redirection is refused when the portal it names is
	// not on this deployment. Portals cannot be listed at all on 3.4, so the tool
	// finds out by being told no, and this is where it gets told.
	if coll == "authorizationprofile" && r.Method == http.MethodPost && f.rejectWebRedirection {
		var body map[string]map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if obj := body[rootAuthProfile]; obj != nil && obj["webRedirection"] != nil {
			iseError(w, http.StatusBadRequest, "Portal not found for the given web redirection")
			return
		}
		// Not a redirect profile, or the retry without one: fall through by
		// re-reading the body the generic path expects.
		raw, _ := json.Marshal(body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}

	// Real 3.4 cannot serialise some of its own authorization profiles. Listing
	// the collection answers 500 on every box seen so far, and an individual
	// profile holding a web redirection answers 500 on its own id. Both are
	// reproduced here because both change what the tool is allowed to assume.
	if coll == "authorizationprofile" && r.Method == http.MethodGet {
		if id == "" && f.authProfileListFails {
			iseError(w, http.StatusInternalServerError,
				"Failed to convert to ERS object, attribute: cisco-av-pair, Error: could not extract ResultSet")
			return
		}
		if id != "" && f.authProfileDetailFails[id] {
			iseError(w, http.StatusInternalServerError,
				"Failed to convert to ERS object, attribute: cisco-av-pair, Error: Exception when converting from attribute value to WebRedirection object")
			return
		}
	}

	// Handle Active Directory addGroups endpoint: PUT /ers/config/activedirectory/{id}/addGroups
	if strings.HasSuffix(path, "/addGroups") && r.Method == http.MethodPut {
		if coll != "activedirectory" {
			iseError(w, http.StatusNotFound, "Resource not found: "+path)
			return
		}
		// addGroups can fail when the domain is not joined
		// (this would be verified on real ISE but we keep it simple in the fake)
		var body map[string]map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		// For testing, we can simulate failure if a flag is set
		// For now, accept it silently
		writeJSONRaw(w, map[string]any{rootActiveDirectory: body[rootActiveDirectory]})
		return
	}

	objs, root, ok := f.collection(coll)
	if !ok {
		iseError(w, http.StatusNotFound, "Resource not found: "+path)
		return
	}
	switch {
	case r.Method == http.MethodGet && id == "":
		f.pagesServed[coll]++
		f.writeSearchResult(w, r, objs)
	case r.Method == http.MethodGet:
		for _, o := range objs {
			if o["id"] == id {
				writeJSONRaw(w, map[string]any{root: o})
				return
			}
		}
		iseError(w, http.StatusNotFound, "Object with id "+id+" not found")
	case r.Method == http.MethodPost:
		var body map[string]map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		obj := body[root]
		if obj == nil {
			iseError(w, http.StatusBadRequest, "expected root key "+root)
			return
		}
		// Real ERS refuses a body containing JSON nulls. Observed on 3.4:
		// "Resource Initialization Failed due to JSON invalidity: please if
		// properties names are correct: ipAddress->..."
		for k, v := range obj {
			if v == nil {
				iseError(w, http.StatusBadRequest,
					"Resource Initialization Failed due to JSON invalidity: please if properties names are correct: "+k+"->null")
				return
			}
		}
		name, _ := obj["name"].(string)
		if name == "" {
			name, _ = obj["mac"].(string)
		}
		for _, o := range objs {
			if o["name"] == name {
				iseError(w, http.StatusBadRequest, "Endpoint or group already exists: "+name)
				return
			}
		}
		stored := maps.Clone(obj)
		stored["id"] = fmt.Sprintf("tgt-%s-%d", coll, len(objs)+1)
		stored["name"] = name
		f.append(coll, stored)
		f.created[coll] = append(f.created[coll], obj)
		w.Header().Set("Location", f.ers.URL+path+"/"+stored["id"].(string))
		w.WriteHeader(http.StatusCreated)
	default:
		iseError(w, http.StatusMethodNotAllowed, "not allowed")
	}
}

func (f *fakeISE) serveAPI(w http.ResponseWriter, r *http.Request) {
	if !f.auth(w, r, f.apiUnauthorized) {
		return
	}

	path := r.URL.Path
	f.mu.Lock()
	defer f.mu.Unlock()

	// Endpoint listing.
	if path == "/api/v1/endpoint" {
		f.pagesServed["openapi-endpoint"]++
		page := f.page(r, f.endpoints)
		if f.apiBareArray {
			writeJSONRaw(w, page)
			return
		}
		writeJSONRaw(w, map[string]any{"response": page, "version": "1.0.0"})
		return
	}

	// Policy endpoints: the policy sets, their authentication and authorization
	// rules, and the shared condition library, for both policy trees.
	if strings.HasPrefix(path, "/api/v1/policy/") && r.Method == http.MethodGet {
		f.pagesServed["policy-"+path]++
		if f.policyForbidden {
			// What a deployment with the policy API locked down answers.
			http.Error(w, `{"message":"insufficient privileges"}`, http.StatusForbidden)
			return
		}
		// Authorization profiles stub list
		if path == "/api/v1/policy/network-access/authorization-profiles" {
			page := f.page(r, f.authProfiles)
			writeJSONRaw(w, map[string]any{"response": page})
			return
		}
		// Conditions. The library lives in two places in this fake: f.conditions,
		// which the policy element tests populate, and f.policies, which the
		// policy usage scan's tests populate. Both are the same collection on a
		// real box, so both are served — serving only one made a scan test see an
		// empty library.
		if path == pathConditions || path == pathTimeConditions || path == pathNetworkConditions {
			items := append(append([]map[string]any{}, f.policies[path]...), f.conditions...)
			if path != pathConditions {
				items = f.policies[path] // time and network conditions are empty on the source
			}
			page := f.page(r, items)
			writeJSONRaw(w, map[string]any{"response": page})
			return
		}
		// Dictionaries
		if path == "/api/v1/policy/network-access/dictionaries" {
			page := f.page(r, f.dictionaries)
			writeJSONRaw(w, map[string]any{"response": page})
			return
		}
		// Policy sets, and each set's authentication and authorization rules.
		// f.policies carries what the policy usage scan's tests registered; the
		// policy set tests use f.policySets and f.policySetRules, and both are
		// the same collection on a real deployment.
		if path == pathPolicySets {
			items := append(append([]map[string]any{}, f.policies[path]...), f.policySets...)
			writeJSONRaw(w, map[string]any{"response": f.page(r, items)})
			return
		}
		if setID, kind, ok := splitRulePath(path); ok {
			items := append(append([]map[string]any{}, f.policies[path]...), f.policySetRules[setID+"|"+kind]...)
			writeJSONRaw(w, map[string]any{"response": f.page(r, items)})
			return
		}
		for _, l := range []struct {
			path string
			objs []map[string]any
		}{
			{pathServiceNames, f.serviceNames},
			{pathSecurityGroups, f.securityGroups},
			{pathIdentityStores, f.identityStores},
		} {
			if path == l.path {
				writeJSONRaw(w, map[string]any{"response": f.page(r, l.objs)})
				return
			}
		}

		items := f.policies[path] // nil is a legitimate empty rule set
		writeJSONRaw(w, map[string]any{"response": f.page(r, items)})
		return
	}

	// Policy set and rule creation.
	if r.Method == http.MethodPost && strings.HasPrefix(path, pathPolicySets) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body == nil {
			iseError(w, http.StatusBadRequest, "empty body")
			return
		}
		if path == pathPolicySets {
			for _, s := range f.policySets {
				if str(s, "name") == str(body, "name") {
					iseError(w, http.StatusBadRequest, "policy set already exists: "+str(body, "name"))
					return
				}
			}
			body["id"] = fmt.Sprintf("tgt-set-%d", len(f.policySets)+1)
			f.policySets = append(f.policySets, body)
			writeJSONRaw(w, map[string]any{"response": body})
			return
		}
		if setID, kind, ok := splitRulePath(path); ok {
			body["id"] = fmt.Sprintf("tgt-rule-%d", len(f.policySetRules[setID+"|"+kind])+1)
			f.policySetRules[setID+"|"+kind] = append(f.policySetRules[setID+"|"+kind], body)
			writeJSONRaw(w, map[string]any{"response": body})
			return
		}
	}

	// Trusted certificate listing (OpenAPI only).
	if path == "/api/v1/certs/trusted-certificate" && r.Method == http.MethodGet {
		f.pagesServed["openapi-cert"]++
		page := f.page(r, f.certs)
		// Real ISE 3.4 returns {"response": [...]}
		writeJSONRaw(w, map[string]any{"response": page})
		return
	}

	// ERS trusted certificate path returns 404 (does not exist in ISE 3.4).
	if strings.HasPrefix(path, "/ers/config/trustedcertificate") {
		iseError(w, http.StatusNotFound, "Resource not found: "+path)
		return
	}

	// Trusted certificate import (create).
	if path == "/api/v1/certs/trusted-certificate/import" && r.Method == http.MethodPost {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body == nil {
			iseError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Check for comma in description (real ISE 3.4 rejects this).
		if desc, ok := body["description"].(string); ok && strings.Contains(desc, ",") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"response": map[string]any{
					"status":  "Fail",
					"message": "Security Check Failed",
					"id":      nil,
				},
			})
			return
		}

		// Check for duplicates by friendly name and binary content.
		name, _ := body["name"].(string)
		data, _ := body["data"].(string)

		for _, existing := range f.certs {
			if str(existing, "friendlyName") == name {
				// This is a duplicate by name - the real error is the "binary equal" one.
				// Check if data matches.
				if str(existing, "pem") == data {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					json.NewEncoder(w).Encode(map[string]any{
						"response": map[string]any{
							"status":  "Fail",
							"message": "Certificates are having same subject, same serial number and they are binary equal. Hence skipping the replace",
							"id":      nil,
						},
					})
					return
				}
			}
		}

		// Create the cert object with real field names and types.
		cert := map[string]any{
			"id":                            fmt.Sprintf("tgt-cert-%d", len(f.certs)+1),
			"friendlyName":                  name,
			"subject":                       "CN=example.com",
			"issuedTo":                      "example.com",
			"issuedBy":                      "example.com",
			"keySize":                       256,
			"signatureAlgorithm":            "SHA256withECDSA",
			"validFrom":                     "Mon Jan 01 00:00:00 UTC 2024",
			"expirationDate":                "Mon Dec 31 23:59:59 UTC 2025",
			"serialNumberDecimalFormat":     "1",
			"status":                        "Enabled",
			"trustedFor":                    "Infrastructure,Endpoints",
			"internalCA":                    false,
			"downloadCRL":                   "off",
			"automaticCRLUpdate":            "off",
			"authenticateBeforeCRLReceived": "off",
			"enableOCSPValidation":          "off",
			"enableServerIdentityCheck":     "off",
			"rejectIfNoStatusFromOCSP":      "off",
			"rejectIfUnreachableFromOCSP":   "off",
			"sha256Fingerprint":             "00112233445566778899aabbccddeeff",
		}

		// Copy from request body if present.
		for _, field := range []string{"description", "trustForIseAuth", "trustForClientAuth", "trustForCertificateBasedAdminAuth", "trustForCiscoServicesAuth"} {
			if v, ok := body[field]; ok {
				cert[field] = v
			}
		}

		// Store the PEM data for later export.
		cert["pem"] = data

		f.certs = append(f.certs, cert)
		if f.created["certs"] == nil {
			f.created["certs"] = []map[string]any{}
		}
		f.created["certs"] = append(f.created["certs"], body)

		// Real ISE 3.4 import response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"response": map[string]any{
				"status":  "Success",
				"message": "Trust certificate was added successfully",
				"id":      cert["id"],
			},
		})
		return
	}

	// Trusted certificate PUT (CRL settings).
	if strings.HasPrefix(path, "/api/v1/certs/trusted-certificate/") && r.Method == http.MethodPut {
		parts := strings.Split(path, "/")
		if len(parts) >= 6 {
			id := parts[5]
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)

			// Real ISE 3.4 refuses these when CRL download is off, and rejects
			// the whole PUT with 400.
			if dl, _ := body["downloadCRL"].(bool); !dl {
				for _, dep := range []string{"automaticCRLUpdate", "enableServerIdentityCheck", "authenticateBeforeCRLReceived", "ignoreCRLExpiration"} {
					if b, _ := body[dep].(bool); b {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]any{"response": map[string]any{
							"message": "One or more of these parameters: automaticCRLUpdate, enableServerIdentityCheck, authenticateBeforeCRLReceived, ignoreCRLExpiration can only be set true if downloadCRL parameter is set to be true",
						}})
						return
					}
				}
			}

			// Find the cert and update it.
			for i, cert := range f.certs {
				if str(cert, "id") == id {
					// Merge in the updates.
					for k, v := range body {
						f.certs[i][k] = v
					}
					// The real PUT replaces rather than patches: a trust flag
					// left out of the body comes back false, which is how a
					// certificate ends up trusted for nothing after an
					// otherwise successful import.
					trusted := []string{}
					for _, m := range []struct{ flag, token string }{
						{"trustForIseAuth", "Infrastructure"},
						{"trustForClientAuth", "Endpoints"},
						{"trustForCiscoServicesAuth", "Cisco Services"},
						{"trustForCertificateBasedAdminAuth", "AdminAuth"},
					} {
						if b, _ := body[m.flag].(bool); b {
							trusted = append(trusted, m.token)
						}
					}
					if len(trusted) == 0 {
						f.certs[i]["trustedFor"] = "Unknown"
					} else {
						f.certs[i]["trustedFor"] = strings.Join(trusted, ",")
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]any{
						"response": f.certs[i],
					})
					return
				}
			}
		}
		iseError(w, http.StatusNotFound, "Certificate not found")
		return
	}

	// Trusted certificate export (by id).
	// Path is /api/v1/certs/trusted-certificate/export/{id}
	if strings.HasPrefix(path, "/api/v1/certs/trusted-certificate/export/") {
		id := strings.TrimPrefix(path, "/api/v1/certs/trusted-certificate/export/")
		for _, cert := range f.certs {
			if str(cert, "id") == id {
				// Return the PEM data stored in the cert.
				pem := str(cert, "pem")
				if pem != "" {
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pem", str(cert, "friendlyName")))
					w.Write([]byte(pem))
					return
				}
				break
			}
		}
		iseError(w, http.StatusNotFound, "Certificate not found")
		return
	}

	// Deployment node listing
	if path == "/api/v1/deployment/node" && r.Method == http.MethodGet {
		writeJSONRaw(w, map[string]any{"response": f.deploymentNodes})
		return
	}

	// System certificate listing per node
	if strings.HasPrefix(path, "/api/v1/certs/system-certificate/") {
		hostName := strings.TrimPrefix(path, "/api/v1/certs/system-certificate/")
		if strings.Contains(hostName, "/") || hostName == "export" || hostName == "import" {
			// A sub-path or one of the action endpoints; handled below.
		} else if r.Method == http.MethodGet {
			f.pagesServed["system-cert-"+hostName]++
			certs := f.systemCerts[hostName]
			if certs == nil {
				certs = []map[string]any{}
			}
			page := f.page(r, certs)
			writeJSONRaw(w, map[string]any{"response": page})
			return
		}
	}

	// System certificate export and import
	if path == "/api/v1/certs/system-certificate/export" && r.Method == http.MethodPost {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		id, _ := body["id"].(string)
		hostName, _ := body["hostName"].(string)

		if hostName == "" || id == "" {
			iseError(w, http.StatusBadRequest, "missing hostName or id")
			return
		}

		// Return cached export if available
		// Keyed by mode as well as id: a keyless export and a with-key export of
		// the same certificate are different bodies, and caching them together
		// handed the tool a ZIP with no key in it.
		mode, _ := body["export"].(string)
		if exportData, ok := f.systemCertExports[id+"|"+mode]; ok {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(exportData)
			return
		}

		// A real export answers a ZIP holding the certificate and, with a private
		// key requested, the encrypted key beside it. The entries must carry real
		// content: an empty .pem let a bug through where the picker parsed the
		// body as bare PEM, found nothing, and reported every certificate as
		// single-name — which quietly unticked the only one worth migrating.
		buf := &bytes.Buffer{}
		z := zip.NewWriter(buf)
		w1, _ := z.Create("cert.pem")
		w1.Write(f.systemCertPEM[id])
		if export, _ := body["export"].(string); export == "CERTIFICATE_WITH_PRIVATE_KEY" {
			w2, _ := z.Create("cert.pvk")
			w2.Write([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque\n-----END ENCRYPTED PRIVATE KEY-----\n"))
		}
		z.Close()

		exportData := buf.Bytes()
		f.systemCertExports[id+"|"+mode] = exportData

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(exportData)
		return
	}

	if path == "/api/v1/certs/system-certificate/import" && r.Method == http.MethodPost {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		name, _ := body["name"].(string)

		if name == "" {
			iseError(w, http.StatusBadRequest, "missing name")
			return
		}

		// Record the created certificate (for testing). systemCertImports keeps
		// them in the order they arrived, which is what the per-node tests read.
		// serveAPI already holds f.mu.
		f.systemCertImports = append(f.systemCertImports, body)
		for hostName := range f.systemCerts {
			f.systemCertCreated[hostName] = append(f.systemCertCreated[hostName], body)
		}

		// Create a cert object
		cert := map[string]any{
			"id":                fmt.Sprintf("sys-cert-%d", len(f.systemCerts)+1),
			"friendlyName":      name,
			"sha256Fingerprint": "00112233445566778899aabbccddeeff",
			"expirationDate":    "Mon Dec 31 23:59:59 UTC 2025",
			"issuedTo":          name,
			"issuedBy":          name,
			"selfSigned":        true,
			"keySize":           2048,
			"usedBy":            "",
			"portalGroupTag":    "",
			"eap":               body["eap"],
			"radius":            body["radius"],
			"tacacs":            body["tacacs"],
			"pxgrid":            body["pxgrid"],
			"ims":               body["ims"],
			"saml":              body["saml"],
			"portal":            body["portal"],
			"admin":             body["admin"],
		}

		// Add to the appropriate node's certs (use first selectable node for now)
		if len(f.deploymentNodes) > 0 {
			hostName := str(f.deploymentNodes[0], "hostname")
			if hostName != "" {
				f.systemCerts[hostName] = append(f.systemCerts[hostName], cert)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"response": map[string]any{
				"status":  "Success",
				"message": "System certificate was added successfully",
				"id":      cert["id"],
			},
		})
		return
	}

	// Condition create (OpenAPI POST)
	if (path == "/api/v1/policy/network-access/condition" || path == "/api/v1/policy/network-access/time-condition" || path == "/api/v1/policy/network-access/network-condition") && r.Method == http.MethodPost {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body == nil {
			iseError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		// Create the condition
		cond := maps.Clone(body)
		cond["id"] = fmt.Sprintf("tgt-cond-%d", len(f.conditions)+1)
		f.conditions = append(f.conditions, cond)
		f.created["condition"] = append(f.created["condition"], body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"response": map[string]any{
				"status":  "Success",
				"message": "Condition was added successfully",
				"id":      cond["id"],
			},
		})
		return
	}

	iseError(w, http.StatusNotFound, "no such OpenAPI resource")
}

func (f *fakeISE) page(r *http.Request, objs []map[string]any) []map[string]any {
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	if size <= 0 {
		size = 20
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * size
	if start >= len(objs) {
		return []map[string]any{}
	}
	end := min(start+size, len(objs))
	return objs[start:end]
}

func (f *fakeISE) writeSearchResult(w http.ResponseWriter, r *http.Request, objs []map[string]any) {
	page := f.page(r, objs)
	res := make([]map[string]any, 0, len(page))
	for _, o := range page {
		res = append(res, map[string]any{
			"id": o["id"], "name": o["name"],
			"link": map[string]any{"rel": "self", "href": f.ers.URL + r.URL.Path + "/" + fmt.Sprint(o["id"]), "type": "application/json"},
		})
	}
	writeJSONRaw(w, map[string]any{"SearchResult": map[string]any{
		"total": len(objs), "resources": res,
	}})
}

func (f *fakeISE) collection(coll string) ([]map[string]any, string, bool) {
	switch coll {
	case "endpointgroup":
		return f.groups, rootEndpointGroup, true
	case "endpoint":
		return f.endpoints, rootEndpoint, true
	case "profilerprofile":
		return f.profiles, "ProfilerProfile", true
	case "node":
		nodes := make([]map[string]any, 0, len(f.nodes))
		for i, n := range f.nodes {
			nodes = append(nodes, map[string]any{"id": fmt.Sprint("node", i), "name": n})
		}
		return nodes, "Node", true
	case "networkdevicegroup":
		return f.networkDeviceGroups, rootNetworkDeviceGroup, true
	case "downloadableacl":
		return f.dacls, rootDownloadableACL, true
	case "authorizationprofile":
		return f.authProfiles, rootAuthProfile, true
	case "idstoresequence":
		return f.idStoreSequences, rootIdStoreSequence, true
	case "activedirectory":
		return f.adJoinPoints, rootActiveDirectory, true
	case "certificateprofile":
		return f.certProfiles, "CertificateProfile", true
	}
	return nil, "", false
}

func (f *fakeISE) append(coll string, o map[string]any) {
	switch coll {
	case "endpointgroup":
		f.groups = append(f.groups, o)
	case "endpoint":
		f.endpoints = append(f.endpoints, o)
	case "profilerprofile":
		f.profiles = append(f.profiles, o)
	case "networkdevicegroup":
		f.networkDeviceGroups = append(f.networkDeviceGroups, o)
	case "downloadableacl":
		f.dacls = append(f.dacls, o)
	case "authorizationprofile":
		f.authProfiles = append(f.authProfiles, o)
	case "idstoresequence":
		f.idStoreSequences = append(f.idStoreSequences, o)
	case "activedirectory":
		f.adJoinPoints = append(f.adJoinPoints, o)
	case "certificateprofile":
		f.certProfiles = append(f.certProfiles, o)
	}
}

func splitERSPath(p string) (coll, id string) {
	p = strings.TrimPrefix(p, "/ers/config/")
	if i := strings.Index(p, "/"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

func writeJSONRaw(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// --- fixtures ----------------------------------------------------------------

func (f *fakeISE) addGroup(id, name string) map[string]any {
	return f.addGroupWithSystemFlag(id, name, false)
}

func (f *fakeISE) addGroupWithSystemFlag(id, name string, systemDefined bool) map[string]any {
	g := map[string]any{
		"id": id, "name": name, "description": name + " description",
		"systemDefined": systemDefined,
		"link":          map[string]any{"rel": "self", "href": f.ers.URL + "/ers/config/endpointgroup/" + id},
	}
	f.groups = append(f.groups, g)
	return g
}

func (f *fakeISE) addProfile(id, name string) {
	f.profiles = append(f.profiles, map[string]any{"id": id, "name": name})
}

func (f *fakeISE) addEndpoint(mac, groupID string, static bool, profileID string) map[string]any {
	e := map[string]any{
		"id": "ep-" + mac, "name": mac, "mac": mac,
		"groupId":                 groupID,
		"staticGroupAssignment":   static,
		"staticProfileAssignment": profileID != "",
		"link":                    map[string]any{"rel": "self", "href": f.ers.URL + "/ers/config/endpoint/ep-" + mac},
	}
	if profileID != "" {
		e["profileId"] = profileID
	}
	f.endpoints = append(f.endpoints, e)
	return e
}

func (f *fakeISE) addSystemCert(hostName, id, name, fingerprint string, roles []string) map[string]any {
	cert := map[string]any{
		"id":                fmt.Sprintf("sys-cert-%s", id),
		"friendlyName":      name,
		"sha256Fingerprint": fingerprint,
		"expirationDate":    "Mon Dec 31 23:59:59 UTC 2099",
		"issuedTo":          "CN=" + name,
		"issuedBy":          "CN=" + name,
		"selfSigned":        true,
		"keySize":           2048,
		"usedBy":            strings.Join(roles, ","),
		"portalGroupTag":    "",
		"nodeStatus":        "Connected",
	}
	if _, ok := f.systemCerts[hostName]; !ok {
		f.systemCerts[hostName] = []map[string]any{}
		f.systemCertCreated[hostName] = []map[string]any{}
	}
	f.systemCerts[hostName] = append(f.systemCerts[hostName], cert)
	return cert
}

// addPolicySet registers a policy set, which on a real box carries almost no
// conditions itself: the references live in the rules that hang off it.
func (f *fakeISE) addPolicySet(tree, id, name string) {
	path := "/api/v1/policy/" + tree + "/policy-set"
	f.policies[path] = append(f.policies[path], map[string]any{"id": id, "name": name})
}

// addRuleWithGroupRef puts a rule referencing an endpoint identity group into one
// of a policy set's rule sets ("authentication" or "authorization"). groupPath is
// what ISE stores, so it may carry the nesting: "Production:Siemens".
func (f *fakeISE) addRuleWithGroupRef(tree, setID, ruleSet, groupPath string) {
	path := "/api/v1/policy/" + tree + "/policy-set/" + setID + "/" + ruleSet
	f.policies[path] = append(f.policies[path], map[string]any{
		"rule": map[string]any{
			"name": "match " + groupPath,
			"condition": map[string]any{
				"conditionType": "ConditionAndBlock",
				"children": []any{
					map[string]any{
						"conditionType":  "ConditionAttributes",
						"dictionaryName": "IdentityGroup",
						"attributeName":  "Name",
						"operator":       "equals",
						"attributeValue": "Endpoint Identity Groups:" + groupPath,
					},
				},
			},
		},
	})
}

// addLibraryConditionWithGroupRef puts a reference in the shared condition
// library, which rules point at rather than inlining.
func (f *fakeISE) addLibraryConditionWithGroupRef(tree, name, groupPath string) {
	path := "/api/v1/policy/" + tree + "/condition"
	f.policies[path] = append(f.policies[path], map[string]any{
		"conditionType":  "LibraryConditionAttributes",
		"name":           name,
		"dictionaryName": "IdentityGroup",
		"attributeName":  "Name",
		"operator":       "equals",
		"attributeValue": "Endpoint Identity Groups:" + groupPath,
	})
}

func quiet(string, ...any) {}

// splitRulePath recognises /api/v1/policy/network-access/policy-set/{id}/{kind}
// for kind in authentication, authorization.
func splitRulePath(path string) (setID, kind string, ok bool) {
	rest, found := strings.CutPrefix(path, pathPolicySets+"/")
	if !found {
		return "", "", false
	}
	setID, kind, found = strings.Cut(rest, "/")
	if !found || (kind != "authentication" && kind != "authorization") {
		return "", "", false
	}
	return setID, kind, true
}

// addPolicySetNA registers a network-access policy set. The older addPolicySet
// writes into f.policies for the policy usage scan's tests and takes a tree
// name; this one is the object the policy set slice reads and writes.
func (f *fakeISE) addPolicySetNA(id, name string, rank int, state, serviceName string, isDefault bool, cond map[string]any) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policySetRules == nil {
		f.policySetRules = map[string][]map[string]any{}
	}
	s := map[string]any{
		"id": id, "name": name, "rank": rank, "state": state,
		"serviceName": serviceName, "default": isDefault, "hitCounts": 0,
		"description": "", "condition": cond,
	}
	f.policySets = append(f.policySets, s)
	return s
}

// addRule nests one rule under a set, in the {"rule": {...}, …} shape ISE uses.
func (f *fakeISE) addRule(setID, kind, name string, isDefault bool, extra map[string]any, cond map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policySetRules == nil {
		f.policySetRules = map[string][]map[string]any{}
	}
	inner := map[string]any{
		"id": "src-" + name, "name": name, "default": isDefault,
		"rank": len(f.policySetRules[setID+"|"+kind]), "state": "enabled",
		"hitCounts": 0, "condition": cond,
	}
	obj := map[string]any{"rule": inner}
	for k, v := range extra {
		obj[k] = v
	}
	f.policySetRules[setID+"|"+kind] = append(f.policySetRules[setID+"|"+kind], obj)
}

func (f *fakeISE) addNamedList(which, name, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := map[string]any{"name": name, "id": id}
	switch which {
	case "service":
		f.serviceNames = append(f.serviceNames, obj)
	case "sgt":
		f.securityGroups = append(f.securityGroups, obj)
	case "store":
		f.identityStores = append(f.identityStores, obj)
	}
}

func (f *fakeISE) addADJoinPoint(id, name, domain string, groups []map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := map[string]any{
		"id":                      id,
		"name":                    name,
		"domain":                  domain,
		"description":             "",
		"enableDomainAllowedList": true,
		"adScopesNames":           "Default_Scope",
		"adAttributes": map[string]any{
			"attributes": []any{},
		},
		"advancedSettings": map[string]any{
			"enablePassChange":              true,
			"enableMachineAuth":             true,
			"enableMachineAccess":           true,
			"agingTime":                     5,
			"enableDialinPermissionCheck":   false,
			"enableCallbackForDialinClient": false,
			"plaintextAuth":                 false,
			"enableFailedAuthProtection":    false,
			"authProtectionType":            "WIRELESS",
			"failedAuthThreshold":           5,
			"enableAuthorizationFlow":       false,
			"identityNotInAdBehaviour":      "SEARCH_JOINED_FOREST",
			"unreachableDomainsBehaviour":   "PROCEED",
			"enableRewrites":                false,
			"rewriteRules":                  []any{},
		},
		"adgroups": map[string]any{
			"groups": groups,
		},
	}
	f.adJoinPoints = append(f.adJoinPoints, obj)
}
