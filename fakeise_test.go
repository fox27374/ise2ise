package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
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
	certExports map[string][]byte // cert id -> export body

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
		nodes:       []string{"ise-src-1"},
		pagesServed: map[string]int{},
		created:     map[string][]map[string]any{},
	}
	f.ers = httptest.NewServer(http.HandlerFunc(f.serveERS))
	f.api = httptest.NewServer(http.HandlerFunc(f.serveAPI))
	t.Cleanup(f.ers.Close)
	t.Cleanup(f.api.Close)
	return f
}

func (f *fakeISE) client() *Client {
	return &Client{
		Host: "fake-ise", User: f.user, Pass: f.pass,
		ersBase: f.ers.URL, apiBase: f.api.URL,
		hc: f.ers.Client(),
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

	// Trusted certificate listing.
	if path == "/api/v1/certs/trusted-certificate" && r.Method == http.MethodGet {
		f.pagesServed["openapi-cert"]++
		page := f.page(r, f.certs)
		if f.apiBareArray {
			writeJSONRaw(w, page)
			return
		}
		writeJSONRaw(w, page)
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

		// Check for duplicates by name.
		name, _ := body["name"].(string)
		for _, existing := range f.certs {
			if str(existing, "name") == name {
				iseError(w, http.StatusBadRequest, "Certificate with name "+name+" already exists")
				return
			}
		}

		// Create the cert object.
		cert := maps.Clone(body)
		cert["id"] = fmt.Sprintf("tgt-cert-%d", len(f.certs)+1)
		if cert["sha256Fingerprint"] == nil {
			// Fake a fingerprint.
			cert["sha256Fingerprint"] = "00112233445566778899aabbccddeeff"
		}
		f.certs = append(f.certs, cert)
		if f.created["certs"] == nil {
			f.created["certs"] = []map[string]any{}
		}
		f.created["certs"] = append(f.created["certs"], body)
		w.WriteHeader(http.StatusCreated)
		writeJSONRaw(w, cert)
		return
	}

	// Trusted certificate export (by id).
	if strings.HasPrefix(path, "/api/v1/certs/trusted-certificate/") && strings.HasSuffix(path, "/export") {
		parts := strings.Split(path, "/")
		if len(parts) >= 7 {
			// parts[5] is the id, parts[6] is "export"
			id := parts[5]
			if body, ok := f.certExports[id]; ok {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Write(body)
				return
			}
		}
		iseError(w, http.StatusNotFound, "Certificate not found")
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
	case "trustedcertificate":
		return f.certs, rootTrustedCert, true
	case "node":
		nodes := make([]map[string]any, 0, len(f.nodes))
		for i, n := range f.nodes {
			nodes = append(nodes, map[string]any{"id": fmt.Sprint("node", i), "name": n})
		}
		return nodes, "Node", true
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
	case "trustedcertificate":
		f.certs = append(f.certs, o)
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
	g := map[string]any{
		"id": id, "name": name, "description": name + " description",
		"systemDefined": false,
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

func quiet(string, ...any) {}
