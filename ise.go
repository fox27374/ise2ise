package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Cisco ISE exposes two REST APIs, both disabled by default:
//
//	ERS      https://<host>:9060/ers/...   (ERS Admin account)
//	OpenAPI  https://<host>/api/v1/...     (API Admin account)
//
// Both are switched on in Administration -> System -> Settings -> API Settings.
// Nothing here parses the ISE version to decide what to do: capability is
// probed, and whatever is unavailable is skipped and reported.

const (
	ersPort  = 9060
	pageSize = 100

	// ERS has no bulk read: every object costs its own GET after the list call.
	// Eight requests in flight is fast enough for a lab-sized deployment and
	// stays well under ISE's per-node ERS throttling, which starts returning
	// 429/500 when a client hammers it. Raise only with a real box to test on.
	detailWorkers = 8

	// A single ISE response body is never legitimately this large; the cap is
	// there so a misdirected request cannot exhaust memory.
	maxRespBody = 32 << 20
)

// Client talks to one ISE deployment. The credentials live in this struct and
// nowhere else: they are never written to disk, never logged and never put in
// a transfer bundle.
type Client struct {
	Host string
	User string
	Pass string

	ersBase string // https://host:9060
	apiBase string // https://host
	hc      *http.Client
}

// normalizeHost accepts what an operator actually types: "ise.example.net",
// "https://ise.example.net", "ise.example.net:443", with or without a path.
func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	h = strings.Trim(h, "/")
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	// Strip a port, but not the colons of a bare IPv6 literal.
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ":") && !strings.Contains(h, "]") {
		if _, err := fmt.Sscanf(h[i+1:], "%d", new(int)); err == nil {
			h = h[:i]
		}
	}
	return h
}

func NewClient(host, user, pass string, verifyTLS bool) *Client {
	host = normalizeHost(host)
	c := &Client{
		Host:    host,
		User:    user,
		Pass:    pass,
		ersBase: fmt.Sprintf("https://%s:%d", host, ersPort),
		apiBase: "https://" + host,
	}
	c.hc = &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			// ISE ships a self-signed certificate. Verification is off unless
			// the operator passes -verify-tls; the UI says so out loud.
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: !verifyTLS},
			MaxIdleConns:        detailWorkers * 2,
			MaxIdleConnsPerHost: detailWorkers * 2,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	return c
}

// APIError carries ISE's own error text. ISE's diagnostics are the only useful
// ones ("ERS is disabled", "Invalid MAC address"), so the body is kept whole
// and only truncated for display.
type APIError struct {
	Method string
	URL    string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.URL, e.Status, snippet([]byte(e.Body)))
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "(empty response body)"
	}
	if len(s) > 600 {
		return s[:600] + " …(truncated)"
	}
	return s
}

func (c *Client) do(method, u string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Pass)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// Never let the URL's userinfo or anything else leak credentials.
		return nil, fmt.Errorf("%s %s: %w", method, u, err)
	}
	defer resp.Body.Close()
	rb, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode >= 400 {
		return rb, &APIError{Method: method, URL: u, Status: resp.StatusCode, Body: string(rb)}
	}
	if readErr != nil {
		return nil, fmt.Errorf("%s %s: reading response: %w", method, u, readErr)
	}
	return rb, nil
}

// doRaw is like do but returns both the body and the response headers, for cases
// where we need the Content-Type or other metadata.
func (c *Client) doRaw(method, u string, body any) ([]byte, http.Header, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return nil, nil, err
	}
	req.SetBasicAuth(c.User, c.Pass)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", method, u, err)
	}
	defer resp.Body.Close()
	rb, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode >= 400 {
		return rb, resp.Header, &APIError{Method: method, URL: u, Status: resp.StatusCode, Body: string(rb)}
	}
	if readErr != nil {
		return nil, resp.Header, fmt.Errorf("%s %s: reading response: %w", method, u, readErr)
	}
	return rb, resp.Header, nil
}

// Stub is one entry of an ERS SearchResult: identity plus name, no content.
type Stub struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type searchResult struct {
	SearchResult struct {
		Total     int    `json:"total"`
		Resources []Stub `json:"resources"`
	} `json:"SearchResult"`
}

// ersList walks every page of an ERS collection and returns the stubs. ERS
// list responses never contain the objects themselves - each one needs its own
// GET <path>/<id>.
func (c *Client) ersList(path string) ([]Stub, error) {
	var out []Stub
	for page := 1; page <= 1000; page++ {
		u := fmt.Sprintf("%s%s?size=%d&page=%d", c.ersBase, path, pageSize, page)
		b, err := c.do(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		var sr searchResult
		if err := json.Unmarshal(b, &sr); err != nil || !bytes.Contains(b, []byte("SearchResult")) {
			return nil, fmt.Errorf("GET %s: expected an ERS SearchResult, received: %s", u, snippet(b))
		}
		out = append(out, sr.SearchResult.Resources...)
		if len(sr.SearchResult.Resources) < pageSize {
			return out, nil
		}
		if sr.SearchResult.Total > 0 && len(out) >= sr.SearchResult.Total {
			return out, nil
		}
	}
	return nil, fmt.Errorf("GET %s: more than 1000 pages; refusing to keep paging", c.ersBase+path)
}

// ersGetByID fetches one object and unwraps ISE's root key (e.g. EndPointGroup).
func (c *Client) ersGetByID(path, id, rootKey string) (map[string]any, error) {
	u := c.ersBase + path + "/" + url.PathEscape(id)
	b, err := c.do(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return unwrap(b, rootKey, u)
}

func unwrap(b []byte, rootKey, u string) (map[string]any, error) {
	var wrap map[string]json.RawMessage
	if err := json.Unmarshal(b, &wrap); err != nil {
		return nil, fmt.Errorf("GET %s: response is not a JSON object, received: %s", u, snippet(b))
	}
	raw, ok := wrap[rootKey]
	if !ok {
		keys := make([]string, 0, len(wrap))
		for k := range wrap {
			keys = append(keys, k)
		}
		return nil, fmt.Errorf("GET %s: expected root key %q, got keys %v in: %s", u, rootKey, keys, snippet(b))
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("GET %s: %q is not a JSON object, received: %s", u, rootKey, snippet(b))
	}
	return obj, nil
}

// ersGetAll fetches every stub's full object with a bounded worker pool.
// Results keep the stub order. The first failure aborts: a half-read family is
// worse than a failed one, because the missing objects would be invisible.
func (c *Client) ersGetAll(path, rootKey string, stubs []Stub) ([]map[string]any, error) {
	out := make([]map[string]any, len(stubs))
	jobs := make(chan int)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		firstEr error
	)
	for w := 0; w < detailWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				mu.Lock()
				stop := firstEr != nil
				mu.Unlock()
				if stop {
					continue
				}
				o, err := c.ersGetByID(path, stubs[i].ID, rootKey)
				mu.Lock()
				if err != nil && firstEr == nil {
					firstEr = err
				}
				out[i] = o
				mu.Unlock()
			}
		}()
	}
	for i := range stubs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if firstEr != nil {
		return nil, firstEr
	}
	return out, nil
}

// ersCreate POSTs one object. ISE wants it wrapped in its root key.
func (c *Client) ersCreate(path, rootKey string, obj map[string]any) error {
	u := c.ersBase + path
	_, err := c.do(http.MethodPost, u, map[string]any{rootKey: obj})
	return err
}

// openAPICreate POSTs an object directly to the OpenAPI (no root key wrapping).
func (c *Client) openAPICreate(path string, obj map[string]any) error {
	u := c.apiBase + path
	_, err := c.do(http.MethodPost, u, obj)
	return err
}

// ersPut updates an ERS object. ISE wants it wrapped in its root key.
func (c *Client) ersPut(path, rootKey string, obj map[string]any) error {
	u := c.ersBase + path
	_, err := c.do(http.MethodPut, u, map[string]any{rootKey: obj})
	return err
}

// errDuplicate marks a create that failed only because the object is already
// there. The target is a fresh standalone, so this is a skip, not a failure.
var errDuplicate = errors.New("already exists on the target")

func isDuplicate(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	if ae.Status != http.StatusBadRequest && ae.Status != http.StatusConflict {
		return false
	}
	b := strings.ToLower(ae.Body)
	return strings.Contains(b, "already exist") || strings.Contains(b, "duplicate") ||
		strings.Contains(b, "same name") || strings.Contains(b, "resource already")
}

// openAPIList reads an OpenAPI collection. The shape is not consistent across
// ISE's OpenAPI resources: some wrap the array in {"response": [...]}, some
// return the bare array. Both are accepted.
func (c *Client) openAPIList(path string) ([]map[string]any, error) {
	var out []map[string]any
	for page := 1; page <= 1000; page++ {
		u := fmt.Sprintf("%s%s?size=%d&page=%d", c.apiBase, path, pageSize, page)
		b, err := c.do(http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		items, err := decodeList(b)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", u, err)
		}
		out = append(out, items...)
		if len(items) < pageSize {
			return out, nil
		}
	}
	return nil, fmt.Errorf("GET %s%s: more than 1000 pages; refusing to keep paging", c.apiBase, path)
}

func decodeList(b []byte) ([]map[string]any, error) {
	t := bytes.TrimSpace(b)
	if len(t) > 0 && t[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(t, &arr); err != nil {
			return nil, fmt.Errorf("response is a JSON array but not of objects, received: %s", snippet(b))
		}
		return arr, nil
	}
	var w struct {
		Response []map[string]any `json:"response"`
	}
	if err := json.Unmarshal(t, &w); err != nil || w.Response == nil {
		return nil, fmt.Errorf("expected a JSON array or {\"response\": [...]}, received: %s", snippet(b))
	}
	return w.Response, nil
}

// --- capability probe --------------------------------------------------------

// Probe is what the operator sees before anything is read or written: which
// APIs answered, which version and nodes the deployment reports, and a plain
// sentence for every capability that is missing.
type Probe struct {
	Host      string   `json:"host"`
	Reachable bool     `json:"reachable"`
	ERS       bool     `json:"ers"`
	OpenAPI   bool     `json:"openapi"`
	Version   string   `json:"version"`
	Nodes     []string `json:"nodes"`
	Notes     []string `json:"notes"`
	VerifyTLS bool     `json:"verifyTls"`
}

// ProbeDeployment never fails as a whole: a missing capability is reported as a
// missing capability, with the reason, not as an aborted probe.
func (c *Client) ProbeDeployment() *Probe {
	p := &Probe{Host: c.Host, Nodes: []string{}, Notes: []string{}}

	version, ersErr := c.iseVersion()
	_, apiErr := c.do(http.MethodGet, c.apiBase+"/api/v1/endpoint?size=1&page=1", nil)

	p.ERS = ersErr == nil
	p.OpenAPI = apiErr == nil
	p.Version = version
	p.Reachable = p.ERS || p.OpenAPI || httpAnswered(ersErr) || httpAnswered(apiErr)

	if ersErr != nil {
		p.Notes = append(p.Notes, "ERS API (port 9060) unavailable: "+explainAPIError(ersErr, p.OpenAPI))
	}
	if apiErr != nil {
		p.Notes = append(p.Notes, "OpenAPI (port 443) unavailable: "+explainAPIError(apiErr, p.ERS))
	}
	if !p.Reachable {
		p.Notes = append(p.Notes, "Neither API answered at all. Check the hostname, that the node is up, and that ports 443 and 9060 are reachable from here.")
		return p
	}
	if p.ERS {
		nodes, err := c.ersList("/ers/config/node")
		if err != nil {
			p.Notes = append(p.Notes, "Could not read the node list: "+explainAPIError(err, true))
		} else {
			for _, n := range nodes {
				p.Nodes = append(p.Nodes, n.Name)
			}
		}
		if p.Version == "" {
			p.Notes = append(p.Notes, "ERS answered but did not report a version in the expected shape.")
		}
	}
	return p
}

func httpAnswered(err error) bool {
	var ae *APIError
	return err != nil && errors.As(err, &ae)
}

// explainAPIError turns a bare status code into something an operator can act
// on. A naked 401 is the worst possible message here, because "the API is
// switched off" and "you typed the password wrong" look identical from
// outside; otherAuthOK (did the *other* API accept the same credentials?) is
// what separates them.
func explainAPIError(err error, otherAuthOK bool) string {
	var ae *APIError
	if !errors.As(err, &ae) {
		return fmt.Sprintf("could not connect (%v). The API is probably not enabled, the hostname is wrong, or a firewall is in the way.", err)
	}
	switch ae.Status {
	case http.StatusUnauthorized:
		if otherAuthOK {
			return "HTTP 401, but the same credentials were accepted by the other API. Enable this API in Administration → System → Settings → API Settings and give the account the matching role (ERS Admin for ERS, API Admin for OpenAPI). ISE said: " + snippet([]byte(ae.Body))
		}
		return "HTTP 401. Either the username/password is wrong, or the API is disabled in Administration → System → Settings → API Settings. ISE said: " + snippet([]byte(ae.Body))
	case http.StatusForbidden:
		return "HTTP 403: the account authenticated but is not authorised. It needs the ERS Admin / API Admin role. ISE said: " + snippet([]byte(ae.Body))
	case http.StatusNotFound:
		return "HTTP 404: the endpoint does not exist on this deployment, which usually means the API is not enabled. ISE said: " + snippet([]byte(ae.Body))
	default:
		return ae.Error()
	}
}

// iseVersion reads the deployment version. It is reported to the operator and
// stored in the bundle for provenance; no behaviour is ever chosen from it.
func (c *Client) iseVersion() (string, error) {
	u := c.ersBase + "/ers/config/op/systemconfig/iseversion"
	b, err := c.do(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	var r struct {
		OperationResult struct {
			ResultValue []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"resultValue"`
		} `json:"OperationResult"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", nil // reachable, just not the documented shape
	}
	for _, kv := range r.OperationResult.ResultValue {
		if strings.EqualFold(kv.Name, "version") {
			return kv.Value, nil
		}
	}
	return "", nil
}
