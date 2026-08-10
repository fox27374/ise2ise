package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ISE paths for trusted certificates.
const (
	pathTrustedCertsAPI = "/api/v1/certs/trusted-certificate"
)

// A trusted certificate's CRL settings, split by the type the OpenAPI PUT
// expects. ISE returns all of them as strings ("on"/"off", "5"), so the export
// converts and the import sends them back in the shape the PUT accepts.
var (
	crlBoolFields = []string{
		"downloadCRL", "automaticCRLUpdate", "ignoreCRLExpiration",
		"authenticateBeforeCRLReceived", "enableOCSPValidation",
		"enableServerIdentityCheck", "rejectIfNoStatusFromOCSP",
		"rejectIfUnreachableFromOCSP",
	}
	crlIntFields = []string{
		"automaticCRLUpdatePeriod", "nonAutomaticCRLUpdatePeriod",
		"crlDownloadFailureRetries",
	}
	// The four trust purposes, in the boolean form both writes use. ISE returns
	// them as the comma-separated `trustedFor` string instead.
	trustFlagFields = []string{
		"trustForIseAuth", "trustForClientAuth",
		"trustForCertificateBasedAdminAuth", "trustForCiscoServicesAuth",
	}

	// ISE refuses these on the PUT when downloadCRL is false. Verified on 3.4:
	// "can only be set true if downloadCRL parameter is set to be true".
	crlDownloadDependentFields = []string{
		"automaticCRLUpdate", "enableServerIdentityCheck",
		"authenticateBeforeCRLReceived", "ignoreCRLExpiration",
	}
	crlStringFields = []string{
		"crlDistributionUrl", "automaticCRLUpdateUnits",
		"nonAutomaticCRLUpdateUnits", "crlDownloadFailureRetriesUnits",
	}
)

// --- export ------------------------------------------------------------------

// ExportTrustedCerts fills the bundle with trusted certificates that the
// operator selected. It reads from the OpenAPI only; the ERS path does not
// exist for this family in ISE 3.4+.
func ExportTrustedCerts(c *Client, b *Bundle, families []string, certNames []string, log func(string, ...any)) error {
	if !slices.Contains(families, familyTrustedCerts) {
		return nil
	}

	log("Listing trusted certificates…")
	certs, err := c.openAPIList(pathTrustedCertsAPI)
	if err != nil {
		return fmt.Errorf("could not read trusted certificates from OpenAPI: %w", err)
	}

	log("Found %d trusted certificates; filtering selected…", len(certs))
	b.Note("Trusted certificates were read from OpenAPI %s.", pathTrustedCertsAPI)

	// Map friendlyName -> full cert object for quick lookup.
	certByName := map[string]map[string]any{}
	for _, cert := range certs {
		if friendlyName := str(cert, "friendlyName"); friendlyName != "" {
			certByName[friendlyName] = cert
		}
	}

	// Selected names -> cert objects.
	selected := []map[string]any{}
	for _, want := range certNames {
		if cert, ok := certByName[want]; ok {
			selected = append(selected, cert)
		} else {
			b.Note("Selected trusted certificate %q no longer exists on the source; skipped.", want)
		}
	}

	out := make([]map[string]any, 0, len(selected))
	nameSeen := map[string]bool{}

	// Export the certificate bodies for each one selected.
	for _, cert := range selected {
		name := str(cert, "friendlyName")
		id := str(cert, "id")
		if id == "" {
			b.Note("Trusted certificate %q has no id; skipped.", name)
			continue
		}
		if truthy(cert, "internalCA") {
			b.Note("Trusted certificate %q is ISE internal CA; skipped.", name)
			continue
		}

		// Fetch the exported body.
		body, headers, err := c.doRaw(http.MethodGet, c.apiBase+pathTrustedCertsAPI+"/export/"+id, nil)
		if err != nil {
			b.Note("Could not export trusted certificate %q: %v", name, err)
			continue
		}

		// Sniff the body and extract certificates.
		contentType := headers.Get("Content-Type")
		chainCerts, notes := extractCertificates(body, contentType)
		b.Notes = append(b.Notes, notes...)

		if len(chainCerts) == 0 {
			b.Note("Trusted certificate %q export returned no parseable certificates; skipped.", name)
			continue
		}

		// The first certificate is the one named; others are named from their CN or fingerprint.
		for i, parsedCert := range chainCerts {
			bundleObj := maps.Clone(cert)
			delete(bundleObj, "id")
			stripLinks(bundleObj)
			// Remove fields from the read response that are not needed.
			delete(bundleObj, "link")

			// Name: first one uses the source friendlyName, others use CN or fingerprint.
			if i == 0 {
				bundleObj["name"] = name
			} else {
				cn := parsedCert.Subject.CommonName
				if cn == "" || nameSeen[cn] || nameExistsInBundle(cn, out) {
					// No CN, collision, or already in bundle: append fingerprint.
					fp := fmt.Sprintf("%x", sha256.Sum256(parsedCert.Raw))
					cn = fp[:8]
				}
				bundleObj["name"] = cn
				nameSeen[cn] = true
			}

			// Check for self-signed + CN in source nodes.
			if isSelfSigned(parsedCert) && isNodeHostname(parsedCert.Subject.CommonName, b.Source.Nodes) {
				b.Note("Trusted certificate %q is self-signed with CN matching a source node hostname; skipped.", name)
				continue
			}

			bundleObj["pem"] = string(pemEncode(parsedCert.Raw))
			bundleObj["fingerprint"] = fmt.Sprintf("%x", sha256.Sum256(parsedCert.Raw))
			bundleObj["notAfter"] = parsedCert.NotAfter.Format("2006-01-02T15:04:05Z07:00")
			bundleObj["subject"] = parsedCert.Subject.String()
			bundleObj["issuer"] = parsedCert.Issuer.String()

			// Parse trustedFor string into the four trust booleans.
			// trustedFor is a comma-separated string like "Infrastructure,Endpoints".
			trustedForStr := str(cert, "trustedFor")
			if trustedForStr != "" {
				bundleObj["trustForIseAuth"] = false
				bundleObj["trustForClientAuth"] = false
				bundleObj["trustForCiscoServicesAuth"] = false
				bundleObj["trustForCertificateBasedAdminAuth"] = false
				for _, token := range strings.Split(trustedForStr, ",") {
					token = strings.TrimSpace(token)
					switch strings.ToLower(token) {
					case "infrastructure":
						bundleObj["trustForIseAuth"] = true
					case "endpoints":
						bundleObj["trustForClientAuth"] = true
					case "cisco services":
						bundleObj["trustForCiscoServicesAuth"] = true
					case "adminauth":
						bundleObj["trustForCertificateBasedAdminAuth"] = true
					default:
						if token != "" {
							b.Note("Trusted certificate %q: unrecognised trustedFor token %q", name, token)
						}
					}
				}
			}
			delete(bundleObj, "trustedFor")

			// The read side and the write side disagree about types: ISE returns
			// "on"/"off" and stringified integers, and the PUT wants booleans and
			// integers. Normalise once, here, so the import can send the bundle's
			// values straight back. Verified against 3.4.
			crlObj := make(map[string]any)
			for _, field := range crlBoolFields {
				v, ok := bundleObj[field]
				delete(bundleObj, field)
				if !ok || v == nil {
					continue
				}
				switch t := v.(type) {
				case bool:
					crlObj[field] = t
				case string:
					switch strings.ToLower(strings.TrimSpace(t)) {
					case "on", "true", "enabled":
						crlObj[field] = true
					case "off", "false", "disabled":
						crlObj[field] = false
					default:
						b.Note("Trusted certificate %q: CRL setting %q reads %q, which is neither on nor off; it was not carried.", name, field, t)
					}
				default:
					b.Note("Trusted certificate %q: CRL setting %q reads %v (%T), not a switch; it was not carried.", name, field, v, v)
				}
			}
			for _, field := range crlIntFields {
				v, ok := bundleObj[field]
				delete(bundleObj, field)
				if !ok || v == nil {
					continue
				}
				switch t := v.(type) {
				case float64: // JSON numbers decode as float64
					crlObj[field] = int(t)
				case string:
					n, err := strconv.Atoi(strings.TrimSpace(t))
					if err != nil {
						b.Note("Trusted certificate %q: CRL setting %q reads %q, which is not a number; it was not carried.", name, field, t)
						continue
					}
					crlObj[field] = n
				default:
					b.Note("Trusted certificate %q: CRL setting %q reads %v (%T), not a number; it was not carried.", name, field, v, v)
				}
			}
			// Units and the distribution URL are free-form strings on both sides
			// and travel unchanged.
			for _, field := range crlStringFields {
				v, ok := bundleObj[field]
				delete(bundleObj, field)
				if s, isStr := v.(string); ok && isStr && s != "" {
					crlObj[field] = s
				}
			}
			if len(crlObj) > 0 {
				bundleObj["crl"] = crlObj
			}

			// Note if OCSP service was configured.
			if ocsp := str(cert, "selectedOCSPService"); ocsp != "" {
				b.Note("Trusted certificate %q has selectedOCSPService=%q; this must be re-selected by hand.", name, ocsp)
			}

			out = append(out, bundleObj)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(str(out[i], "name")) < strings.ToLower(str(out[j], "name"))
	})
	b.Objects[familyTrustedCerts] = out
	log("Captured %d trusted certificates.", len(out))
	return nil
}

// fetchTrustedCertsOpenAPI reads the full certificate objects from the OpenAPI.
// The shape already has everything needed; no second read is necessary.
func fetchTrustedCertsOpenAPI(c *Client) ([]map[string]any, error) {
	return c.openAPIList(pathTrustedCertsAPI)
}

// fetchTrustedCerts is a compatibility wrapper for code that needs stubs (id + friendlyName).
// It calls the OpenAPI and extracts the minimal fields.
func fetchTrustedCerts(c *Client, log func(string, ...any)) ([]Stub, string, error) {
	certs, err := fetchTrustedCertsOpenAPI(c)
	if err != nil {
		return nil, "", fmt.Errorf("could not read trusted certificates from OpenAPI %s: %w", pathTrustedCertsAPI, err)
	}
	stubs := make([]Stub, 0, len(certs))
	for _, cert := range certs {
		stubs = append(stubs, Stub{ID: str(cert, "id"), Name: str(cert, "friendlyName")})
	}
	return stubs, "OpenAPI " + pathTrustedCertsAPI, nil
}

// extractCertificates sniffs the body and extracts certificates, handling PEM, DER, and ZIP.
func extractCertificates(body []byte, contentType string) ([]*x509.Certificate, []string) {
	var notes []string
	var certs []*x509.Certificate

	// Try PEM first.
	if bytes.HasPrefix(body, []byte("-----BEGIN")) {
		for {
			block, rest := pem.Decode(body)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					certs = append(certs, cert)
				}
			}
			body = rest
		}
		if len(certs) > 0 {
			return certs, notes
		}
	}

	// Try DER.
	if len(body) > 0 && body[0] == 0x30 {
		if cert, err := x509.ParseCertificate(body); err == nil {
			return []*x509.Certificate{cert}, notes
		}
	}

	// Try ZIP.
	if len(body) > 4 && body[0] == 0x50 && body[1] == 0x4b && body[2] == 0x03 && body[3] == 0x04 {
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err == nil {
			for _, f := range zr.File {
				rc, err := f.Open()
				if err != nil {
					notes = append(notes, fmt.Sprintf("ZIP entry %q: could not open", f.Name))
					continue
				}
				entryBody, _ := io.ReadAll(rc)
				rc.Close()

				// Try PEM in ZIP entry.
				if bytes.HasPrefix(entryBody, []byte("-----BEGIN")) {
					for {
						block, rest := pem.Decode(entryBody)
						if block == nil {
							break
						}
						if block.Type == "CERTIFICATE" {
							if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
								certs = append(certs, cert)
							}
						}
						entryBody = rest
					}
					continue
				}

				// Try DER in ZIP entry.
				if len(entryBody) > 0 && entryBody[0] == 0x30 {
					if cert, err := x509.ParseCertificate(entryBody); err == nil {
						certs = append(certs, cert)
						continue
					}
				}

				// Neither PEM nor DER; skip with a note.
				leading := entryBody
				if len(leading) > 8 {
					leading = leading[:8]
				}
				notes = append(notes, fmt.Sprintf("ZIP entry %q is neither PEM nor DER (starts with %x); skipped.", f.Name, leading))
			}
			if len(certs) > 0 {
				return certs, notes
			}
		}
	}

	// Unrecognized format.
	leading := body
	if len(leading) > 8 {
		leading = leading[:8]
	}
	notes = append(notes, fmt.Sprintf("Trusted certificate export is unrecognised format (Content-Type: %q, starts with %x); skipped.", contentType, leading))
	return nil, notes
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// isNodeHostname reports whether host is one of the deployment's nodes. ISE
// names a node by its short hostname in /ers/config/node ("ibk-sda-ise1") but
// issues its default server certificate to the FQDN
// ("ibk-sda-ise1.ntslab.loc"), so an exact comparison never matches and the
// per-node certificates end up offered for export. Verified on 3.4.
func isNodeHostname(host string, nodes []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	short, _, _ := strings.Cut(host, ".")
	for _, n := range nodes {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if host == n || short == n {
			return true
		}
		if nShort, _, _ := strings.Cut(n, "."); nShort != "" && nShort == short {
			return true
		}
	}
	return false
}

func pemEncode(der []byte) []byte {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	return buf.Bytes()
}

func nameExistsInBundle(name string, objs []map[string]any) bool {
	for _, o := range objs {
		if str(o, "name") == name {
			return true
		}
	}
	return false
}

// TrustedCertInfo is what the picker endpoint returns.
type TrustedCertInfo struct {
	Name          string `json:"name"`
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	ExpiresAt     string `json:"expiresAt"`
	Excluded      bool   `json:"excluded"`
	ExcludeReason string `json:"excludeReason,omitempty"`
}

// ListTrustedCerts lists all trusted certificates from the source, computing exclusion reasons.
// It fetches the source nodes from /ers/config/node to identify self-signed node certificates.
func ListTrustedCerts(c *Client) ([]TrustedCertInfo, error) {
	// Get full certificate objects from the OpenAPI.
	certs, err := fetchTrustedCertsOpenAPI(c)
	if err != nil {
		return nil, err
	}

	// Get source node hostnames to detect self-signed node certificates.
	sourceNodes := []string{}
	if nodes, err := c.ersList("/ers/config/node"); err == nil {
		for _, node := range nodes {
			sourceNodes = append(sourceNodes, node.Name)
		}
	}

	var result []TrustedCertInfo
	for _, cert := range certs {
		friendlyName := str(cert, "friendlyName")
		if friendlyName == "" {
			continue // Skip certs without a name.
		}

		excluded := false
		reason := ""

		if truthy(cert, "internalCA") {
			excluded = true
			reason = "ISE internal CA"
		}

		// Self-signed check: issuedTo == issuedBy combined with node hostname check.
		if !excluded && str(cert, "issuedTo") == str(cert, "issuedBy") {
			if isNodeHostname(str(cert, "issuedTo"), sourceNodes) {
				excluded = true
				reason = "Self-signed with CN matching a source node hostname"
			}
		}

		// Parse expirationDate from Java format if possible; pass raw if parsing fails.
		expiresAt := str(cert, "expirationDate")
		if expiresAt != "" {
			// Try parsing Java format: "Mon Aug 04 09:14:23 CEST 2036"
			if parsed, err := time.Parse("Mon Jan 02 15:04:05 MST 2006", expiresAt); err == nil {
				expiresAt = parsed.Format("2006-01-02T15:04:05Z07:00")
			}
			// If parsing fails, pass the raw string through.
		}

		result = append(result, TrustedCertInfo{
			Name:          friendlyName,
			Subject:       str(cert, "subject"),
			Issuer:        str(cert, "issuer"),
			ExpiresAt:     expiresAt,
			Excluded:      excluded,
			ExcludeReason: reason,
		})
	}

	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name) })
	return result, nil
}

// certPassword derives the password ISE encrypts an exported private key with.
// ISE requires alphanumeric, 8–100 characters; the bundle passphrase rule is 12
// characters of anything, so it cannot be handed over verbatim. base32 of a
// SHA-256 over a fixed label and the passphrase is alphanumeric by construction
// and identical on both sides.
func certPassword(passphrase string) string {
	const label = "ise2ise system certificate v1"
	hash := sha256.Sum256([]byte(label + passphrase))
	// base32.StdEncoding with padding stripped, truncated to 32 chars
	b32 := base32.StdEncoding.EncodeToString(hash[:])
	b32 = strings.TrimRight(b32, "=")
	if len(b32) > 32 {
		return b32[:32]
	}
	return b32
}

// SystemCertInfo is what the picker endpoint returns for system certificates.
type SystemCertInfo struct {
	Fingerprint        string   `json:"fingerprint"`
	Name               string   `json:"name"`
	Node               string   `json:"node"`
	Nodes              []string `json:"nodes"`
	Subject            string   `json:"subject"`
	SANs               []string `json:"sans"`
	KeySize            int      `json:"keySize"`
	UsedBy             string   `json:"usedBy"`
	Roles              []string `json:"roles"`
	GroupTag           string   `json:"groupTag"`
	PortalsUsingTheTag []string `json:"portalsUsingTheTag"`
	ExpiresAt          string   `json:"expiresAt"`
	SelfSigned         bool     `json:"selfSigned"`
	Ticked             bool     `json:"ticked"`
	Disabled           bool     `json:"disabled"`
	Reason             string   `json:"reason,omitempty"`
}

// ListSystemCerts lists all system certificates from the source, grouped by fingerprint.
// It fetches from /api/v1/certs/system-certificate/{hostName} per node.
func ListSystemCerts(c *Client) ([]SystemCertInfo, error) {
	// Fetch all Admin-persona nodes from /api/v1/deployment/node
	nodes, err := c.openAPIList(pathDeploymentNode)
	if err != nil {
		return nil, fmt.Errorf("could not read deployment nodes: %w", err)
	}

	adminNodes := []string{}
	for _, node := range nodes {
		roles, _ := node["roles"].([]any)
		for _, role := range roles {
			if rs, _ := role.(string); strings.Contains(rs, "Admin") {
				if hostName := str(node, "hostname"); hostName != "" {
					adminNodes = append(adminNodes, hostName)
				}
				break
			}
		}
	}

	// If no Admin nodes found, try to use node names from earlier reads
	if len(adminNodes) == 0 {
		// Fallback: use ERS node names, but mark this as incomplete
		if stubs, err := c.ersList("/ers/config/node"); err == nil {
			for _, stub := range stubs {
				adminNodes = append(adminNodes, stub.Name)
			}
		}
	}

	// Deduplicate by fingerprint, collecting which nodes hold each cert
	byFingerprint := map[string]*SystemCertInfo{}
	firstNodeByFP := map[string]string{}

	for _, hostName := range adminNodes {
		certs, err := c.openAPIList(fmt.Sprintf("%s/%s", pathSystemCertsAPI, hostName))
		if err != nil {
			// One node's failure does not stop reading others
			continue
		}

		for _, cert := range certs {
			fp := str(cert, "sha256Fingerprint")
			// Normalize fingerprint: lowercase, strip whitespace and colons
			fp = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fp, ":", ""), " ", ""))
			if fp == "" {
				continue
			}

			if _, seen := byFingerprint[fp]; !seen {
				// First sighting: fetch the certificate body to parse details
				id := str(cert, "id")
				if id == "" {
					continue
				}

				// Export with CERTIFICATE only (no private key, no password)
				// POST to /api/v1/certs/system-certificate/export with {id, hostName, export}
				body, err := c.do(http.MethodPost, c.apiBase+pathSystemCertsAPI+"/export", map[string]any{
					"id":       id,
					"hostName": hostName,
					"export":   "CERTIFICATE",
				})
				if err != nil {
					continue
				}

				// The export answers a ZIP holding one .pem, not bare PEM — the
				// same shape the with-key export uses. Sniffing covers all three
				// forms, and reading this wrong is invisible: the row simply
				// loses its SANs and reads as single-name, which is how a
				// multi-SAN certificate ends up unticked.
				var parsedCert *x509.Certificate
				if found, _ := extractCertificates(body, ""); len(found) > 0 {
					parsedCert = found[0]
				}

				// Build the info object
				info := &SystemCertInfo{
					Fingerprint:        fp,
					Name:               str(cert, "friendlyName"),
					Node:               hostName,
					Nodes:              []string{hostName},
					Subject:            str(cert, "issuedTo"),
					KeySize:            int(numField(cert, "keySize")),
					GroupTag:           str(cert, "groupTag"),
					PortalsUsingTheTag: parseStringArray(cert, "portalsUsingTheTag"),
					ExpiresAt:          formatJavaDate(str(cert, "expirationDate")),
					SelfSigned:         truthy(cert, "selfSigned"),
					Ticked:             false, // Set below based on rules
					Disabled:           false, // Set below based on expiry
					Roles:              parseRoles(str(cert, "usedBy")),
				}

				// Extract SANs and full subject from certificate if parsed
				if parsedCert != nil {
					info.Subject = parsedCert.Subject.String()
					for _, san := range parsedCert.DNSNames {
						info.SANs = append(info.SANs, san)
					}
					for _, ip := range parsedCert.IPAddresses {
						info.SANs = append(info.SANs, ip.String())
					}
				}

				// Apply ticking rules
				if info.SelfSigned {
					info.Ticked = false
					info.Reason = "Self-signed"
				} else if isWildcardOrMultiSAN(info) {
					info.Ticked = true
				} else if info.KeySize == 0 {
					info.Ticked = false
					info.Reason = "Unknown key size"
				} else {
					info.Ticked = false
					info.Reason = "Single-name certificate"
				}

				// Check expiry
				if info.ExpiresAt != "" {
					if exp, err := time.Parse(time.RFC3339, info.ExpiresAt); err == nil && exp.Before(time.Now()) {
						info.Disabled = true
						info.Reason = fmt.Sprintf("Expired on %s", exp.Format("2006-01-02"))
					}
				}

				byFingerprint[fp] = info
				firstNodeByFP[fp] = hostName
			} else {
				// Additional node with same fingerprint: record it
				if info := byFingerprint[fp]; hostName != firstNodeByFP[fp] {
					info.Nodes = append(info.Nodes, hostName)
				}
			}
		}
	}

	result := make([]SystemCertInfo, 0, len(byFingerprint))
	for _, info := range byFingerprint {
		result = append(result, *info)
	}

	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result, nil
}

func numField(obj map[string]any, key string) float64 {
	switch v := obj[key].(type) {
	case float64:
		return v
	case string:
		if f, _ := strconv.ParseFloat(v, 64); f > 0 {
			return f
		}
	}
	return 0
}

func parseStringArray(obj map[string]any, key string) []string {
	switch v := obj[key].(type) {
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, _ := item.(string); s != "" {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return v
	}
	return nil
}

func formatJavaDate(javaDate string) string {
	if javaDate == "" {
		return ""
	}
	// Try parsing Java Date.toString() format: "Mon Aug 04 09:14:23 CEST 2036"
	if parsed, err := time.Parse("Mon Jan 02 15:04:05 MST 2006", javaDate); err == nil {
		return parsed.Format(time.RFC3339)
	}
	// Return raw if parsing fails
	return javaDate
}

func parseRoles(usedBy string) []string {
	if usedBy == "" {
		return nil
	}
	roles := []string{}
	for _, part := range strings.Split(usedBy, ",") {
		role := strings.TrimSpace(part)
		if role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}

func isWildcardOrMultiSAN(info *SystemCertInfo) bool {
	cn := extractCN(info.Subject)
	if strings.HasPrefix(cn, "*.") {
		return true
	}
	dnsCount := 0
	for _, san := range info.SANs {
		if !strings.Contains(san, ".") || strings.Contains(san, ":") {
			continue // Skip IPs
		}
		dnsCount++
	}
	return dnsCount > 1
}

func extractCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return ""
}

// ExportSystemCerts fills the bundle with system certificates selected by fingerprint.
// It reads from the OpenAPI and handles both API exports (with password) and ZIP imports.
func ExportSystemCerts(c *Client, b *Bundle, families []string, fingerprints []string, passphrase string, zips []map[string]any, zipPassword string, log func(string, ...any)) error {
	if !slices.Contains(families, familySystemCerts) {
		return nil
	}

	// Map fingerprints to retrieve: normalize them
	wantFP := map[string]bool{}
	for _, fp := range fingerprints {
		normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fp, ":", ""), " ", ""))
		wantFP[normalized] = true
	}

	log("Listing system certificates…")
	certs, err := ListSystemCerts(c)
	if err != nil {
		return fmt.Errorf("could not read system certificates: %w", err)
	}

	log("Found %d system certificates; filtering selected…", len(certs))
	b.Note("System certificates were read from OpenAPI %s.", pathSystemCertsAPI)

	// Fetch full cert objects from each node for lookup by fingerprint
	certsByNode := map[string][]map[string]any{}
	for _, cert := range certs {
		for _, node := range cert.Nodes {
			if _, ok := certsByNode[node]; !ok {
				if nodeList, _ := c.openAPIList(fmt.Sprintf("%s/%s", pathSystemCertsAPI, node)); nodeList != nil {
					certsByNode[node] = nodeList
				}
			}
		}
	}

	out := make([]map[string]any, 0, len(certs))
	for _, cert := range certs {
		if !wantFP[cert.Fingerprint] {
			continue
		}

		// Find the full cert object on the primary node
		var certObj map[string]any
		nodeList := certsByNode[cert.Node]
		for _, obj := range nodeList {
			if str(obj, "sha256Fingerprint") == cert.Fingerprint {
				certObj = obj
				break
			}
		}

		if certObj == nil {
			b.Note("System certificate %q not found on node %s; skipped.", cert.Name, cert.Node)
			continue
		}

		id := str(certObj, "id")
		if id == "" {
			b.Note("System certificate %q has no id; skipped.", cert.Name)
			continue
		}

		// Export with CERTIFICATE_WITH_PRIVATE_KEY and the derived password
		body, err := c.do(http.MethodPost, c.apiBase+pathSystemCertsAPI+"/export", map[string]any{
			"id":       id,
			"hostName": cert.Node,
			"export":   "CERTIFICATE_WITH_PRIVATE_KEY",
			"password": certPassword(passphrase),
		})
		if err != nil {
			b.Note("Could not export system certificate %q: %v", cert.Name, err)
			continue
		}

		// Walk the ZIP: parse entry as certificate = pem, entry that doesn't parse = .pvk
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			b.Note("System certificate %q export is not a valid ZIP: %v", cert.Name, err)
			continue
		}

		var pemData, keyBlob string
		for _, f := range zr.File {
			rc, _ := f.Open()
			entryBody, _ := io.ReadAll(rc)
			rc.Close()

			// Try to parse as certificate
			if bytes.HasPrefix(entryBody, []byte("-----BEGIN")) {
				block, _ := pem.Decode(entryBody)
				if block != nil && block.Type == "CERTIFICATE" {
					pemData = string(entryBody)
					continue
				}
			}

			// If not certificate, treat as private key
			if strings.Contains(string(entryBody), "ENCRYPTED PRIVATE KEY") {
				keyBlob = string(entryBody)
			}
		}

		if pemData == "" {
			b.Note("System certificate %q export has no .pem entry; skipped.", cert.Name)
			continue
		}
		if keyBlob == "" {
			b.Note("System certificate %q export has no .pvk entry; skipped.", cert.Name)
			continue
		}

		bundleObj := map[string]any{
			"name":           cert.Name,
			"pem":            pemData,
			"keyBlob":        keyBlob,
			"keySource":      "api",
			"fingerprint":    cert.Fingerprint,
			"notAfter":       cert.ExpiresAt,
			"subject":        cert.Subject,
			"issuer":         "",
			"selfSigned":     cert.SelfSigned,
			"keySize":        cert.KeySize,
			"sans":           cert.SANs,
			"portalGroupTag": cert.GroupTag,
			"sourceNode":     cert.Node,
			"admin":          false,
			"eap":            slices.Contains(cert.Roles, "EAP Authentication"),
			"radius":         slices.Contains(cert.Roles, "RADIUS DTLS") || slices.Contains(cert.Roles, "RADSec"),
			"tacacs":         slices.Contains(cert.Roles, "TACACS"),
			"pxgrid":         slices.Contains(cert.Roles, "pxGrid"),
			"ims":            slices.Contains(cert.Roles, "ISE Messaging Service"),
			"saml":           slices.Contains(cert.Roles, "SAML"),
			"portal":         slices.Contains(cert.Roles, "Portal"),
		}

		out = append(out, bundleObj)
	}

	// Handle ZIP imports from 3.2 GUI path
	for _, zipInfo := range zips {
		// User selected roles from UI; keep name as-is
		// keySource: "zip", no re-encryption
		bundleObj := map[string]any{
			"name":           str(zipInfo, "name"),
			"pem":            str(zipInfo, "pem"),
			"keyBlob":        str(zipInfo, "keyBlob"),
			"keySource":      "zip",
			"fingerprint":    str(zipInfo, "fingerprint"),
			"notAfter":       str(zipInfo, "expiresAt"),
			"subject":        str(zipInfo, "subject"),
			"issuer":         "",
			"selfSigned":     zipInfo["selfSigned"],
			"keySize":        zipInfo["keySize"],
			"sans":           zipInfo["sans"],
			"portalGroupTag": "",
			"sourceNode":     "",
			"admin":          false,
			"eap":            truthy(zipInfo, "eap"),
			"radius":         truthy(zipInfo, "radius"),
			"tacacs":         truthy(zipInfo, "tacacs"),
			"pxgrid":         truthy(zipInfo, "pxgrid"),
			"ims":            truthy(zipInfo, "ims"),
			"saml":           truthy(zipInfo, "saml"),
			"portal":         truthy(zipInfo, "portal"),
		}
		out = append(out, bundleObj)
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(str(out[i], "name")) < strings.ToLower(str(out[j], "name"))
	})
	b.Objects[familySystemCerts] = out
	log("Captured %d system certificates.", len(out))
	return nil
}

// --- pre-flight and import ---------------------------------------------------

// These are called from endpoints.go's Preflight and ApplyImport, not as standalone exports.
