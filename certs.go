package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// ISE paths for trusted certificates.
const (
	pathTrustedCertsAPI = "/api/v1/certs/trusted-certificate"
	pathTrustedCerts    = "/ers/config/trustedcertificate"
	rootTrustedCert     = "TrustedCertificate"
)

// --- export ------------------------------------------------------------------

// ExportTrustedCerts fills the bundle with trusted certificates that the
// operator selected.
func ExportTrustedCerts(c *Client, b *Bundle, families []string, certNames []string, log func(string, ...any)) error {
	if !slices.Contains(families, familyTrustedCerts) {
		return nil
	}

	log("Listing trusted certificates…")
	stubs, source, err := fetchTrustedCerts(c, log)
	if err != nil {
		return err
	}
	log("Found %d trusted certificates from %s; reading them…", len(stubs), source)
	b.Note("Trusted certificates were read from %s.", source)

	// Map stub name -> id for quick lookup.
	stubByName := map[string]string{}
	for _, s := range stubs {
		stubByName[s.Name] = s.ID
	}

	// Selected names -> source ids.
	selected := map[string]string{}
	for _, want := range certNames {
		if id, ok := stubByName[want]; ok {
			selected[want] = id
		} else {
			b.Note("Selected trusted certificate %q no longer exists on the source; skipped.", want)
		}
	}

	out := make([]map[string]any, 0, len(selected))
	nameSeen := map[string]bool{}
	for _, g := range b.Objects[familyEndpointGroups] {
		if name := str(g, "name"); name != "" {
			nameSeen[name] = true
		}
	}
	for _, ep := range b.Objects[familyEndpoints] {
		if name := str(ep, "mac"); name != "" {
			nameSeen[name] = true
		}
	}

	// Read the full metadata for each certificate.
	certs := make([]map[string]any, 0, len(selected))
	for certName, certID := range selected {
		cert, err := c.ersGetByID(pathTrustedCerts, certID, rootTrustedCert)
		if err != nil {
			b.Note("Could not read trusted certificate %q: %v", certName, err)
			continue
		}
		certs = append(certs, cert)
	}

	// Export the certificate bodies for each one selected.
	for _, cert := range certs {
		name := str(cert, "name")
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
		body, headers, err := c.doRaw(http.MethodGet, c.apiBase+pathTrustedCertsAPI+"/"+id+"/export", nil)
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

			// Name: first one uses the source name, others use CN or fingerprint.
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
			if isSelfSigned(parsedCert) && slices.Contains(b.Source.Nodes, parsedCert.Subject.CommonName) {
				b.Note("Trusted certificate %q is self-signed with CN matching a source node hostname; skipped.", name)
				continue
			}

			bundleObj["pem"] = string(pemEncode(parsedCert.Raw))
			bundleObj["fingerprint"] = fmt.Sprintf("%x", sha256.Sum256(parsedCert.Raw))
			bundleObj["notAfter"] = parsedCert.NotAfter.Format("2006-01-02T15:04:05Z07:00")
			bundleObj["subject"] = parsedCert.Subject.String()
			bundleObj["issuer"] = parsedCert.Issuer.String()

			// The four trustFor* flags and the allow*/validate* flags are already
			// in bundleObj, cloned from the source object, and travel verbatim.
			// ApplyImport picks the ones the import payload accepts.

			// Carry CRL settings if present.
			crlFields := []string{"downloadCRL", "crlDistributionUrl", "automaticCRLUpdate", "automaticCRLUpdatePeriod", "automaticCRLUpdateUnits", "crlDownloadFailureRetries", "nonAutomaticCRLUpdatePeriod", "ignoreCRLExpiration", "rejectIfNoStatusFromOCSP", "rejectIfUnreachableFromOCSP"}
			crlObj := make(map[string]any)
			for _, field := range crlFields {
				if v, ok := bundleObj[field]; ok {
					crlObj[field] = v
					delete(bundleObj, field)
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

// fetchTrustedCerts tries OpenAPI first, then falls back to ERS.
func fetchTrustedCerts(c *Client, log func(string, ...any)) ([]Stub, string, error) {
	log("Reading trusted certificates from the OpenAPI…")
	certs, err := c.openAPIList(pathTrustedCertsAPI)
	if err == nil {
		stubs := make([]Stub, 0, len(certs))
		for _, cert := range certs {
			stubs = append(stubs, Stub{ID: str(cert, "id"), Name: str(cert, "name")})
		}
		return stubs, "OpenAPI " + pathTrustedCertsAPI, nil
	}
	log("OpenAPI trusted certificate list unavailable (%v); falling back to ERS.", err)

	stubs, ersErr := c.ersList(pathTrustedCerts)
	if ersErr != nil {
		return nil, "", fmt.Errorf("could not read trusted certificates from either API. OpenAPI: %v. ERS: %w", err, ersErr)
	}
	return stubs, "ERS " + pathTrustedCerts, nil
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
func ListTrustedCerts(c *Client) ([]TrustedCertInfo, error) {
	stubs, _, err := fetchTrustedCerts(c, func(string, ...any) {})
	if err != nil {
		return nil, err
	}

	var result []TrustedCertInfo
	sourceNodes := []string{} // In real usage, this would come from a probe; for picker, we have no context.
	// The picker can't know the source nodes, so self-signed detection uses just the selfSigned field.

	for _, stub := range stubs {
		cert, err := c.ersGetByID(pathTrustedCerts, stub.ID, rootTrustedCert)
		if err != nil {
			continue // Skip on read error.
		}

		excluded := false
		reason := ""

		if truthy(cert, "internalCA") {
			excluded = true
			reason = "ISE internal CA"
		}

		// Self-signed check: try the field first, then fallback to string comparison.
		if !excluded && (truthy(cert, "selfSigned") || str(cert, "subject") == str(cert, "issuer")) {
			if slices.Contains(sourceNodes, str(cert, "subject")) {
				excluded = true
				reason = "Self-signed with CN matching a source node hostname"
			}
		}

		result = append(result, TrustedCertInfo{
			Name:          stub.Name,
			Subject:       str(cert, "subject"),
			Issuer:        str(cert, "issuer"),
			ExpiresAt:     str(cert, "expirationDate"),
			Excluded:      excluded,
			ExcludeReason: reason,
		})
	}

	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name) })
	return result, nil
}

// --- pre-flight and import ---------------------------------------------------

// These are called from endpoints.go's Preflight and ApplyImport, not as standalone exports.
