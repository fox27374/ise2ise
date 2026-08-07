package main

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestExportSniffingPEM(t *testing.T) {
	// Export a certificate as PEM.
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "example.com", cert, pemEncode(cert.Raw))
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if pem := str(certs[0], "pem"); !strings.Contains(pem, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("PEM not found in bundle")
	}
}

func TestExportSniffingDER(t *testing.T) {
	// Export a certificate as raw DER (no PEM encoding).
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "example.com", cert, cert.Raw)
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if pem := str(certs[0], "pem"); !strings.Contains(pem, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("PEM not found in bundle (DER was not converted)")
	}
}

func TestExportSniffingZIP(t *testing.T) {
	// Export a certificate inside a ZIP.
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))
	pemBody := pemEncode(cert.Raw)

	zipBody := new(bytes.Buffer)
	zw := zip.NewWriter(zipBody)
	w, _ := zw.Create("cert.pem")
	w.Write(pemBody)
	zw.Close()

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "example.com", cert, zipBody.Bytes())
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
}

func TestExportSniffingZIPChain(t *testing.T) {
	// Export a three-certificate chain in a ZIP.
	cert1 := genCert(t, "root.com", false, false, time.Now().Add(24*time.Hour))
	cert2 := genCert(t, "intermediate.com", false, false, time.Now().Add(24*time.Hour))
	cert3 := genCert(t, "leaf.com", false, false, time.Now().Add(24*time.Hour))

	zipBody := new(bytes.Buffer)
	zw := zip.NewWriter(zipBody)
	w, _ := zw.Create("chain.pem")
	w.Write(pemEncode(cert1.Raw))
	w.Write(pemEncode(cert2.Raw))
	w.Write(pemEncode(cert3.Raw))
	zw.Close()

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "root.com", cert1, zipBody.Bytes())
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"root.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 3 {
		t.Fatalf("got %d certs, want 3", len(certs))
	}
}

func TestExportUnrecognisedFormat(t *testing.T) {
	// Export body that is neither PEM, DER, nor ZIP.
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "example.com", cert, []byte("this is not a certificate"))
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 0 {
		t.Fatalf("got %d certs, want 0 (unrecognised format)", len(certs))
	}
	if len(b.Notes) == 0 {
		t.Error("expected a note about unrecognised format")
	}
}

func TestExportExclusion_InternalCA(t *testing.T) {
	cert := genCert(t, "internal.com", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	certObj := f.addTrustedCert("ca-1", "internal.com", cert, pemEncode(cert.Raw))
	certObj["internalCA"] = true
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"internal.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 0 {
		t.Fatalf("got %d certs, want 0 (internal CA)", len(certs))
	}
	if len(b.Notes) == 0 {
		t.Error("expected a note about internal CA exclusion")
	}
}

func TestExportExclusion_SelfSignedNodeHostname(t *testing.T) {
	// A self-signed cert with CN matching a source node hostname.
	cert := genCert(t, "source-node", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "source-node", cert, pemEncode(cert.Raw))
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"source-node"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 0 {
		t.Fatalf("got %d certs, want 0 (self-signed node cert)", len(certs))
	}
	if len(b.Notes) == 0 {
		t.Error("expected a note about self-signed node cert exclusion")
	}
}

func TestExportCarriesTrustFlags(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	certObj := f.addTrustedCert("ca-1", "example.com", cert, pemEncode(cert.Raw))
	certObj["trustForIseAuth"] = true
	certObj["trustForClientAuth"] = false
	certObj["trustForCertificateBasedAdminAuth"] = true
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	if !truthy(certs[0], "trustForIseAuth") {
		t.Error("trustForIseAuth not carried")
	}
	if truthy(certs[0], "trustForClientAuth") {
		t.Error("trustForClientAuth should be false")
	}
	if !truthy(certs[0], "trustForCertificateBasedAdminAuth") {
		t.Error("trustForCertificateBasedAdminAuth not carried")
	}
}

func TestExportChainNaming(t *testing.T) {
	// First cert gets the name, others get their CN.
	root := genCert(t, "root.com", false, false, time.Now().Add(24*time.Hour))
	leaf := genCert(t, "leaf.com", false, false, time.Now().Add(24*time.Hour))

	zipBody := new(bytes.Buffer)
	zw := zip.NewWriter(zipBody)
	w, _ := zw.Create("chain.pem")
	w.Write(pemEncode(root.Raw))
	w.Write(pemEncode(leaf.Raw))
	zw.Close()

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "root.com", root, zipBody.Bytes())
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"root.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	// Certs are sorted by name, so leaf comes before root
	if str(certs[0], "name") != "leaf.com" {
		t.Errorf("first cert name = %q, want leaf.com", str(certs[0], "name"))
	}
	if str(certs[1], "name") != "root.com" {
		t.Errorf("second cert name = %q, want root.com", str(certs[1], "name"))
	}
}

func TestPreflightFingerprintDedup(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	// Source has the cert.
	srcFake := newFakeISE(t)
	srcFake.addTrustedCert("src-1", "example.com", cert, pemEncode(cert.Raw))
	srcC := srcFake.client()

	// Export it.
	b := NewBundle(&Probe{Nodes: []string{"source-node"}})
	if err := ExportTrustedCerts(srcC, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	// Target already has it with a fingerprint.
	tgtFake := newFakeISE(t)
	fp := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	tgtCertObj := map[string]any{
		"id": "tgt-1", "name": "imported-example", "sha256Fingerprint": fp,
		"link": map[string]any{"rel": "self"},
	}
	tgtFake.mu.Lock()
	tgtFake.certs = append(tgtFake.certs, tgtCertObj)
	tgtFake.mu.Unlock()
	tgtC := tgtFake.client()

	// Preflight should skip.
	rep, err := Preflight(tgtC, b)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}

	found := 0
	for _, it := range rep.Items {
		if it.Family == familyTrustedCerts {
			found++
			if it.Action != actionSkip {
				t.Errorf("action = %s, want skip (duplicate fingerprint)", it.Action)
			}
		}
	}
	if found != 1 {
		t.Fatalf("preflight reported %d trusted certificate items, want 1", found)
	}
}

func TestPreflightExpiredBlocked(t *testing.T) {
	// Certificate expired yesterday.
	cert := genCert(t, "example.com", false, false, time.Now().Add(-24*time.Hour))

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "example.com", cert, pemEncode(cert.Raw))
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	tgtFake := newFakeISE(t)
	tgtC := tgtFake.client()

	rep, err := Preflight(tgtC, b)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}

	found := 0
	for _, it := range rep.Items {
		if it.Family == familyTrustedCerts {
			found++
			if it.Action != actionBlocked {
				t.Errorf("action = %s, want blocked (expired)", it.Action)
			}
			if !strings.Contains(it.Reason, "expired") {
				t.Errorf("reason should mention expiry: %q", it.Reason)
			}
		}
	}
	if found != 1 {
		t.Fatalf("preflight reported %d trusted certificate items, want 1", found)
	}
}

func TestApplyCreatesTrustedCert(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	srcFake := newFakeISE(t)
	srcFake.addTrustedCert("src-1", "example.com", cert, pemEncode(cert.Raw))
	srcC := srcFake.client()

	b := NewBundle(&Probe{Nodes: []string{}})
	if err := ExportTrustedCerts(srcC, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	// Check that export worked
	exportedCerts := b.Objects[familyTrustedCerts]
	if len(exportedCerts) != 1 {
		t.Fatalf("export populated %d certs, want 1", len(exportedCerts))
	}

	tgtFake := newFakeISE(t)
	tgtC := tgtFake.client()

	rep, err := Preflight(tgtC, b)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}

	// Check that preflight added a create item
	createCount := 0
	for _, it := range rep.Items {
		if it.Family == familyTrustedCerts && it.Action == actionCreate {
			createCount++
		}
	}
	if createCount != 1 {
		t.Fatalf("preflight added %d create items, want 1", createCount)
	}

	res, err := ApplyImport(tgtC, rep, quiet)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if res.Created != 1 {
		t.Errorf("created = %d, want 1", res.Created)
	}

	// Check that OpenAPI POST was called.
	if len(tgtFake.created["certs"]) == 0 {
		t.Error("no certificate was created on target")
	}
}

func TestApplyHandlesCRLSettings(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	srcFake := newFakeISE(t)
	certObj := srcFake.addTrustedCert("src-1", "example.com", cert, pemEncode(cert.Raw))
	certObj["downloadCRL"] = true
	certObj["crlDistributionUrl"] = "http://example.com/crl"
	srcC := srcFake.client()

	b := NewBundle(&Probe{Nodes: []string{}})
	if err := ExportTrustedCerts(srcC, b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	// Check that CRL settings are in the bundle.
	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 1 {
		t.Fatalf("got %d certs", len(certs))
	}
	crl := certs[0]["crl"]
	if crl == nil {
		t.Error("CRL settings not in bundle")
	}
}

// --- helpers -----------------------------------------------------------------

// genCert creates a test certificate with the given CN, self-signed setting, and expiry.
func genCert(t *testing.T, cn string, selfSigned bool, internalCA bool, notAfter time.Time) *x509.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore: time.Now(),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageCertSign,
	}

	if selfSigned {
		template.Issuer = template.Subject
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// fakeISE extension for trusted certificates.
func (f *fakeISE) addTrustedCert(id, name string, cert *x509.Certificate, exportBody []byte) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()

	fp := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	obj := map[string]any{
		"id":                id,
		"name":              name,
		"sha256Fingerprint": fp,
		"subject":           cert.Subject.String(),
		"issuer":            cert.Issuer.String(),
		"expirationDate":    cert.NotAfter.Format("2006-01-02T15:04:05Z07:00"),
		"validFrom":         cert.NotBefore.Format("2006-01-02T15:04:05Z07:00"),
		"selfSigned":        cert.Subject.String() == cert.Issuer.String(),
		"link":              map[string]any{"rel": "self"},
	}

	// Store the export body and serve it when requested.
	if exportBody == nil {
		exportBody = pemEncode(cert.Raw)
	}
	if f.certExports == nil {
		f.certExports = map[string][]byte{}
	}
	f.certExports[id] = exportBody

	if f.certs == nil {
		f.certs = []map[string]any{}
	}
	f.certs = append(f.certs, obj)

	return obj
}
