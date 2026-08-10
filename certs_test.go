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

// Real ISE names a node by its short hostname in /ers/config/node but issues
// its default server certificate to the FQDN, so an exact comparison never
// matches and the per-node certificates get offered for export. Observed on
// 3.4: node "ibk-sda-ise1", certificate CN "ibk-sda-ise1.ntslab.loc".
func TestExportExclusion_SelfSignedNodeFQDN(t *testing.T) {
	cert := genCert(t, "ibk-sda-ise1.ntslab.loc", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	f.addTrustedCert("ca-1", "ibk-sda-ise1.ntslab.loc", cert, pemEncode(cert.Raw))
	c := f.client()

	b := NewBundle(&Probe{Nodes: []string{"ibk-sda-ise1"}})
	if err := ExportTrustedCerts(c, b, []string{familyTrustedCerts}, []string{"ibk-sda-ise1.ntslab.loc"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	if got := len(b.Objects[familyTrustedCerts]); got != 0 {
		t.Fatalf("got %d certs, want 0: a node's own FQDN certificate must not travel", got)
	}
}

func TestIsNodeHostname(t *testing.T) {
	nodes := []string{"ibk-sda-ise1"}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"ibk-sda-ise1.ntslab.loc", true},
		{"ibk-sda-ise1", true},
		{"IBK-SDA-ISE1.NTSLAB.LOC", true},
		{"ibk-sda-ise2.ntslab.loc", false},
		{"ca.example.com", false},
		{"", false},
	} {
		if got := isNodeHostname(tc.host, nodes); got != tc.want {
			t.Errorf("isNodeHostname(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestExportCarriesTrustFlags(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	certObj := f.addTrustedCert("ca-1", "example.com", cert, pemEncode(cert.Raw))
	// In real ISE 3.4, trust flags come in a single trustedFor comma-separated string.
	// Set it to test parsing of different combinations.
	certObj["trustedFor"] = "Infrastructure,AdminAuth"
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
	// Renamed on the target, which is the case fingerprint matching exists for:
	// a real 3.4 target answered exactly this way after the certificate was
	// renamed in its GUI.
	tgtCertObj := map[string]any{
		"id": "tgt-1", "name": "imported-example", "friendlyName": "imported-example",
		"sha256Fingerprint": fp,
		"link":              map[string]any{"rel": "self"},
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
			if !strings.Contains(it.Reason, `"imported-example"`) {
				t.Errorf("reason = %q, want the target's own name for the certificate", it.Reason)
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

	res, err := ApplyImport(tgtC, rep, "test-passphrase-1234567890", map[string]bool{}, false, quiet)
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

// ISE 3.4 returns CRL settings as "on"/"off" and stringified integers, while
// the OpenAPI PUT that writes them back wants booleans and integers. Observed
// values, straight off the lab.
func TestExportNormalisesCRLTypes(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	f := newFakeISE(t)
	certObj := f.addTrustedCert("src-1", "example.com", cert, pemEncode(cert.Raw))
	certObj["downloadCRL"] = "on"
	certObj["ignoreCRLExpiration"] = "off"
	certObj["automaticCRLUpdatePeriod"] = "5"
	certObj["automaticCRLUpdateUnits"] = "Minutes"
	certObj["crlDistributionUrl"] = "http://crl.example.com/test.crl"

	b := NewBundle(&Probe{Nodes: []string{}})
	if err := ExportTrustedCerts(f.client(), b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}
	certs := b.Objects[familyTrustedCerts]
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	crl, ok := certs[0]["crl"].(map[string]any)
	if !ok {
		t.Fatalf("crl is %T, want map", certs[0]["crl"])
	}
	if crl["downloadCRL"] != true {
		t.Errorf(`downloadCRL = %v (%T), want true`, crl["downloadCRL"], crl["downloadCRL"])
	}
	if crl["ignoreCRLExpiration"] != false {
		t.Errorf(`ignoreCRLExpiration = %v (%T), want false`, crl["ignoreCRLExpiration"], crl["ignoreCRLExpiration"])
	}
	if crl["automaticCRLUpdatePeriod"] != 5 {
		t.Errorf(`automaticCRLUpdatePeriod = %v (%T), want int 5`, crl["automaticCRLUpdatePeriod"], crl["automaticCRLUpdatePeriod"])
	}
	if crl["automaticCRLUpdateUnits"] != "Minutes" {
		t.Errorf(`automaticCRLUpdateUnits = %v, want "Minutes" carried through`, crl["automaticCRLUpdateUnits"])
	}
	if crl["crlDistributionUrl"] != "http://crl.example.com/test.crl" {
		t.Errorf("crlDistributionUrl = %v", crl["crlDistributionUrl"])
	}
	for _, n := range b.Notes {
		if strings.Contains(n, "automaticCRLUpdateUnits") {
			t.Errorf("units field wrongly reported as unexpected: %s", n)
		}
	}
}

// A source certificate with CRL download off but automatic update on is the
// normal factory state, and sending it back verbatim makes ISE 3.4 reject the
// entire PUT. The dependent flags must be forced false so the rest of the
// settings still land.
func TestApplyCRLDependentFlagsWithDownloadOff(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	srcFake := newFakeISE(t)
	certObj := srcFake.addTrustedCert("src-1", "example.com", cert, pemEncode(cert.Raw))
	certObj["downloadCRL"] = "off"
	certObj["automaticCRLUpdate"] = "on"
	certObj["ignoreCRLExpiration"] = "on"
	certObj["crlDistributionUrl"] = "http://crl.example.com/a.crl"

	b := NewBundle(&Probe{Nodes: []string{}})
	if err := ExportTrustedCerts(srcFake.client(), b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	tgtFake := newFakeISE(t)
	tgtC := tgtFake.client()
	rep, err := Preflight(tgtC, b)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	res, err := ApplyImport(tgtC, rep, "test-passphrase-1234567890", map[string]bool{}, false, quiet)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("created = %d, want 1", res.Created)
	}
	for _, e := range res.Errors {
		if strings.Contains(e, "CRL") {
			t.Errorf("CRL settings should have applied, got error: %s", e)
		}
	}
	// The distribution URL must still have landed despite the forced flags.
	for _, c := range tgtFake.certs {
		if str(c, "friendlyName") == "example.com" {
			if got := str(c, "crlDistributionUrl"); got != "http://crl.example.com/a.crl" {
				t.Errorf("crlDistributionUrl = %q, want it carried through", got)
			}
		}
	}
}

// The CRL PUT replaces the object, so it must carry the trust flags again or
// the certificate ends up trusted for nothing on a target where the import had
// just set them correctly. Observed on 3.4 as "trustedFor": "Unknown".
func TestApplyCRLPutKeepsTrustFlags(t *testing.T) {
	cert := genCert(t, "example.com", false, false, time.Now().Add(24*time.Hour))

	srcFake := newFakeISE(t)
	certObj := srcFake.addTrustedCert("src-1", "example.com", cert, pemEncode(cert.Raw))
	certObj["trustedFor"] = "Infrastructure,Endpoints"
	certObj["downloadCRL"] = "on"
	certObj["crlDistributionUrl"] = "http://crl.example.com/a.crl"

	b := NewBundle(&Probe{Nodes: []string{}})
	if err := ExportTrustedCerts(srcFake.client(), b, []string{familyTrustedCerts}, []string{"example.com"}, quiet); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	tgtFake := newFakeISE(t)
	tgtC := tgtFake.client()
	rep, err := Preflight(tgtC, b)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	if _, err := ApplyImport(tgtC, rep, "test-passphrase-1234567890", map[string]bool{}, false, quiet); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	found := false
	for _, c := range tgtFake.certs {
		if str(c, "friendlyName") != "example.com" {
			continue
		}
		found = true
		got := str(c, "trustedFor")
		if !strings.Contains(got, "Infrastructure") || !strings.Contains(got, "Endpoints") {
			t.Errorf("trustedFor = %q after the CRL PUT, want Infrastructure and Endpoints preserved", got)
		}
	}
	if !found {
		t.Fatal("certificate was not created on the target")
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
// addTrustedCert creates a certificate with real ISE 3.4 field names and types.
func (f *fakeISE) addTrustedCert(id, friendlyName string, cert *x509.Certificate, exportBody []byte) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()

	fp := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))

	// Real ISE 3.4.0.608 response format for trusted certificates.
	obj := map[string]any{
		"id":                            id,
		"friendlyName":                  friendlyName,
		"subject":                       cert.Subject.String(),
		"issuedTo":                      cert.Subject.CommonName,
		"issuedBy":                      cert.Issuer.CommonName,
		"keySize":                       256,
		"signatureAlgorithm":            "SHA256withECDSA",
		"validFrom":                     cert.NotBefore.Format("Mon Jan 02 15:04:05 MST 2006"),
		"expirationDate":                cert.NotAfter.Format("Mon Jan 02 15:04:05 MST 2006"),
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
		"sha256Fingerprint":             fp,
		"link":                          map[string]any{"rel": "self"},
	}

	// Store the export body (PEM format).
	if exportBody == nil {
		exportBody = pemEncode(cert.Raw)
	}
	obj["pem"] = string(exportBody)

	if f.certs == nil {
		f.certs = []map[string]any{}
	}
	f.certs = append(f.certs, obj)

	return obj
}

func TestCertPassword(t *testing.T) {
	// Test that certPassword produces alphanumeric, stable output of correct length
	passphrase := "my-secret-passphrase-12345"
	pwd := certPassword(passphrase)

	// Must be alphanumeric
	for _, c := range pwd {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("certPassword contains non-alphanumeric character: %c", c)
		}
	}

	// Must be 32 characters
	if len(pwd) != 32 {
		t.Errorf("certPassword length = %d, want 32", len(pwd))
	}

	// Must be stable (same input -> same output)
	pwd2 := certPassword(passphrase)
	if pwd != pwd2 {
		t.Errorf("certPassword not stable: got %q then %q", pwd, pwd2)
	}

	// Different passphrase -> different password
	pwd3 := certPassword("different-passphrase")
	if pwd == pwd3 {
		t.Errorf("certPassword should differ for different passphrases, got %q for both", pwd)
	}
}
