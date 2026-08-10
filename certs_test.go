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
	rep, err := Preflight(tgtC, b, nil)
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

	rep, err := Preflight(tgtC, b, nil)
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

	rep, err := Preflight(tgtC, b, nil)
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

	res, err := ApplyImport(tgtC, rep, "test-passphrase-1234567890", "", map[string]bool{}, false, quiet)
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
	rep, err := Preflight(tgtC, b, nil)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	res, err := ApplyImport(tgtC, rep, "test-passphrase-1234567890", "", map[string]bool{}, false, quiet)
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
	rep, err := Preflight(tgtC, b, nil)
	if err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	if _, err := ApplyImport(tgtC, rep, "test-passphrase-1234567890", "", map[string]bool{}, false, quiet); err != nil {
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

// sysCertBundle builds a bundle holding one system certificate, as an export
// from a source node would have written it.
func sysCertBundle(t *testing.T, cert *x509.Certificate, name string, extra map[string]any) *Bundle {
	t.Helper()
	b := NewBundle(&Probe{Nodes: []string{"ibk-sda-ise1"}})
	obj := map[string]any{
		"name":        name,
		"pem":         string(pemEncode(cert.Raw)),
		"keyBlob":     "-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque\n-----END ENCRYPTED PRIVATE KEY-----\n",
		"keySource":   "api",
		"fingerprint": fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
		"notAfter":    cert.NotAfter.Format(time.RFC3339),
		"subject":     cert.Subject.String(),
		"issuer":      cert.Issuer.String(),
		"selfSigned":  cert.Subject.String() == cert.Issuer.String(),
		"sourceNode":  "ibk-sda-ise1",
		"eap":         true,
		"admin":       true,
	}
	for k, v := range extra {
		obj[k] = v
	}
	b.Objects[familySystemCerts] = []map[string]any{obj}
	return b
}

// twoNodeTarget is a target deployment with two Admin nodes, as the lab's is.
func twoNodeTarget(t *testing.T) *fakeISE {
	t.Helper()
	f := newFakeISE(t)
	f.mu.Lock()
	f.deploymentNodes = []map[string]any{
		{"hostname": "ISE-178", "fqdn": "ISE-178.ntslab.loc", "ipAddress": "172.24.89.178",
			"roles": []any{"PrimaryAdmin", "PrimaryMonitoring"}, "nodeStatus": "Connected"},
		{"hostname": "ISE-179", "fqdn": "ISE-179.ntslab.loc", "ipAddress": "172.24.89.179",
			"roles": []any{"SecondaryAdmin"}, "nodeStatus": "Connected"},
		{"hostname": "ISE-180", "fqdn": "ISE-180.ntslab.loc", "ipAddress": "172.24.89.180",
			"roles": []any{"PolicyService"}, "nodeStatus": "Connected"},
	}
	f.systemCerts["ISE-178"] = []map[string]any{}
	f.systemCerts["ISE-179"] = []map[string]any{}
	f.mu.Unlock()
	return f
}

// dialRecorder points every node client at the one fake deployment while
// recording which host the import asked for.
func dialRecorder(f *fakeISE, dialed *[]string) func(string) *Client {
	return func(host string) *Client {
		*dialed = append(*dialed, host)
		c := f.client()
		c.Host = host
		return c
	}
}

// The import API has no node field, so a certificate lands on whichever node's
// URL received the POST. The bundle's sourceNode says where the certificate was
// read from and must never decide where it is written: an import that dialled it
// would write the target's certificates back onto the source deployment.
func TestSystemCertImportDialsTargetNodesNotTheSource(t *testing.T) {
	cert := genCert(t, "*.ntslab.loc", true, false, time.Now().Add(365*24*time.Hour))
	b := sysCertBundle(t, cert, "wildcard.ntslab.loc", nil)

	tgt := twoNodeTarget(t)
	c := tgt.client()
	var dialed []string
	c.nodeDialer = dialRecorder(tgt, &dialed)

	rep, err := Preflight(c, b, nil)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if rep.Create != 2 {
		t.Fatalf("want one create per admin node (2), got %d: %+v", rep.Create, rep.Items)
	}
	if _, err := ApplyImport(c, rep, "test-passphrase-1234567890", "", nil, false, quiet); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, host := range dialed {
		if strings.Contains(host, "ibk-sda-ise1") {
			t.Fatalf("import dialled the source node %q; target addresses only", host)
		}
	}
	want := map[string]bool{"172.24.89.178": false, "172.24.89.179": false}
	for _, host := range dialed {
		if _, ok := want[host]; !ok {
			t.Errorf("import dialled %q, which is not a selected target node", host)
		}
		want[host] = true
	}
	for host, seen := range want {
		if !seen {
			t.Errorf("target node %s never received the certificate", host)
		}
	}
}

// A node the operator unticked must not appear in the report at all: the counts
// the operator confirms are the writes that happen.
func TestSystemCertPreflightHonoursNodeSelection(t *testing.T) {
	cert := genCert(t, "*.ntslab.loc", true, false, time.Now().Add(365*24*time.Hour))
	b := sysCertBundle(t, cert, "wildcard.ntslab.loc", nil)

	tgt := twoNodeTarget(t)
	c := tgt.client()

	rep, err := Preflight(c, b, []string{"ISE-179"})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if rep.Create != 1 {
		t.Fatalf("want 1 create for the one selected node, got %d", rep.Create)
	}
	for _, it := range rep.Items {
		if it.Family == familySystemCerts && strings.Contains(it.Name, "ISE-178") {
			t.Errorf("unselected node ISE-178 still produced an item: %q", it.Name)
		}
	}
	var offered, selected int
	for _, tn := range rep.TargetNodes {
		if tn.Selectable {
			offered++
		}
		if tn.Selected {
			selected++
		}
	}
	if offered != 2 || selected != 1 {
		t.Errorf("want 2 selectable nodes and 1 selected, got %d and %d", offered, selected)
	}
	for _, tn := range rep.TargetNodes {
		if tn.Hostname == "ISE-180" && tn.Selectable {
			t.Error("a PolicyService node was offered; it serves no admin API")
		}
	}
}

// Taking over the admin certificate restarts the node's application and can
// lock the operator out of the GUI mid-migration, so it happens only when asked.
func TestSystemCertAdminRoleOffUnlessTicked(t *testing.T) {
	cert := genCert(t, "*.ntslab.loc", true, false, time.Now().Add(365*24*time.Hour))
	tgt := twoNodeTarget(t)
	c := tgt.client()
	c.nodeDialer = func(host string) *Client { return tgt.client() }

	for _, tc := range []struct {
		name      string
		adminRole bool
		want      bool
	}{
		{"not ticked", false, false},
		{"ticked", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := sysCertBundle(t, cert, "wildcard-"+tc.name, nil)
			rep, err := Preflight(c, b, []string{"ISE-178"})
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			if _, err := ApplyImport(c, rep, "test-passphrase-1234567890", "", nil, tc.adminRole, quiet); err != nil {
				t.Fatalf("apply: %v", err)
			}
			tgt.mu.Lock()
			defer tgt.mu.Unlock()
			last := tgt.systemCertImports[len(tgt.systemCertImports)-1]
			if got, _ := last["admin"].(bool); got != tc.want {
				t.Errorf("admin role = %v, want %v", got, tc.want)
			}
			for _, flag := range []string{"allowReplacementOfCertificates", "allowReplacementOfPortalGroupTag", "allowRoleTransferForSameSubject"} {
				if v, _ := last[flag].(bool); v {
					t.Errorf("%s was true; import never overwrites what a node may be serving", flag)
				}
			}
		})
	}
}

// A key exported from the ISE GUI is encrypted with the password set there,
// which only the operator can supply. Writing it with an empty password would
// fail on the box with ISE's own wording; failing here says what to do instead.
func TestSystemCertZipSourceNeedsItsOwnPassword(t *testing.T) {
	cert := genCert(t, "*.ntslab.loc", true, false, time.Now().Add(365*24*time.Hour))
	tgt := twoNodeTarget(t)
	c := tgt.client()
	c.nodeDialer = func(host string) *Client { return tgt.client() }

	b := sysCertBundle(t, cert, "from-the-gui", map[string]any{"keySource": "zip"})
	rep, err := Preflight(c, b, []string{"ISE-178"})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	res, err := ApplyImport(c, rep, "test-passphrase-1234567890", "", nil, false, quiet)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Failed != 1 || res.Created != 0 {
		t.Fatalf("want the certificate refused for want of its ZIP password, got %+v", res)
	}
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0], "password") {
		t.Errorf("the error should name the missing password, got %v", res.Errors)
	}

	res2, err := ApplyImport(c, rep, "test-passphrase-1234567890", "the-gui-password", nil, false, quiet)
	if err != nil {
		t.Fatalf("apply with password: %v", err)
	}
	if res2.Created != 1 {
		t.Fatalf("want the certificate created once the password is given, got %+v", res2)
	}
	tgt.mu.Lock()
	defer tgt.mu.Unlock()
	last := tgt.systemCertImports[len(tgt.systemCertImports)-1]
	if last["password"] != "the-gui-password" {
		t.Errorf("the ZIP password did not reach ISE, got %v", last["password"])
	}
}

// ISE refuses a system certificate whose chain it cannot build, so the tool says
// so up front rather than letting the write fail - and a CA arriving in the same
// bundle counts as present, the way an endpoint group created in the same run
// does.
func TestSystemCertIssuerMustBeTrustedOnTarget(t *testing.T) {
	ca := genCert(t, "NTSLAB-RootCA", true, false, time.Now().Add(365*24*time.Hour))
	leaf := genCert(t, "*.ntslab.loc", false, false, time.Now().Add(365*24*time.Hour))
	leafObj := map[string]any{"issuer": ca.Subject.String(), "selfSigned": false}

	tgt := twoNodeTarget(t)
	c := tgt.client()

	b := sysCertBundle(t, leaf, "wildcard.ntslab.loc", leafObj)
	rep, err := Preflight(c, b, []string{"ISE-178"})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if rep.Blocked != 1 || rep.Create != 0 {
		t.Fatalf("want the certificate blocked for a missing issuer, got %d blocked %d create", rep.Blocked, rep.Create)
	}
	if !strings.Contains(rep.Items[0].Reason, "NTSLAB-RootCA") {
		t.Errorf("the reason should name the issuer, got %q", rep.Items[0].Reason)
	}

	// Now the same bundle also carries the CA, in the trusted family.
	b2 := sysCertBundle(t, leaf, "wildcard.ntslab.loc", leafObj)
	b2.Objects[familyTrustedCerts] = []map[string]any{{
		"name": "NTSLAB-RootCA", "pem": string(pemEncode(ca.Raw)),
		"subject":     ca.Subject.String(),
		"fingerprint": fmt.Sprintf("%x", sha256.Sum256(ca.Raw)),
		"notAfter":    ca.NotAfter.Format(time.RFC3339),
	}}
	rep2, err := Preflight(c, b2, []string{"ISE-178"})
	if err != nil {
		t.Fatalf("preflight with the CA in the bundle: %v", err)
	}
	var sysCreate int
	for _, it := range rep2.Items {
		if it.Family == familySystemCerts && it.Action == actionCreate {
			sysCreate++
		}
	}
	if sysCreate != 1 {
		t.Fatalf("the CA travels in the same bundle, so the certificate should be creatable; items: %+v", rep2.Items)
	}
}

// A GUI-exported ZIP is the 3.2 route, and everything the target needs beyond
// the two files in it comes from the operator: the name and the roles. Dropping
// either leaves a certificate that either cannot be created or does nothing.
func TestExportCarriesUploadedZipWithItsNameAndRoles(t *testing.T) {
	cert := genCert(t, "*.ntslab.loc", true, false, time.Now().Add(365*24*time.Hour))
	src := newFakeISE(t)
	b := NewBundle(&Probe{Nodes: []string{"ibk-sda-ise1"}})

	// Shaped as handleExport builds it from the attachment plus the request.
	zips := []map[string]any{{
		"filename":    "ise-wildcard.zip",
		"name":        "wildcard.ntslab.loc",
		"pem":         string(pemEncode(cert.Raw)),
		"keyBlob":     "-----BEGIN ENCRYPTED PRIVATE KEY-----\nopaque\n-----END ENCRYPTED PRIVATE KEY-----\n",
		"fingerprint": fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
		"expiresAt":   cert.NotAfter.Format(time.RFC3339),
		"subject":     cert.Subject.String(),
		"eap":         true,
		"portal":      true,
	}}

	if err := ExportSystemCerts(src.client(), b, []string{familySystemCerts}, nil, "test-passphrase-1234567890", zips, "gui-password", quiet); err != nil {
		t.Fatalf("export: %v", err)
	}
	objs := b.Objects[familySystemCerts]
	if len(objs) != 1 {
		t.Fatalf("want the attached ZIP in the bundle, got %d objects", len(objs))
	}
	got := objs[0]
	if str(got, "name") != "wildcard.ntslab.loc" {
		t.Errorf("name = %q, want the operator's choice", str(got, "name"))
	}
	if str(got, "keySource") != "zip" {
		t.Errorf("keySource = %q, want zip", str(got, "keySource"))
	}
	if str(got, "pem") == "" {
		t.Error("the certificate itself did not travel; the import has nothing to send as data")
	}
	if str(got, "keyBlob") == "" {
		t.Error("the private key did not travel")
	}
	if !truthy(got, "eap") || !truthy(got, "portal") {
		t.Errorf("the roles the operator ticked did not travel: %+v", got)
	}
	if truthy(got, "admin") {
		t.Error("an attached ZIP must not arrive with the admin role")
	}
}

// The keyless export the picker uses answers a ZIP, not bare PEM. Parsing it as
// PEM fails silently: the row keeps its name and loses its SANs, so a multi-SAN
// certificate — the only kind worth migrating — reads as single-name and arrives
// unticked. Found against a real 3.4 box on 2026-08-10.
func TestPickerReadsSANsFromTheExportZip(t *testing.T) {
	multi := genCertWithSANs(t, "ise.ntslab.loc", []string{"ise.ntslab.loc", "ise01.ntslab.loc", "ise02.ntslab.loc"})
	single := genCertWithSANs(t, "ISE01.ntslab.loc", []string{"ISE01.ntslab.loc"})

	f := newFakeISE(t)
	f.mu.Lock()
	f.deploymentNodes = []map[string]any{{
		"hostname": "ISE01", "ipAddress": "10.0.0.1", "nodeStatus": "Connected",
		"roles": []any{"PrimaryAdmin"},
	}}
	f.systemCerts["ISE01"] = []map[string]any{}
	f.mu.Unlock()
	f.addSystemCert("ISE01", "multi", "wildcard-ish", "aa11", []string{"Admin"})
	f.addSystemCert("ISE01", "single", "node cert", "bb22", []string{"EAP Authentication"})
	f.mu.Lock()
	f.systemCertPEM["sys-cert-multi"] = pemEncode(multi.Raw)
	f.systemCertPEM["sys-cert-single"] = pemEncode(single.Raw)
	// CA-issued, as the real multi-SAN certificate on the lab source is: a
	// self-signed one is unticked on its own merits, which is a different rule.
	for _, c := range f.systemCerts["ISE01"] {
		c["selfSigned"] = false
		c["issuedBy"] = "NTSLAB Vault CA"
	}
	f.mu.Unlock()

	rows, err := ListSystemCerts(f.client())
	if err != nil {
		t.Fatalf("ListSystemCerts: %v", err)
	}

	byName := map[string]SystemCertInfo{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	m, ok := byName["wildcard-ish"]
	if !ok {
		t.Fatalf("the multi-SAN certificate is missing from the picker: %+v", rows)
	}
	if len(m.SANs) != 3 {
		t.Errorf("SANs = %v, want the three in the certificate; an empty list means the ZIP was not read", m.SANs)
	}
	if !m.Ticked {
		t.Errorf("a multi-SAN certificate must be ticked by default, reason given was %q", m.Reason)
	}
	if s := byName["node cert"]; s.Ticked {
		t.Error("a single-name certificate must not be ticked by default")
	}
}

// genCertWithSANs is genCert with subject alternative names, which is what the
// picker's default-tick rule actually reads.
func genCertWithSANs(t *testing.T, cn string, dns []string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     dns,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// The bundle has to carry the issuer and the source's own admin role, or two
// designed behaviours quietly stop working: pre-flight cannot block a
// certificate whose issuer the target does not trust, and the admin checkbox on
// the import step has nothing to act on. Both were empty against a real box.
func TestExportRecordsIssuerAndAdminRole(t *testing.T) {
	cert := genCertWithSANs(t, "ise.ntslab.loc", []string{"ise.ntslab.loc", "ise01.ntslab.loc"})

	f := newFakeISE(t)
	f.mu.Lock()
	f.deploymentNodes = []map[string]any{{
		"hostname": "ISE01", "ipAddress": "10.0.0.1", "nodeStatus": "Connected",
		"roles": []any{"PrimaryAdmin"},
	}}
	f.systemCerts["ISE01"] = []map[string]any{}
	f.mu.Unlock()
	f.addSystemCert("ISE01", "multi", "the wildcard", "aa11", []string{"Admin", "EAP Authentication"})
	f.mu.Lock()
	f.systemCertPEM["sys-cert-multi"] = pemEncode(cert.Raw)
	for _, c := range f.systemCerts["ISE01"] {
		c["selfSigned"] = false
	}
	f.mu.Unlock()

	rows, err := ListSystemCerts(f.client())
	if err != nil {
		t.Fatalf("picker: %v", err)
	}
	b := NewBundle(&Probe{Nodes: []string{"ISE01"}})
	if err := ExportSystemCerts(f.client(), b, []string{familySystemCerts}, []string{rows[0].Fingerprint}, "test-passphrase-1234567890", nil, "", quiet); err != nil {
		t.Fatalf("export: %v", err)
	}
	objs := b.Objects[familySystemCerts]
	if len(objs) != 1 {
		t.Fatalf("exported %d objects, want 1", len(objs))
	}
	if got := str(objs[0], "issuer"); got != cert.Issuer.String() {
		t.Errorf("issuer = %q, want %q; an empty issuer disables the chain check", got, cert.Issuer.String())
	}
	if !truthy(objs[0], "admin") {
		t.Error("the source's admin role did not travel, so the import's admin checkbox can never take effect")
	}
}
