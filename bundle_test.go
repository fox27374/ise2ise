package main

import (
	"bytes"
	"strings"
	"testing"
)

const testPass = "correct horse battery staple"

func sampleBundle() *Bundle {
	b := NewBundle(&Probe{Host: "ise-src.example.net", Version: "3.3.0.430", Nodes: []string{"ise-src-1", "ise-src-2"}})
	b.Objects[familyEndpointGroups] = []map[string]any{{"name": "Printers", "description": "static printers"}}
	b.Objects[familyEndpoints] = []map[string]any{
		{"mac": "AA:BB:CC:DD:EE:01", "groupName": "Printers", "staticGroupAssignment": true},
	}
	b.Note("one note")
	return b
}

func TestBundleRoundTrip(t *testing.T) {
	sealed, err := SealBundle(sampleBundle(), testPass)
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	if !bytes.HasPrefix(sealed, []byte(bundleMagic)) {
		t.Error("bundle does not start with its magic")
	}
	if sealed[len(bundleMagic)] != bundleFormat {
		t.Error("format version byte missing")
	}
	// The point of encrypting: nothing recognisable on disk.
	if bytes.Contains(sealed, []byte("Printers")) || bytes.Contains(sealed, []byte("AA:BB:CC")) {
		t.Fatal("plaintext leaked into the sealed bundle")
	}

	got, err := OpenBundle(sealed, testPass)
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	if got.Source.Host != "ise-src.example.net" || got.Source.ISEVersion != "3.3.0.430" || len(got.Source.Nodes) != 2 {
		t.Errorf("source provenance lost: %+v", got.Source)
	}
	if len(got.Objects[familyEndpoints]) != 1 || got.Objects[familyEndpoints][0]["mac"] != "AA:BB:CC:DD:EE:01" {
		t.Errorf("objects lost: %+v", got.Objects)
	}
	if len(got.Notes) != 1 {
		t.Errorf("notes lost: %v", got.Notes)
	}
	if got.ExportedAt.IsZero() {
		t.Error("exportedAt lost")
	}
}

func TestBundleWrongPassphrase(t *testing.T) {
	sealed, err := SealBundle(sampleBundle(), testPass)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenBundle(sealed, testPass+"x")
	if err == nil {
		t.Fatal("a wrong passphrase must not open the bundle")
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Errorf("operator-facing message expected, got %q", err)
	}
}

func TestBundleTamperedCiphertext(t *testing.T) {
	sealed, err := SealBundle(sampleBundle(), testPass)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-20] ^= 0xff
	if _, err := OpenBundle(sealed, testPass); err == nil {
		t.Fatal("tampered ciphertext must be rejected")
	}
}

func TestBundleTamperedHeaderIsAuthenticated(t *testing.T) {
	sealed, err := SealBundle(sampleBundle(), testPass)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte of the nonce inside the header: it is GCM additional data, so
	// the header cannot be swapped even though it is not encrypted.
	sealed[headerLen-1] ^= 0x01
	if _, err := OpenBundle(sealed, testPass); err == nil {
		t.Fatal("a modified header must be rejected")
	}
}

func TestBundleNotABundle(t *testing.T) {
	if _, err := OpenBundle([]byte("hello"), testPass); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "too short") {
		t.Errorf("got %q", err)
	}
	junk := append([]byte("NOTISE2X"), bytes.Repeat([]byte{0}, 64)...)
	if _, err := OpenBundle(junk, testPass); err == nil || !strings.Contains(err.Error(), "not an ise2ise bundle") {
		t.Errorf("got %v", err)
	}
}

func TestBundleRejectsShortPassphrase(t *testing.T) {
	if _, err := SealBundle(sampleBundle(), "short"); err == nil {
		t.Fatal("a five-character passphrase must be refused")
	}
}
