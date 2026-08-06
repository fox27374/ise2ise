package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The bundle is the transfer artifact: written on the machine that can reach
// the source deployment, carried by hand, read on the machine that can reach
// the target. It will grow to hold private keys and device secrets, so it is
// always encrypted with an operator passphrase - there is no plaintext mode.
//
// On disk:
//
//	magic "ISE2ISE" | format version (1 byte) | salt (16) | nonce (12) | AES-256-GCM ciphertext
//
// The 36-byte header is passed to GCM as additional data, so a bundle cannot be
// re-headed with a different version or have its salt swapped without the open
// failing.

const (
	bundleMagic    = "ISE2ISE"
	bundleFormat   = 1
	saltLen        = 16
	nonceLen       = 12
	headerLen      = len(bundleMagic) + 1 + saltLen + nonceLen
	pbkdf2Iters    = 600000 // OWASP 2023 floor for PBKDF2-HMAC-SHA256
	keyLen         = 32     // AES-256
	minPassphrase  = 12
	bundleFileName = "ise2ise-bundle.enc"
)

// Bundle is the plaintext inside. It never contains credentials of any kind.
type Bundle struct {
	Tool          string                      `json:"tool"`
	FormatVersion int                         `json:"formatVersion"`
	ExportedAt    time.Time                   `json:"exportedAt"`
	Source        BundleSource                `json:"source"`
	Objects       map[string][]map[string]any `json:"objects"`
	Notes         []string                    `json:"notes"`
}

// BundleSource records where the objects came from. Host and node names are
// provenance for the operator; nothing decides behaviour from them.
type BundleSource struct {
	Host       string   `json:"host"`
	ISEVersion string   `json:"iseVersion"`
	Nodes      []string `json:"nodes"`
}

func NewBundle(p *Probe) *Bundle {
	b := &Bundle{
		Tool:          "ise2ise",
		FormatVersion: bundleFormat,
		ExportedAt:    time.Now().UTC(),
		Objects:       map[string][]map[string]any{},
		Notes:         []string{},
	}
	if p != nil {
		b.Source = BundleSource{Host: p.Host, ISEVersion: p.Version, Nodes: p.Nodes}
	}
	return b
}

func (b *Bundle) Note(format string, a ...any) {
	b.Notes = append(b.Notes, fmt.Sprintf(format, a...))
}

var errBadPassphrase = errors.New("wrong passphrase, or the bundle is corrupt or was tampered with")

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iters, keyLen)
}

// SealBundle encrypts a bundle for transport.
func SealBundle(b *Bundle, passphrase string) ([]byte, error) {
	if len([]rune(passphrase)) < minPassphrase {
		return nil, fmt.Errorf("passphrase must be at least %d characters", minPassphrase)
	}
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}

	header := make([]byte, headerLen)
	copy(header, bundleMagic)
	header[len(bundleMagic)] = bundleFormat
	salt := header[len(bundleMagic)+1 : len(bundleMagic)+1+saltLen]
	nonce := header[len(bundleMagic)+1+saltLen:]
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(header, nonce, plain, header), nil
}

// OpenBundle decrypts and parses a bundle. Every failure mode that an operator
// can actually cause - typo in the passphrase, truncated file, wrong file -
// comes back as one clear sentence rather than a raw GCM error.
func OpenBundle(data []byte, passphrase string) (*Bundle, error) {
	if len(data) < headerLen+16 {
		return nil, errors.New("this file is too short to be an ise2ise bundle")
	}
	if string(data[:len(bundleMagic)]) != bundleMagic {
		return nil, errors.New("this file is not an ise2ise bundle (bad magic)")
	}
	if v := data[len(bundleMagic)]; v != bundleFormat {
		return nil, fmt.Errorf("bundle format version %d, this build understands %d", v, bundleFormat)
	}
	header := data[:headerLen]
	salt := header[len(bundleMagic)+1 : len(bundleMagic)+1+saltLen]
	nonce := header[len(bundleMagic)+1+saltLen:]

	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, data[headerLen:], header)
	if err != nil {
		return nil, errBadPassphrase
	}
	var b Bundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, fmt.Errorf("bundle decrypted but its contents are not valid ise2ise JSON: %w", err)
	}
	if b.Tool != "ise2ise" {
		return nil, fmt.Errorf("bundle decrypted but was not written by ise2ise (tool=%q)", b.Tool)
	}
	if b.Objects == nil {
		b.Objects = map[string][]map[string]any{}
	}
	return &b, nil
}

func newGCM(passphrase string, salt []byte) (cipher.AEAD, error) {
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}
