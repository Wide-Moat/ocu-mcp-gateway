// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestMTLSMaterial generates a real ephemeral CA and a CA-signed client
// pair (the minimal-shelf self-signed-CA substrate, §8) and writes the three PEM
// files LoadMTLSConfig consumes. No mock material: the loader must parse real
// x509/PEM or the test proves nothing about the boot path.
func writeTestMTLSMaterial(t *testing.T) (caPath, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	clKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen client key: %v", err)
	}
	clTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ocu-mcp-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clDER, err := x509.CreateCertificate(rand.Reader, clTmpl, caCert, &clKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	clKeyDER, err := x509.MarshalECPrivateKey(clKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	caPath = filepath.Join(dir, "ca.pem")
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client-key.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)
	writePEM(t, certPath, "CERTIFICATE", clDER)
	writePEM(t, keyPath, "EC PRIVATE KEY", clKeyDER)
	return caPath, certPath, keyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestLoadMTLSConfigLoadsMaterialAndFloorsTLS13 pins the happy path the shipped
// composition root walks when -control-url is set: the CA lands in RootCAs, the
// client pair is presented (that is the "m" in mTLS), and the minimum version is
// the NFR-SEC-37 TLS-1.3 floor.
func TestLoadMTLSConfigLoadsMaterialAndFloorsTLS13(t *testing.T) {
	ca, cert, key := writeTestMTLSMaterial(t)
	cfg, err := LoadMTLSConfig(ca, cert, key)
	if err != nil {
		t.Fatalf("LoadMTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("minimum TLS version must be 1.3 (NFR-SEC-37 floor), got %x", cfg.MinVersion)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs must carry the configured CA (the minimal-shelf self-signed CA is not in any system pool)")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("the client pair must be presented on the dial (mTLS), got %d certificates", len(cfg.Certificates))
	}
}

// TestLoadMTLSConfigRequiresAllThreePaths pins fail-closed on partial material:
// a CA without a client pair is server-auth-only TLS (not mTLS), and a client
// pair without the CA cannot verify Control (the self-signed CA is not in the
// system pool). Every partial combination is refused.
func TestLoadMTLSConfigRequiresAllThreePaths(t *testing.T) {
	ca, cert, key := writeTestMTLSMaterial(t)
	for _, tc := range []struct {
		name             string
		ca, cert, keyArg string
	}{
		{"no CA", "", cert, key},
		{"no client cert", ca, "", key},
		{"no client key", ca, cert, ""},
		{"nothing", "", "", ""},
	} {
		if _, err := LoadMTLSConfig(tc.ca, tc.cert, tc.keyArg); err == nil {
			t.Errorf("%s: partial mTLS material must be refused (fail-closed)", tc.name)
		}
	}
}

func TestLoadMTLSConfigFailsClosedOnBadMaterial(t *testing.T) {
	ca, cert, key := writeTestMTLSMaterial(t)

	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not pem at all"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, err := LoadMTLSConfig(garbage, cert, key); err == nil {
		t.Error("a CA file with no parsable certificate must be refused")
	}

	if _, err := LoadMTLSConfig(filepath.Join(t.TempDir(), "absent.pem"), cert, key); err == nil {
		t.Error("a missing CA file must be refused")
	}

	// A mismatched pair (cert from one keypair, key from another) must be refused.
	_, otherCert, _ := writeTestMTLSMaterial(t)
	if _, err := LoadMTLSConfig(ca, otherCert, key); err == nil {
		t.Error("a client cert/key mismatch must be refused")
	}
}
