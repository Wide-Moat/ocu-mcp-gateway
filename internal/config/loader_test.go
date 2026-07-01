// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package config

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// writeBootSet writes a boot-set JSON file and returns its path.
func writeBootSet(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bootset.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write boot-set: %v", err)
	}
	return p
}

// schemaSalt is a schema-valid salt (>= 16 lowercase-hex chars; 32 bytes here).
func schemaSalt() string { return hex.EncodeToString(make([]byte, 32)) }

// activeRecord builds a schema-valid record JSON for a secret under a deployment.
func activeRecord(t *testing.T, keyID, secret, tenant, deployment string) string {
	t.Helper()
	salt := schemaSalt()
	hash, err := auth.HashForRecord(salt, secret)
	if err != nil {
		t.Fatalf("HashForRecord: %v", err)
	}
	return `{"key_id":"` + keyID + `","key_hash":"` + hash + `","salt":"` + salt +
		`","tenant":"` + tenant + `","deployment":"` + deployment +
		`","status":"active","created_at":"2026-03-01T12:00:00Z"}`
}

func TestFileLoaderLoadsActiveKey(t *testing.T) {
	secret := "sk-ocu-config-test-key"
	content := `{"version":1,"records":[` + activeRecord(t, "k1", secret, "t", "deploy-1") + `]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: "deploy-1"}

	ks, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c, err := ks.Resolve(secret)
	if err != nil {
		t.Fatalf("Resolve loaded key: %v", err)
	}
	if c.KeyID != "k1" || c.Tenant != "t" || c.Deployment != "deploy-1" {
		t.Fatalf("resolved caller mismatch: %+v", c)
	}
}

func TestFileLoaderMissingFileFailsClosed(t *testing.T) {
	loader := &FileKeySetLoader{Path: "/nonexistent/boot-set.json", Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a missing boot-set file must fail (boot fails closed)")
	}
}

func TestFileLoaderMalformedJSONFails(t *testing.T) {
	loader := &FileKeySetLoader{Path: writeBootSet(t, `{not json`), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a malformed boot-set must fail")
	}
}

// An empty deployment is a construction fail-closed: the deployment guard cannot
// be disabled.
func TestFileLoaderEmptyDeploymentFailsClosed(t *testing.T) {
	content := `{"version":1,"records":[` + activeRecord(t, "k1", "sk-ocu-x", "t", "deploy-1") + `]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: ""}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("an empty -deployment must fail the load (the deployment guard cannot be disabled)")
	}
}

// A record scoped to another deployment reds the WHOLE load (boot-reject, not
// served-with-holes) — the layer-i homogeneity guard, ADR-0027 (3b).
func TestFileLoaderForeignDeploymentBootRejects(t *testing.T) {
	// Two records: one for this deployment, one foreign. The foreign one must
	// reject the entire set, not just be dropped.
	ours := activeRecord(t, "k1", "sk-ocu-ours", "t", "deploy-1")
	foreign := activeRecord(t, "k2", "sk-ocu-foreign", "t", "deploy-OTHER")
	content := `{"version":1,"records":[` + ours + `,` + foreign + `]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a foreign-deployment record must boot-reject the whole set (fail-closed, not served-with-holes)")
	}
}

// The schema forbids an empty records array (minItems 1); the loader refuses it.
func TestFileLoaderZeroRecordsFailsClosed(t *testing.T) {
	loader := &FileKeySetLoader{Path: writeBootSet(t, `{"version":1,"records":[]}`), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a zero-record boot-set must fail the load (schema minItems 1 / fail-fast)")
	}
}

// A non-"active" status violates the schema's const "active" (revoked/expired are
// omitted before render) — the set is refused.
func TestFileLoaderNonActiveStatusFailsSchema(t *testing.T) {
	salt := schemaSalt()
	hash, _ := auth.HashForRecord(salt, "sk-ocu-x")
	content := `{"version":1,"records":[{"key_id":"k","key_hash":"` + hash + `","salt":"` + salt +
		`","tenant":"t","deployment":"deploy-1","status":"revoked","created_at":"2026-03-01T12:00:00Z"}]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a non-active status must fail the schema (const active) — the whole set is refused")
	}
}

// An unsalted-looking / malformed key_hash (not 64 lowercase-hex) violates the
// schema KeyHash pattern.
func TestFileLoaderMalformedHashFailsSchema(t *testing.T) {
	salt := schemaSalt()
	content := `{"version":1,"records":[{"key_id":"k","key_hash":"NOT-A-HEX-HASH","salt":"` + salt +
		`","tenant":"t","deployment":"deploy-1","status":"active","created_at":"2026-03-01T12:00:00Z"}]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a malformed key_hash must fail the schema (KeyHash pattern ^[0-9a-f]{64}$)")
	}
}

// An extra field must be rejected (additionalProperties:false forbids smuggling a
// plaintext secret into a record).
func TestFileLoaderExtraFieldFailsSchema(t *testing.T) {
	salt := schemaSalt()
	hash, _ := auth.HashForRecord(salt, "sk-ocu-x")
	content := `{"version":1,"records":[{"key_id":"k","key_hash":"` + hash + `","salt":"` + salt +
		`","tenant":"t","deployment":"deploy-1","status":"active","created_at":"2026-03-01T12:00:00Z","secret":"sk-ocu-leaked"}]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("an extra field must fail the schema (additionalProperties:false — no secret smuggling)")
	}
}

func TestFileLoaderInvalidExpiryFails(t *testing.T) {
	salt := schemaSalt()
	hash, _ := auth.HashForRecord(salt, "sk-ocu-x")
	// A syntactically date-time-ish but unparseable expiry: use a value the schema
	// date-time format rejects so the load fails at schema time.
	content := `{"version":1,"records":[{"key_id":"k","key_hash":"` + hash + `","salt":"` + salt +
		`","tenant":"t","deployment":"deploy-1","status":"active","expires_at":"not-a-date","created_at":"2026-03-01T12:00:00Z"}]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("an invalid expires_at must fail the load")
	}
}

// An unsupported envelope version fails (the schema pins version const 1).
func TestFileLoaderUnsupportedVersionFails(t *testing.T) {
	content := `{"version":2,"records":[` + activeRecord(t, "k", "sk-ocu-x", "t", "deploy-1") + `]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content), Deployment: "deploy-1"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("an unsupported boot-set version must fail the load")
	}
}
