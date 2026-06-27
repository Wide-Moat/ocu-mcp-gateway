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

func TestFileLoaderLoadsActiveKey(t *testing.T) {
	salt := hex.EncodeToString([]byte("salt-1"))
	secret := "sk-ocu-config-test-key"
	hash, err := auth.HashForRecord(salt, secret)
	if err != nil {
		t.Fatalf("HashForRecord: %v", err)
	}
	content := `{"version":1,"keys":[{"key_id":"k1","key_hash":"` + hash + `","salt":"` + salt + `","tenant":"t","audience":"a","status":"active"}]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content)}

	ks, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c, err := ks.Resolve(secret)
	if err != nil {
		t.Fatalf("Resolve loaded key: %v", err)
	}
	if c.KeyID != "k1" || c.Tenant != "t" {
		t.Fatalf("resolved caller mismatch: %+v", c)
	}
}

func TestFileLoaderMissingFileFailsClosed(t *testing.T) {
	loader := &FileKeySetLoader{Path: "/nonexistent/boot-set.json"}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a missing boot-set file must fail (boot fails closed)")
	}
}

func TestFileLoaderMalformedJSONFails(t *testing.T) {
	loader := &FileKeySetLoader{Path: writeBootSet(t, `{not json`)}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("a malformed boot-set must fail")
	}
}

func TestFileLoaderEmptyKeysAuthenticatesNothing(t *testing.T) {
	loader := &FileKeySetLoader{Path: writeBootSet(t, `{"version":1,"keys":[]}`)}
	ks, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("an empty key list should load (distinct from a load failure): %v", err)
	}
	if _, err := ks.Resolve("sk-ocu-anything"); err == nil {
		t.Fatal("an empty key set must authenticate nothing")
	}
}

func TestFileLoaderUnknownStatusFailsClosed(t *testing.T) {
	salt := hex.EncodeToString([]byte("s"))
	secret := "sk-ocu-typo-status"
	hash, _ := auth.HashForRecord(salt, secret)
	// "actve" is a typo — must map to StatusUnknown, which never authenticates.
	content := `{"version":1,"keys":[{"key_id":"k","key_hash":"` + hash + `","salt":"` + salt + `","tenant":"t","audience":"a","status":"actve"}]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content)}
	ks, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := ks.Resolve(secret); err == nil {
		t.Fatal("a key with an unknown status must fail closed (not authenticate)")
	}
}

func TestFileLoaderInvalidExpiryFails(t *testing.T) {
	salt := hex.EncodeToString([]byte("s"))
	hash, _ := auth.HashForRecord(salt, "sk-ocu-x")
	content := `{"version":1,"keys":[{"key_id":"k","key_hash":"` + hash + `","salt":"` + salt + `","tenant":"t","audience":"a","status":"active","expires_at":"not-a-date"}]}`
	loader := &FileKeySetLoader{Path: writeBootSet(t, content)}
	if _, err := loader.Load(context.Background()); err == nil {
		t.Fatal("an invalid expires_at must fail the load")
	}
}
