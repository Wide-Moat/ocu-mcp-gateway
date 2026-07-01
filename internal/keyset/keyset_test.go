// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package keyset

import (
	"strings"
	"testing"
)

// a schema-valid record + envelope building block. key_hash is 64 lowercase-hex,
// salt is 32 lowercase-hex (>= 16), status const "active".
const validHash = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const validSalt = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

func validRecord() string {
	return `{"key_id":"a1b2c3d4e5f6a7b8c9d0e1f2","key_hash":"` + validHash + `","salt":"` + validSalt +
		`","tenant":"tenant-a","deployment":"deploy-1","status":"active","created_at":"2026-03-01T12:00:00Z"}`
}

func validSet() []byte {
	return []byte(`{"version":1,"records":[` + validRecord() + `]}`)
}

func TestValidSetPasses(t *testing.T) {
	if err := Validate(validSet()); err != nil {
		t.Fatalf("a schema-valid boot-set must pass, got %v", err)
	}
}

// The schema is fail-closed on the bad-render classes the contract pins.
func TestSchemaRejects(t *testing.T) {
	cases := map[string]string{
		"empty records (minItems 1)":  `{"version":1,"records":[]}`,
		"wrong version const":         `{"version":2,"records":[` + validRecord() + `]}`,
		"missing records":             `{"version":1}`,
		"non-active status":           `{"version":1,"records":[{"key_id":"k","key_hash":"` + validHash + `","salt":"` + validSalt + `","tenant":"t","deployment":"d","status":"revoked","created_at":"2026-03-01T12:00:00Z"}]}`,
		"malformed key_hash":          `{"version":1,"records":[{"key_id":"k","key_hash":"NOTHEX","salt":"` + validSalt + `","tenant":"t","deployment":"d","status":"active","created_at":"2026-03-01T12:00:00Z"}]}`,
		"short salt (< 16 hex)":       `{"version":1,"records":[{"key_id":"k","key_hash":"` + validHash + `","salt":"abcd","tenant":"t","deployment":"d","status":"active","created_at":"2026-03-01T12:00:00Z"}]}`,
		"extra field (addl:false)":    `{"version":1,"records":[{"key_id":"k","key_hash":"` + validHash + `","salt":"` + validSalt + `","tenant":"t","deployment":"d","status":"active","created_at":"2026-03-01T12:00:00Z","secret":"sk-ocu-leak"}]}`,
		"missing required deployment": `{"version":1,"records":[{"key_id":"k","key_hash":"` + validHash + `","salt":"` + validSalt + `","tenant":"t","status":"active","created_at":"2026-03-01T12:00:00Z"}]}`,
		"top-level extra field":       `{"version":1,"records":[` + validRecord() + `],"extra":"x"}`,
		"not JSON":                    `{not json`,
	}
	for name, doc := range cases {
		if err := Validate([]byte(doc)); err == nil {
			t.Errorf("%s: must be rejected by the schema, got nil error", name)
		}
	}
}

// A key_hash that is the UNSALTED digest shape is still rejected only if it fails
// the pattern; the schema pins 64 lowercase-hex, so an uppercase or wrong-length
// hash (the shapes a naive unsalted projection might produce) is refused. This
// guards the pass-the-hash floor at the shape level.
func TestUppercaseHashRejected(t *testing.T) {
	upper := strings.ToUpper(validHash)
	doc := `{"version":1,"records":[{"key_id":"k","key_hash":"` + upper + `","salt":"` + validSalt + `","tenant":"t","deployment":"d","status":"active","created_at":"2026-03-01T12:00:00Z"}]}`
	if err := Validate([]byte(doc)); err == nil {
		t.Error("an uppercase key_hash must be rejected (pattern ^[0-9a-f]{64}$)")
	}
}
