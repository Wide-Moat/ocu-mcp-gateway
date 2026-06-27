// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package config holds the gateway's boot configuration and the minimal-shelf
// boot-set loader. The boot-set is a Control-owned, root-owned hashed-entries
// file on the minimal shelf (the gateway never owns a key DB and never issues
// keys — it only consumes the salted-hash set Control delivers on the config
// plane). The full shelf supplies a config-plane loader behind the same
// auth.KeySetLoader seam.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// FileKeySetLoader loads the minimal-shelf boot-set from a root-owned JSON file
// of hashed key records. It is the concrete auth.KeySetLoader for the minimal
// shelf. Plaintext is never in the file — only salted-SHA-256 hashes — so a read
// of this file discloses no usable credential.
type FileKeySetLoader struct {
	// Path is the boot-set file path (Control-delivered, root-owned).
	Path string
	// Now is injected for deterministic expiry in tests; nil defaults to
	// time.Now at key-set construction.
	Now func() time.Time
}

// keyRecordWire is the on-disk JSON shape of one boot-set entry. It mirrors the
// ADR-0027 record (frozen on PR #311): {key_id, key_hash, salt, tenant,
// deployment/audience, expires_at, status, created_at}. created_at is read but
// not used for authentication (it is provenance only).
type keyRecordWire struct {
	KeyID     string `json:"key_id"`
	KeyHash   string `json:"key_hash"`
	Salt      string `json:"salt"`
	Tenant    string `json:"tenant"`
	Audience  string `json:"audience"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339; empty = non-expiring
	Status    string `json:"status"`               // "active" | "revoked"
	CreatedAt string `json:"created_at,omitempty"`
}

// bootSetWire is the file envelope: a versioned list of records, so a future
// format change is detectable rather than silently mis-parsed.
type bootSetWire struct {
	Version int             `json:"version"`
	Keys    []keyRecordWire `json:"keys"`
}

// Load reads and parses the boot-set file into an auth.KeySet. A missing or
// unreadable file is an error (boot fails closed — the daemon must not bind a
// listener against an absent key set). An empty key list parses to a set that
// authenticates nothing (fail-closed), which is distinct from a load failure so
// boot can tell "loaded, empty" from "could not load".
func (l *FileKeySetLoader) Load(_ context.Context) (auth.KeySet, error) {
	raw, err := os.ReadFile(l.Path)
	if err != nil {
		return nil, fmt.Errorf("config: read boot-set %q: %w", l.Path, err)
	}
	var env bootSetWire
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("config: parse boot-set %q: %w", l.Path, err)
	}
	records := make([]auth.KeyRecord, 0, len(env.Keys))
	for i, k := range env.Keys {
		rec, err := k.toRecord()
		if err != nil {
			return nil, fmt.Errorf("config: boot-set %q entry %d: %w", l.Path, i, err)
		}
		records = append(records, rec)
	}
	return auth.NewStaticKeySet(records, l.Now), nil
}

// toRecord maps a wire record to an auth.KeyRecord, parsing the status and
// optional expiry. An unknown status maps to StatusUnknown (which never
// authenticates), so a typo in the file fails closed rather than admitting.
func (k keyRecordWire) toRecord() (auth.KeyRecord, error) {
	var exp time.Time
	if k.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, k.ExpiresAt)
		if err != nil {
			return auth.KeyRecord{}, fmt.Errorf("invalid expires_at %q: %w", k.ExpiresAt, err)
		}
		exp = t
	}
	var status auth.KeyStatus
	switch k.Status {
	case "active":
		status = auth.StatusActive
	case "revoked":
		status = auth.StatusRevoked
	default:
		status = auth.StatusUnknown
	}
	return auth.KeyRecord{
		KeyID:     k.KeyID,
		KeyHash:   k.KeyHash,
		Salt:      k.Salt,
		Tenant:    k.Tenant,
		Audience:  k.Audience,
		ExpiresAt: exp,
		Status:    status,
	}, nil
}
