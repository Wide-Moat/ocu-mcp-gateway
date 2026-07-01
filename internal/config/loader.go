// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package config holds the gateway's boot configuration and the minimal-shelf
// boot-set loader. The boot-set is a Control-owned, root-owned hashed-entries
// file on the minimal shelf (the gateway never owns a key DB and never issues
// keys — it only consumes the salted-hash set Control delivers on the config
// plane). The full shelf supplies a config-plane loader behind the same
// auth.KeySetLoader seam.
//
// The boot-set is validated against the vendored canon schema
// (contracts/mcp/mcp-key-set.schema.json, ADR-0027) BEFORE it is mapped: a file
// that violates the frozen shape (empty records, a non-"active" status, an
// unsalted-looking hash, an extra field smuggling a secret) is refused at boot,
// fail-closed, rather than served with holes.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/keyset"
)

// FileKeySetLoader loads the minimal-shelf boot-set from a root-owned JSON file
// of hashed key records. It is the concrete auth.KeySetLoader for the minimal
// shelf. Plaintext is never in the file — only salted-SHA-256 hashes — so a read
// of this file discloses no usable credential.
type FileKeySetLoader struct {
	// Path is the boot-set file path (Control-delivered, root-owned).
	Path string
	// Deployment is this gateway's own deployment scope. The loaded set MUST be
	// homogeneous and equal to it: any record scoped to another deployment reds
	// the whole load (boot-reject, fail-closed — a foreign-deployment set is a
	// confused-deputy vector). An empty Deployment is a construction error, so
	// "deployment guard off" is not expressible.
	Deployment string
	// Now is injected for deterministic expiry in tests; nil defaults to
	// time.Now at key-set construction.
	Now func() time.Time
}

// keyRecordWire is the on-disk JSON shape of one boot-set record. It mirrors the
// frozen mcp-key-set.schema.json HashedKeyRecord (ADR-0027): {key_id, key_hash,
// salt, tenant, deployment, status, created_at, expires_at?}. created_at is read
// but not used for authentication (it is provenance only).
type keyRecordWire struct {
	KeyID      string `json:"key_id"`
	KeyHash    string `json:"key_hash"`
	Salt       string `json:"salt"`
	Tenant     string `json:"tenant"`
	Deployment string `json:"deployment"`
	Status     string `json:"status"` // schema-pinned const "active" on the wire
	ExpiresAt  string `json:"expires_at,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// bootSetFormatVersion is the only boot-set envelope version this build
// understands. A file with a different version is refused (fail-closed) rather
// than mis-parsed. It matches the schema's `version` const 1.
const bootSetFormatVersion = 1

// bootSetWire is the file envelope: a versioned list of records, matching the
// schema's {version, records}.
type bootSetWire struct {
	Version int             `json:"version"`
	Records []keyRecordWire `json:"records"`
}

// Load reads, schema-validates, and parses the boot-set file into an auth.KeySet.
// A missing or unreadable file, a schema violation, a heterogeneous or
// foreign-deployment set, or an invalid field is an error (boot fails closed —
// the daemon must not bind a listener against an absent or malformed key set).
func (l *FileKeySetLoader) Load(_ context.Context) (auth.KeySet, error) {
	if l.Deployment == "" {
		return nil, fmt.Errorf("config: boot-set load requires a non-empty gateway deployment (the deployment guard cannot be disabled; fail-closed)")
	}
	raw, err := os.ReadFile(l.Path)
	if err != nil {
		return nil, fmt.Errorf("config: read boot-set %q: %w", l.Path, err)
	}

	// Validate against the vendored canon schema BEFORE mapping. This enforces the
	// frozen shape (records minItems 1, status const "active", key_hash/salt
	// patterns, additionalProperties:false) so a bad render is refused at the
	// source, not served with holes.
	if err := keyset.Validate(raw); err != nil {
		return nil, fmt.Errorf("config: boot-set %q fails the mcp-key-set schema (fail-closed): %w", l.Path, err)
	}

	var env bootSetWire
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("config: parse boot-set %q: %w", l.Path, err)
	}
	// The schema pins version const 1, but check explicitly too: a future v2
	// parsed as v1 would silently mis-read fields. Fail-closed on a mismatch.
	if env.Version != bootSetFormatVersion {
		return nil, fmt.Errorf("config: boot-set %q has unsupported version %d (this build understands version %d)", l.Path, env.Version, bootSetFormatVersion)
	}
	// The schema already forbids an empty records array (minItems 1); this is a
	// belt-and-braces fail-fast in case the schema is ever relaxed.
	if len(env.Records) == 0 {
		return nil, fmt.Errorf("config: boot-set %q contains zero records; refusing to load (a key-less gateway authenticates nobody — fail-fast)", l.Path)
	}

	records := make([]auth.KeyRecord, 0, len(env.Records))
	for i, k := range env.Records {
		// Boot-time deployment homogeneity guard (layer i): every record MUST be
		// scoped to THIS gateway's deployment. A single foreign-deployment record
		// reds the whole load — the set is refused, never served with the foreign
		// record dropped (a served-with-holes set would silently mask a bad render
		// or a swapped-in foreign set; that confused-deputy class is boot-rejected).
		if k.Deployment != l.Deployment {
			return nil, fmt.Errorf("config: boot-set %q record %d is scoped to deployment %q, not this gateway's %q; refusing the whole set (fail-closed, boot-reject not served-with-holes)", l.Path, i, k.Deployment, l.Deployment)
		}
		rec, err := k.toRecord()
		if err != nil {
			return nil, fmt.Errorf("config: boot-set %q record %d: %w", l.Path, i, err)
		}
		records = append(records, rec)
	}
	return auth.NewStaticKeySet(records, l.Deployment, l.Now), nil
}

// toRecord maps a wire record to an auth.KeyRecord, parsing the status and
// optional expiry. The schema already pins status to const "active"; an
// unexpected value still maps to StatusUnknown (which never authenticates) so a
// bypass of the schema check fails closed rather than admitting.
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
	default:
		// The wire is schema-pinned to "active"; anything else (only reachable if
		// the schema check is bypassed) fails closed.
		status = auth.StatusUnknown
	}
	return auth.KeyRecord{
		KeyID:      k.KeyID,
		KeyHash:    k.KeyHash,
		Salt:       k.Salt,
		Tenant:     k.Tenant,
		Deployment: k.Deployment,
		ExpiresAt:  exp,
		Status:     status,
	}, nil
}
