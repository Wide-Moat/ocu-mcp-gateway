// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// KeyPrefix is the mandatory prefix of a minimal-shelf caller key. It makes a
// leaked key scanner-detectable (a gitleaks/trufflehog rule targets it) and lets
// the authenticator reject a non-prefixed bearer before any hashing.
const KeyPrefix = "sk-ocu-"

// KeyRecord is one boot-set entry: the at-rest shape of an issued caller key,
// per ADR-0027 (frozen on PR #311). The secret itself is NEVER stored — only its
// salted SHA-256 hash. Salt is per-key. The record binds the key to a tenant and
// a deployment/audience scope, carries an optional expiry, and a status that
// revocation flips.
//
// Storage rejects LiteLLM's unsalted SHA-256 (pass-the-hash advisory
// GHSA-69x8-hrgq-fjj8): the stored hash is sha256(salt‖secret), so a leaked hash
// set cannot be used to authenticate without also inverting SHA-256 per salt.
type KeyRecord struct {
	// KeyID is the stable, non-secret identifier of this key (the audit handle).
	KeyID string
	// KeyHash is the hex-encoded sha256(salt‖secret). The plaintext secret is
	// never stored.
	KeyHash string
	// Salt is the per-key salt mixed before hashing (hex-encoded).
	Salt string
	// Tenant is the tenant this key authenticates as.
	Tenant string
	// Audience is the deployment-scope / audience-equivalent this key is valid
	// for. A key absent from THIS deployment's set never resolves.
	Audience string
	// ExpiresAt is the optional expiry; the zero value means non-expiring (the
	// one-click path is not blocked by a forced expiry).
	ExpiresAt time.Time
	// Status is the lifecycle status; only StatusActive authenticates.
	Status KeyStatus
}

// KeyStatus is a key record's lifecycle status. Revocation flips it away from
// active; only an active, unexpired key authenticates.
type KeyStatus uint8

const (
	// StatusUnknown is the zero value; it never authenticates (fail-closed for a
	// record with an unset status).
	StatusUnknown KeyStatus = iota
	// StatusActive is the only status that authenticates.
	StatusActive
	// StatusRevoked is a revoked key; it never authenticates.
	StatusRevoked
)

// staticKeySet is the minimal-shelf KeySet: a boot-loaded set of salted-hash key
// records resolved in-process. It satisfies the KeySet seam without any network
// I/O — resolution hashes the presented bearer with each candidate record's salt
// and constant-time compares against that record's stored hash.
type staticKeySet struct {
	records []KeyRecord
	// now is injected so a test can drive expiry deterministically; production
	// passes time.Now.
	now func() time.Time
}

// NewStaticKeySet builds a minimal-shelf KeySet from boot-loaded records. The now
// func defaults to time.Now when nil. An empty record set is permitted (it simply
// authenticates nothing — fail-closed), so boot can distinguish "loaded, empty"
// from "failed to load" at the loader seam rather than here.
func NewStaticKeySet(records []KeyRecord, now func() time.Time) KeySet {
	if now == nil {
		now = time.Now
	}
	// Copy the slice so a caller cannot mutate the set after construction.
	cp := make([]KeyRecord, len(records))
	copy(cp, records)
	return &staticKeySet{records: cp, now: now}
}

// Resolve hashes the presented bearer with each active, unexpired record's salt
// and constant-time compares against that record's stored hash, returning the
// matched record's Caller binding on a hit. A miss returns ErrUnauthenticated.
//
// It is constant-time per record (subtle.ConstantTimeCompare) so a timing
// side-channel cannot probe the set byte-by-byte. The prefix check does NOT
// short-circuit the compare loop: a prefix-miss and a prefix-hit-compare-fail are
// timing-INDISTINGUISHABLE, because the full per-record comparison runs in BOTH
// cases. Folding the prefix into the loop instead of an early return closes the
// micro-leak that a fast "no prefix" response would otherwise reveal — even
// though the prefix is public, keeping the path uniform removes one timing oracle
// for free (architect pin). A bearer without the prefix simply never hashes to a
// stored value, so it falls through to the no-match return after the same work.
func (s *staticKeySet) Resolve(bearer string) (Caller, error) {
	hasPrefix := strings.HasPrefix(bearer, KeyPrefix)

	now := s.now()
	var matched *KeyRecord
	for i := range s.records {
		rec := &s.records[i]
		if rec.Status != StatusActive {
			continue
		}
		if !rec.ExpiresAt.IsZero() && now.After(rec.ExpiresAt) {
			continue
		}
		want, err := hex.DecodeString(rec.KeyHash)
		if err != nil {
			// A malformed stored hash never authenticates; skip it fail-closed
			// rather than treating a decode error as a match.
			continue
		}
		got := hashBearer(rec.Salt, bearer)
		// Constant-time compare. The match is ANDed with the (public) prefix
		// flag so a prefixless bearer can never be accepted even on the
		// astronomically-unlikely hash coincidence — without a secret-dependent
		// early exit.
		eq := subtle.ConstantTimeCompare(want, got)
		if eq == 1 && hasPrefix {
			matched = rec
			// Do not break: continuing keeps the comparison count independent of
			// WHERE in the set the match sat, so position is not timing-leaked.
			// matched is set once; a well-formed set has unique hashes.
		}
	}
	if matched == nil {
		return Caller{}, ErrUnauthenticated
	}
	return Caller{
		KeyID:    matched.KeyID,
		Tenant:   matched.Tenant,
		Audience: matched.Audience,
	}, nil
}

// hashBearer computes sha256(salt‖secret) for a presented bearer, returning the
// raw digest bytes. The salt is the record's hex-encoded per-key salt; it is
// decoded and prepended to the bearer bytes before hashing. A salt that fails to
// decode hashes against empty salt, which will simply never match a correctly
// salted stored hash (fail-closed), so a corrupt salt cannot create a match.
func hashBearer(saltHex, bearer string) []byte {
	salt, _ := hex.DecodeString(saltHex)
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(bearer))
	return h.Sum(nil)
}

// HashForRecord computes the at-rest hex hash for a (salt, secret) pair, the
// inverse of what Resolve verifies. It is the helper the Control mint path would
// use to populate a KeyRecord.KeyHash; exposing it here keeps the hash scheme in
// one place so the verifier and the producer can never diverge. It is NOT a key
// issuer (Control mints keys; the gateway never does) — only the hash function.
func HashForRecord(saltHex, secret string) (string, error) {
	if !strings.HasPrefix(secret, KeyPrefix) {
		return "", fmt.Errorf("auth: secret must carry the %q prefix", KeyPrefix)
	}
	return hex.EncodeToString(hashBearer(saltHex, secret)), nil
}

// staticAuthenticator is the minimal-shelf CallerAuthenticator: it validates the
// transport bearer against a boot-loaded staticKeySet in-process. It is the
// concrete that plugs into the ingress Handler on the minimal shelf; the
// full-shelf OAuth-RS authenticator is a sibling concrete behind the same seam.
type staticAuthenticator struct {
	keys KeySet
}

// NewStaticAuthenticator builds the minimal-shelf authenticator over a boot-loaded
// key set. A nil set is a construction error (fail-closed): an authenticator with
// no set would have nothing to validate against.
func NewStaticAuthenticator(keys KeySet) (CallerAuthenticator, error) {
	if keys == nil {
		return nil, fmt.Errorf("auth: NewStaticAuthenticator requires a non-nil KeySet (fail-closed)")
	}
	return &staticAuthenticator{keys: keys}, nil
}

// Authenticate resolves the transport bearer against the boot-loaded set. It
// reads identity ONLY from cred.Bearer (transport material), never a body, and
// performs no per-request Control lookup. An empty bearer or any resolution miss
// is ErrUnauthenticated (fail-closed).
func (a *staticAuthenticator) Authenticate(_ context.Context, cred TransportCredential) (Caller, error) {
	if cred.Bearer == "" {
		return Caller{}, ErrUnauthenticated
	}
	return a.keys.Resolve(cred.Bearer)
}
