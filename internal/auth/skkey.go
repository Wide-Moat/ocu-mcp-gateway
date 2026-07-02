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
	// Deployment is the deployment scope this key is valid for (the key-set
	// schema's `deployment`, ADR-0027). A key whose deployment does not match this
	// gateway's deployment is refused (the resolve-time second layer of the
	// deployment guard; the boot loader also refuses a heterogeneous set).
	Deployment string
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
	// deployment is this gateway's own deployment scope. Resolve refuses a record
	// whose Deployment does not match it (the resolve-time second layer of the
	// deployment guard, defence-in-depth behind the boot loader's homogeneity
	// check). It is set from the gateway's -deployment config at construction.
	deployment string
	// now is injected so a test can drive expiry deterministically; production
	// passes time.Now.
	now func() time.Time
}

// NewStaticKeySet builds a minimal-shelf KeySet from boot-loaded records, bound to
// this gateway's deployment. The now func defaults to time.Now when nil. An empty
// record set is permitted (it simply authenticates nothing — fail-closed), so boot
// can distinguish "loaded, empty" from "failed to load" at the loader seam rather
// than here. Resolve refuses any record whose Deployment does not equal deployment
// (the resolve-time deployment guard).
func NewStaticKeySet(records []KeyRecord, deployment string, now func() time.Time) KeySet {
	if now == nil {
		now = time.Now
	}
	// Copy the slice so a caller cannot mutate the set after construction.
	cp := make([]KeyRecord, len(records))
	copy(cp, records)
	return &staticKeySet{records: cp, deployment: deployment, now: now}
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
		// Resolve-time deployment guard (layer ii): a record scoped to another
		// deployment never authenticates here, even if it somehow reached the set
		// past the boot loader's homogeneity check (a future non-boot load path).
		// A confused-deputy foreign key thus cannot resolve against this gateway.
		if rec.Deployment != s.deployment {
			continue
		}
		want, err := hex.DecodeString(rec.KeyHash)
		if err != nil {
			// A malformed stored hash never authenticates; skip it fail-closed
			// rather than treating a decode error as a match.
			continue
		}
		got, gerr := hashBearer(rec.Salt, bearer)
		if gerr != nil {
			// A record whose salt does not decode never authenticates (it would
			// be an unsalted hash — pass-the-hash). Skip it fail-closed, like the
			// malformed stored hash above; salt validity is an at-rest record
			// attribute, not secret-dependent, so the skip leaks no timing about
			// the bearer.
			continue
		}
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
		KeyID:      matched.KeyID,
		Tenant:     matched.Tenant,
		Deployment: matched.Deployment,
	}, nil
}

// hashBearer computes sha256(salt‖secret) for a presented bearer, returning the
// raw digest bytes. The salt is the record's hex-encoded per-key salt; it is
// decoded and prepended to the bearer bytes before hashing. A salt that fails to
// decode is an ERROR, never a silent partial-salt hash: a self-audit showed the
// old ignore-the-error path was mirrored by the producer (HashForRecord), so a
// corrupt salt round-tripped into an effectively UNSALTED sha256(secret) that
// authenticated — the pass-the-hash weakness the salt exists to prevent
// (GHSA-69x8-hrgq-fjj8). Fail-closed on both sides instead.
func hashBearer(saltHex, bearer string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, fmt.Errorf("auth: salt is not decodable hex (fail-closed, never hashed unsalted): %w", err)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(bearer))
	return h.Sum(nil), nil
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
	digest, err := hashBearer(saltHex, secret)
	if err != nil {
		// Refuse to mint a record hash over a corrupt salt — the producer half
		// of the fail-closed pair (the verifier half is Resolve's skip).
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

// staticAuthenticator is the minimal-shelf CallerAuthenticator: it validates the
// transport bearer against a boot-loaded staticKeySet in-process. It is the
// concrete that plugs into the ingress Handler on the minimal shelf; the
// full-shelf OAuth-RS authenticator is a sibling concrete behind the same seam.
type staticAuthenticator struct {
	// provider returns the CURRENT key set on each call, so a boot-set Refresh
	// (an atomic swap upstream) takes effect on the next resolve without rebuilding
	// the authenticator. A snapshot authenticator wraps a constant provider.
	provider func() KeySet
}

// NewStaticAuthenticator builds the minimal-shelf authenticator over a FIXED
// boot-loaded key set (a snapshot). A nil set is a construction error
// (fail-closed): an authenticator with no set would have nothing to validate
// against. Use NewStaticAuthenticatorLive when the set is refreshed at runtime.
func NewStaticAuthenticator(keys KeySet) (CallerAuthenticator, error) {
	if keys == nil {
		return nil, fmt.Errorf("auth: NewStaticAuthenticator requires a non-nil KeySet (fail-closed)")
	}
	return &staticAuthenticator{provider: func() KeySet { return keys }}, nil
}

// NewStaticAuthenticatorLive builds the authenticator over a LIVE key-set
// provider (the boot sequencer's live pointer), so a Refresh that swaps the set
// is seen on the next resolve — the path by which a revoked key stops
// authenticating within the refresh window (NFR-SEC-04). A nil provider is a
// construction error. The provider MAY return nil (e.g. before the first load);
// Authenticate treats a nil set as authenticate-nothing (fail-closed), never a
// nil-deref or an admit-all.
func NewStaticAuthenticatorLive(provider func() KeySet) (CallerAuthenticator, error) {
	if provider == nil {
		return nil, fmt.Errorf("auth: NewStaticAuthenticatorLive requires a non-nil provider (fail-closed)")
	}
	return &staticAuthenticator{provider: provider}, nil
}

// Authenticate resolves the transport bearer against the CURRENT boot-loaded set.
// It reads identity ONLY from cred.Bearer (transport material), never a body, and
// performs no per-request Control lookup. An empty bearer, a nil current set, or
// any resolution miss is ErrUnauthenticated (fail-closed).
func (a *staticAuthenticator) Authenticate(_ context.Context, cred TransportCredential) (Caller, error) {
	if cred.Bearer == "" {
		return Caller{}, ErrUnauthenticated
	}
	ks := a.provider()
	if ks == nil {
		// No current set (pre-load, or a provider returning nil) → authenticate
		// nothing, never nil-deref or admit-all.
		return Caller{}, ErrUnauthenticated
	}
	return ks.Resolve(cred.Bearer)
}
