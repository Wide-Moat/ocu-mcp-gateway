// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// A self-audit found hashBearer silently ignoring a salt hex-decode error and
// hashing with the PARTIAL (typically empty) decode result. The old comment
// claimed a corrupt salt "cannot create a match" — false: the PRODUCER
// (HashForRecord) and the VERIFIER (Resolve → hashBearer) ignored the error
// IDENTICALLY, so a record minted with a corrupt salt round-trips and
// authenticates as an effectively UNSALTED sha256(secret) — the exact
// pass-the-hash weakness the per-key salt exists to prevent (GHSA-69x8-hrgq-fjj8;
// the boot loader's schema check guards the file path, but HashForRecord and
// NewStaticKeySet accept records from any future path). Fail-closed now: a salt
// that does not decode REFUSES on both sides.

// TestHashForRecordRefusesUndecodableSalt pins the producer side: minting a
// record hash over a corrupt salt is an error, never a silent unsalted hash.
func TestHashForRecordRefusesUndecodableSalt(t *testing.T) {
	if _, err := HashForRecord("zz-not-hex", "sk-ocu-secret"); err == nil {
		t.Error("HashForRecord must refuse a salt that does not hex-decode (a silent partial decode mints an unsalted hash)")
	}
}

// TestResolveSkipsRecordWithUndecodableSalt pins the verifier side: a record
// whose stored hash is exactly what the OLD ignore-the-error path computed
// (sha256 of the bare secret — empty decoded salt) must NOT authenticate. Under
// the old behavior this test goes RED because Resolve reproduces the same
// partial decode and matches; fail-closed, the record is skipped.
func TestResolveSkipsRecordWithUndecodableSalt(t *testing.T) {
	const secret = "sk-ocu-secret"
	unsalted := sha256.Sum256([]byte(secret))
	rec := KeyRecord{
		KeyID:      "key-corrupt-salt",
		KeyHash:    hex.EncodeToString(unsalted[:]),
		Salt:       "zz-not-hex",
		Tenant:     "tenant-a",
		Deployment: "deploy-1",
		Status:     StatusActive,
	}
	ks := NewStaticKeySet([]KeyRecord{rec}, "deploy-1", nil)
	if _, err := ks.Resolve(secret); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a record with an undecodable salt must never authenticate (it would be an unsalted hash — pass-the-hash); got %v", err)
	}
}
