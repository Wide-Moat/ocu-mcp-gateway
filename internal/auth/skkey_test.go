// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// mkRecord builds a KeyRecord whose stored hash is the salted SHA-256 of secret,
// the same scheme Resolve verifies — so a test exercises the real crypto path,
// not a stub.
func mkRecord(t *testing.T, keyID, saltHex, secret, tenant, audience string, status KeyStatus, exp time.Time) KeyRecord {
	t.Helper()
	hash, err := HashForRecord(saltHex, secret)
	if err != nil {
		t.Fatalf("HashForRecord: %v", err)
	}
	return KeyRecord{
		KeyID: keyID, KeyHash: hash, Salt: saltHex,
		Tenant: tenant, Audience: audience, Status: status, ExpiresAt: exp,
	}
}

func TestStaticKeySetResolvesActiveKey(t *testing.T) {
	salt := hex.EncodeToString([]byte("per-key-salt-1"))
	secret := "sk-ocu-abc123def456"
	rec := mkRecord(t, "key-1", salt, secret, "tenant-a", "deploy-x", StatusActive, time.Time{})
	ks := NewStaticKeySet([]KeyRecord{rec}, nil)

	c, err := ks.Resolve(secret)
	if err != nil {
		t.Fatalf("Resolve active key: %v", err)
	}
	if c.KeyID != "key-1" || c.Tenant != "tenant-a" || c.Audience != "deploy-x" {
		t.Fatalf("resolved Caller mismatch: %+v", c)
	}
}

func TestStaticKeySetRejectsWrongSecret(t *testing.T) {
	salt := hex.EncodeToString([]byte("per-key-salt-2"))
	rec := mkRecord(t, "key-1", salt, "sk-ocu-correct-secret", "t", "d", StatusActive, time.Time{})
	ks := NewStaticKeySet([]KeyRecord{rec}, nil)

	_, err := ks.Resolve("sk-ocu-wrong-secret")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated for wrong secret, got %v", err)
	}
}

func TestStaticKeySetRejectsMissingPrefix(t *testing.T) {
	salt := hex.EncodeToString([]byte("salt"))
	rec := mkRecord(t, "key-1", salt, "sk-ocu-secret", "t", "d", StatusActive, time.Time{})
	ks := NewStaticKeySet([]KeyRecord{rec}, nil)

	// A bearer without the sk-ocu- prefix is structurally rejected.
	_, err := ks.Resolve("not-a-key-secret")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated for prefixless bearer, got %v", err)
	}
}

func TestStaticKeySetRejectsRevoked(t *testing.T) {
	salt := hex.EncodeToString([]byte("salt"))
	secret := "sk-ocu-revoked-key"
	rec := mkRecord(t, "key-1", salt, secret, "t", "d", StatusRevoked, time.Time{})
	ks := NewStaticKeySet([]KeyRecord{rec}, nil)

	if _, err := ks.Resolve(secret); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated for revoked key, got %v", err)
	}
}

func TestStaticKeySetRejectsExpired(t *testing.T) {
	salt := hex.EncodeToString([]byte("salt"))
	secret := "sk-ocu-expired-key"
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rec := mkRecord(t, "key-1", salt, secret, "t", "d", StatusActive, past)
	fixedNow := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	ks := NewStaticKeySet([]KeyRecord{rec}, fixedNow)

	if _, err := ks.Resolve(secret); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want ErrUnauthenticated for expired key, got %v", err)
	}
}

func TestStaticKeySetNonExpiringWhenZeroExpiry(t *testing.T) {
	salt := hex.EncodeToString([]byte("salt"))
	secret := "sk-ocu-eternal-key"
	rec := mkRecord(t, "key-1", salt, secret, "t", "d", StatusActive, time.Time{}) // zero expiry = non-expiring
	ks := NewStaticKeySet([]KeyRecord{rec}, nil)

	if _, err := ks.Resolve(secret); err != nil {
		t.Fatalf("a zero-expiry key must not expire; got %v", err)
	}
}

func TestStaticKeySetEmptyAuthenticatesNothing(t *testing.T) {
	ks := NewStaticKeySet(nil, nil)
	if _, err := ks.Resolve("sk-ocu-anything"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("an empty key set must authenticate nothing; got %v", err)
	}
}

func TestHashForRecordRejectsPrefixlessSecret(t *testing.T) {
	if _, err := HashForRecord(hex.EncodeToString([]byte("s")), "no-prefix"); err == nil {
		t.Fatal("HashForRecord must reject a secret without the sk-ocu- prefix")
	}
}

func TestStaticAuthenticatorRejectsEmptyBearer(t *testing.T) {
	ks := NewStaticKeySet(nil, nil)
	a, err := NewStaticAuthenticator(ks)
	if err != nil {
		t.Fatalf("NewStaticAuthenticator: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), TransportCredential{Bearer: ""}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty bearer must be ErrUnauthenticated, got %v", err)
	}
}

func TestStaticAuthenticatorResolvesViaSeam(t *testing.T) {
	salt := hex.EncodeToString([]byte("salt"))
	secret := "sk-ocu-good-key"
	rec := mkRecord(t, "key-9", salt, secret, "tnt", "aud", StatusActive, time.Time{})
	a, err := NewStaticAuthenticator(NewStaticKeySet([]KeyRecord{rec}, nil))
	if err != nil {
		t.Fatalf("NewStaticAuthenticator: %v", err)
	}
	c, err := a.Authenticate(context.Background(), TransportCredential{Bearer: secret})
	if err != nil {
		t.Fatalf("Authenticate good key: %v", err)
	}
	if c.KeyID != "key-9" {
		t.Fatalf("want KeyID key-9, got %q", c.KeyID)
	}
}

func TestNewStaticAuthenticatorNilSetFailsClosed(t *testing.T) {
	if _, err := NewStaticAuthenticator(nil); err == nil {
		t.Fatal("NewStaticAuthenticator(nil) must fail closed")
	}
}
