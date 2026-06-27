// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
)

// staticCred is a test ServiceCredential presenting a fixed token/principal.
type staticCred struct {
	token     string
	principal string
	err       error
}

func (c staticCred) Token(context.Context) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	return c.token, nil
}
func (c staticCred) Principal() string { return c.principal }

// goodTLS is a minimal non-nil mTLS config for tests. MinVersion is set to TLS
// 1.2 deliberately so TestMinTLS13RaisesVersion can prove minTLS13 raises it to
// 1.3 (the production floor); this is test-only input, never a served config.
func goodTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func TestNewWithDialRequiresServiceCredential(t *testing.T) {
	_, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "https://control:8443", TLS: goodTLS()},
		nil,
	)
	if err == nil {
		t.Fatal("a nil ServiceCredential must fail closed (NFR-SEC-26)")
	}
}

func TestNewWithDialRequiresMTLSWhenEndpointSet(t *testing.T) {
	_, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "https://control:8443", TLS: nil}, // no mTLS
		staticCred{token: "t", principal: "gw"},
	)
	if !errors.Is(err, ErrForwardFailed) {
		t.Fatalf("a configured endpoint without mTLS must fail (NFR-SEC-37), got %v", err)
	}
}

func TestNewWithDialRequiresIdentity(t *testing.T) {
	_, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: ""},
		DialConfig{TLS: goodTLS()},
		staticCred{token: "t", principal: "gw"},
	)
	if err == nil {
		t.Fatal("an empty service identity must fail closed")
	}
}

func TestMinTLS13RaisesVersion(t *testing.T) {
	got := minTLS13(goodTLS())
	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf("minTLS13 must raise the minimum to TLS 1.3, got %x", got.MinVersion)
	}
}

func TestDialForwardFailsClosedOnCredError(t *testing.T) {
	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "https://control:8443", TLS: goodTLS()},
		staticCred{err: errors.New("token source down"), principal: "gw"},
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	_, ferr := f.Forward(context.Background(), SessionRequest{})
	if !errors.Is(ferr, ErrNoServiceCredential) {
		t.Fatalf("a credential error must fail closed with ErrNoServiceCredential, got %v", ferr)
	}
	if !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("must also wrap ErrForwardFailed, got %v", ferr)
	}
}

// TestDialForwardDoesNotInventFields proves the dial path does NOT fabricate the
// session-request wire fields — it fails closed pending the frozen PR #293 schema
// rather than sending an invented body. This guards against the fail-open class
// of an invented cross-component contract.
func TestDialForwardPendingFrozenSchema(t *testing.T) {
	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "https://control:8443", TLS: goodTLS()},
		staticCred{token: "tok", principal: "gw-principal"},
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	_, ferr := f.Forward(context.Background(), SessionRequest{})
	// The credential is good, the mTLS is valid — so the ONLY remaining gate is
	// the pending #293 wire fields. It must fail closed there, not pretend success
	// and not invent a body.
	if !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("the dial path must fail closed pending #293, got %v", ferr)
	}
}

func TestDialForwardNoEndpointFailsClosed(t *testing.T) {
	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "", TLS: goodTLS()}, // no endpoint
		staticCred{token: "t", principal: "gw"},
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, ferr := f.Forward(context.Background(), SessionRequest{}); !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("no endpoint must fail closed, got %v", ferr)
	}
}
