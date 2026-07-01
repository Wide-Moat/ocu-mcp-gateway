// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
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

// validProvisioning is an admissible deployment ProvisioningPolicy for tests: a
// real (non-Unspecified) workload trust profile, a single-scope mount, a
// deny-default egress, and a set pids cap. It models the deployment config the
// gateway is constructed with, so a test can reach the create-build path.
func validProvisioning() ProvisioningPolicy {
	pids := int64(512)
	return ProvisioningPolicy{
		WorkloadTrustProfile: WorkloadTrustProfileInternalWorkforce,
		MountIntent:          MountIntent{Destination: "/workspace", FilesystemID: "fs-1", ReadOnly: false, CacheDurationS: 30},
		EgressPolicy:         EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store", FilesystemID: "fs-1"},
		ResourceCaps:         ResourceCaps{CPUCores: 1.0, MemoryBytes: 512 << 20, PIDsLimit: &pids},
	}
}

func TestNewWithDialRequiresServiceCredential(t *testing.T) {
	_, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "https://control:8443", TLS: goodTLS()},
		nil,
		validProvisioning(),
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
		validProvisioning(),
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
		validProvisioning(),
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
		validProvisioning(),
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
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	_, ferr := f.Forward(context.Background(), SessionRequest{Principal: auth.Caller{Tenant: "tenant-a"}})
	// The credential is good, the mTLS is valid, and the create builds+validates —
	// so the ONLY remaining gate is the gRPC round-trip. It must fail closed there,
	// not pretend success.
	if !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("the dial path must fail closed pending the gRPC round-trip, got %v", ferr)
	}
}

func TestDialForwardNoEndpointFailsClosed(t *testing.T) {
	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "", TLS: goodTLS()}, // no endpoint
		staticCred{token: "t", principal: "gw"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, ferr := f.Forward(context.Background(), SessionRequest{}); !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("no endpoint must fail closed, got %v", ferr)
	}
}
