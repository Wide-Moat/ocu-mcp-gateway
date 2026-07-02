// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"testing"
)

// The endpoint-only legacy constructor was REMOVED (§III): it let a composition
// root construct a forwarder with a Control endpoint but WITHOUT the mTLS
// (NFR-SEC-37) and service-credential (NFR-SEC-26) guards that live on
// NewControlForwarderWithDial — the "guarded path exists, production does not
// walk it" class. Construction and fail-closed behavior are covered by
// dial_test.go against the ONLY remaining constructor; the shipped composition
// root is pinned by cmd/ocu-mcp-gatewayd/wiring_test.go.

func TestControlForwarderExposesIdentityNotCaller(t *testing.T) {
	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{}, // no endpoint: boots, every Forward fails closed
		staticCred{token: "t", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if f.Identity().Name != "ocu-mcp-gateway" {
		t.Fatalf("Identity should return the gateway service principal, got %q", f.Identity().Name)
	}
}
