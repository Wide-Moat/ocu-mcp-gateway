// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"fmt"
)

// ServiceIdentity is the gateway's own identity presented on the F5 forward. It
// is the transport's own material (a host-local signing key on the minimal shelf,
// a customer-PKI workload identity on the full shelf), set at construction from
// config — NEVER a value a caller supplies. A caller therefore cannot influence
// the forward principal (P1-S2 mitigation). It carries no operator scope.
type ServiceIdentity struct {
	// Name is the gateway service principal name presented upstream. It is the
	// gateway's own identity, distinct from any caller.
	Name string
}

// ControlForwarder forwards session requests to the Control/operator API over the
// F5 leg under the gateway's own ServiceIdentity. The concrete transport (an
// mTLS/workload-identity HTTP client to the Control plane) is wired from config;
// until a Control endpoint is configured it fails closed on every forward, so the
// gateway never silently drops a request or admits an unattested forward.
//
// This is NOT a mock: it is the real forwarder shell that presents the gateway
// service identity and fails closed absent a configured upstream. The HTTP dial
// to a live Control endpoint is the remaining wire-up; the security properties
// (service-identity-only, no caller credential, fail-closed) are enforced here
// regardless of whether the endpoint is set.
type ControlForwarder struct {
	identity ServiceIdentity
	endpoint string // Control/operator API base URL; empty => fail closed
}

// NewControlForwarder builds the forwarder with the gateway service identity and
// the Control endpoint. An empty identity name is a construction error: a forward
// MUST present a service principal, and an unnamed identity would forward
// anonymously. An empty endpoint is permitted at construction (the scaffold may
// boot without a live Control), but every Forward then fails closed.
func NewControlForwarder(identity ServiceIdentity, endpoint string) (*ControlForwarder, error) {
	if identity.Name == "" {
		return nil, fmt.Errorf("forward: NewControlForwarder requires a non-empty service identity (fail-closed)")
	}
	return &ControlForwarder{identity: identity, endpoint: endpoint}, nil
}

// Forward sends req to the Control/operator API under the gateway service
// identity. It attaches ONLY the gateway service principal — the caller
// credential is not reachable from req (SessionRequest has no field for it). With
// no configured endpoint it fails closed with ErrForwardFailed rather than
// pretending success.
func (f *ControlForwarder) Forward(_ context.Context, req SessionRequest) (SessionResponse, error) {
	if f.endpoint == "" {
		return SessionResponse{}, fmt.Errorf("%w: no Control endpoint configured", ErrForwardFailed)
	}
	// A live forward dials f.endpoint presenting f.identity as the service
	// principal (mTLS client cert / workload identity), carrying req.ToolCall and
	// req.Principal (the resolved, non-secret caller handle) — and NEVER a caller
	// credential. The HTTP round-trip to a live Control endpoint is the remaining
	// wire-up; the security shape (service-identity-only, fail-closed) is fixed
	// here. Until then, a configured-but-unreachable endpoint also fails closed.
	_ = req
	return SessionResponse{}, fmt.Errorf("%w: Control transport not yet wired (endpoint %q)", ErrForwardFailed, f.endpoint)
}

// Identity returns the gateway service identity this forwarder presents. It is
// exposed so a boot-time check can assert the forwarder carries a named service
// principal (and an audit/diagnostic can record WHICH principal forwards),
// without exposing any caller material.
func (f *ControlForwarder) Identity() ServiceIdentity {
	return f.identity
}
