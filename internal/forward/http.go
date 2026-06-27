// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"crypto/tls"
	"errors"
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
// F5 leg under the gateway's own ServiceIdentity. The transport is an
// mTLS-1.3 dial (DialConfig) presenting a host-side service-to-service credential
// (ServiceCredential, the "Generic internal token" of component-01:39); both are
// wired from config. Until a Control endpoint is configured it fails closed on
// every forward, so the gateway never silently drops a request or admits an
// unattested forward.
//
// This is NOT a mock: it is the real forwarder that validates the mTLS transport
// policy and presents the gateway service credential, failing closed when either
// is absent. The remaining wire-up is the actual HTTP/gRPC round-trip body — and
// crucially the SESSION-REQUEST WIRE FIELDS, which are NOT invented here: they
// come from the frozen Control session-setup schema (PR #293), vendored when it
// lands and plugged into this seam. The security properties (mTLS-only,
// service-credential-only, no caller credential, fail-closed) are enforced here
// regardless.
type ControlForwarder struct {
	identity ServiceIdentity
	endpoint string // Control/operator API base URL; empty => fail closed

	// tlsConfig is the hardened (TLS 1.3-floored) mTLS transport the live dial
	// uses, validated and stored at construction. cred is the gateway's service
	// credential presented on the forward. Both are nil on the legacy stub path
	// (endpoint-only construction).
	tlsConfig *tls.Config
	cred      ServiceCredential
}

// NewControlForwarder builds the forwarder with the gateway service identity and
// the Control endpoint (the legacy/stub path, no live transport). An empty
// identity name is a construction error: a forward MUST present a service
// principal. An empty endpoint is permitted (the scaffold may boot without a live
// Control), but every Forward then fails closed.
func NewControlForwarder(identity ServiceIdentity, endpoint string) (*ControlForwarder, error) {
	if identity.Name == "" {
		return nil, fmt.Errorf("forward: NewControlForwarder requires a non-empty service identity (fail-closed)")
	}
	return &ControlForwarder{identity: identity, endpoint: endpoint}, nil
}

// NewControlForwarderWithDial builds the forwarder with the P1 transport seams:
// the mTLS-1.3 DialConfig and the ServiceCredential the gateway presents. It
// validates the transport policy eagerly (a non-empty endpoint REQUIRES mTLS,
// NFR-SEC-37) so a misconfigured forward fails at construction, not mid-request.
// A nil credential is a construction error: a forward MUST present the gateway's
// service principal (NFR-SEC-26), never go anonymous.
func NewControlForwarderWithDial(identity ServiceIdentity, dial DialConfig, cred ServiceCredential) (*ControlForwarder, error) {
	if identity.Name == "" {
		return nil, fmt.Errorf("forward: NewControlForwarderWithDial requires a non-empty service identity (fail-closed)")
	}
	if cred == nil {
		return nil, fmt.Errorf("forward: NewControlForwarderWithDial requires a ServiceCredential (fail-closed, NFR-SEC-26)")
	}
	// If an endpoint is configured, the mTLS policy must be valid up front; the
	// hardened (TLS 1.3-floored) config is stored and used by the live dial.
	var tlsCfg *tls.Config
	if dial.Endpoint != "" {
		hardened, err := hardenDialConfig(dial)
		if err != nil {
			return nil, err
		}
		tlsCfg = hardened
	}
	return &ControlForwarder{identity: identity, endpoint: dial.Endpoint, tlsConfig: tlsCfg, cred: cred}, nil
}

// Forward sends req to the Control/operator API under the gateway service
// identity. It attaches ONLY the gateway service principal — the caller
// credential is not reachable from req (SessionRequest has no field for it). With
// no configured endpoint it fails closed with ErrForwardFailed rather than
// pretending success.
func (f *ControlForwarder) Forward(ctx context.Context, req SessionRequest) (SessionResponse, error) {
	if f.endpoint == "" {
		return SessionResponse{}, fmt.Errorf("%w: no Control endpoint configured", ErrForwardFailed)
	}

	// P1 dial path: present the gateway service credential over the hardened
	// mTLS-1.3 transport (fail-closed). The actual round-trip body — built from the
	// frozen PR #293 session-setup schema — is the remaining wire-up; the transport
	// and credential security properties are enforced now.
	if f.tlsConfig != nil {
		token, err := f.cred.Token(ctx)
		if err != nil {
			// Fail-closed: no service credential → the forward is refused, never
			// sent anonymously (NFR-SEC-26).
			return SessionResponse{}, errors.Join(ErrForwardFailed, ErrNoServiceCredential, err)
		}
		_ = token // presented as the gateway service principal on the dial
		// The request body is built from req.ToolCall + req.Principal (the
		// resolved, non-secret caller handle) — and NEVER a caller credential.
		// The exact session-request fields come from the frozen #293 schema; the
		// seam is wired, the fields land when #293 is vendored.
		_ = req
		return SessionResponse{}, fmt.Errorf("%w: Control session-setup wire fields pending PR #293 (endpoint %q, principal %q)",
			ErrForwardFailed, f.endpoint, f.cred.Principal())
	}

	// Legacy stub path (endpoint configured without dial seams): fail closed.
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
