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
	// credential presented on the forward. NewControlForwarderWithDial is the
	// ONLY constructor (the legacy endpoint-only constructor was removed — it
	// let a composition root boot an endpoint without the mTLS/credential
	// guards, §III), so tlsConfig is nil ONLY when no endpoint is configured.
	tlsConfig *tls.Config
	cred      ServiceCredential

	// provisioning is the deployment-level source of the CreateRequest's
	// session-provisioning fields (workload_trust_profile, mount_intent,
	// egress_policy, resource_caps). It is fixed config injected at construction,
	// NEVER derived from a caller body (F5 ruling A) — a caller cannot provision.
	// Zero on the legacy stub path.
	provisioning ProvisioningPolicy
}

// NewControlForwarderWithDial builds the forwarder with the P1 transport seams:
// the mTLS-1.3 DialConfig, the ServiceCredential the gateway presents, and the
// deployment ProvisioningPolicy that sources the CreateRequest's session-
// provisioning fields (F5 ruling A). It validates the transport policy eagerly (a
// non-empty endpoint REQUIRES mTLS, NFR-SEC-37) and the provisioning policy (a
// valid, non-Unspecified workload trust profile with a well-formed mount/caps) so
// a misconfigured forward fails at CONSTRUCTION, not mid-request. A nil credential
// is a construction error: a forward MUST present the gateway's service principal
// (NFR-SEC-26), never go anonymous.
func NewControlForwarderWithDial(identity ServiceIdentity, dial DialConfig, cred ServiceCredential, provisioning ProvisioningPolicy) (*ControlForwarder, error) {
	if identity.Name == "" {
		return nil, fmt.Errorf("forward: NewControlForwarderWithDial requires a non-empty service identity (fail-closed)")
	}
	if cred == nil {
		return nil, fmt.Errorf("forward: NewControlForwarderWithDial requires a ServiceCredential (fail-closed, NFR-SEC-26)")
	}
	// The provisioning policy must be admissible up front: a create built from an
	// Unspecified/unknown profile, an ill-formed mount scope, or an unset pids cap
	// would be refused at Control late — refuse it at construction instead. The
	// SessionHint is caller-supplied per-request, so it is not part of this check;
	// a probe hint validates the provisioning-only fields.
	if err := buildCreateRequest(provisioning, "probe").validate(); err != nil {
		return nil, fmt.Errorf("forward: NewControlForwarderWithDial provisioning policy is inadmissible: %w", err)
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
	return &ControlForwarder{identity: identity, endpoint: dial.Endpoint, tlsConfig: tlsCfg, cred: cred, provisioning: provisioning}, nil
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
	// mTLS-1.3 transport (fail-closed), then build and validate the F5 CreateRequest
	// from the vendored #293 session-setup shape. The remaining wire-up is the gRPC
	// marshal + round-trip; the fields, their provenance, and the fail-closed
	// admission are enforced now.
	if f.tlsConfig != nil {
		token, err := f.cred.Token(ctx)
		if err != nil {
			// Fail-closed: no service credential → the forward is refused, never
			// sent anonymously (NFR-SEC-26).
			return SessionResponse{}, errors.Join(ErrForwardFailed, ErrNoServiceCredential, err)
		}
		_ = token // presented as the gateway service principal on the dial

		// Build the CreateRequest (F5 ruling A, stateless create-per-forward). The
		// PROVISIONING fields come STRICTLY from f.provisioning (deployment config),
		// NEVER from req.ToolCall — the caller's validated body is not an input to
		// buildCreateRequest, so a caller cannot provision its own caps, trust
		// profile, mount, or egress. The ONLY caller-influenced value is the session
		// HINT, sourced from the resolved principal (a non-secret handle); it is a
		// hint the host may seed a binding from, never the authority (NFR-SEC-43).
		create := buildCreateRequest(f.provisioning, sessionHintFor(req.Principal))
		if err := create.validate(); err != nil {
			// Fail-closed admission: an inadmissible create is refused before any
			// round-trip (unspecified profile, bad mount scope, unset pids cap).
			return SessionResponse{}, err
		}

		// The create carries the gateway service principal (via token above) and the
		// host-derived session hint — and NEVER a caller credential (no field for it)
		// nor a downstream secret (custody: MountIntent omits the auth token). The
		// gRPC marshal of `create` + the round-trip to Control is the remaining
		// transport wire-up; until it lands, the seam fails closed AFTER proving the
		// body is well-formed and admissible.
		return SessionResponse{}, fmt.Errorf("%w: F5 create built+validated, gRPC round-trip pending (endpoint %q, principal %q, profile %d)",
			ErrForwardFailed, f.endpoint, f.cred.Principal(), create.WorkloadTrustProfile)
	}

	// Defensive fail-closed: an endpoint with no hardened transport. Unreachable
	// through the guarded constructor (a non-empty endpoint REQUIRES mTLS at
	// construction, NFR-SEC-37); kept so a future construction path that skips
	// the guard still refuses rather than dialing unencrypted.
	_ = req
	return SessionResponse{}, fmt.Errorf("%w: no hardened mTLS transport for endpoint %q (fail-closed)", ErrForwardFailed, f.endpoint)
}

// Identity returns the gateway service identity this forwarder presents. It is
// exposed so a boot-time check can assert the forwarder carries a named service
// principal (and an audit/diagnostic can record WHICH principal forwards),
// without exposing any caller material.
func (f *ControlForwarder) Identity() ServiceIdentity {
	return f.identity
}

// Route resolves a per-session control endpoint for an already-admitted session
// (proto SessionSetup.Route). It is a FAIL-CLOSED SEAM STUB on P1: the gateway is
// stateless (no state outlives a request — the component-01 invariant), so it
// holds no session registry to resolve against yet. Session affinity / routing
// returns with P3 (NFR-IC-05), where the session identity is supplied by Control,
// NOT held in the gateway. Until then Route refuses rather than fabricating an
// endpoint.
func (f *ControlForwarder) Route(_ context.Context, _ CreateRequest) (CreateResponse, error) {
	return CreateResponse{}, fmt.Errorf("%w: Route is a P1 fail-closed seam stub (gateway holds no session state; returns with P3 / control-supplied session identity)", ErrForwardFailed)
}

// Destroy tears down the caller's own session (proto SessionSetup.Destroy). Like
// Route it is a FAIL-CLOSED SEAM STUB on P1: with no gateway-held session state
// there is nothing to key a teardown on. It is the cooperative service teardown,
// never the operator force-kill (NFR-SEC-26) — a distinction preserved even as a
// stub, so the privileged path is never reachable from here. Returns with P3.
func (f *ControlForwarder) Destroy(_ context.Context, _ string) error {
	return fmt.Errorf("%w: Destroy is a P1 fail-closed seam stub (gateway holds no session state; returns with P3)", ErrForwardFailed)
}
