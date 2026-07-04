// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// The F5 wire is HTTP/JSON over the hardened mTLS-1.3 transport, NOT gRPC. The
// Control gateway-ingress (ocu-control internal/ingress/gateway) mounts a minimal
// JSON service surface — POST /v1alpha/sessions (create), /v1alpha/sessions/destroy,
// /v1alpha/sessions/status — and decodes each body with DisallowUnknownFields. The
// session-setup proto (contracts/proto/.../session_setup.proto) is the docs-of-
// record for the FIELD SEMANTICS; the wire codec is JSON. The gRPC surface named in
// 08-contracts §1 is a future follow-up that Control itself declares (serve.go), not
// a blocker for the live chain — this is the canon-sanctioned JSON path.
const (
	// createPath is the Control gateway-ingress create route.
	createPath = "/v1alpha/sessions"
	// destroyPath is the cooperative service teardown route (NOT operator force-kill).
	destroyPath = "/v1alpha/sessions/destroy"
)

// createBodyWire is the EXACT JSON shape the Control gateway-ingress createBody
// decodes (ocu-control serve.go), decoded there with DisallowUnknownFields. The
// gateway sends ONLY these three fields; sending a richer body (mount_intent,
// egress, caps) would be rejected 400 by the unknown-field guard until Control
// widens createBody (a coordinated follow-up, G1b). The rich frozen-proto
// CreateRequest still drives the IN-GATEWAY admission build+validate before the
// forward; only the wire projection is these three fields.
//
//   - session_hint: the caller-derived hint (the resolved Tenant), never authority
//     (NFR-SEC-43). Control derives the real session_id from the mTLS SAN.
//   - image: empty on a bare G3 create — the sandbox image ref is PIN-PENDING at
//     the gatekeeper (#205 reconciliation); the gateway does not invent it.
//   - control_pub_key: empty on a bare G3 create — the raw Ed25519 public key is
//     staged for the exec channel, which Control drives (ADR-0024, the G2 exec-
//     driver); the gateway does not generate the key pair.
type createBodyWire struct {
	SessionHint   string `json:"session_hint"`
	Image         string `json:"image"`
	ControlPubKey []byte `json:"control_pub_key"`
}

// destroyBodyWire is the Control gateway-ingress destroy body: a session hint that
// ADDRESSES the caller's OWN session through the host-derived binding. It is a hint,
// never authority (NFR-SEC-43) — a foreign hint yields not-found, never a teardown.
type destroyBodyWire struct {
	SessionHint string `json:"session_hint"`
}

// sessionResponseWire is the Control gateway-ingress reply: the host-derived key
// and the numeric lifecycle state, and nothing else. The gateway surfaces ONLY the
// key as a stable correlation handle to the caller (identifier-minimization,
// invariant #5); the state is not relayed as caller-addressable authority.
type sessionResponseWire struct {
	Key   string `json:"key"`
	State int    `json:"state"`
}

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
// This is NOT a mock: it is the real forwarder that performs a live HTTP/JSON
// create round-trip to Control over the hardened mTLS transport, presenting the
// gateway service credential and failing closed when the transport, the credential,
// or the create admission is absent/invalid. The SESSION-REQUEST WIRE FIELDS are
// NOT invented: the FIELD SEMANTICS come from the frozen Control session-setup proto
// (session_setup.proto, PR #293), and the JSON wire projection is exactly the shape
// Control's gateway-ingress createBody decodes (session_hint, image, control_pub_key).
// The security properties (mTLS-only, service-credential-only, no caller credential,
// fail-closed) are enforced on every path.
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

	// Live F5 dial path: present the gateway service credential over the hardened
	// mTLS-1.3 transport (fail-closed), build+validate the F5 CreateRequest from the
	// frozen session-setup shape, then perform the HTTP/JSON create round-trip to
	// Control. The security properties (mTLS-only, service-credential-only, no caller
	// credential, fail-closed admission) are enforced before a byte leaves.
	if f.tlsConfig != nil {
		token, err := f.cred.Token(ctx)
		if err != nil {
			// Fail-closed: no service credential → the forward is refused, never
			// sent anonymously (NFR-SEC-26).
			return SessionResponse{}, errors.Join(ErrForwardFailed, ErrNoServiceCredential, err)
		}

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

		// The JSON wire projection is EXACTLY the three fields Control's createBody
		// decodes (DisallowUnknownFields). The rich provisioning fields built+validated
		// above are an IN-GATEWAY admission gate; the wire carries only the hint
		// (image / control_pub_key are empty on a bare G3 create — PIN-PENDING / G2).
		// A caller credential appears nowhere: the body has no field for it, and the
		// service principal is asserted by the mTLS client cert + the bearer token,
		// never the caller's key.
		wire := createBodyWire{SessionHint: create.SessionHint}
		respBody, err := f.postJSON(ctx, token, createPath, wire)
		if err != nil {
			return SessionResponse{}, err
		}

		var reply sessionResponseWire
		if err := json.Unmarshal(respBody, &reply); err != nil {
			return SessionResponse{}, fmt.Errorf("%w: decode create reply: %w", ErrForwardFailed, err)
		}

		// Identifier-minimization at the boundary (invariant #5): the host-derived key
		// is surfaced ONLY as the stable correlation handle — never as an addressable
		// session id or internal topology. The lifecycle state is not relayed as
		// caller authority. The ingress response path performs the final minimization.
		return SessionResponse{Correlation: reply.Key}, nil
	}

	// Defensive fail-closed: an endpoint with no hardened transport. Unreachable
	// through the guarded constructor (a non-empty endpoint REQUIRES mTLS at
	// construction, NFR-SEC-37); kept so a future construction path that skips
	// the guard still refuses rather than dialing unencrypted.
	_ = req
	return SessionResponse{}, fmt.Errorf("%w: no hardened mTLS transport for endpoint %q (fail-closed)", ErrForwardFailed, f.endpoint)
}

// postJSON performs one mTLS HTTP/JSON POST to Control under the gateway service
// identity: it marshals body, dials endpoint+path over the hardened TLS-1.3
// transport (presenting the gateway CLIENT CERT — the "m" in mTLS — and the service
// bearer token), and returns the response body on a 2xx. A non-2xx, a transport
// error, or an over-large reply is a fail-closed ErrForwardFailed — never a
// fabricated success. The caller credential is not reachable here: only the service
// token and the client cert assert identity, and body is a gateway-built value.
//
// A fresh http.Client is built per call over f.tlsConfig rather than cached so the
// forwarder holds no long-lived connection state (no state outlives a request —
// the component-01 invariant); the transport config itself is the stored, hardened
// one. Response reads are bounded (maxReplyBytes) so a hostile/oversized reply
// cannot exhaust memory.
func (f *ControlForwarder) postJSON(ctx context.Context, token, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request body: %w", ErrForwardFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrForwardFailed, err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	// The service token is presented as the gateway's OWN service principal (the
	// host-side "Generic internal token", §8) — NEVER a caller credential. Control
	// primarily attests the gateway by the verified mTLS client-cert SAN; the bearer
	// is the service-to-service token, not any caller sk-ocu- key.
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: f.tlsConfig}}
	resp, err := client.Do(req)
	if err != nil {
		// A transport / TLS / dial failure is a fail-closed refusal, never a silent
		// drop or a pretended success.
		return nil, fmt.Errorf("%w: F5 %s round-trip: %w", ErrForwardFailed, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bound the reply read so an oversized/hostile response cannot exhaust memory.
	const maxReplyBytes = 64 << 10
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: read F5 %s reply: %w", ErrForwardFailed, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// A non-2xx (auth-fail, admission conflict, not-found, provider error) is a
		// fail-closed refusal to the caller. The status is recorded, but the reply
		// body is NOT surfaced verbatim to the caller (it may carry control-side
		// detail); the ingress maps this to a leak-free 502 (invariant #5).
		return nil, fmt.Errorf("%w: control returned status %d on %s", ErrForwardFailed, resp.StatusCode, path)
	}
	return respBody, nil
}

// Identity returns the gateway service identity this forwarder presents. It is
// exposed so a boot-time check can assert the forwarder carries a named service
// principal (and an audit/diagnostic can record WHICH principal forwards),
// without exposing any caller material.
func (f *ControlForwarder) Identity() ServiceIdentity {
	return f.identity
}

// Route resolves a per-session control endpoint for an already-admitted session
// (proto SessionSetup.Route). It is a FAIL-CLOSED SEAM STUB, and deliberately so:
// the canon RouteResponse{control_endpoint} needs a PER-SESSION control endpoint,
// which is the address of the exec channel — and Control does not yet expose one.
// The Control gateway-ingress /v1alpha/sessions/status returns {key, state}, NOT a
// control_endpoint, so resolving Route through status would return the wrong
// contract (a key/state where an endpoint is owed). The per-session control_endpoint
// appears when Control implements the exec-driver (the G2 exec-driver wave, ADR-0024
// / NFR-IC-05); Route correctly comes alive then, over the same mTLS transport. Until
// then it refuses rather than fabricating an endpoint.
func (f *ControlForwarder) Route(_ context.Context, _ CreateRequest) (CreateResponse, error) {
	return CreateResponse{}, fmt.Errorf("%w: Route returns when Control exposes a per-session control_endpoint (G2 exec-driver, ADR-0024); status returns key/state, not an endpoint", ErrForwardFailed)
}

// Destroy tears down the caller's OWN session over the live F5 leg (proto
// SessionSetup.Destroy → POST /v1alpha/sessions/destroy). It is the COOPERATIVE
// service teardown, NEVER the operator force-kill (NFR-SEC-26) — the privileged
// force path is absent from this service surface. The sessionHint ADDRESSES the
// caller's own session; Control keys ownership on the host-attested mTLS SAN, so a
// foreign or absent hint yields a not-found refusal, never another tenant's teardown
// (NFR-SEC-43). With no configured endpoint or hardened transport it fails closed.
func (f *ControlForwarder) Destroy(ctx context.Context, sessionHint string) error {
	if f.endpoint == "" {
		return fmt.Errorf("%w: no Control endpoint configured", ErrForwardFailed)
	}
	if f.tlsConfig == nil {
		return fmt.Errorf("%w: no hardened mTLS transport for endpoint %q (fail-closed)", ErrForwardFailed, f.endpoint)
	}
	token, err := f.cred.Token(ctx)
	if err != nil {
		return errors.Join(ErrForwardFailed, ErrNoServiceCredential, err)
	}
	if _, err := f.postJSON(ctx, token, destroyPath, destroyBodyWire{SessionHint: sessionHint}); err != nil {
		return err
	}
	return nil
}
