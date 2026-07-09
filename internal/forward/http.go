// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"
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
	// execPath is the Control gateway-ingress exec route (G2 exec-driver). It runs
	// a command in the session the create hop provisioned, keyed by the SAME
	// session_hint.
	execPath = "/v1alpha/sessions/exec"
)

// createBodyWire is the EXACT JSON shape the Control gateway-ingress createBody
// decodes (ocu-control serve.go:300), decoded there with DisallowUnknownFields:
// session_hint, image, and the deployment-sourced mount_intent + egress_policy.
// The rich frozen-proto CreateRequest still drives the IN-GATEWAY admission
// build+validate before the forward; this is the wire PROJECTION of it.
//
//   - session_hint: the caller-derived hint (the resolved Tenant), never authority
//     (NFR-SEC-43). Control derives the real session_id from the mTLS SAN.
//   - image: empty on a bare create — the sandbox image ref is PIN-PENDING at the
//     gatekeeper (#205 reconciliation); the gateway does not invent it.
//   - mount_intent / egress_policy: projected STRICTLY from the deployment
//     provisioning (f.provisioning, F5 ruling A — never a caller body). Control
//     needs egress_policy (default_deny) to materialize; without it materialize is
//     refused. mount_intent is a pointer so an ABSENT scope omits it (Control
//     treats a PRESENT mount as requiring exactly one filesystem_id XOR
//     memory_store_id; an ABSENT mount is the legitimate no-scope session,
//     ADR-0017).
//
// There is deliberately NO control_pub_key: Control's createBody has no such field
// and rejects it as unknown (a 400 on the live control — this was the F5 502 root).
// The exec channel (G2, ADR-0024) will be a future ADDITIVE field Control adds,
// not one the gateway smuggles onto a create body Control does not accept.
type createBodyWire struct {
	SessionHint  string            `json:"session_hint"`
	Image        string            `json:"image"`
	MountIntent  *mountIntentWire  `json:"mount_intent,omitempty"`
	EgressPolicy *egressPolicyWire `json:"egress_policy,omitempty"`
}

// mountIntentWire / egressPolicyWire are the wire projections of the deployment
// MountIntent / EgressPolicy, field names matching Control's mountIntentBody /
// egressPolicyBody exactly. They carry NO credential (custody: the Storage-JWT
// rides the F7 mount-config push, never a create body).
type mountIntentWire struct {
	Destination    string `json:"destination"`
	FilesystemID   string `json:"filesystem_id"`
	MemoryStoreID  string `json:"memory_store_id"`
	ReadOnly       bool   `json:"read_only"`
	CacheDurationS uint32 `json:"cache_duration_s"`
}

type egressPolicyWire struct {
	DefaultDeny     bool   `json:"default_deny"`
	AllowedUpstream string `json:"allowed_upstream"`
	FilesystemID    string `json:"filesystem_id"`
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

// execBodyWire is the EXACT JSON shape Control's gateway-ingress execBody decodes
// (ocu-control serve.go:251), decoded there with DisallowUnknownFields. The gateway
// sends the addressed session_hint (the SAME one the create hop used — the exec
// addresses the session create just provisioned, NOT the reply key, which is a
// host-derived correlation and not an addressable hint), the command argv, and the
// deployment timeout ceiling. Env/Cwd/StdinB64 are carried for completeness but a
// bare tool-call leaves them empty. There is NO credential field: the Storage-JWT
// rides the F7 mount push, never an exec body (custody).
type execBodyWire struct {
	SessionHint string            `json:"session_hint"`
	Argv        []string          `json:"argv"`
	Env         map[string]string `json:"env,omitempty"`
	Cwd         string            `json:"cwd,omitempty"`
	StdinB64    string            `json:"stdin_b64,omitempty"`
	TimeoutS    uint32            `json:"timeout_s"`
}

// execResponseWire is Control's execResponse (serve.go:289): the guest child's
// exit code and the base64-captured, per-stream-bounded output with truncation
// flags. A non-zero ExitCode is a legitimate TOOL outcome (a Tier-2 error the
// caller sees), NOT a transport failure — the ingress projects it into a
// CallToolResult{isError:true}, it does not become an ErrForwardFailed.
type execResponseWire struct {
	ExitCode        uint8  `json:"exit_code"`
	StdoutB64       string `json:"stdout_b64"`
	StderrB64       string `json:"stderr_b64"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

// ExecResult is the projected, transport-neutral result of the exec hop the
// ingress relays to the caller. It carries the guest child's captured output
// (already base64-decoded from the wire) and the tool-outcome flag. IsToolError is
// the Tier-2 distinction: a non-zero guest exit is a tool error (isError:true in
// the CallToolResult), which is NOT a forward failure — the forward itself
// succeeded, the command ran and reported a non-zero status.
type ExecResult struct {
	Stdout          string
	Stderr          string
	IsToolError     bool
	StdoutTruncated bool
	StderrTruncated bool
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
// Control's gateway-ingress createBody decodes (session_hint, image, mount_intent,
// egress_policy — the mount/egress projected from deployment provisioning). The
// security properties (mTLS-only, service-credential-only, no caller credential,
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
		create := buildCreateRequest(f.provisioning, sessionHintFor(req.Principal, req.SessionHint))
		if err := create.validate(); err != nil {
			// Fail-closed admission: an inadmissible create is refused before any
			// round-trip (unspecified profile, bad mount scope, unset pids cap).
			return SessionResponse{}, err
		}

		// The JSON wire projection is EXACTLY the fields Control's createBody decodes
		// (DisallowUnknownFields): session_hint + image + the mount_intent and
		// egress_policy PROJECTED from the deployment provisioning (Control needs
		// egress_policy to materialize). These come from `create` (built strictly
		// from f.provisioning), never a caller body — F5 ruling A holds. A caller
		// credential appears nowhere: the body has no field for it, and the service
		// principal is asserted by the mTLS client cert + the bearer token, never the
		// caller's key.
		wire := createBodyWire{
			SessionHint:  create.SessionHint,
			EgressPolicy: egressWireFrom(create.EgressPolicy),
			MountIntent:  mountWireFrom(create.MountIntent),
		}
		respBody, err := f.postJSON(ctx, token, createPath, wire)
		if err != nil {
			return SessionResponse{}, err
		}

		var reply sessionResponseWire
		if err := json.Unmarshal(respBody, &reply); err != nil {
			return SessionResponse{}, fmt.Errorf("%w: decode create reply: %w", ErrForwardFailed, err)
		}

		// (2nd hop) EXEC — the G2 exec-driver leg. The create hop provisioned the
		// session; the exec hop runs the caller's command IN it and captures the
		// guest child's output. It addresses the session by the SAME session_hint
		// create used (create.SessionHint), NOT reply.Key — the key is a host-derived
		// correlation, not an addressable hint. A tool-call with no argv (a tool that
		// has no exec projection) skips the exec hop and returns the create-only
		// correlation. The exec runs under the same service credential + mTLS
		// transport, so it inherits the fail-closed posture: a down/refusing exec
		// route is a postJSON non-2xx → ErrForwardFailed, never a fabricated success.
		if len(req.ToolCall.Argv) == 0 {
			return SessionResponse{Correlation: reply.Key}, nil
		}

		execWire := execBodyWire{
			SessionHint: create.SessionHint,
			Argv:        req.ToolCall.Argv,
			TimeoutS:    clampExecTimeout(f.provisioning.ExecTimeoutSeconds),
		}
		// The opaque stdin payload (the file tools' arguments JSON) rides base64 into
		// the exec body; Control decodes it into the guest child's stdin. The gateway
		// does not read it — it is the caller's own bytes, relayed verbatim (invariant
		// #3). Empty for a tool that carries everything in argv (e.g. bash_tool), in
		// which case StdinB64 stays empty (omitempty) and no stdin is pumped.
		if len(req.ToolCall.Stdin) > 0 {
			execWire.StdinB64 = base64.StdEncoding.EncodeToString(req.ToolCall.Stdin)
		}
		execBody, err := f.postJSON(ctx, token, execPath, execWire)
		if err != nil {
			// A transport-level exec failure (route down, non-2xx) fails the whole
			// tool-call closed (invariant #9). The command did NOT run, so a success
			// would be a lie — this is the fake-green guard.
			return SessionResponse{}, err
		}

		var execReply execResponseWire
		if err := json.Unmarshal(execBody, &execReply); err != nil {
			return SessionResponse{}, fmt.Errorf("%w: decode exec reply: %w", ErrForwardFailed, err)
		}
		result, err := projectCallToolResult(execReply)
		if err != nil {
			return SessionResponse{}, err
		}

		// Identifier-minimization at the boundary (invariant #5): the host-derived key
		// is surfaced ONLY as the stable correlation handle — never as an addressable
		// session id or internal topology. The projected CallToolResult carries the
		// guest output; the ingress response path performs the final outbound
		// validation and JSON-RPC framing before it reaches the caller.
		return SessionResponse{Correlation: reply.Key, Result: result}, nil
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

	// Bound the reply read so an oversized/hostile response cannot exhaust memory, but
	// the bound MUST cover a LEGAL control reply or io.LimitReader truncates the JSON
	// mid-string and the reply is lost as a 502 (task #127). The reply is a JSON
	// envelope carrying base64(stdout)+base64(stderr); control bounds each stream at
	// controlReplyStreamCeiling, so a legal reply is at most
	// 2×ceil(ceiling×4/3)+envelope. maxReplyBytes is that bound with headroom — see the
	// cross-component sizing invariant on the constant.
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

// egressWireFrom projects the deployment EgressPolicy onto the wire. Control needs
// the egress_policy (default_deny) to materialize a session, so it is always sent.
func egressWireFrom(e EgressPolicy) *egressPolicyWire {
	return &egressPolicyWire{
		DefaultDeny:     e.DefaultDeny,
		AllowedUpstream: e.AllowedUpstream,
		FilesystemID:    e.FilesystemID,
	}
}

// mountWireFrom projects the deployment MountIntent onto the wire ONLY when it
// names a scope. Control treats a PRESENT mount_intent as requiring exactly one
// filesystem_id XOR memory_store_id; a scope-less mount is the legitimate no-scope
// (compute/exec) session, which is expressed by OMITTING mount_intent (ADR-0017),
// not by sending an empty one (which Control would reject as "neither scope").
func mountWireFrom(m MountIntent) *mountIntentWire {
	if m.FilesystemID == "" && m.MemoryStoreID == "" {
		return nil
	}
	return &mountIntentWire{
		Destination:    m.Destination,
		FilesystemID:   m.FilesystemID,
		MemoryStoreID:  m.MemoryStoreID,
		ReadOnly:       m.ReadOnly,
		CacheDurationS: m.CacheDurationS,
	}
}

// callToolResult / contentBlock are the MCP CallToolResult projection the exec hop
// produces (matching the vendored boundedCallToolResult overlay: content text
// blocks + the Tier-2 isError flag). The gateway emits only text content for exec
// output. The struct is marshaled to the result bytes the ingress validates
// against KindCallToolResult and frames into the JSON-RPC reply.
type callToolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CROSS-COMPONENT SIZING INVARIANT (task #127). The gateway's byte bounds MUST be
// reconciled with control's exec-reply ceiling, or a LEGAL reply is silently lost:
//
//   - controlReplyStreamCeiling is control's per-stream capture ceiling
//     (ocu-control guestexec/driver.go defaultStdioCap = 8 MiB). It is mirrored here
//     as the number the gateway sizes against; the two MUST be cross-checked when
//     either moves (they diverged 340× — 64 KiB vs 8 MiB — which is task #127).
//   - maxReplyBytes (the F5 reply read cap) MUST be >= 2×ceil(ceiling×4/3)+envelope:
//     a reply carries base64(stdout)+base64(stderr) (each grows ×4/3) in a JSON
//     envelope. Below that, io.LimitReader truncates the JSON mid-string, the reply
//     fails to parse, and the whole result is dropped as a 502.
//   - maxExecContentBytes (the per-stream content bound) MUST be >= the ceiling, so
//     boundContent NEVER fires on a legal reply (a legal stream reaches the caller
//     whole). It only truncates a stream that already exceeded control's ceiling, and
//     when it does the truncation is SURFACED to the caller (not silent).
const (
	// controlReplyStreamCeiling mirrors ocu-control defaultStdioCap (8 MiB per stream).
	controlReplyStreamCeiling = 8 << 20
	// maxReplyBytes bounds the F5 reply read. 24 MiB covers two 8 MiB streams base64'd
	// (≈10.7 MiB each) plus the JSON envelope, with headroom — so a legal control reply
	// always parses (2×ceil(8MiB×4/3) ≈ 21.4 MiB < 24 MiB).
	maxReplyBytes = 24 << 20
	// maxExecContentBytes bounds the per-stream captured output the gateway relays in a
	// CallToolResult content block. It is >= controlReplyStreamCeiling so boundContent
	// never fires on a legal reply; it is a rune-safe truncation (never splits a
	// multi-byte rune) that only trims a stream already past control's ceiling, and the
	// caller is told when it fires.
	maxExecContentBytes = controlReplyStreamCeiling
)

// projectCallToolResult maps Control's execResponse into the MCP CallToolResult the
// caller receives. The TWO-TIER error model (x-ocu-error-model): a NON-ZERO guest
// exit is a Tier-2 TOOL error — isError:true with the sanitized stderr as content —
// NOT a transport failure (the forward itself succeeded). A zero exit projects the
// stdout as content with isError:false. The captured streams are base64 on the wire
// (a []byte, never a credential); a decode failure is a fail-closed ErrForwardFailed
// (a malformed control reply must not become a silent empty success). Output is
// bounded (maxExecContentBytes) as defence-in-depth over control's own ceiling.
func projectCallToolResult(reply execResponseWire) ([]byte, error) {
	stdout, err := base64.StdEncoding.DecodeString(reply.StdoutB64)
	if err != nil {
		return nil, fmt.Errorf("%w: exec stdout_b64 is not valid base64", ErrForwardFailed)
	}
	stderr, err := base64.StdEncoding.DecodeString(reply.StderrB64)
	if err != nil {
		return nil, fmt.Errorf("%w: exec stderr_b64 is not valid base64", ErrForwardFailed)
	}

	isErr := reply.ExitCode != 0
	// On a tool error the model must see the failure: relay stderr, falling back to
	// stdout if the child wrote its diagnostic there. On success relay stdout.
	text := string(stdout)
	if isErr {
		if len(stderr) > 0 {
			text = string(stderr)
		} else {
			text = string(stdout)
		}
		// A non-zero exit with NO output on EITHER stream would otherwise be an EMPTY
		// error content block — the model would see isError:true but no reason. Surface
		// the control-reported exit code so a silent failure is still legible, matching
		// the PoC shape "output if output else [Exit code: N]" (mcp_tools.py:456). The
		// gap test is RAW byte length on BOTH streams (not a trimmed/whitespace test) so
		// it mirrors the PoC's Python truthiness exactly. This is the ONLY layer that
		// synthesizes the marker — control/guest never do (a double-marker would be a
		// bug); the synthesis runs BEFORE boundContent so the marker is itself bounded.
		//
		// The gateway relays exit-code FACTS and does NOT interpret per-command exit
		// semantics: there is deliberately no PoC-style table rewriting a tool's exit
		// (e.g. grep-exit-1 → "No matches found"). The isError model makes that heuristic
		// obsolete, and guessing a command from an sh -c string in the protocol path is
		// unsound — recorded as a PoC-vs-fleet contrast, not a bug. A signal-derived exit
		// (e.g. 137) stays "[Exit code: 137]", not a signal name.
		if len(stdout) == 0 && len(stderr) == 0 {
			text = fmt.Sprintf("[Exit code: %d]", reply.ExitCode)
		}
	}

	// Determine whether the RELAYED stream was truncated — either control already
	// truncated it at its ceiling (the wire flag), or the gateway's boundContent is
	// about to trim it. text carries stderr when a tool error wrote to stderr, else
	// stdout, so the matching control flag is chosen the same way.
	controlTruncated := reply.StdoutTruncated
	if isErr && len(stderr) > 0 {
		controlTruncated = reply.StderrTruncated
	}
	bounded := boundContent(text)
	gatewayTruncated := len(bounded) < len(text)
	text = bounded

	// Surface truncation to the caller so a clipped body is never presented as
	// complete. This is the SAME single-synthesis layer as the [Exit code: N] marker —
	// control/guest never annotate; the gateway is the one place a truncation note is
	// added. A truncated SUCCESS is still a success (isError unchanged): the note is
	// informational, not an error. N is the byte length actually relayed.
	if controlTruncated || gatewayTruncated {
		text += fmt.Sprintf("\n[output truncated at %d bytes]", len(text))
	}

	result := callToolResult{
		Content: []contentBlock{{Type: "text", Text: text}},
		IsError: isErr,
	}
	blob, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal CallToolResult: %w", ErrForwardFailed, err)
	}
	return blob, nil
}

// boundContent rune-safely truncates a content string to maxExecContentBytes so an
// oversized stream cannot push the CallToolResult over its ceiling. It truncates on
// a rune boundary (never a partial multi-byte rune).
func boundContent(s string) string {
	if len(s) <= maxExecContentBytes {
		return s
	}
	// Back off to a rune boundary at or before the byte cap.
	cut := maxExecContentBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
