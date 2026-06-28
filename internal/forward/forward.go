// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package forward is the F5 leg: the gateway → Control/operator API session-
// request forward. It enforces invariant #3 — the caller credential NEVER
// appears on the forward leg, in a forwarded argument, or on any path reaching
// the sandbox; the forward carries ONLY the gateway's own service identity
// (NFR-SEC-09, NFR-SEC-26).
//
// The non-forwarding property is made a TYPE FACT, not a discipline: the value
// this package forwards (SessionRequest) has no field that can carry the caller
// bearer, and the only caller-derived data it carries is the host-derived
// principal handle (KeyID/Tenant) the auth seam already resolved — never the
// raw credential. A handler cannot forward the bearer because there is no field
// on the wire shape to put it in. The service identity is injected by the
// transport (the gateway's own signing material / workload identity), not passed
// in from the caller side, so a caller cannot influence the forward principal.
//
// The forward also carries no operator scope: the gateway holds only a service
// principal, so the Control/operator API never treats a forwarded request as
// more privileged than a service create (P1-S2 mitigation). The operator surface
// sits on a separate ingress this package has no route to (invariant #4 / network
// half, NFR-SEC-52).
package forward

import (
	"context"
	"errors"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// ErrForwardFailed is the fail-closed forward refusal. A forward that cannot be
// completed (Control unreachable, service-identity unavailable, audit not yet
// durable) is a refusal to the caller, never a silent success: fail-closed is
// the default on the forward boundary (invariant #9).
var ErrForwardFailed = errors.New("forward: session request forward failed (fail-closed)")

// SessionRequest is the value the gateway forwards to the Control/operator API
// on F5. Its shape is the load-bearing guard for invariant #3: it has NO field
// for a caller bearer, an upstream credential, or a session JWT, so a forwarded
// request CANNOT carry the caller's credential by construction. The only
// caller-derived data is the resolved principal handle — a non-secret KeyID and
// Tenant the auth seam produced from the boot-set record, never the raw key.
//
// The body the caller supplied is carried as already-validated ToolCall data
// (the profile validator ran pre-forward); a body id is a HINT the Control plane
// cross-checks host-side and never an authority (NFR-SEC-43, P1-T2) — the
// gateway does not derive the session binding from it.
type SessionRequest struct {
	// Principal is the resolved, non-secret caller handle (KeyID + Tenant +
	// Audience) the auth seam returned. It attributes the request for the
	// Control plane's own authz and for audit, WITHOUT carrying the credential.
	// It is an auth.Caller by type, and auth.Caller has no credential field —
	// so even the principal cannot smuggle the bearer.
	Principal auth.Caller

	// ToolCall is the validated MCP tool-call payload to act on. It has passed
	// the two-pass profile validation before reaching here; the gateway forwards
	// the request to the Control plane and goes no further (no sandbox edge).
	ToolCall ToolCall
}

// ToolCall is the validated, bounded tool-call the gateway forwards. It carries
// the tool name and the (already size- and schema-checked) arguments, and
// NOTHING credential-bearing. Arguments are opaque validated bytes here — the
// gateway does not re-interpret them, and there is no Authorization/Bearer field
// to leak the caller credential into a forwarded argument (invariant #3).
type ToolCall struct {
	// Name is the MCP tool name (boundedTool.name, minLength 1).
	Name string
	// Arguments is the validated CallToolRequest.params.arguments payload,
	// bounded by maxToolArgumentsBytes. It is forwarded verbatim; the gateway
	// injects no credential into it.
	Arguments []byte
}

// SessionResponse is what the Control/operator API returns on F5, relayed back
// to the caller. It is identifier-minimized at the gateway boundary before it
// reaches the caller (invariant #5): the gateway strips any session id /
// container_name / internal host/route the Control plane may include, surfacing
// only a stable correlation handle. The minimization is performed by the ingress
// response path, not here; this type is the transport for the relayed result.
type SessionResponse struct {
	// Correlation is the stable, leak-free correlation id surfaced to the caller.
	// It is NOT a session id and carries no internal topology.
	Correlation string
	// Result is the bounded, validated result payload to relay to the caller.
	Result []byte
}

// Forwarder performs the F5 forward under the gateway's own service identity. The
// concrete implementation (an mTLS/workload-identity client to the Control plane)
// lives below this seam; the service identity is the transport's own, never a
// value a caller supplies. A Forwarder MUST:
//   - present ONLY the gateway service principal upstream, never the caller
//     credential (which is not even reachable from SessionRequest);
//   - fail closed (ErrForwardFailed) on any non-success, never admit a partial
//     or unattested forward;
//   - hold no caller token after the call returns (no state outlives the
//     request).
type Forwarder interface {
	// Forward sends req to the Control/operator API under the gateway service
	// identity and returns the relayed SessionResponse, or ErrForwardFailed
	// (possibly wrapped). It MUST NOT attach the caller credential to the
	// upstream call.
	Forward(ctx context.Context, req SessionRequest) (SessionResponse, error)
}
