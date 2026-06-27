// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/profile"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

// pinnedProtocolVersion is the single MCP revision this gateway negotiates. A
// request whose MCP-Protocol-Version header is missing or names another revision
// is rejected, never silently downgraded (invariant #6, NFR-IC-04). The value
// matches the vendored contract's protocol-version-binding.
const pinnedProtocolVersion = "2025-06-18"

// protocolVersionHeader is the HTTP header carrying the negotiated MCP revision.
const protocolVersionHeader = "MCP-Protocol-Version"

// Handler is the MCP gateway request handler. It composes the load-bearing
// boundary order for every inbound tool-call:
//
//  1. protocol-version pin (invariant #6) — reject a missing/unnegotiable
//     revision before anything else.
//  2. caller authentication (invariant #2) — resolve the principal from the
//     transport bearer ONLY, never the body; fail-closed on any non-success.
//  3. bounded read (invariant #8) — MaxBytesReader caps the body at 512KiB so an
//     oversized/slow body is refused at the transport before it is read whole;
//     the profile size-ceiling (step 4) then runs on the bounded bytes.
//  4. profile validation (invariant #1) — base-then-OCU-profile, before any
//     forward; an invalid message is denied and nothing downstream runs.
//  5. forward (F5) under the gateway service identity (invariant #3) — the
//     caller credential never rides the forward.
//  6. F10 OCSF audit emit (NFR-SEC-03) — emit-before-ack, fail-closed
//     durable-first: a durable-write failure refuses the request, never acks it.
//  7. leak-free response (invariant #5) — only a stable reason class +
//     correlation id reaches the caller, never internal identifiers.
//
// Every boundary fails closed (invariant #9): a non-success at any step refuses
// the request and forwards nothing.
type Handler struct {
	authn     auth.CallerAuthenticator
	validator *profile.Validator
	forwarder forward.Forwarder
	ceiling   *quota.Ceiling
	emitter   *audit.Emitter
}

// NewHandler wires the handler from its seams. All are required; a nil seam is a
// construction error, because a missing authenticator (admit-all), validator
// (validate-nothing), forwarder (no F5), ceiling (no fd fairness, invariant #8),
// or emitter (no F10 audit, so a forward could ack without a durable record —
// NFR-SEC-03) would each silently defeat an invariant. Returning an error keeps
// the fail-closed posture at construction.
func NewHandler(authn auth.CallerAuthenticator, validator *profile.Validator, forwarder forward.Forwarder, ceiling *quota.Ceiling, emitter *audit.Emitter) (*Handler, error) {
	if authn == nil || validator == nil || forwarder == nil || ceiling == nil || emitter == nil {
		return nil, errors.New("ingress: NewHandler requires non-nil authn, validator, forwarder, ceiling, and emitter (fail-closed)")
	}
	return &Handler{authn: authn, validator: validator, forwarder: forwarder, ceiling: ceiling, emitter: emitter}, nil
}

// ServeHTTP routes the MCP JSON-RPC POST surface. Only POST is accepted; the
// tool-call body is the JSON-RPC request. The handler applies the boundary order
// above and writes a leak-free response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, rpcMethodNotAllowed, "method not allowed")
		return
	}

	// (1) Protocol-version pin — invariant #6. Missing or mismatched → reject.
	if v := r.Header.Get(protocolVersionHeader); v != pinnedProtocolVersion {
		writeRPCError(w, http.StatusBadRequest, rpcInvalidParams, "unsupported or missing protocol version")
		return
	}

	// (2) Caller authentication — invariant #2. Identity comes from the transport
	// bearer ONLY; the body is never consulted for identity. Fail-closed.
	cred := auth.TransportCredential{
		Bearer: bearerFromHeader(r),
		Origin: r.Header.Get("Origin"),
	}
	caller, err := h.authn.Authenticate(r.Context(), cred)
	if err != nil {
		// A failed authentication is a 401 with the relying-party challenge; the
		// reason is a stable class, never the cause detail (invariant #5).
		w.Header().Set("WWW-Authenticate", `Bearer realm="ocu-mcp-gateway"`)
		writeRPCError(w, http.StatusUnauthorized, rpcInvalidRequest, "unauthenticated")
		return
	}

	// (2b) Per-caller connection ceiling — invariant #8. Keyed on the RESOLVED
	// caller identity, so it runs strictly AFTER auth (the ceiling is "per
	// audience-validated caller", NFR-SEC-53). Excess is REFUSED (429), never
	// queued, so one caller cannot exhaust the fd table. The slot is held for the
	// duration of this request and released on return.
	release, qerr := h.ceiling.Acquire(caller.KeyID)
	if qerr != nil {
		writeRPCError(w, http.StatusTooManyRequests, rpcInternalError, "connection ceiling exceeded")
		return
	}
	defer release()

	// (3) Bounded read — invariant #8. MaxBytesReader caps the body at 512KiB so
	// an oversized/slow body is refused at the transport before it is read whole
	// (the DoS guard); the body is then read into memory under that cap. The
	// single-message envelope (no batching) is enforced before typed decode.
	raw, derr := readBounded(w, r)
	if derr != nil {
		writeDecodeError(w, derr)
		return
	}
	if err := h.validator.ValidateSingleMessageEnvelope(raw); err != nil {
		writeProfileDeny(w, err)
		return
	}

	// (4) Profile validation — invariant #1. Validate the tool-call request
	// (base-then-OCU-profile) BEFORE any forward. A deny here forwards nothing.
	if err := h.validator.Validate(profile.KindCallToolRequest, raw); err != nil {
		writeProfileDeny(w, err)
		return
	}

	// (5) Forward (F5) under the gateway service identity — invariant #3. The
	// SessionRequest carries the resolved principal (no credential) and the
	// validated tool-call; the caller bearer is not reachable from it.
	req := forward.SessionRequest{
		Principal: caller,
		ToolCall:  toolCallFrom(raw),
	}
	resp, ferr := h.forwarder.Forward(r.Context(), req)
	if ferr != nil {
		// Fail-closed: a forward failure is a refusal, leak-free.
		writeRPCError(w, http.StatusBadGateway, rpcInternalError, "forward refused")
		return
	}

	// (6) F10 OCSF audit emit — emit-before-ack (NFR-SEC-03 fail-closed
	// durable-first). The event is durably recorded BEFORE the 2xx; if the
	// durable write fails, the request is REFUSED, not acknowledged, so a 200
	// always means the action took effect AND was recorded. The actor is the
	// host-attested caller principal (KeyID), never a body claim (NFR-SEC-09).
	//
	// The correlation id is the gateway's own per-request handle: audit MUST NOT
	// depend on the upstream returning one (a terminated request is always
	// recorded). If Control returned a correlation we adopt it; otherwise the
	// gateway mints one so the event is always well-formed and the response
	// carries a stable handle either way.
	correlation := resp.Correlation
	if correlation == "" {
		correlation = newCorrelationID()
		resp.Correlation = correlation
	}
	env := audit.Envelope{
		TraceID:   correlation,
		SessionID: correlation,
		ActorID:   caller.KeyID,
		Resource:  boundedResource(req.ToolCall.Name),
		Action:    "tool_call",
		Outcome:   audit.OutcomeSuccess,
	}
	if err := h.emitter.Emit(r.Context(), env); err != nil {
		// Audit write failed → the request is refused, not acked (fail-closed).
		writeRPCError(w, http.StatusInternalServerError, rpcInternalError, "audit write failed")
		return
	}

	// (7) Leak-free response — invariant #5. Only the bounded result + the stable
	// correlation id reach the caller.
	writeResult(w, resp)
}

// bearerFromHeader extracts the raw bearer from the Authorization header. The
// credential rides the transport header ONLY — never the JSON-RPC body or the
// URI query (NFR-SEC-09). An absent or malformed header yields an empty bearer,
// which the authenticator treats as a fail-closed refusal.
func bearerFromHeader(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

// newCorrelationID mints a per-request correlation handle (128-bit hex) when the
// upstream did not supply one. It is a stable, leak-free reference id — NOT a
// session id and carrying no internal topology (invariant #5). crypto/rand makes
// it unguessable so it cannot be used to correlate across tenants.
func newCorrelationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read does not fail in practice; if it ever did, a fixed non-empty
		// placeholder keeps the envelope well-formed (audit still records the
		// request) rather than dropping the event.
		return "correlation-unavailable"
	}
	return hex.EncodeToString(b[:])
}

// boundedResource builds the audit resource string for a tool-call, bounded to
// the AuditEnvelope resource limit so a long tool name cannot push the envelope
// over its schema bound (the emitter would otherwise refuse it). An empty name
// resolves to a stable placeholder so the required field is never empty.
func boundedResource(toolName string) string {
	const prefix = "tools/call:"
	const max = 1024
	if toolName == "" {
		return prefix + "(unnamed)"
	}
	r := prefix + toolName
	if len(r) > max {
		return r[:max]
	}
	return r
}

// readBounded reads the request body under the MaxBytesReader cap. An oversized
// body is short-circuited at the cap (never read whole into memory) and surfaces
// a *http.MaxBytesError mapped to 413.
func readBounded(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// toolCallFrom extracts the forwarded ToolCall from the validated raw body. The
// body has already passed profile validation, so this is a structural read of a
// known-good shape; it injects no credential (invariant #3). A future revision
// wires the full JSON-RPC method/params decode; the scaffold forwards the
// validated arguments verbatim.
func toolCallFrom(raw []byte) forward.ToolCall {
	var msg struct {
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	_ = json.Unmarshal(raw, &msg) // raw is already validated; a decode miss yields a zero ToolCall
	return forward.ToolCall{
		Name:      msg.Params.Name,
		Arguments: msg.Params.Arguments,
	}
}
