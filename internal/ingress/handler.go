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
	"strings"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/profile"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/projection"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/serialize"
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
//     4b. per-session tool-call serialization (NFR-IC-05) — sequential per session
//     by default, per-skill parallel opt-in; the slot spans forward + emit.
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
	authn      auth.CallerAuthenticator
	validator  *profile.Validator
	forwarder  forward.Forwarder
	ceiling    *quota.Ceiling
	origin     OriginPolicy
	emitter    *audit.Emitter
	serializer *serialize.Serializer
}

// NewHandler wires the handler from its seams. The authenticator, validator,
// forwarder, ceiling, emitter, and serializer are all required; a nil seam is a
// construction error, because a missing authenticator (admit-all), validator
// (validate-nothing), forwarder (no F5), ceiling (no fd fairness, invariant #8),
// emitter (no F10 audit, so a forward could ack without a durable record —
// NFR-SEC-03), or serializer (no per-session tool-call ordering — NFR-IC-05)
// would each silently defeat an invariant. The origin policy is a value (its zero
// value admits only originless requests — the safe DNS-rebinding default), so it
// is passed by value, not checked for nil. Returning an error keeps the
// fail-closed posture at construction.
func NewHandler(authn auth.CallerAuthenticator, validator *profile.Validator, forwarder forward.Forwarder, ceiling *quota.Ceiling, origin OriginPolicy, emitter *audit.Emitter, serializer *serialize.Serializer) (*Handler, error) {
	if authn == nil || validator == nil || forwarder == nil || ceiling == nil || emitter == nil || serializer == nil {
		return nil, errors.New("ingress: NewHandler requires non-nil authn, validator, forwarder, ceiling, emitter, and serializer (fail-closed)")
	}
	return &Handler{authn: authn, validator: validator, forwarder: forwarder, ceiling: ceiling, origin: origin, emitter: emitter, serializer: serializer}, nil
}

// ServeHTTP routes the MCP JSON-RPC POST surface. Only POST is accepted; the
// tool-call body is the JSON-RPC request. The handler applies the boundary order
// above and writes a leak-free response.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, http.StatusMethodNotAllowed, rpcMethodNotAllowed, "method not allowed")
		return
	}

	// (1) Protocol-version pin, early header-only fast-path — invariant #6. A
	// PRESENT-but-mismatched MCP-Protocol-Version is an actively-wrong client and
	// is rejected here, before any body read or auth, with zero parser surface
	// exposed. A MISSING header is NOT decided here: `initialize` is spec-exempt
	// (the client cannot send a version it has not yet negotiated — MCP 2025-06-18
	// streamable-HTTP), so the absent case defers to the post-parse gate below,
	// where the method is known. This keeps the pin header-only and body-free for
	// unauthenticated callers while still admitting a conforming SDK handshake.
	if v := r.Header.Get(protocolVersionHeader); v != "" && v != pinnedProtocolVersion {
		writeRPCError(w, http.StatusBadRequest, rpcInvalidParams, "unsupported or missing protocol version")
		return
	}

	// (1b) Origin validation — DNS-rebinding guard (x-ocu-authz: "Origin header
	// MUST be validated"). A disallowed present Origin is refused before auth, so
	// a browser tricked into hitting the gateway's local bind cannot proceed. A
	// CLI/non-browser caller sends no Origin and is allowed.
	origin := r.Header.Get("Origin")
	if !h.origin.Allowed(origin) {
		writeRPCError(w, http.StatusForbidden, rpcInvalidRequest, "origin not allowed")
		return
	}

	// (2) Caller authentication — invariant #2. Identity comes from the transport
	// bearer ONLY; the body is never consulted for identity. Fail-closed.
	cred := auth.TransportCredential{
		Bearer: bearerFromHeader(r),
		Origin: origin,
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
	// duration of this request and released on return. A ceiling refusal is a
	// TERMINATED request with a validated identity, so it is recorded (§XI): the
	// refusal audit is durable-first fail-closed, symmetric to success — if the
	// refusal cannot be recorded the request is 500, never a silently-unrecorded
	// rejection (a repudiation hole).
	release, qerr := h.ceiling.Acquire(caller.KeyID)
	if qerr != nil {
		// The ceiling runs BEFORE the body is read, so no request id is known yet; the
		// refusal is a pre-parse transport-fault served 429 (non-2xx), legitimately
		// id-less (the SDK catches it on the transport, never parses a body). A nil id
		// serializes as null.
		if !h.recordRefusal(w, r, nil, caller.KeyID, "tools/call:(ceiling-refused)") {
			return
		}
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
		// The envelope check runs on the raw body; the id (if the body carried a
		// parseable one) is echoed so a well-formed-message-but-denied request is
		// correlatable. A body too malformed to yield an id echoes a null id.
		writeProfileDeny(w, idFrom(raw), err)
		return
	}

	// (3a) JSON-RPC notification — a message with NO id (or a notifications/*
	// method) is fire-and-forget: it takes NO response body. The stateless
	// streamable-HTTP transport the SDK speaks acknowledges it 202 Accepted with an
	// empty body. The SDK sends notifications/initialized right after initialize;
	// answering it with a JSON-RPC error (or any body) closes the SDK transport
	// (BrokenResourceError) on the next request. A notification NEVER reaches the
	// forwarder or the validation path — it is acknowledged and dropped.
	if isNotification(raw) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// (3a2) Protocol-version pin, ABSENT-header arm — invariant #6. The early
	// fast-path above already rejected a present-but-mismatched header; what
	// remains is the ABSENT header. The MCP streamable-HTTP spec (2025-06-18,
	// "Protocol Version Header") requires the header on every request AFTER
	// initialization but NOT on initialize itself, because the version is not yet
	// negotiated — the client learns it from the initialize RESULT. A conforming
	// SDK therefore POSTs initialize with no version header; gating it would
	// deadlock the handshake. So an absent header is accepted ONLY for initialize;
	// every other method with no version header is rejected here (now that the
	// method is known), never silently downgraded, and never forwarded.
	if r.Header.Get(protocolVersionHeader) == "" && methodFrom(raw) != "initialize" {
		writeRPCError(w, http.StatusBadRequest, rpcInvalidParams, "unsupported or missing protocol version")
		return
	}

	// (3b) MCP handshake — answered GATEWAY-LOCAL, never forwarded. The official
	// client SDK runs initialize + tools/list before it can call a tool; the
	// gateway answers both here (behind auth) so it is a drop-in for the old
	// endpoint. These methods NEVER build a SessionRequest and NEVER reach the
	// forwarder — only tools/call forwards — so the method-confusion guard
	// (invariant #17) holds: a handshake method cannot ride the F5 leg. Any method
	// that is NOT a handshake method falls through to the tools/call path below,
	// where the allowlist denies anything that is not tools/call.
	switch methodFrom(raw) {
	case "initialize":
		writeInitializeResult(w, raw)
		return
	case "tools/list":
		writeToolsList(w, raw)
		return
	}

	// (4) Profile validation — invariant #1. Validate the tool-call request
	// (base-then-OCU-profile) BEFORE any forward. A deny here forwards nothing.
	// Only tools/call reaches here; the allowlist refuses any other method -32601.
	if err := h.validator.Validate(profile.KindCallToolRequest, raw); err != nil {
		// Post-parse deny: the id is known, so the deny echoes it — an id-less deny on
		// the 400/413 status the SDK parses would hang the client (issue #38).
		writeProfileDeny(w, idFrom(raw), err)
		return
	}

	req := forward.SessionRequest{
		Principal: caller,
		ToolCall:  toolCallFrom(raw),
		// The chat scope keys the session per-chat so a chat's tool-calls reuse one
		// guest session (control resumes it) instead of colliding on a per-tenant
		// reservation (the 409). Read from the X-Chat-Id TRANSPORT header, never the
		// JSON body (invariant #2); a caller-influenced HINT, never identity
		// (NFR-SEC-43).
		SessionHint: r.Header.Get("X-Chat-Id"),
	}

	// (4b) Per-session tool-call serialization — NFR-IC-05. Tool execution is
	// serialized per session by default; parallelism is a per-skill deployment
	// opt-in, never a caller body field. This runs AFTER the ceiling (which bounds
	// total in-flight first) and AFTER validation (so the tool name for the
	// parallel predicate comes from a validated body). The session key is the
	// RESOLVED caller's Tenant — the minimal-shelf session-scoping principal
	// (NFR-SEC-43), read from the auth-resolved record, never from a caller body
	// field. Keying on the resolved principal (not req.ToolCall.Name) is the
	// load-bearing property pinned by TestSerializeKeyedOnPrincipalNotToolName. The
	// slot is held across forward + emit (settled state) so call N+1 of a session
	// cannot overtake the durable record of call N — the per-session history is
	// strictly executed → recorded → next. A session queue at its bound is refused
	// (fail-closed), never parked unboundedly (a DoS guard on the caller-supplied
	// key).
	srel, serr := h.serializer.Acquire(caller.Tenant, req.ToolCall.Name)
	if serr != nil {
		// Post-parse refusal: echo the id (issue #38 invariant — any error after the
		// id is parsed is correlatable, never id-less).
		writeRPCErrorWithID(w, idFrom(raw), http.StatusTooManyRequests, rpcInternalError, "session serialization queue full")
		return
	}
	defer srel()

	// (5) Forward (F5) under the gateway service identity — invariant #3. The
	// SessionRequest carries the resolved principal (no credential) and the
	// validated tool-call; the caller bearer is not reachable from it.
	resp, ferr := h.forwarder.Forward(r.Context(), req)
	if ferr != nil {
		// Operator diagnostic: log the EXACT forward error (fail-closed class +
		// endpoint + path + control status) so a distroless container surfaces WHY
		// the 502 happened. The forward error carries no credential or body, so the
		// log is actionable without leaking. The caller-facing response below stays
		// leak-free regardless.
		logForwardFailure(ferr, boundedResource(req.ToolCall.Name))
		// Fail-closed: a forward failure is a refusal, leak-free. It is a
		// terminated request with a validated identity, so it is recorded (§XI)
		// durable-first before the 502 — symmetric to the success emit.
		if !h.recordRefusal(w, r, idFrom(raw), caller.KeyID, boundedResource(req.ToolCall.Name)) {
			return
		}
		// Post-parse refusal: echo the id (issue #38). Served 502 (non-2xx), which the
		// SDK catches on the transport, but the invariant is uniform — every post-parse
		// error echoes the id regardless of status.
		writeRPCErrorWithID(w, idFrom(raw), http.StatusBadGateway, rpcInternalError, "forward refused")
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
		// Audit write failed → the request is refused, not acked (fail-closed). This
		// is post-parse, so the id is echoed (issue #38).
		writeRPCErrorWithID(w, idFrom(raw), http.StatusInternalServerError, rpcInternalError, "audit write failed")
		return
	}

	// (7) Leak-free response — invariant #5. The forwarded CallToolResult is
	// VALIDATED OUTBOUND (KindCallToolResult) before it reaches the caller and framed
	// into the JSON-RPC result envelope with the ECHOED request id so the SDK
	// correlates it. A result that fails outbound validation is a fail-closed refusal
	// (a malformed/oversized body is never handed to the caller, NFR-SEC-51). Only
	// the bounded result + the stable correlation id reach the wire.
	h.writeToolResult(w, resp, idFrom(raw))
}

// recordRefusal durably records a TERMINATED, post-auth refusal (§XI, F11): a
// ceiling (429) or forward (502) refusal of a request whose caller identity was
// already validated. It emits an OutcomeFailure OCSF event with the host-attested
// actor (KeyID), durable-first fail-closed and SYMMETRIC to the success emit —
// the repudiation control (NFR-SEC-03) is that the record EXISTS, so a refusal we
// cannot durably record is a repudiation hole, not a swallow.
//
// It returns true when the caller may proceed to write the intended refusal
// status (the audit event landed). It returns false when the audit write FAILED —
// in which case it has already written a leak-free 500, and the caller must
// return without writing the original refusal code (a refusal we could not record
// becomes a 500, never a silently-unrecorded rejection).
//
// Pre-auth refusals (401 auth-fail, 403 origin) do NOT call this: at their
// boundary order no caller is resolved, so there is no attested actor to record.
// That omission is deliberate (a placeholder actor would be false attribution);
// it is documented on the audit package and pinned by TestPreAuthRefusalsDoNotEmit.
//
// id is the request id to echo on the fail-closed 500 this writes when the refusal
// cannot be recorded. It is the parsed request id on the forward-refused path (known,
// so the 500 is correlatable) and nil on the ceiling path (pre-body-read, no id yet —
// a 429/500 non-2xx the SDK catches on the transport); a nil id serializes as null.
func (h *Handler) recordRefusal(w http.ResponseWriter, r *http.Request, id jsonRPCID, actorKeyID, resource string) (proceed bool) {
	correlation := newCorrelationID()
	env := audit.Envelope{
		TraceID:   correlation,
		SessionID: correlation,
		ActorID:   actorKeyID,
		Resource:  resource,
		Action:    "tool_call",
		Outcome:   audit.OutcomeFailure,
	}
	if err := h.emitter.Emit(r.Context(), env); err != nil {
		// The refusal could not be durably recorded → fail closed with a 500,
		// exactly as the success path does on an audit-write failure. The caller
		// must NOT then also write the original refusal code. The id (parsed on the
		// forward-refused path, nil on the pre-parse ceiling path) is echoed.
		writeRPCErrorWithID(w, id, http.StatusInternalServerError, rpcInternalError, "audit write failed")
		return false
	}
	return true
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

// methodFrom extracts the JSON-RPC method name from the (envelope-validated) raw
// body so the handler can route the MCP handshake methods gateway-local before the
// tools/call forward path. A decode miss yields an empty method, which is not a
// handshake method and falls through to the allowlist deny.
func methodFrom(raw []byte) string {
	var msg struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(raw, &msg)
	return msg.Method
}

// isNotification reports whether the message is a JSON-RPC notification —
// fire-and-forget, taking no response. Per JSON-RPC a message with NO id is a
// notification; the MCP notifications/* methods are notifications by name. Either
// is acknowledged 202 with an empty body and never forwarded. The id is decoded as
// RawMessage so a present-but-null id (`"id":null`) is also treated as absent (the
// JSON-RPC spec's notification form).
func isNotification(raw []byte) bool {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(raw, &msg)
	idAbsent := len(msg.ID) == 0 || string(msg.ID) == "null"
	return idAbsent || strings.HasPrefix(msg.Method, "notifications/")
}

// toolCallFrom extracts the forwarded ToolCall from the validated raw body. The
// body has already passed profile validation, so this is a structural read of a
// known-good shape; it injects no credential (invariant #3). It also derives the
// guest command Argv (the G2 exec-driver input) from the tool arguments, keeping
// the command-parsing in ingress so the forward package holds the arguments opaque.
func toolCallFrom(raw []byte) forward.ToolCall {
	var msg struct {
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	_ = json.Unmarshal(raw, &msg) // raw is already validated; a decode miss yields a zero ToolCall
	// The tool→exec projection (argv + opaque stdin) comes from the leaf projection
	// package, the SINGLE source of truth shared with the forward-level e2e so the argv
	// and guest scripts cannot drift between production and test (invariant #3: the
	// arguments ride as opaque stdin, never parsed or interpolated into the argv).
	argv, stdin := projection.Project(msg.Params.Name, msg.Params.Arguments)
	return forward.ToolCall{
		Name:      msg.Params.Name,
		Arguments: msg.Params.Arguments,
		Argv:      argv,
		Stdin:     stdin,
	}
}
