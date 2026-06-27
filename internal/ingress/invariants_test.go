// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/profile"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

const validToolCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`

// post builds a POST request with the given bearer/version/body, runs it through
// h, and returns the recorder.
func post(h *Handler, version, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if version != "" {
		req.Header.Set(protocolVersionHeader, version)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// acceptingHandler wires a handler that authenticates any non-empty bearer and
// records what the forward carried, so a test can drive the post-auth path.
func acceptingHandler(t *testing.T, fwd forward.Forwarder, ceiling *quota.Ceiling) *Handler {
	t.Helper()
	if ceiling == nil {
		ceiling = quota.NewCeiling(64)
	}
	h, err := NewHandler(
		acceptAuth{caller: auth.Caller{KeyID: "k1", Tenant: "t1", Audience: "a1"}},
		newValidator(t), fwd, ceiling, NewOriginPolicy(nil), newEmitter(t),
	)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h
}

// Invariant #6 — protocol-version pin. A missing or mismatched MCP-Protocol-
// Version is rejected, never silently downgraded.
func TestInvariant6_ProtocolVersionPinned(t *testing.T) {
	h := acceptingHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, nil)

	if rec := post(h, "", "sk-ocu-x", validToolCall); rec.Code != http.StatusBadRequest {
		t.Errorf("missing protocol version must be 400, got %d", rec.Code)
	}
	if rec := post(h, "2024-01-01", "sk-ocu-x", validToolCall); rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched protocol version must be 400, got %d", rec.Code)
	}
	// Sanity: the pinned version passes the version gate (and fails later at the
	// fail-closed forward, 502 — not 400).
	if rec := post(h, pinnedProtocolVersion, "sk-ocu-x", validToolCall); rec.Code == http.StatusBadRequest {
		t.Errorf("pinned protocol version must pass the version gate, got 400")
	}
}

// Invariant #2 — identity from the transport, fail-closed. No bearer → 401; the
// body is never consulted for identity (a body that names a principal cannot
// authenticate).
func TestInvariant2_IdentityFromTransportNotBody(t *testing.T) {
	h := acceptingHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, nil)

	// A body that "claims" a principal but carries no bearer is unauthenticated.
	bodyWithClaim := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{},"caller":"admin"}}`
	if rec := post(h, pinnedProtocolVersion, "", bodyWithClaim); rec.Code != http.StatusUnauthorized {
		t.Errorf("a body-claimed identity with no bearer must be 401, got %d", rec.Code)
	}
}

// Invariant #1 — validate before forward. A batched array body is denied (400)
// and never forwarded; the recording forwarder must not have been called.
func TestInvariant1_ValidateBeforeForward(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{}, err: nil}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-x", `[{"jsonrpc":"2.0"}]`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a batched array body must be 400, got %d", rec.Code)
	}
	if fwd.got != nil {
		t.Error("an invalid message was forwarded; validation must run BEFORE the forward (invariant #1)")
	}
}

// Invariant #3 (wire-level) — the caller credential never rides the forward. On a
// successful auth+validate, the SessionRequest the forwarder received carries the
// resolved principal but NO credential (the type has no field for it; this asserts
// the runtime value too).
func TestInvariant3_NoCredentialOnForward(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}, err: nil}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-supersecret", validToolCall)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid call should reach the forward and return 200, got %d", rec.Code)
	}
	if fwd.got == nil {
		t.Fatal("the forward was not called on a valid call")
	}
	// The resolved principal rode the forward; the raw bearer did not. Serialize
	// the whole SessionRequest and assert the secret string is absent.
	blob, _ := json.Marshal(fwd.got)
	if strings.Contains(string(blob), "supersecret") {
		t.Error("the caller credential appeared in the forwarded SessionRequest (invariant #3)")
	}
	if fwd.got.Principal.KeyID != "k1" {
		t.Errorf("the forward should carry the resolved principal handle, got %q", fwd.got.Principal.KeyID)
	}
}

// Invariant #5 — leak-free outbound. A forward failure surfaces only a stable
// reason class, never an internal cause/topology. The forwarder returns a
// realistically-wrapped error (the same shape ControlForwarder produces, carrying
// the endpoint/transport detail in its cause) so the test proves the handler does
// NOT relay that cause — a bare sentinel would not exercise the leak path.
func TestInvariant5_LeakFreeOutbound(t *testing.T) {
	leakyErr := fmt.Errorf("%w: Control transport not wired (endpoint %q)", forward.ErrForwardFailed, "https://control.internal:8443")
	fwd := &recordingForwarder{err: leakyErr}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-x", validToolCall)
	body, _ := io.ReadAll(rec.Body)
	s := string(body)
	// The body must carry a stable JSON-RPC error with a fixed message, and must
	// NOT echo any internal cause text.
	if !strings.Contains(s, `"error"`) {
		t.Errorf("forward failure should yield a JSON-RPC error envelope, got %q", s)
	}
	for _, leak := range []string{"endpoint", "Control", "ErrForwardFailed", "transport", "wired"} {
		if strings.Contains(s, leak) {
			t.Errorf("outbound error leaked internal detail %q: %q (invariant #5)", leak, s)
		}
	}
}

// Invariant #8 — per-caller connection ceiling refuses, not queues. With a
// ceiling of 1 already saturated for the caller, a second concurrent request is
// refused 429 immediately.
func TestInvariant8_ConnectionCeilingRefuses(t *testing.T) {
	ceiling := quota.NewCeiling(1)
	// Pre-saturate the caller's single slot (the handler keys on caller KeyID "k1").
	release, err := ceiling.Acquire("k1")
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	defer release()

	h := acceptingHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, ceiling)
	rec := post(h, pinnedProtocolVersion, "sk-ocu-x", validToolCall)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("a caller at its ceiling must be refused 429 (not queued), got %d", rec.Code)
	}
}

// Invariant #9 — fail-closed forward boundary. A forward error is a refusal
// (502), never a silent 200.
func TestInvariant9_FailClosedForward(t *testing.T) {
	h := acceptingHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, nil)
	rec := post(h, pinnedProtocolVersion, "sk-ocu-x", validToolCall)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("a forward failure must be a 502 refusal, got %d", rec.Code)
	}
}

// F10 audit — emit-before-ack, fail-closed durable-first (NFR-SEC-03). A durable
// audit-write failure REFUSES the request (500), never acks it with a 200, so a
// 200 always means the action was durably recorded.
func TestF10_AuditWriteFailureIsRefusal(t *testing.T) {
	em, err := audit.NewEmitter(failingSink{})
	if err != nil {
		t.Fatalf("emitter: %v", err)
	}
	h, err := NewHandler(
		acceptAuth{caller: auth.Caller{KeyID: "k1"}},
		newValidator(t),
		&recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}, // forward SUCCEEDS
		quota.NewCeiling(64), NewOriginPolicy(nil), em,
	)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	rec := post(h, pinnedProtocolVersion, "sk-ocu-x", validToolCall)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a forward that succeeds but whose audit write fails must be refused (500), got %d", rec.Code)
	}
}

// F10 audit — the emitted actor is the host-attested caller (KeyID), never a body
// claim (NFR-SEC-09). A capturing sink records the payload; the actor.user.uid
// must be the resolved KeyID, and a body-supplied "caller" must NOT appear.
func TestF10_AuditActorIsHostAttested(t *testing.T) {
	sink := &capturingSink{}
	em, _ := audit.NewEmitter(sink)
	h, err := NewHandler(
		acceptAuth{caller: auth.Caller{KeyID: "resolved-key-9"}},
		newValidator(t),
		&recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}},
		quota.NewCeiling(64), NewOriginPolicy(nil), em,
	)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	bodyWithClaim := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},"caller":"admin"}}`
	rec := post(h, pinnedProtocolVersion, "sk-ocu-x", bodyWithClaim)
	if rec.Code != http.StatusOK {
		t.Fatalf("happy path must be 200, got %d", rec.Code)
	}
	if len(sink.payloads) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(sink.payloads))
	}
	s := string(sink.payloads[0])
	if !strings.Contains(s, "resolved-key-9") {
		t.Error("audit actor must be the host-attested resolved KeyID")
	}
	if strings.Contains(s, "admin") {
		t.Error("a body-supplied caller claim must NOT appear in the audit actor (NFR-SEC-09)")
	}
}

// Sanity: the NewHandler constructor is fail-closed on any nil seam (admit-all /
// validate-nothing / no-F5 / no-fairness would each defeat an invariant).
func TestNewHandlerFailsClosedOnNilSeam(t *testing.T) {
	v := newValidator(t)
	fwd := &recordingForwarder{}
	c := quota.NewCeiling(1)
	a := acceptAuth{}
	em := newEmitter(t)
	cases := []struct {
		name  string
		authn auth.CallerAuthenticator
		val   *profile.Validator
		f     forward.Forwarder
		cl    *quota.Ceiling
		em    *audit.Emitter
	}{
		{"nil authn", nil, v, fwd, c, em},
		{"nil validator", a, nil, fwd, c, em},
		{"nil forwarder", a, v, nil, c, em},
		{"nil ceiling", a, v, fwd, nil, em},
		{"nil emitter", a, v, fwd, c, nil},
	}
	for _, tc := range cases {
		if _, err := NewHandler(tc.authn, tc.val, tc.f, tc.cl, NewOriginPolicy(nil), tc.em); err == nil {
			t.Errorf("%s: NewHandler must fail closed, got nil error", tc.name)
		}
	}
}
