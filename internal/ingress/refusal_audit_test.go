// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/serialize"
)

// §XI (F11): every terminated request WITH A VALIDATED IDENTITY is recorded —
// the post-auth refusals (429 ceiling, 502 forward) emit an OutcomeFailure audit
// event with the resolved actor, durable-first fail-closed, SYMMETRIC to the
// success path. A self-audit found NO refusal path emitted: the only Emit was the
// OutcomeSuccess one after a successful forward, so canon spec line 64/75
// ("emit per terminated request … plus a rejection event on a ceiling refusal",
// NFR-SEC-03) was unmet. Pre-auth refusals (401 auth-fail, 403 origin) have no
// resolved caller at that boundary order and are a DELIBERATE transport-layer
// omission — asserted below to stay non-emitting so the exclusion is pinned too.

// recordingSink captures every emitted OCSF payload so a test can assert the
// outcome/actor of a refusal event, not just the count.
type recordingSink struct {
	mu       sync.Mutex
	payloads [][]byte
}

func (s *recordingSink) Publish(_ context.Context, _ string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	s.payloads = append(s.payloads, cp)
	return nil
}

func (s *recordingSink) events() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.payloads))
	for _, p := range s.payloads {
		var m map[string]any
		if err := json.Unmarshal(p, &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// refusalHandler wires a handler with a recording audit sink and the given
// forwarder/ceiling, resolving the caller from the bearer (so the actor is
// observable and distinct per test).
func refusalHandler(t *testing.T, fwd forward.Forwarder, ceiling *quota.Ceiling, sink audit.Sink) *Handler {
	t.Helper()
	em, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("emitter: %v", err)
	}
	if ceiling == nil {
		ceiling = quota.NewCeiling(64)
	}
	h, err := NewHandler(
		tenantFromBearerAuth{},
		newValidator(t), fwd, ceiling, NewOriginPolicy(nil), em, serialize.NewSerializer(64, nil),
	)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return h
}

// eventsWithStatusID returns the OCSF events whose status_id equals want (the
// gateway renders status_id: 1=Success, 2=Failure). JSON numbers unmarshal to
// float64.
func eventsWithStatusID(events []map[string]any, want float64) []map[string]any {
	var out []map[string]any
	for _, e := range events {
		if sid, ok := e["status_id"].(float64); ok && sid == want {
			out = append(out, e)
		}
	}
	return out
}

// actorUID reads the host-attested actor uid (actor.user.uid) from an OCSF event.
func actorUID(e map[string]any) string {
	actor, ok := e["actor"].(map[string]any)
	if !ok {
		return ""
	}
	user, ok := actor["user"].(map[string]any)
	if !ok {
		return ""
	}
	uid, _ := user["uid"].(string)
	return uid
}

func failureEvents(_ *testing.T, events []map[string]any) []map[string]any {
	return eventsWithStatusID(events, 2)
}

// TestForwardRefusalIsRecorded proves a 502 forward refusal emits an
// OutcomeFailure event with the resolved actor (§XI). Red-probe: remove the 502
// refusal emit and this goes RED (no failure event recorded).
func TestForwardRefusalIsRecorded(t *testing.T) {
	sink := &recordingSink{}
	h := refusalHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, nil, sink)

	rec := post(h, pinnedProtocolVersion, "t-actor", validToolCall)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("forward failure must be 502, got %d", rec.Code)
	}
	fails := failureEvents(t, sink.events())
	if len(fails) != 1 {
		t.Fatalf("a terminated (502) request must record exactly one OutcomeFailure event, got %d", len(fails))
	}
	if got := actorUID(fails[0]); got != "t-actor" {
		t.Errorf("the refusal event's actor must be the resolved caller (t-actor), got %v", got)
	}
}

// TestCeilingRefusalIsRecorded proves a 429 ceiling refusal emits an
// OutcomeFailure event with the resolved actor (§XI, the rejection event canon
// line 75 names explicitly). Red-probe: remove the 429 refusal emit → RED.
func TestCeilingRefusalIsRecorded(t *testing.T) {
	sink := &recordingSink{}
	fwd := &blockingForwarder{entered: make(chan struct{}), release: make(chan struct{})}
	h := refusalHandler(t, fwd, quota.NewCeiling(1), sink)

	// Request A holds the only ceiling slot (parks in forward).
	done := make(chan int, 1)
	go func() { done <- post(h, pinnedProtocolVersion, "t-ceil", validToolCall).Code }()
	<-fwd.entered

	// Request B (same caller) is refused 429 by the ceiling.
	recB := post(h, pinnedProtocolVersion, "t-ceil", validToolCall)
	if recB.Code != http.StatusTooManyRequests {
		t.Fatalf("ceiling refusal must be 429, got %d", recB.Code)
	}

	close(fwd.release)
	if codeA := <-done; codeA != http.StatusOK {
		t.Fatalf("the slot-holder must succeed, got %d", codeA)
	}

	// Exactly one failure event (B's ceiling refusal), with B's actor.
	fails := failureEvents(t, sink.events())
	if len(fails) != 1 {
		t.Fatalf("the 429 ceiling refusal must record exactly one OutcomeFailure event, got %d", len(fails))
	}
	if got := actorUID(fails[0]); got != "t-ceil" {
		t.Errorf("the ceiling refusal event's actor must be the resolved caller (t-ceil), got %v", got)
	}
}

// TestRefusalAuditIsFailClosed proves the refusal audit is durable-first,
// SYMMETRIC to success: if the durable write of the refusal event fails, the
// request is refused 500 — a refusal we cannot record is a repudiation hole, not
// a swallow. Red-probe: make the refusal emit best-effort (ignore its error) and
// this goes RED (502 leaks through instead of 500).
func TestRefusalAuditIsFailClosed(t *testing.T) {
	h := refusalHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, nil, failingSink{})

	rec := post(h, pinnedProtocolVersion, "t-actor", validToolCall)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a refusal whose audit write fails must be 500 (durable-first, symmetric to success), got %d", rec.Code)
	}
}

// TestPreAuthRefusalsDoNotEmit pins the deliberate exclusion: 401 (auth-fail)
// and 403 (origin) fire BEFORE a caller is resolved, so they have no attested
// actor and MUST NOT emit a per-request OCSF event (a placeholder actor would be
// false attribution — worse than omission). This is a documented transport-layer
// omission, not a gap; the test keeps it from silently acquiring an emit.
func TestPreAuthRefusalsDoNotEmit(t *testing.T) {
	// 401: reject-all auth.
	sink401 := &recordingSink{}
	em, err := audit.NewEmitter(sink401)
	if err != nil {
		t.Fatalf("emitter: %v", err)
	}
	h401, err := NewHandler(rejectAllAuth{}, newValidator(t), &recordingForwarder{}, quota.NewCeiling(64), NewOriginPolicy(nil), em, serialize.NewSerializer(64, nil))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if rec := post(h401, pinnedProtocolVersion, "sk-ocu-bad", validToolCall); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if n := len(sink401.events()); n != 0 {
		t.Errorf("a 401 auth-failure must NOT emit an OCSF event (no attested actor); got %d", n)
	}

	// 403: a disallowed Origin, refused before auth.
	sink403 := &recordingSink{}
	h403 := refusalHandler(t, &recordingForwarder{}, nil, sink403)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(validToolCall))
	req.Header.Set(protocolVersionHeader, pinnedProtocolVersion)
	req.Header.Set("Authorization", "Bearer t-a")
	req.Header.Set("Origin", "https://evil.example")
	recW := httptest.NewRecorder()
	h403.ServeHTTP(recW, req)
	if recW.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", recW.Code)
	}
	if n := len(sink403.events()); n != 0 {
		t.Errorf("a 403 origin refusal (pre-auth, no attested actor) must NOT emit an OCSF event; got %d", n)
	}
}

// TestSuccessStillRecorded is a regression guard: the §XI refusal wiring must not
// disturb the success path — a forwarded request still records exactly one
// OutcomeSuccess event with the actor.
func TestSuccessStillRecorded(t *testing.T) {
	sink := &recordingSink{}
	h := refusalHandler(t, &recordingForwarder{resp: forward.SessionResponse{}}, nil, sink)
	if rec := post(h, pinnedProtocolVersion, "t-ok", validToolCall); rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	events := sink.events()
	if len(events) != 1 {
		t.Fatalf("success must record exactly one event, got %d", len(events))
	}
	if events[0]["status_id"] != float64(1) {
		t.Errorf("the success event must map to OCSF Success, got %v", events[0]["status"])
	}
}
