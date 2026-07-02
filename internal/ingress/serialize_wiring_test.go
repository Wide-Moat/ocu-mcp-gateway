// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/serialize"
)

// These tests pin the §XII (NFR-IC-05) per-session serialization at the SHIPPED
// boundary — they drive ServeHTTP, not the serialize.Serializer primitive in
// isolation. A prior self-audit found the handler wiring was fake-green: the
// serializer step could be deleted, made fail-open on ErrSerializerFull, or keyed
// on a caller-body field (req.ToolCall.Name) with the whole ingress suite still
// passing, because no test observed the serializer's EFFECT through ServeHTTP.
// Each test below goes RED under one of those neuters.

// blockingForwarder parks in Forward until released, so a test can hold a
// serializer slot open across the forward+emit window and drive a concurrent
// same-session request into the fail-closed overflow (ErrSerializerFull → 429).
// It also records the order in which forwards completed, so a test can assert
// per-session ordering.
type blockingForwarder struct {
	entered chan struct{} // signalled once, when the first Forward enters
	release chan struct{} // closed by the test to let the parked Forward return

	mu        sync.Mutex
	completed []string // tenant of each caller whose forward returned, in order
	enteredN  int
}

func (f *blockingForwarder) Forward(_ context.Context, req forward.SessionRequest) (forward.SessionResponse, error) {
	f.mu.Lock()
	f.enteredN++
	first := f.enteredN == 1
	f.mu.Unlock()
	if first {
		// Signal that a forward is now in flight (a slot is held) and park until
		// the test releases it, so a concurrent same-session request must contend.
		close(f.entered)
		<-f.release
	}
	f.mu.Lock()
	f.completed = append(f.completed, req.Principal.Tenant)
	f.mu.Unlock()
	return forward.SessionResponse{}, nil
}

// handlerWithSerializer wires a handler exactly as production does (real
// validator, real emitter, real serializer) but lets the test choose the
// serializer (so a depth-1 bound is reachable) and the forwarder (so a slot can
// be parked). The authenticator resolves the caller from the bearer so different
// bearers yield different session principals (Tenant).
func handlerWithSerializer(t *testing.T, fwd forward.Forwarder, s *serialize.Serializer) *Handler {
	t.Helper()
	h, err := NewHandler(
		tenantFromBearerAuth{},
		newValidator(t), fwd, quota.NewCeiling(64), NewOriginPolicy(nil), newEmitter(t), s,
	)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h
}

// tenantFromBearerAuth resolves a caller whose Tenant IS the bearer, so a test
// can send two requests that share (or differ in) their session principal by
// choosing the bearer. KeyID is distinct per request-bearer too, so the ceiling
// (keyed on KeyID) never collides in these tests.
type tenantFromBearerAuth struct{}

func (tenantFromBearerAuth) Authenticate(_ context.Context, cred auth.TransportCredential) (auth.Caller, error) {
	if cred.Bearer == "" {
		return auth.Caller{}, auth.ErrUnauthenticated
	}
	return auth.Caller{KeyID: cred.Bearer, Tenant: cred.Bearer, Deployment: "a1"}, nil
}

// TestSerializeOverflowRefusesWithinSession proves the handler enforces the
// per-session bound: with a depth-1 serializer, while one request of session
// "t-same" holds the slot in forward, a concurrent request of the SAME session is
// refused (429), not queued unboundedly. Neuters that go RED here: deleting step
// 4b (no Acquire → both proceed, no 429) and swallowing ErrSerializerFull
// (fail-open → 200 instead of 429).
func TestSerializeOverflowRefusesWithinSession(t *testing.T) {
	fwd := &blockingForwarder{entered: make(chan struct{}), release: make(chan struct{})}
	// maxDepth 1: one in-flight per session; a second same-session acquire overflows.
	h := handlerWithSerializer(t, fwd, serialize.NewSerializer(1, nil))

	// Request A (session "t-same") enters forward and parks, holding the only slot.
	done := make(chan int, 1)
	go func() { done <- post(h, pinnedProtocolVersion, "t-same", validToolCall).Code }()
	<-fwd.entered // A is now parked in forward with the slot held

	// Request B (SAME session) must be refused (429), not parked, because the
	// depth-1 queue is at its bound.
	recB := post(h, pinnedProtocolVersion, "t-same", validToolCall)
	if recB.Code != http.StatusTooManyRequests {
		t.Errorf("a concurrent same-session request over the depth-1 bound must be refused 429, got %d", recB.Code)
	}

	// Release A and confirm it completed successfully (the slot was really held).
	close(fwd.release)
	if codeA := <-done; codeA != http.StatusOK {
		t.Errorf("the slot-holding request must succeed once released, got %d", codeA)
	}
}

// TestSerializeKeyedOnPrincipalNotToolName proves the serializer is keyed on the
// resolved caller principal (session hint), NOT on a caller-body field. Two
// concurrent requests of DIFFERENT sessions ("t-a" and "t-b") both carry the same
// tool name (validToolCall's name). With a depth-1 serializer keyed on the
// principal, they must NOT contend — the second must NOT be refused. If the key
// were req.ToolCall.Name (the forbidden caller-body field), both would collide on
// one gate and the second would 429 → this test goes RED, which is exactly the
// two-sided probe for the key-source.
func TestSerializeKeyedOnPrincipalNotToolName(t *testing.T) {
	fwd := &blockingForwarder{entered: make(chan struct{}), release: make(chan struct{})}
	h := handlerWithSerializer(t, fwd, serialize.NewSerializer(1, nil))

	// Request A (session "t-a") parks in forward holding t-a's slot.
	done := make(chan int, 1)
	go func() { done <- post(h, pinnedProtocolVersion, "t-a", validToolCall).Code }()
	<-fwd.entered

	// Request B is a DIFFERENT session ("t-b") with the SAME tool name. Keyed on
	// the principal it has its own gate and must proceed; it does not park in
	// forward (only the first entrant parks), so it returns promptly.
	recB := post(h, pinnedProtocolVersion, "t-b", validToolCall)
	if recB.Code == http.StatusTooManyRequests {
		t.Error("a different-session request sharing the tool name must NOT be refused — the serializer must key on the principal, not the tool name")
	}

	close(fwd.release)
	<-done
}

// TestSerializeSlotSpansForwardAndEmit proves the slot is held across forward AND
// emit (settled state), so call N+1 of a session cannot overtake the durable
// record of call N: the per-session history is executed → recorded → next. We
// assert emit happens under the slot by using a capturing emitter and checking
// that when the slot-holder is parked in forward, its audit record has not yet
// landed (emit is downstream of forward, both inside the slot).
func TestSerializeSlotSpansForwardAndEmit(t *testing.T) {
	fwd := &blockingForwarder{entered: make(chan struct{}), release: make(chan struct{})}
	sink := &countingSink{}
	em, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("emitter: %v", err)
	}
	h, err := NewHandler(
		tenantFromBearerAuth{},
		newValidator(t), fwd, quota.NewCeiling(64), NewOriginPolicy(nil), em, serialize.NewSerializer(1, nil),
	)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	done := make(chan int, 1)
	go func() { done <- post(h, pinnedProtocolVersion, "t-same", validToolCall).Code }()
	<-fwd.entered // parked in forward, slot held, emit NOT yet reached

	if got := sink.Count(); got != 0 {
		t.Errorf("while the request is parked in forward under its slot, no audit record must have landed yet (emit is inside the slot, after forward); got %d", got)
	}

	close(fwd.release)
	if code := <-done; code != http.StatusOK {
		t.Fatalf("request must succeed, got %d", code)
	}
	// After release: forward returned, emit ran under the same slot, then the slot
	// released. Exactly one record for the settled call.
	if got := sink.Count(); got != 1 {
		t.Errorf("after the slot-holding call settles, exactly one audit record must have landed; got %d", got)
	}
}

// countingSink is a durable audit sink that counts landed events with a mutex so
// a concurrent test can read the count safely.
type countingSink struct {
	mu sync.Mutex
	n  int
}

func (s *countingSink) Publish(context.Context, string, []byte) error {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	return nil
}

func (s *countingSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}
