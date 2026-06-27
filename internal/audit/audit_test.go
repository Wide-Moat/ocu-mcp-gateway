// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

// validEnvelope returns a schema-valid envelope for tests to mutate.
func validEnvelope() Envelope {
	return Envelope{
		TraceID:   "trace-abc",
		SessionID: "sess-1",
		ActorID:   "key-1",
		Resource:  "tools/call:echo",
		Action:    "tool_call",
		Outcome:   OutcomeSuccess,
	}
}

func TestEnvelopeValidateAcceptsValid(t *testing.T) {
	if err := validEnvelope().Validate(); err != nil {
		t.Fatalf("a valid envelope must pass: %v", err)
	}
}

func TestEnvelopeValidateRequiresEachField(t *testing.T) {
	cases := map[string]func(*Envelope){
		"trace_id":   func(e *Envelope) { e.TraceID = "" },
		"session_id": func(e *Envelope) { e.SessionID = "" },
		"actor_id":   func(e *Envelope) { e.ActorID = "" },
		"resource":   func(e *Envelope) { e.Resource = "" },
		"action":     func(e *Envelope) { e.Action = "" },
	}
	for field, mut := range cases {
		e := validEnvelope()
		mut(&e)
		if err := e.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("missing %s must fail validation, got %v", field, err)
		}
	}
}

func TestEnvelopeValidateBoundsFields(t *testing.T) {
	e := validEnvelope()
	e.ActorID = strings.Repeat("a", maxActorID+1)
	if err := e.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("an over-bound actor_id must fail validation, got %v", err)
	}
}

func TestEnvelopeValidateRejectsBadOutcome(t *testing.T) {
	e := validEnvelope()
	e.Outcome = Outcome("bogus")
	if err := e.Validate(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("an out-of-enum outcome must fail validation, got %v", err)
	}
}

func TestToApiActivityShape(t *testing.T) {
	e := validEnvelope()
	e.Sequence = 7
	raw, err := e.ToApiActivity()
	if err != nil {
		t.Fatalf("ToApiActivity: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if obj["class_uid"].(float64) != ocsfClassUID {
		t.Errorf("class_uid should be %d, got %v", ocsfClassUID, obj["class_uid"])
	}
	if obj["status_id"].(float64) != statusIDSuccess {
		t.Errorf("success outcome should map to status_id %d", statusIDSuccess)
	}
	meta := obj["metadata"].(map[string]any)
	if meta["sequence"].(float64) != 7 {
		t.Errorf("sequence should ride metadata.sequence, got %v", meta["sequence"])
	}
	if meta["correlation_uid"] != "trace-abc" {
		t.Errorf("trace_id should ride metadata.correlation_uid, got %v", meta["correlation_uid"])
	}
	// actor_id is host-attested and rides actor.user.uid, never a body field.
	actor := obj["actor"].(map[string]any)["user"].(map[string]any)
	if actor["uid"] != "key-1" {
		t.Errorf("actor_id should ride actor.user.uid, got %v", actor["uid"])
	}
}

// okSink durably accepts every event; failSink never does.
type okSink struct {
	mu       sync.Mutex
	payloads [][]byte
	channels []string
}

func (s *okSink) Publish(_ context.Context, channel string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.channels = append(s.channels, channel)
	s.payloads = append(s.payloads, payload)
	return nil
}

type failSink struct{ err error }

func (s failSink) Publish(context.Context, string, []byte) error { return s.err }

func TestNewEmitterNilSinkFailsClosed(t *testing.T) {
	if _, err := NewEmitter(nil); err == nil {
		t.Fatal("NewEmitter(nil) must fail closed")
	}
}

func TestEmitDurableSuccess(t *testing.T) {
	sink := &okSink{}
	em, err := NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	if err := em.Emit(context.Background(), validEnvelope()); err != nil {
		t.Fatalf("Emit on a durable sink must succeed: %v", err)
	}
	if len(sink.payloads) != 1 {
		t.Fatalf("expected 1 published event, got %d", len(sink.payloads))
	}
	if sink.channels[0] != channelAddress {
		t.Errorf("must emit on the gateway channel %q, got %q", channelAddress, sink.channels[0])
	}
}

// TestEmitWriteFailureIsRefusal is the fail-closed durable-first enforcing test:
// a durable-write failure is a REFUSAL (ErrAuditWriteFailed), not a silent loss.
func TestEmitWriteFailureIsRefusal(t *testing.T) {
	em, err := NewEmitter(failSink{err: errors.New("bus down")})
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}
	err = em.Emit(context.Background(), validEnvelope())
	if !errors.Is(err, ErrAuditWriteFailed) {
		t.Fatalf("a durable-write failure must be ErrAuditWriteFailed (a refusal), got %v", err)
	}
}

// TestEmitInvalidEnvelopeRefused proves an invalid envelope is never published.
func TestEmitInvalidEnvelopeRefused(t *testing.T) {
	sink := &okSink{}
	em, _ := NewEmitter(sink)
	bad := validEnvelope()
	bad.ActorID = "" // missing required host-attested identity
	if err := em.Emit(context.Background(), bad); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("an invalid envelope must be refused, got %v", err)
	}
	if len(sink.payloads) != 0 {
		t.Fatal("an invalid envelope must NEVER be published")
	}
}

// TestSequenceMonotonicAndUnique proves the per-source sequence is monotonic and
// distinct across concurrent emits (NFR-SEC-48) — the pipeline derives chain
// order from it, so duplicates or rewinds would corrupt the chain.
func TestSequenceMonotonicAndUnique(t *testing.T) {
	sink := &okSink{}
	em, _ := NewEmitter(sink)
	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = em.Emit(context.Background(), validEnvelope())
		}()
	}
	wg.Wait()
	// Collect the sequences from the published payloads; they must be exactly
	// 0..n-1 with no duplicate.
	seen := make(map[float64]bool, n)
	for _, p := range sink.payloads {
		var obj map[string]any
		_ = json.Unmarshal(p, &obj)
		s := obj["metadata"].(map[string]any)["sequence"].(float64)
		if seen[s] {
			t.Fatalf("duplicate sequence %v — the chain order would be corrupted", s)
		}
		seen[s] = true
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct sequences, got %d", n, len(seen))
	}
}

// TestWriteFailureStillConsumesSequence proves a refused emit still consumes its
// sequence slot, so a gap (not a reused number) is visible to the pipeline.
func TestWriteFailureStillConsumesSequence(t *testing.T) {
	em, _ := NewEmitter(failSink{err: errors.New("down")})
	_ = em.Emit(context.Background(), validEnvelope())
	_ = em.Emit(context.Background(), validEnvelope())
	if em.CurrentSequence() != 2 {
		t.Fatalf("two refused emits must still advance the sequence to 2, got %d", em.CurrentSequence())
	}
}
