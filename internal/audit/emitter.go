// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"errors"
	"sync/atomic"
)

// channelAddress is the gateway's own audit fan-in channel (the audit-fanin
// contract's mcpGatewayAudit address). The gateway emits ONLY here.
const channelAddress = "audit.ingest.mcp-gateway"

// ErrAuditWriteFailed is the fail-closed audit refusal: the durable write did
// not succeed, so the request it would record MUST be refused, not acknowledged
// (NFR-SEC-03 fail-closed durable-first). A 2xx on a gateway request therefore
// means the action took effect AND was durably recorded; an audit-write failure
// is a refusal, never a silent loss.
var ErrAuditWriteFailed = errors.New("audit: durable write failed, request refused (fail-closed)")

// Sink is the durable audit-bus seam. The concrete bus (NATS/Kafka/AMQP — a
// component-spec decision, contract #150, protocol-agnostic in the AsyncAPI) lives
// below this seam. A Sink MUST return nil ONLY when the event is durably
// committed; any other outcome (transport error, non-durable accept, timeout) is
// a non-nil error the Emitter turns into a fail-closed refusal.
type Sink interface {
	// Publish durably commits the OCSF payload to the named channel and returns
	// nil ONLY on a confirmed durable write. It MUST NOT report success on a
	// best-effort or in-flight send.
	Publish(ctx context.Context, channel string, payload []byte) error
}

// Emitter renders and durably publishes OCSF ApiActivity events for the gateway,
// fail-closed durable-first. It owns the per-source monotonic sequence counter
// (NFR-SEC-48): each emitted event gets the next sequence, never reused or
// rewound, and the pipeline derives chain order from it.
type Emitter struct {
	sink Sink
	seq  atomic.Uint64
}

// NewEmitter builds the emitter over a durable Sink. A nil sink is a construction
// error: an emitter with no sink could not fail closed (it would have nowhere to
// write and might be mistaken for a no-op emit). Returning an error keeps the
// fail-closed posture at construction.
func NewEmitter(sink Sink) (*Emitter, error) {
	if sink == nil {
		return nil, errors.New("audit: NewEmitter requires a non-nil Sink (fail-closed)")
	}
	return &Emitter{sink: sink}, nil
}

// Emit renders env as an OCSF ApiActivity and durably publishes it, returning nil
// ONLY when the durable write is confirmed. The order is: assign the next
// monotonic sequence → Validate → render → Publish → check the write. A
// validation failure or a write failure both return a non-nil error (wrapping
// ErrInvalidEnvelope or ErrAuditWriteFailed) so the caller refuses the request
// rather than acknowledging an unrecorded action.
//
// The caller MUST treat a non-nil return as a refusal of the request being
// audited (emit-before-ack): it calls Emit, and only on nil does it acknowledge.
// The sequence is assigned even on a later failure so a gap is visible to the
// pipeline (a skipped sequence signals a refused emit, not a silent loss); the
// counter never rewinds.
func (e *Emitter) Emit(ctx context.Context, env Envelope) error {
	// Assign the next monotonic sequence first, so concurrent emits get distinct,
	// ordered sequences and a failed emit still consumes its slot (a visible gap).
	env.Sequence = e.seq.Add(1) - 1

	if err := env.Validate(); err != nil {
		return err
	}
	payload, err := env.ToApiActivity()
	if err != nil {
		return err
	}
	if err := e.sink.Publish(ctx, channelAddress, payload); err != nil {
		// Fail-closed: the durable write did not succeed, so the request is
		// refused. The cause is wrapped but the caller maps only the stable
		// ErrAuditWriteFailed to the wire (leak-free).
		return errors.Join(ErrAuditWriteFailed, err)
	}
	return nil
}

// CurrentSequence returns the next sequence value that will be assigned. It is
// exposed for the monotonicity test and a diagnostic gauge; it never mutates.
func (e *Emitter) CurrentSequence() uint64 {
	return e.seq.Load()
}
