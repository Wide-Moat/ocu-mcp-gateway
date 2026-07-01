// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package audit is the F10 OCSF audit fan-in emitter for the MCP gateway. It
// emits one OCSF ApiActivity event per terminated request (with the validated,
// host-attested caller identity) plus a rejection event on a connection-ceiling
// refusal, on the gateway's own fan-in channel (audit.ingest.mcp-gateway).
//
// The contract is the vendored audit-fanin AsyncAPI (contracts/audit/
// audit-fanin.asyncapi.yaml, byte-identical from canon; see VENDORED.md). The
// gateway is ONE of five host-side emitters; it emits ONLY ApiActivity, ONLY on
// its own channel.
//
// Emit is fail-closed durable-first (NFR-SEC-03, mirrors the sibling control
// plane's audit contract): the order is Emit → check the durable write succeeded
// → only then acknowledge the request. An audit-write failure is a REFUSAL, not
// a silent loss. The hash-chain linkage (prev_hash/chain_hash) is authored by
// the pipeline at ingest, NOT here — the gateway supplies only the per-source
// monotonic sequence and the pipeline derives chain order from it.
package audit

import (
	"errors"
	"fmt"
)

// Field bounds from the AuditEnvelope schema (NFR-MAINT-AUDIT-SCHEMA /
// NFR-SEC-51-derived defaults, not frozen). A value over its bound is a
// programming error at construction, caught by Validate, not silently truncated.
const (
	maxTraceID   = 128
	maxSessionID = 128
	maxActorID   = 256
	maxResource  = 1024
	maxAction    = 128
)

// Outcome is the bounded request outcome, aligning the OCSF status_id. The set is
// closed (the contract enum is success|failure|unknown).
type Outcome string

const (
	// OutcomeSuccess — the request was handled and forwarded without refusal.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure — the request was refused (auth, validation, ceiling,
	// forward fail-closed).
	OutcomeFailure Outcome = "failure"
	// OutcomeUnknown — the outcome could not be determined (reserved; the
	// gateway resolves to success/failure in practice).
	OutcomeUnknown Outcome = "unknown"
)

// valid reports whether o is one of the closed enum values. An unset/invalid
// outcome fails Validate rather than emitting an out-of-enum value.
func (o Outcome) valid() bool {
	switch o {
	case OutcomeSuccess, OutcomeFailure, OutcomeUnknown:
		return true
	default:
		return false
	}
}

// Envelope is the OCU mandatory audit-envelope (the AuditEnvelope schema): the
// seven required, bounded fields every emitted event carries. The pipeline's
// hash-chain fields are NOT here (the pipeline authors them at ingest); the
// gateway supplies the per-source monotonic Sequence and the pipeline derives
// chain order.
//
// actor_id is HOST-ATTESTED (NFR-SEC-09): for the gateway it is the resolved
// caller principal handle (the auth seam's KeyID), never a body-supplied claim.
type Envelope struct {
	// TraceID is the UUID/hex cross-surface correlation id (≤128). It is the
	// correlationId the pipeline keys on.
	TraceID string
	// SessionID is the container/session binding (≤128). On the gateway it is the
	// correlation handle for the request; the gateway holds no session registry,
	// so this is a request-scoped correlation value, not an authority.
	SessionID string
	// ActorID is the host-attested service/caller identity (≤256, NFR-SEC-09).
	ActorID string
	// Resource is the target object of the action (≤1024).
	Resource string
	// Action is the privileged/lifecycle action name (≤128).
	Action string
	// Outcome aligns the OCSF status_id (success|failure|unknown).
	Outcome Outcome
	// Sequence is the per-source MONOTONIC sequence (≥0, NFR-SEC-48). The
	// pipeline derives chain order from it; the gateway never reuses or rewinds
	// it.
	Sequence uint64
}

// ErrInvalidEnvelope is returned when an Envelope violates the schema (a missing
// required field, an over-bound value, or an out-of-enum outcome). It is caught
// before emit so a malformed event is never published — a fail-closed
// construction guard, not a silent drop.
var ErrInvalidEnvelope = errors.New("audit: envelope violates the audit-fanin schema")

// Validate enforces the AuditEnvelope schema's required-and-bounded contract. It
// is called before every emit so an event that would violate the published
// contract is refused at the source, never sent.
func (e Envelope) Validate() error {
	if e.TraceID == "" || len(e.TraceID) > maxTraceID {
		return fmt.Errorf("%w: trace_id required, ≤%d", ErrInvalidEnvelope, maxTraceID)
	}
	if e.SessionID == "" || len(e.SessionID) > maxSessionID {
		return fmt.Errorf("%w: session_id required, ≤%d", ErrInvalidEnvelope, maxSessionID)
	}
	if e.ActorID == "" || len(e.ActorID) > maxActorID {
		return fmt.Errorf("%w: actor_id required, ≤%d", ErrInvalidEnvelope, maxActorID)
	}
	if e.Resource == "" || len(e.Resource) > maxResource {
		return fmt.Errorf("%w: resource required, ≤%d", ErrInvalidEnvelope, maxResource)
	}
	if e.Action == "" || len(e.Action) > maxAction {
		return fmt.Errorf("%w: action required, ≤%d", ErrInvalidEnvelope, maxAction)
	}
	if !e.Outcome.valid() {
		return fmt.Errorf("%w: outcome must be success|failure|unknown, got %q", ErrInvalidEnvelope, e.Outcome)
	}
	return nil
}
