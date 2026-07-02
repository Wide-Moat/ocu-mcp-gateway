// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package audit is the F10 OCSF audit fan-in emitter for the MCP gateway. It
// emits one OCSF ApiActivity event per terminated request WITH A VALIDATED
// IDENTITY — the success path plus the post-auth refusals (a 429 connection-
// ceiling refusal and a 502 forward refusal), each with the host-attested caller
// identity — on the gateway's own fan-in channel (audit.ingest.mcp-gateway).
//
// The two PRE-AUTH refusals (a 401 auth-failure and a 403 origin rejection) fire
// before a caller is resolved, so they have NO attested actor and are counted at
// the transport layer, NOT the OCSF fan-in. This is a DELIBERATE omission, not a
// gap: a placeholder actor on an OCSF event would be false attribution, worse
// than the omission (NFR-SEC-09 — the audit actor is host-attested or absent,
// never guessed). The exclusion is pinned by
// internal/ingress/refusal_audit_test.go (TestPreAuthRefusalsDoNotEmit).
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
	// OutcomeFailure — a terminated request WITH A VALIDATED IDENTITY was refused
	// after auth: a connection-ceiling refusal (429) or a forward fail-closed
	// refusal (502). Pre-auth refusals (401/403) carry no attested actor and are
	// not emitted (see the package doc).
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
