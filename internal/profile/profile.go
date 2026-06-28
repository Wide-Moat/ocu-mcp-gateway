// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package profile is the OCU constraint-profile validator at the MCP gateway
// ingress. It enforces invariant #1: every inbound tool-call (and every
// outbound result/error/discovery message) is validated against the MCP base
// schema THEN the OCU profile before any forward, and an unknown field or
// out-of-bound payload is rejected PRE-BUFFER with a structured deny, never
// partially acted on (NFR-SEC-51, NFR-SEC-46).
//
// The contract is a conform-not-define overlay (contracts/mcp/2025-06-18/
// ocu-constraints.schema.json, vendored byte-identical from canon; see
// VENDORED.md). The overlay is NON-self-executing: it has no root type, and a
// validator pointed at it alone accepts everything. Validation therefore
// DISPATCHES by message kind — each MCP message is checked against the one
// named $def the x-ocu-overlay-map binds it to (boundedError, boundedTool,
// boundedCallToolResult, boundedInitializeResult, jsonRpcSingleMessage). A
// blind whole-body validation would be a fail-open no-op; the dispatch is the
// contract.
//
// Two-pass ordering is load-bearing: the MCP base schema is applied FIRST
// (structural conformance to public MCP revision 2025-06-18), then this profile
// (the OCU-side bounds). This package owns the profile pass; the base pass is a
// seam (BaseValidator) so the public MCP schema can be wired in without
// redefining MCP types here (OCU is a Conformist — it does not restate the base).
package profile

import (
	"errors"
	"fmt"
)

// Kind names the MCP message kind being validated. The set is closed and maps
// 1:1 onto the overlay's x-ocu-overlay-map. An unknown kind is a programming
// error at the dispatch site, never a silently-accepted message.
type Kind uint8

const (
	// KindInvalid is the zero value; validating it is always a fail-closed deny,
	// so a forgotten dispatch arm rejects rather than admits.
	KindInvalid Kind = iota
	// KindCallToolRequest is an inbound tools/call request; its params.arguments
	// are bounded by maxToolArgumentsBytes (NFR-SEC-46/51). Validated against the
	// base CallToolRequest then the argument bound.
	KindCallToolRequest
	// KindCallToolResult is an outbound CallToolResult (boundedCallToolResult):
	// content block count ≤ maxContentBlocks and total serialized size ≤
	// maxCallToolResultBytes, enforced pre-buffer (NFR-SEC-46).
	KindCallToolResult
	// KindTool is a Tool definition in a tools/list or tools/call (boundedTool):
	// description ≤ maxToolDescriptionBytes (NFR-SEC-51).
	KindTool
	// KindError is a JSON-RPC error object (boundedError): a Tier-1 protocol
	// error with a stable reason code only, message ≤ maxErrorMessageBytes and
	// data ≤ maxErrorDataBytes, no topology/stack (NFR-SEC-51).
	KindError
	// KindInitializeResult is an InitializeResult (boundedInitializeResult): the
	// pinned revision, tools-only capability set, instructions ≤
	// maxInstructionsBytes (NFR-SEC-51, NFR-IC-04).
	KindInitializeResult
)

// String renders a Kind for diagnostics and the structured deny reason. An
// out-of-range value renders as "kind_unknown" so a forgotten arm surfaces in
// the record rather than mislabelling.
func (k Kind) String() string {
	switch k {
	case KindCallToolRequest:
		return "call_tool_request"
	case KindCallToolResult:
		return "call_tool_result"
	case KindTool:
		return "tool"
	case KindError:
		return "error"
	case KindInitializeResult:
		return "initialize_result"
	default:
		return "kind_unknown"
	}
}

// defName maps a Kind to the overlay $def the x-ocu-overlay-map binds it to. An
// unknown kind maps to the empty string, which the validator treats as a
// fail-closed deny (no def → no admit).
func (k Kind) defName() string {
	switch k {
	case KindCallToolRequest:
		// CallToolRequest has no dedicated bounded $def; its argument bound is
		// enforced as a pre-buffer byte check (maxToolArgumentsBytes) alongside
		// the base-schema pass, because the cap is a serialized-size ceiling the
		// gateway measures before decoding, not a JSON Schema keyword.
		return ""
	case KindCallToolResult:
		return "boundedCallToolResult"
	case KindTool:
		return "boundedTool"
	case KindError:
		return "boundedError"
	case KindInitializeResult:
		return "boundedInitializeResult"
	default:
		return ""
	}
}

// ErrDenied is the structured-deny sentinel: validation rejected the message.
// It is returned PRE-BUFFER for an inbound message (the body is never partially
// acted on) and carries only a stable reason class plus the failing kind — never
// a session id, container_name, internal host/route, or stack detail
// (invariant #5, NFR-SEC-51). Callers match it with errors.Is and surface only
// its bounded reason to the wire.
var ErrDenied = errors.New("profile: message denied by OCU constraint profile")

// Deny is the structured rejection a validator returns. It carries a stable,
// enumerable Reason class and the message Kind, and NOTHING caller-derived: no
// echoed payload, no offending value, no internal identifier. The wire-facing
// error envelope is built from Reason alone, so a deny cannot become an
// information-leak side channel (invariant #5).
type Deny struct {
	// Kind is the message kind that failed validation.
	Kind Kind
	// Reason is the stable reason class. It is one of a closed set (see the
	// Reason* constants) so the outbound error envelope maps it to a fixed
	// JSON-RPC code without ever interpolating caller data.
	Reason Reason
}

func (d *Deny) Error() string {
	return fmt.Sprintf("%v: %s message denied: %s", ErrDenied, d.Kind, d.Reason)
}

// Unwrap lets errors.Is(err, ErrDenied) match a *Deny.
func (d *Deny) Unwrap() error { return ErrDenied }

// Reason is the stable, leak-free reason class on a Deny. The set is closed and
// maps to JSON-RPC error codes at the wire boundary; it never carries
// caller-supplied text.
type Reason uint8

const (
	// ReasonUnknown is the zero value; it maps to the internal-error code and is
	// never a normal outcome (a real deny always sets a specific reason).
	ReasonUnknown Reason = iota
	// ReasonBaseSchema: the message failed the MCP base-schema pass (malformed
	// per public MCP revision 2025-06-18). Maps to -32600/-32602.
	ReasonBaseSchema
	// ReasonProfileSchema: the message passed the base pass but violated an OCU
	// overlay $def (e.g. an unknown capability, a non-pinned protocolVersion).
	ReasonProfileSchema
	// ReasonOverSize: a serialized-size ceiling was exceeded (arguments, result,
	// error message/data, description, instructions). Rejected pre-buffer.
	ReasonOverSize
	// ReasonBatching: an HTTP body that is a JSON array (batching removed in
	// 2025-06-18; jsonRpcSingleMessage requires a single object).
	ReasonBatching
)

// String renders a Reason as a stable reason class string for diagnostics. It is
// caller-data-free and safe to surface.
func (r Reason) String() string {
	switch r {
	case ReasonBaseSchema:
		return "base_schema_violation"
	case ReasonProfileSchema:
		return "profile_constraint_violation"
	case ReasonOverSize:
		return "payload_over_size_bound"
	case ReasonBatching:
		return "batching_not_permitted"
	default:
		return "internal"
	}
}

// BaseValidator is the MCP base-schema pass seam. The OCU profile is an overlay
// that does NOT restate MCP base types, so the base pass is supplied here rather
// than redefined: a concrete validator wires the public MCP revision 2025-06-18
// schema in. The base pass runs FIRST; only a message that conforms to the base
// is then checked against the OCU profile.
//
// A nil BaseValidator is a fail-closed configuration error at validator
// construction, not a skipped pass: skipping the base pass would let a
// structurally-malformed message reach the profile pass (or worse, the forward)
// — the two-pass order is load-bearing.
type BaseValidator interface {
	// ValidateBase reports whether raw conforms to the MCP base schema for the
	// given kind, returning a non-nil error (wrapping ErrDenied with
	// ReasonBaseSchema) when it does not. It MUST NOT mutate raw.
	ValidateBase(kind Kind, raw []byte) error
}
