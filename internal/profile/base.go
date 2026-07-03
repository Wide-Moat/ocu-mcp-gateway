// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import (
	"encoding/json"
)

// jsonRPCBaseValidator is a structural MCP base-schema pass: it checks that a
// message is well-formed JSON-RPC 2.0 (the base layer MCP rides) before the OCU
// profile overlay runs. It is the conform-not-define base pass the OCU profile
// overlays — NOT a redefinition of every MCP type (OCU is a Conformist). The
// full public MCP revision 2025-06-18 schema is the authoritative base; wiring it
// in (as a compiled jsonschema resource) is a follow-up that drops in behind this
// same BaseValidator seam without touching the profile pass.
//
// What it enforces today (structural, real — not a stub): the body is a single
// JSON object, it carries the "jsonrpc":"2.0" marker, and per-kind it has the
// minimal required shape (a tools/call request names a method+params; a result
// carries its result field). A malformed message is rejected here, before the
// overlay, so the two-pass order holds.
type jsonRPCBaseValidator struct{}

// NewJSONRPCBaseValidator returns the structural JSON-RPC base pass. It is the
// default base wired into the gateway scaffold; a full-MCP-schema base validator
// replaces it behind the BaseValidator seam without any profile-pass change.
func NewJSONRPCBaseValidator() BaseValidator {
	return jsonRPCBaseValidator{}
}

// ValidateBase checks structural JSON-RPC 2.0 conformance for the given kind. It
// returns a non-nil error (mapped by the caller to a ReasonBaseSchema deny) when
// the message is not a single object, is missing the jsonrpc marker, or lacks the
// kind's minimal required field. It does not mutate raw.
func (jsonRPCBaseValidator) ValidateBase(kind Kind, raw []byte) error {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		// Not a single JSON object (an array, scalar, or malformed body).
		return errBaseMalformed
	}

	// Only the top-level JSON-RPC REQUEST carries the "jsonrpc":"2.0" marker as a
	// validated message here. A boundedError (KindError) is the standalone
	// JSON-RPC error OBJECT (the `error` member's value: {code, message, data?}),
	// validated in isolation like a Tool or an InitializeResult sub-object — it
	// has no jsonrpc marker of its own (CR fix: requiring one rejected every valid
	// bare error object). So the marker is required ONLY for KindCallToolRequest.
	if kind == KindCallToolRequest {
		if err := requireJSONRPCMarker(doc); err != nil {
			return err
		}
	}

	switch kind {
	case KindCallToolRequest:
		// A tools/call request names a method and params, and its params are
		// STRICT-VALIDATED (the contract requires CallToolRequest.params.arguments
		// to be strict-validated input — x-ocu-limits.maxToolArgumentsBytes). There
		// is no CallToolRequest overlay $def, so this strict check IS the request
		// validation: params.name MUST be a non-empty string and, if present,
		// params.arguments MUST be a JSON object. tools/call is the main attack
		// surface, so a malformed request is rejected here, never forwarded.
		//
		// The method NAME is checked against the inbound allowlist, not merely for
		// presence: a self-audit found method-confusion — a request whose method was
		// NOT tools/call (an invented evil/pwn, or a real-but-off-surface
		// resources/list) rode this path and was forwarded on F5 as a tool-call. The
		// legitimate inbound surface through this handler is exactly tools/call (the
		// handshake is client-side; F5 carries only a ToolCall), so an off-allowlist
		// method is refused here (mapped to JSON-RPC -32601 method-not-found), never
		// forwarded. The allowlist is a named, extensible set so a future inbound
		// method is a one-line add + its own validator + its own test.
		if err := requireAllowedMethod(doc); err != nil {
			return err
		}
		paramsRaw, ok := doc["params"]
		if !ok {
			return errBaseMalformed
		}
		if err := validateCallToolParams(paramsRaw); err != nil {
			return err
		}
	case KindError:
		// boundedError IS the JSON-RPC error OBJECT ({code, message, data?}) — the
		// value of a response's `error` member, validated standalone. Its required
		// fields are code+message (per the contract's boundedError.required), NOT a
		// nested `error` field (CR fix: checking doc["error"] rejected every valid
		// error object, since the object has code/message, not error).
		if _, ok := doc["code"]; !ok {
			return errBaseMalformed
		}
		if _, ok := doc["message"]; !ok {
			return errBaseMalformed
		}
	case KindCallToolResult:
		if _, ok := doc["content"]; !ok {
			return errBaseMalformed
		}
	case KindInitializeResult:
		if _, ok := doc["protocolVersion"]; !ok {
			return errBaseMalformed
		}
	case KindTool:
		if _, ok := doc["name"]; !ok {
			return errBaseMalformed
		}
	}
	return nil
}

// validateCallToolParams strict-validates a tools/call request's params: name
// MUST be a non-empty string (the tool to invoke), and arguments, if present,
// MUST be a JSON object (never a scalar or array). This is the strict-validated
// input the contract requires for CallToolRequest; tools/call has no overlay
// $def, so this is where its request structure is enforced before any forward.
func validateCallToolParams(paramsRaw json.RawMessage) error {
	var params struct {
		Name      *string         `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		// params is not an object (a scalar/array body) — malformed.
		return errBaseMalformed
	}
	// name is required and must be a non-empty string.
	if params.Name == nil || *params.Name == "" {
		return errBaseMalformed
	}
	// arguments, when present, must be a JSON object — not a scalar or array. An
	// absent arguments is permitted (a no-arg tool call).
	if len(params.Arguments) > 0 {
		trimmed := trimLeadingSpace(params.Arguments)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return errBaseMalformed
		}
	}
	return nil
}

// trimLeadingSpace drops leading JSON whitespace so the first significant byte
// can be inspected (an object opens with '{').
func trimLeadingSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	return b[i:]
}

// inboundMethodAllowlist is the exact set of JSON-RPC methods this gateway
// handler accepts as an inbound request. It is exactly {"tools/call"}: the
// handler does no method routing, the MCP handshake (initialize / capability
// negotiation) is performed client-side and never reaches this handler, and the
// F5 SessionRequest can carry only a ToolCall. It is a set (not a lone constant)
// so a future inbound method is a one-line add here alongside its own validator
// and test — and so deleting the guard reds TestMethodAllowlistIsExactlyToolsCall.
var inboundMethodAllowlist = map[string]struct{}{
	"tools/call": {},
}

// methodAllowed reports whether method is on the inbound allowlist. It is the
// single source of truth for the accepted inbound surface; the guard and the
// membership test both read it, so they cannot diverge.
func methodAllowed(method string) bool {
	_, ok := inboundMethodAllowlist[method]
	return ok
}

// requireAllowedMethod fails closed when the request's "method" is missing or is
// not on the inbound allowlist. An off-allowlist method returns errMethodNotFound
// (mapped to JSON-RPC -32601), NOT errBaseMalformed, so a method-confusion attempt
// is refused with "method not found" rather than mislabelled as a malformed body.
func requireAllowedMethod(doc map[string]json.RawMessage) error {
	raw, ok := doc["method"]
	if !ok {
		return errBaseMalformed
	}
	var method string
	if err := json.Unmarshal(raw, &method); err != nil {
		// method present but not a JSON string — a malformed request, not a
		// well-formed off-allowlist method.
		return errBaseMalformed
	}
	if !methodAllowed(method) {
		return errMethodNotFound
	}
	return nil
}

// requireJSONRPCMarker fails if the message lacks "jsonrpc":"2.0".
func requireJSONRPCMarker(doc map[string]json.RawMessage) error {
	v, ok := doc["jsonrpc"]
	if !ok {
		return errBaseMalformed
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil || s != "2.0" {
		return errBaseMalformed
	}
	return nil
}

// errBaseMalformed is the internal base-pass failure. The caller maps it to a
// ReasonBaseSchema deny; it carries no caller data.
var errBaseMalformed = &baseError{}

type baseError struct{}

func (*baseError) Error() string { return "profile: message failed MCP base-schema structural check" }

// errMethodNotFound is the base-pass failure for a well-formed request whose
// method is not on the inbound allowlist. The caller maps it to a
// ReasonMethodNotFound deny (JSON-RPC -32601), distinct from errBaseMalformed, so
// a method-confusion attempt is refused as "method not found" rather than
// mislabelled as a malformed body. It carries no caller data (never the method
// value).
var errMethodNotFound = &methodNotFoundError{}

type methodNotFoundError struct{}

func (*methodNotFoundError) Error() string {
	return "profile: request method is not on the inbound allowlist (method not found)"
}
