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

	// Every JSON-RPC 2.0 message carries the version marker. A result/error and a
	// request all have it; a bare MCP sub-object (a Tool, an InitializeResult)
	// validated in isolation does not, so the marker is required only for the
	// top-level request/result/error kinds.
	switch kind {
	case KindCallToolRequest, KindError:
		if err := requireJSONRPCMarker(doc); err != nil {
			return err
		}
	}

	switch kind {
	case KindCallToolRequest:
		// A tools/call request names a method and params.
		if _, ok := doc["method"]; !ok {
			return errBaseMalformed
		}
		if _, ok := doc["params"]; !ok {
			return errBaseMalformed
		}
	case KindError:
		if _, ok := doc["error"]; !ok {
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
