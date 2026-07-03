// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import (
	"errors"
	"testing"
)

func TestBoundedToolValidation(t *testing.T) {
	v, _ := NewValidator(stubBase{}, DefaultLimits())

	// Valid tool.
	if err := v.Validate(KindTool, []byte(`{"name":"echo","inputSchema":{"type":"object"}}`)); err != nil {
		t.Errorf("a valid tool must pass, got %v", err)
	}
	// Missing required name → profile (or base) deny.
	if err := v.Validate(KindTool, []byte(`{"inputSchema":{"type":"object"}}`)); err == nil {
		t.Error("a tool with no name must be denied")
	}
	// inputSchema type must be object.
	if err := v.Validate(KindTool, []byte(`{"name":"x","inputSchema":{"type":"array"}}`)); err == nil {
		t.Error("a tool whose inputSchema type is not object must be denied")
	}
}

func TestBoundedCallToolResultValidation(t *testing.T) {
	v, _ := NewValidator(stubBase{}, DefaultLimits())

	if err := v.Validate(KindCallToolResult, []byte(`{"content":[{"type":"text","text":"ok"}]}`)); err != nil {
		t.Errorf("a valid result must pass, got %v", err)
	}
	// Missing content.
	if err := v.Validate(KindCallToolResult, []byte(`{"isError":true}`)); err == nil {
		t.Error("a result with no content must be denied")
	}
}

func TestBoundedErrorValidation(t *testing.T) {
	v, _ := NewValidator(stubBase{}, DefaultLimits())

	if err := v.Validate(KindError, []byte(`{"code":-32602,"message":"bad"}`)); err != nil {
		t.Errorf("a valid error must pass, got %v", err)
	}
	// A non-enumerated code is denied.
	if err := v.Validate(KindError, []byte(`{"code":-12345,"message":"x"}`)); err == nil {
		t.Error("a non-standard JSON-RPC code must be denied")
	}
}

func TestInvalidKindFailsClosed(t *testing.T) {
	v, _ := NewValidator(stubBase{}, DefaultLimits())
	if err := v.Validate(KindInvalid, []byte(`{}`)); !errors.Is(err, ErrDenied) {
		t.Fatalf("KindInvalid must be a fail-closed deny, got %v", err)
	}
}

func TestKindString(t *testing.T) {
	cases := map[Kind]string{
		KindCallToolRequest:  "call_tool_request",
		KindCallToolResult:   "call_tool_result",
		KindTool:             "tool",
		KindError:            "error",
		KindInitializeResult: "initialize_result",
		KindInvalid:          "kind_unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestReasonString(t *testing.T) {
	cases := map[Reason]string{
		ReasonBaseSchema:     "base_schema_violation",
		ReasonProfileSchema:  "profile_constraint_violation",
		ReasonOverSize:       "payload_over_size_bound",
		ReasonBatching:       "batching_not_permitted",
		ReasonMethodNotFound: "method_not_found",
		ReasonUnknown:        "internal",
	}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("Reason(%d).String() = %q, want %q", r, got, want)
		}
	}
}

func TestProfileBytesIsACopy(t *testing.T) {
	a := ProfileBytes()
	if len(a) == 0 {
		t.Fatal("ProfileBytes returned empty")
	}
	a[0] = 'X' // mutate the copy
	b := ProfileBytes()
	if b[0] == 'X' {
		t.Error("ProfileBytes must return a copy; mutation leaked into the embedded contract")
	}
}

func TestDenyErrorMessageLeakFree(t *testing.T) {
	d := &Deny{Kind: KindError, Reason: ReasonOverSize}
	msg := d.Error()
	if msg == "" {
		t.Fatal("Deny.Error() empty")
	}
	if !errors.Is(d, ErrDenied) {
		t.Error("Deny must unwrap to ErrDenied")
	}
}

// TestBaseValidatorStructural exercises the JSON-RPC base pass directly.
func TestBaseValidatorStructural(t *testing.T) {
	b := NewJSONRPCBaseValidator()

	// A well-formed tools/call request (named tool, object arguments) passes.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{}}}`)); err != nil {
		t.Errorf("valid request: %v", err)
	}
	// A named tool with NO arguments (a no-arg call) passes.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}`)); err != nil {
		t.Errorf("no-arg call: %v", err)
	}
	// STRICT (CR#1 fix): params with no name is rejected — tools/call is the main
	// attack surface, the request structure is strict-validated.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`)); err == nil {
		t.Error("a tools/call with no params.name must fail base pass (strict-validated input)")
	}
	// STRICT: params.name empty is rejected.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":""}}`)); err == nil {
		t.Error("a tools/call with an empty params.name must fail base pass")
	}
	// STRICT: params.arguments as an array (not an object) is rejected.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x","arguments":[1,2]}}`)); err == nil {
		t.Error("a tools/call whose arguments is an array must fail base pass")
	}
	// STRICT: params as a scalar (not an object) is rejected.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":"oops"}`)); err == nil {
		t.Error("a tools/call whose params is a scalar must fail base pass")
	}
	// Missing jsonrpc marker fails.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"method":"tools/call","params":{"name":"x"}}`)); err == nil {
		t.Error("missing jsonrpc marker must fail base pass")
	}
	// Missing method fails.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","params":{"name":"x"}}`)); err == nil {
		t.Error("missing method must fail base pass")
	}
	// An array body fails (not a single object).
	if err := b.ValidateBase(KindCallToolRequest, []byte(`[1,2,3]`)); err == nil {
		t.Error("an array body must fail base pass")
	}
	// Error kind is the standalone error OBJECT: required code+message, no jsonrpc
	// marker (CR fix). A bare {code,message} passes; missing either fails.
	if err := b.ValidateBase(KindError, []byte(`{"code":-32602,"message":"bad"}`)); err != nil {
		t.Errorf("a valid error object must pass base pass: %v", err)
	}
	if err := b.ValidateBase(KindError, []byte(`{"message":"no code"}`)); err == nil {
		t.Error("an error object with no code must fail base pass")
	}
	if err := b.ValidateBase(KindError, []byte(`{"code":-32602}`)); err == nil {
		t.Error("an error object with no message must fail base pass")
	}
	// Tool kind requires name (no jsonrpc marker required for a bare sub-object).
	if err := b.ValidateBase(KindTool, []byte(`{"inputSchema":{}}`)); err == nil {
		t.Error("a tool with no name must fail base pass")
	}
	if err := b.ValidateBase(KindTool, []byte(`{"name":"x"}`)); err != nil {
		t.Errorf("a named tool sub-object should pass base pass: %v", err)
	}
}
