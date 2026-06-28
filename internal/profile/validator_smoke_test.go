// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import (
	"errors"
	"testing"
)

// stubBase is a no-op base pass that always accepts, so these smoke tests
// exercise the OCU profile pass in isolation. The real base pass (the public
// MCP schema) is wired at the ingress; here we prove the overlay $defs compile
// and dispatch.
type stubBase struct{}

func (stubBase) ValidateBase(Kind, []byte) error { return nil }

// TestNewValidatorCompilesEmbeddedProfile proves the embedded constraint profile
// compiles into per-$def schemas at construction — the load-bearing boot step.
func TestNewValidatorCompilesEmbeddedProfile(t *testing.T) {
	v, err := NewValidator(stubBase{}, Limits{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	for _, name := range []string{
		"jsonRpcSingleMessage", "boundedError", "boundedTool",
		"boundedCallToolResult", "boundedInitializeResult",
	} {
		if v.defs[name] == nil {
			t.Errorf("overlay $def %q did not compile", name)
		}
	}
}

// TestNilBaseFailsClosed proves a nil base pass is a construction error, not a
// silently-skipped pass — the two-pass order is load-bearing.
func TestNilBaseFailsClosed(t *testing.T) {
	if _, err := NewValidator(nil, Limits{}); err == nil {
		t.Fatal("NewValidator(nil base) must fail closed; got nil error")
	}
}

// TestBatchingRejected proves jsonRpcSingleMessage rejects a JSON array body
// (batching removed in 2025-06-18) with the stable batching reason.
func TestBatchingRejected(t *testing.T) {
	v, err := NewValidator(stubBase{}, Limits{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	err = v.ValidateSingleMessageEnvelope([]byte(`[{"jsonrpc":"2.0"}]`))
	if err == nil {
		t.Fatal("a batched array body must be denied")
	}
	var d *Deny
	if !errors.As(err, &d) || d.Reason != ReasonBatching {
		t.Fatalf("want ReasonBatching deny, got %v", err)
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatal("deny must wrap ErrDenied")
	}
}

// TestSingleObjectAccepted proves a single JSON object body passes the envelope
// check.
func TestSingleObjectAccepted(t *testing.T) {
	v, err := NewValidator(stubBase{}, Limits{})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := v.ValidateSingleMessageEnvelope([]byte(`{"jsonrpc":"2.0","id":1}`)); err != nil {
		t.Fatalf("a single object body must pass; got %v", err)
	}
}

// TestOverSizeRejectedPreBuffer proves a CallToolResult over the byte ceiling is
// denied with ReasonOverSize before any schema work.
func TestOverSizeRejectedPreBuffer(t *testing.T) {
	v, err := NewValidator(stubBase{}, Limits{
		MaxCallToolResultBytes: 16, // tiny ceiling for the test
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	big := []byte(`{"content":[{"type":"text","text":"this is well over sixteen bytes"}]}`)
	err = v.Validate(KindCallToolResult, big)
	var d *Deny
	if !errors.As(err, &d) || d.Reason != ReasonOverSize {
		t.Fatalf("want ReasonOverSize deny, got %v", err)
	}
}

// TestInitializeResultRejectsExtraCapability proves the profile pass rejects a
// capability other than tools (additionalProperties:false in the contract).
func TestInitializeResultRejectsExtraCapability(t *testing.T) {
	v, err := NewValidator(stubBase{}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	// Valid except for a forbidden "prompts" capability.
	body := []byte(`{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false},"prompts":{}},"serverInfo":{"name":"x","version":"1"}}`)
	err = v.Validate(KindInitializeResult, body)
	var d *Deny
	if !errors.As(err, &d) || d.Reason != ReasonProfileSchema {
		t.Fatalf("want ReasonProfileSchema deny for extra capability, got %v", err)
	}
}

// TestInitializeResultAcceptsToolsOnly proves a tools-only InitializeResult with
// the pinned revision passes the profile pass.
func TestInitializeResultAcceptsToolsOnly(t *testing.T) {
	v, err := NewValidator(stubBase{}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	body := []byte(`{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"x","version":"1"}}`)
	if err := v.Validate(KindInitializeResult, body); err != nil {
		t.Fatalf("a tools-only InitializeResult must pass; got %v", err)
	}
}
