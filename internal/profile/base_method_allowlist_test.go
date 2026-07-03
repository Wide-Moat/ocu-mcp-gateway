// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import "testing"

// These tests pin the inbound METHOD allowlist at the base pass. A prior
// self-audit found method-confusion: the base pass checked only that the
// "method" KEY was present, never its VALUE, so any JSON-RPC request carrying a
// params.name (e.g. resources/list, or an invented evil/pwn) rode the tools/call
// path and was forwarded on F5 as if it were a tool-call.
//
// The legitimate inbound method-set through this gateway handler is exactly
// {"tools/call"} (firsthand-enumerated: the handler does no method routing, the
// MCP handshake is client-side, and the F5 SessionRequest can carry only a
// ToolCall). The allowlist is a named, extensible set so a future method
// (ping, tools/list) is a one-line add + its own validator + its own test, not a
// rewrite — and so deleting the guard is a RED-on-a-named-test keystone.

// TestBaseRejectsNonToolsCallMethod is the two-sided keystone: a method that is
// NOT on the allowlist must fail the base pass. Deleting the allowlist guard in
// ValidateBase makes this test RED.
func TestBaseRejectsNonToolsCallMethod(t *testing.T) {
	b := NewJSONRPCBaseValidator()

	// (a) an invented/hostile method with an otherwise-valid tools/call shape.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"evil/pwn","params":{"name":"x"}}`)); err == nil {
		t.Error("a non-tools/call method (evil/pwn) must fail the base pass, not ride the tools/call path")
	}
	// (b) a real MCP method that is NOT this gateway's inbound surface.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"resources/list","params":{"name":"x"}}`)); err == nil {
		t.Error("resources/list is not on the inbound allowlist and must fail the base pass")
	}
	// (c) a handshake method that is client-side, never inbound here.
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"initialize","params":{"name":"x"}}`)); err == nil {
		t.Error("initialize is negotiated client-side and is not inbound here; it must fail the base pass")
	}
}

// TestBaseAdmitsToolsCallMethod proves the allowlist does not over-reject: the
// one legitimate inbound method still passes (with its existing strict params
// validation intact).
func TestBaseAdmitsToolsCallMethod(t *testing.T) {
	b := NewJSONRPCBaseValidator()
	if err := b.ValidateBase(KindCallToolRequest, []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{}}}`)); err != nil {
		t.Errorf("tools/call is the allowlisted inbound method and must pass, got %v", err)
	}
}

// TestMethodAllowlistIsExactlyToolsCall pins the allowlist membership itself, so
// a change that widens it (or empties it) surfaces on a named test rather than
// silently. This is the keystone guard: the allowlist is the single source of
// truth for the inbound surface.
func TestMethodAllowlistIsExactlyToolsCall(t *testing.T) {
	if !methodAllowed("tools/call") {
		t.Error("tools/call must be on the inbound method allowlist")
	}
	for _, m := range []string{"resources/list", "initialize", "ping", "notifications/cancelled", "evil/pwn", ""} {
		if methodAllowed(m) {
			t.Errorf("%q must NOT be on the inbound method allowlist (the surface is exactly tools/call)", m)
		}
	}
}
