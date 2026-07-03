// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// These tests pin the inbound method allowlist at the SHIPPED boundary (they
// drive ServeHTTP, not the base validator in isolation). A prior self-audit found
// method-confusion: a request whose JSON-RPC method was NOT tools/call (an
// invented evil/pwn, or a real-but-off-surface resources/list) passed validation
// and was FORWARDED on F5 as if it were a tool-call, and audited as one. The
// handler must instead deny it -32601 "method not found" and forward nothing.

// TestUnknownMethodNotForwarded is the two-sided keystone at the handler: a
// non-allowlisted method must be denied -32601 and the recording forwarder must
// never be called. Deleting the allowlist guard makes this test RED (the request
// reaches the forward and returns 502/200 instead of the method deny).
func TestUnknownMethodNotForwarded(t *testing.T) {
	cases := map[string]string{
		"invented hostile method": `{"jsonrpc":"2.0","id":1,"method":"evil/pwn","params":{"name":"echo","arguments":{}}}`,
		"real off-surface method": `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{"name":"echo","arguments":{}}}`,
		"client-side handshake":   `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"name":"echo","arguments":{}}}`,
	}
	for name, reqBody := range cases {
		t.Run(name, func(t *testing.T) {
			// The forwarder would SUCCEED if reached — so if the method guard were
			// absent the response would be 200, making the deny assertion meaningful.
			fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
			h := acceptingHandler(t, fwd, nil)

			rec := post(h, pinnedProtocolVersion, "sk-ocu-good", reqBody)

			// (1) It must be a client-error deny, not a 200 and not a 502 forward
			// refusal — the request never reaches the forward.
			if rec.Code == http.StatusOK {
				t.Fatalf("a non-tools/call method must NOT succeed (it was forwarded as a tool-call); got 200")
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("a non-tools/call method must be denied 400 (method not found), got %d", rec.Code)
			}
			// (2) The JSON-RPC code must be -32601 "method not found".
			var env struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("response is not a JSON-RPC error envelope: %v (body %q)", err, rec.Body.String())
			}
			if env.Error.Code != rpcMethodNotAllowed {
				t.Errorf("a non-tools/call method must map to JSON-RPC %d (method not found), got %d", rpcMethodNotAllowed, env.Error.Code)
			}
			// (3) The forward must never have been called.
			if fwd.got != nil {
				t.Error("a non-tools/call method reached the F5 forward; it must be denied before the forward (method-confusion hole)")
			}
		})
	}
}

// TestToolsCallStillForwards proves the allowlist does not break the one
// legitimate inbound method: a well-formed tools/call still reaches the forward
// and returns 200.
func TestToolsCallStillForwards(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", validToolCall)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid tools/call must still reach the forward and return 200, got %d", rec.Code)
	}
	if fwd.got == nil {
		t.Error("a valid tools/call must reach the F5 forward")
	}
}
