// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// An authenticated caller can send a tools/call with ANY name — the base/OCU
// profile validation only requires params.name to be a non-empty string (invariant
// #1); it does not check the name against the advertised tool set. Before this
// guard, an unadvertised name (one with no gateway exec projection, e.g. a made-up
// "evil_tool" or an off-surface real tool) still reached the forwarder: Forward()
// unconditionally runs the CREATE round-trip to Control BEFORE it ever looks at
// req.ToolCall.Argv, so Control materializes a REAL session for a tool-call the
// gateway cannot even execute. The 502/-32602 the caller eventually sees does not
// undo that side effect — deny-by-default must refuse the call BEFORE any
// provisioning, not merely shape an honest error after provisioning already
// happened. This is a DIFFERENT defect from the "unimplemented tool" -32602 path
// (response.go's writeToolResult): that one shapes the RESPONSE for a name that
// reached the forwarder and got a create-only reply; this guard stops an
// unadvertised name from reaching the forwarder AT ALL.
//
// Keystone: the recording forwarder must NEVER be invoked for an unadvertised
// name — the observable proxy for "no session was materialized" (in the live
// fleet: no ocu-sess container exists for this call). Red-probe: removing the
// allowlist check makes fwd.got non-nil for "evil_tool" (the call reaches
// Forward()).
func TestUnadvertisedToolNameNotForwarded(t *testing.T) {
	cases := []string{
		"evil_tool",      // never existed
		"sub_agent",      // delisted permanently (MANIFESTO non-goal) — must stay refused
		"describe_image", // a real PoC tool with no fleet analog (parity audit #141 finding 3)
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
			h := acceptingHandler(t, fwd, nil)

			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
			rec := post(h, pinnedProtocolVersion, "sk-ocu-good", body)

			if fwd.got != nil {
				t.Errorf("tool name %q is not advertised (no tools_list.json entry) but reached the F5 forward — Control materializes a session for a tool-call the gateway cannot serve (deny-by-default hole)", name)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("an unadvertised tool name must still be a well-formed JSON-RPC error (200 + error envelope, matching the existing unimplemented-tool contract), got %d", rec.Code)
			}
			var env struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("response is not a JSON-RPC envelope: %v (body %q)", err, rec.Body.String())
			}
			if env.Error.Code != rpcInvalidParams {
				t.Errorf("an unadvertised tool name must map to JSON-RPC %d (matching the unimplemented-tool contract), got %d", rpcInvalidParams, env.Error.Code)
			}
		})
	}
}

// TestAdvertisedToolNamesStillForward proves the allowlist does not regress the
// tools the gateway actually serves, plus the synthetic resolve_scope tool (D5),
// which rides the SAME tools/call pipeline but is deliberately NOT in
// tools_list.json (no client-facing discovery entry — it is invoked directly by
// the D5 client, not chosen by the model from tools/list).
func TestAdvertisedToolNamesStillForward(t *testing.T) {
	for _, name := range []string{"bash_tool", "create_file", "str_replace", "view", "resolve_scope"} {
		t.Run(name, func(t *testing.T) {
			fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
			h := acceptingHandler(t, fwd, nil)

			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
			rec := post(h, pinnedProtocolVersion, "sk-ocu-good", body)

			if fwd.got == nil {
				t.Errorf("advertised tool %q must still reach the F5 forward", name)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("advertised tool %q must still return 200, got %d (body %q)", name, rec.Code, rec.Body.String())
			}
		})
	}
}
