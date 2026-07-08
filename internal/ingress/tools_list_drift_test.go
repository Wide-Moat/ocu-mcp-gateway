// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"sort"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The gateway advertises exactly the tools it can actually serve. Advertising a tool
// it cannot serve (no exec projection) hangs the SDK on a create-only forward — a
// far worse failure than omitting the tool. Until the file-op tools get gateway
// argv projections (the Q2 follow-up), the only tool the gateway serves end-to-end
// is bash_tool. sub_agent is a permanent non-goal (the OCU fleet does not run the
// agent loop — MANIFESTO v1), so it is never advertised. This drift-guard pins the
// advertised set so re-adding a tool WITHOUT a working projection reds here.

// expectedAdvertisedTools is the frozen set tools/list must advertise. It is
// bash_tool ONLY today; a tool is added here in the SAME change that gives it a
// working gateway projection, never before (advertising a non-functional tool
// hangs the client).
var expectedAdvertisedTools = []string{"bash_tool"}

// TestToolsListIsExpectedSetOnly is the drift-guard keystone: the advertised
// tools/list set MUST equal expectedAdvertisedTools exactly. Re-adding str_replace/
// create_file/view before their projection lands, or leaving sub_agent advertised,
// reds this.
//
// Red-probe: adding any other tool name to the embedded tools_list.json (or to the
// expected set without a matching entry) reds the set-equality assertion.
func TestToolsListIsExpectedSetOnly(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list returned %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("tools/list response is not a JSON-RPC result: %v (body %q)", err, rec.Body.String())
	}

	got := make([]string, 0, len(env.Result.Tools))
	for _, tool := range env.Result.Tools {
		got = append(got, tool.Name)
	}
	sort.Strings(got)

	want := append([]string(nil), expectedAdvertisedTools...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("tools/list advertises %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tools/list advertises %v, want exactly %v", got, want)
		}
	}
}

// TestSubAgentIsNeverAdvertised pins the permanent non-goal explicitly: sub_agent
// (the agent-delegation tool) must never appear in tools/list — the OCU fleet does
// not run the agent loop (MANIFESTO v1). This is a standalone guard so the intent
// survives even if expectedAdvertisedTools is later widened for the file ops.
//
// Red-probe: re-adding sub_agent to the embedded list reds this.
func TestSubAgentIsNeverAdvertised(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)

	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("tools/list response is not a JSON-RPC result: %v (body %q)", err, rec.Body.String())
	}
	for _, tool := range env.Result.Tools {
		if tool.Name == "sub_agent" {
			t.Errorf("sub_agent must never be advertised (agent loop is a v1 non-goal), but tools/list includes it")
		}
	}
}
