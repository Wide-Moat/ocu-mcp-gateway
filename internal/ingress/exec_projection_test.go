// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The G2 exec-driver ingress half: the handler derives the guest command argv from
// the validated tool arguments (a bash_tool {"command":"..."} becomes
// ["/bin/sh","-c",command]) so the forward's exec hop can run it, and it frames the
// forwarded CallToolResult into the JSON-RPC reply with the ECHOED request id,
// VALIDATING it outbound (KindCallToolResult) before it reaches the caller. These
// close the fake-green root: the old create-only path returned {"jsonrpc":"2.0"}
// with no result, so a tool-call never carried a command down nor a result back.

// TestBashToolArgvIsDerivedFromCommand is the argv keystone: a tools/call for
// bash_tool with {"command":"echo hi"} must forward Argv=["/bin/sh","-c","echo hi"]
// so the exec hop runs the caller's command. The command-parsing lives in ingress
// (the forward keeps arguments opaque, invariant #3), so this is where it is pinned.
//
// The interpreter is the POSIX /bin/sh (an ABSOLUTE path, `-c` not `-lc`): `-l`
// (login) is a bash/ash extension, undefined for a busybox `sh`, and a login shell
// is not wanted for a stateless tool-call (no profiles, env comes from the
// container config, determinism is a sandbox plus). An image that supports bash_tool
// GUARANTEES a POSIX /bin/sh (the guest-image contract), so the gateway does not
// depend on a `bash` binary that no guest contract promises, nor on PATH resolution
// in a near-empty guest.
//
// Red-probe: with no argvFromToolCall the forwarded Argv is empty and this reds;
// with the prior ["bash","-lc",...] the interpreter/flag assertions red.
func TestBashToolArgvIsDerivedFromCommand(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{
		Correlation: "c1",
		Result:      validCallToolResult("hi\n", false),
	}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"bash_tool","arguments":{"command":"echo hi"}}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("a valid bash_tool call must be 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if fwd.got == nil {
		t.Fatal("the tool-call must reach the forwarder")
	}
	argv := fwd.got.ToolCall.Argv
	if len(argv) != 3 || argv[0] != "/bin/sh" || argv[1] != "-c" || argv[2] != "echo hi" {
		t.Errorf("bash_tool {\"command\":\"echo hi\"} must forward argv [/bin/sh -c \"echo hi\"], got %v", argv)
	}
}

// TestExecResultIsFramedWithEchoedID is the framing keystone: the forwarded
// CallToolResult is wrapped in a JSON-RPC result envelope carrying the SAME id the
// request used (echoed), so the SDK correlates the response. The old create-only
// path wrote a minimal {"jsonrpc":"2.0"} with no id and no result.
//
// Red-probe: writing the result without echoing the id (or without the result at
// all) reds this.
func TestExecResultIsFramedWithEchoedID(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{
		Correlation: "c1",
		Result:      validCallToolResult("hi\n", false),
	}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"bash_tool","arguments":{"command":"echo hi"}}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var reply struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("response must be a JSON-RPC result envelope, got %q (%v)", rec.Body.String(), err)
	}
	if reply.JSONRPC != "2.0" {
		t.Errorf("reply must be jsonrpc 2.0, got %q", reply.JSONRPC)
	}
	if string(reply.ID) != "42" {
		t.Errorf("reply must echo the request id 42, got %s", reply.ID)
	}
	if len(reply.Result.Content) == 0 || reply.Result.Content[0].Text != "hi\n" {
		t.Errorf("reply.result must carry the guest stdout, got %+v", reply.Result.Content)
	}
}

// TestMalformedExecResultFailsClosed is the OUTBOUND-VALIDATION keystone: if the
// forwarder returns a result that is NOT a valid CallToolResult (a control/guest
// bug, a projection error), the gateway must NOT relay it as a 200 success. Outbound
// validation (KindCallToolResult) refuses it and the request fails closed (500) —
// a leak-free refusal, never a malformed body handed to the caller (invariant #5,
// NFR-SEC-51). This is the insertion point: outbound was previously unvalidated.
//
// Red-probe: without the outbound Validate the malformed body is written as a 200
// and this reds. Neuter (valid result) → 200.
func TestMalformedExecResultFailsClosed(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{
		Correlation: "c1",
		// A result that violates the CallToolResult contract (content is not the
		// required array of blocks — a scalar). Outbound validation must reject it.
		Result: []byte(`{"content":"not-an-array-of-blocks"}`),
	}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"bash_tool","arguments":{"command":"echo hi"}}}`)

	if rec.Code == http.StatusOK {
		t.Fatalf("a malformed CallToolResult must NOT be relayed as a 200 success; body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a malformed outbound result must fail closed (500), got %d", rec.Code)
	}
}

// validCallToolResult builds a valid MCP CallToolResult JSON with one text block.
func validCallToolResult(text string, isError bool) []byte {
	b, _ := json.Marshal(struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}{
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{{Type: "text", Text: text}},
		IsError: isError,
	})
	return b
}
