// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The file tools (create_file, view, str_replace) execute in the guest the SAME way
// bash_tool does — as an exec projection, not a guest RPC. Each projects to a small
// program the guest runs over exec: the interpreter runs a fixed script and the
// tool's arguments ride as an OPAQUE JSON payload on the child's stdin (never
// interpolated into the argv), so arbitrary bytes in a path or file body — newlines,
// quotes, NUL — can never break out of an argument into the command. The gateway does
// NOT parse the arguments (invariant #3 holds even more strictly than for bash, whose
// command string the gateway does read to build its argv): the whole arguments object
// is forwarded verbatim as the stdin payload.

const fileInterpreter = "/usr/bin/python3"

// projectionCase drives a tools/call for a file tool and returns what reached the
// forwarder, so the argv shape and the opaque stdin passthrough can be asserted.
func fileToolForward(t *testing.T, name, argumentsJSON string) *forward.SessionRequest {
	t.Helper()
	fwd := &recordingForwarder{resp: forward.SessionResponse{
		Correlation: "c1",
		Result:      validCallToolResult("ok", false),
	}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+name+`","arguments":`+argumentsJSON+`}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid %s call must be 200, got %d (%s)", name, rec.Code, rec.Body.String())
	}
	if fwd.got == nil {
		t.Fatalf("the %s call must reach the forwarder", name)
	}
	return fwd.got
}

// TestCreateFileProjectsToInterpreterWithStdin is the create_file keystone: it
// projects to [/usr/bin/python3 -c <script>] and carries the arguments JSON verbatim
// on stdin. Red-probe: the pre-Q2 argvFromToolCall returned nil for create_file (the
// -32602 create-only path), so the argv/stdin assertions red.
func TestCreateFileProjectsToInterpreterWithStdin(t *testing.T) {
	args := `{"description":"d","file_text":"hello\nworld","path":"/tmp/a.txt"}`
	got := fileToolForward(t, "create_file", args)

	argv := got.ToolCall.Argv
	if len(argv) != 3 || argv[0] != fileInterpreter || argv[1] != "-c" {
		t.Fatalf("create_file must project to [%s -c <script>], got %v", fileInterpreter, argv)
	}
	if len(argv[2]) == 0 {
		t.Error("create_file script (argv[2]) must be non-empty")
	}
	// The stdin payload is the arguments object, carried VERBATIM (the same bytes the
	// caller sent, opaque — the gateway does not re-serialize or parse it).
	if string(got.ToolCall.Stdin) != args {
		t.Errorf("create_file stdin must be the arguments JSON verbatim.\n got: %s\nwant: %s", got.ToolCall.Stdin, args)
	}
}

// TestStrReplaceProjectsToInterpreterWithStdin is the str_replace keystone.
func TestStrReplaceProjectsToInterpreterWithStdin(t *testing.T) {
	args := `{"description":"d","old_str":"foo","new_str":"bar","path":"/tmp/a.txt"}`
	got := fileToolForward(t, "str_replace", args)

	argv := got.ToolCall.Argv
	if len(argv) != 3 || argv[0] != fileInterpreter || argv[1] != "-c" {
		t.Fatalf("str_replace must project to [%s -c <script>], got %v", fileInterpreter, argv)
	}
	if string(got.ToolCall.Stdin) != args {
		t.Errorf("str_replace stdin must be the arguments JSON verbatim, got %s", got.ToolCall.Stdin)
	}
}

// TestViewProjectsToInterpreterWithStdin is the view keystone.
func TestViewProjectsToInterpreterWithStdin(t *testing.T) {
	args := `{"description":"d","path":"/tmp/a.txt"}`
	got := fileToolForward(t, "view", args)

	argv := got.ToolCall.Argv
	if len(argv) != 3 || argv[0] != fileInterpreter || argv[1] != "-c" {
		t.Fatalf("view must project to [%s -c <script>], got %v", fileInterpreter, argv)
	}
	if string(got.ToolCall.Stdin) != args {
		t.Errorf("view stdin must be the arguments JSON verbatim, got %s", got.ToolCall.Stdin)
	}
}

// TestFileToolStdinIsOpaqueNotReparsed pins invariant #3 for the file tools: the
// stdin payload is the caller's arguments bytes UNCHANGED — the gateway does not
// canonicalize, re-order, or strip fields. A payload with an unusual (but valid) key
// order and extra whitespace must pass through byte-identical.
//
// Red-probe: a projection that re-marshals the parsed arguments (changing byte order
// / whitespace) reds this.
func TestFileToolStdinIsOpaqueNotReparsed(t *testing.T) {
	// Deliberately non-canonical: spaces, a trailing field, a specific key order.
	args := `{ "path":"/tmp/z" , "file_text":"x" , "description":"d" }`
	got := fileToolForward(t, "create_file", args)
	if string(got.ToolCall.Stdin) != args {
		t.Errorf("stdin must be the caller's exact bytes (opaque, invariant #3).\n got: %s\nwant: %s", got.ToolCall.Stdin, args)
	}
}

// TestBashToolStillProjectsUnchanged guards that adding the file tools did not alter
// the bash_tool projection (still [/bin/sh -c command], no stdin).
func TestBashToolStillProjectsUnchanged(t *testing.T) {
	got := fileToolForward(t, "bash_tool", `{"command":"echo hi","description":"d"}`)
	argv := got.ToolCall.Argv
	if len(argv) != 3 || argv[0] != "/bin/sh" || argv[1] != "-c" || argv[2] != "echo hi" {
		t.Errorf("bash_tool must still project to [/bin/sh -c \"echo hi\"], got %v", argv)
	}
	if len(got.ToolCall.Stdin) != 0 {
		t.Errorf("bash_tool carries its command in argv, not stdin; stdin must be empty, got %q", got.ToolCall.Stdin)
	}
}

// TestFileToolsAreAdvertised pins that create_file/view/str_replace are re-listed in
// tools/list now that they execute, while sub_agent stays delisted (the agent-loop
// non-goal). Red-probe: removing a file tool from tools_list.json reds this;
// re-adding sub_agent reds TestSubAgentIsNeverAdvertised.
func TestFileToolsAreAdvertised(t *testing.T) {
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
	advertised := map[string]bool{}
	for _, tool := range env.Result.Tools {
		advertised[tool.Name] = true
	}
	for _, want := range []string{"bash_tool", "create_file", "view", "str_replace"} {
		if !advertised[want] {
			t.Errorf("tools/list must advertise %q now that it executes", want)
		}
	}
	if advertised["sub_agent"] {
		t.Error("sub_agent must stay delisted (agent-loop non-goal)")
	}
}
