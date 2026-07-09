// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/projection"
)

// The @L4 tool-surface scenarios from deploy/tests/journeys/mcp_tool_surface.feature.
// L4 is the gateway internal/forward e2e: real create+exec hops, an EXECUTING
// control-mock that runs the REAL committed projection scripts (via projection.Project,
// never an inlined copy) with distinct stdout/stderr capture. It owns every behavior
// decided AT OR ABOVE the exec contract — projection, script semantics, and result
// shaping (exit->isError, stream->content, the [Exit code: N] shape). Behavior BELOW
// the contract (real exit transport, truncation, timeout, persistence) is @L5, the
// journeys peer's.
//
// Every scenario drives the REAL forward through forwardToolL4 and asserts on the
// projected CallToolResult, so it proves the composition end to end, not a unit in
// isolation. The three-way stream probe (TestExecMockSeparatesStdoutStderrAndExit) is
// the anti-fake-green anchor that makes the stream/exit assertions here non-vacuous.

// forwardToolL4 drives one tool-call through the real forward create+exec sequence
// against an executing control-mock, and returns the projected CallToolResult (decoded)
// plus the exec body the mock received. name+arguments go through the REAL
// projection.Project, so the argv+stdin are exactly what production sends. It skips if
// the interpreter the projection targets is not on the test host.
func forwardToolL4(t *testing.T, name, argumentsJSON string) (callToolResultShape, controlExecBody) {
	t.Helper()
	argv, stdin := projection.Project(name, []byte(argumentsJSON))
	if len(argv) == 0 {
		t.Fatalf("%s must have an exec projection for an L4 scenario, got none", name)
	}
	// The projection's interpreter must be runnable on the host (python3 for the file
	// tools, /bin/sh for bash_tool); otherwise the guest-side behavior cannot be run
	// here and the scenario skips.
	if _, err := exec.LookPath(argv[0]); err != nil {
		base := argv[0]
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		if _, err := exec.LookPath(base); err != nil {
			t.Skipf("interpreter %q not on the test host; the guest runs it", argv[0])
		}
	}

	pki := newMTLSTestPKI(t)
	ctl := &twoHopControl{}
	srv := ctl.serveWith(t, pki, runProjectedExec(t))
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)
	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-l4",
		ToolCall:    ToolCall{Name: name, Argv: argv, Stdin: stdin},
	})
	if err != nil {
		t.Fatalf("%s L4 forward must succeed at the transport (a tool error is Tier-2, not a transport fail), got %v", name, err)
	}
	var shape callToolResultShape
	if uerr := json.Unmarshal(resp.Result, &shape); uerr != nil {
		t.Fatalf("%s result must be a CallToolResult, got %q (%v)", name, resp.Result, uerr)
	}
	return shape, ctl.gotExec
}

// resultText returns the single content block's text, failing if the shape is not the
// expected one-text-block result. Assertions use EXACT equality (not contains): a
// contains check is vacuous on the negative-space cases (it passes on both the marker
// and a lucky stderr), so the exact text is the contract.
func resultText(t *testing.T, shape callToolResultShape) string {
	t.Helper()
	if len(shape.Content) != 1 || shape.Content[0].Type != "text" {
		t.Fatalf("result must be exactly one text content block, got %+v", shape.Content)
	}
	return shape.Content[0].Text
}

// The @L4 @bash @error / @happy / @contrast scenarios pin the exit→content SHAPING
// contract (Fable ruling): the gateway synthesizes the PoC literal "[Exit code: N]"
// ONLY when a non-zero exit wrote NOTHING to either stream (raw byte length on both,
// mirroring the PoC Python truthiness), relays real output otherwise, and never
// synthesizes on success. It relays exit-code facts and does NOT interpret per-command
// exit semantics (the grep-no-match contrast). Each asserts the EXACT result text.

// A — non-zero exit, no output → the synthesized marker. THE keystone: reds against the
// NEUTER that removed the shaping.
func TestL4BashExitNoOutputSynthesizesMarker(t *testing.T) {
	shape, _ := forwardToolL4(t, "bash_tool", `{"command":"exit 7"}`)
	if !shape.IsError {
		t.Errorf("a non-zero exit must be isError:true, got %+v", shape)
	}
	if got := resultText(t, shape); got != "[Exit code: 7]" {
		t.Errorf("a no-output non-zero exit must be exactly \"[Exit code: 7]\", got %q", got)
	}
}

// B — non-zero exit with stderr → relay the stderr, NOT the marker (equality proves the
// marker is absent).
func TestL4BashExitWithStderrRelaysStderr(t *testing.T) {
	shape, _ := forwardToolL4(t, "bash_tool", `{"command":"echo boom 1>&2; exit 3"}`)
	if !shape.IsError {
		t.Errorf("a non-zero exit must be isError:true, got %+v", shape)
	}
	if got := resultText(t, shape); got != "boom\n" {
		t.Errorf("a non-zero exit with stderr must relay it exactly (\"boom\\n\"), got %q", got)
	}
}

// C — non-zero exit with stdout ONLY → relay the stdout (pins the stdout fallback; a
// regression to stderr-only would drop the diagnostic the child wrote to stdout).
func TestL4BashExitWithStdoutOnlyRelaysStdout(t *testing.T) {
	shape, _ := forwardToolL4(t, "bash_tool", `{"command":"echo cause; exit 5"}`)
	if !shape.IsError {
		t.Errorf("a non-zero exit must be isError:true, got %+v", shape)
	}
	if got := resultText(t, shape); got != "cause\n" {
		t.Errorf("a non-zero exit with stdout-only must relay it exactly (\"cause\\n\"), got %q", got)
	}
}

// D — @contrast: grep no-match (exit 1, no output) is a tool error carrying the marker.
// The gateway does NOT rewrite it to a PoC-style "No matches found": it relays the exit
// fact. This pins the deliberate PoC-vs-fleet divergence AND exercises synthesis on a
// real command.
func TestL4BashGrepNoMatchIsExitCodeError(t *testing.T) {
	shape, _ := forwardToolL4(t, "bash_tool", `{"command":"printf hay > /tmp/f && grep needle /tmp/f"}`)
	if !shape.IsError {
		t.Errorf("grep no-match (exit 1) must be isError:true under the fleet contract, got %+v", shape)
	}
	if got := resultText(t, shape); got != "[Exit code: 1]" {
		t.Errorf("grep no-match must be exactly \"[Exit code: 1]\" (no per-command rewriting), got %q", got)
	}
}

// E — success guard: a zero exit with no output is a silent success, text exactly "".
// The marker must NOT over-fire on success (and no PoC "[No output]" cruft creeps in).
func TestL4BashZeroExitNoOutputIsSilentSuccess(t *testing.T) {
	shape, _ := forwardToolL4(t, "bash_tool", `{"command":"true"}`)
	if shape.IsError {
		t.Errorf("a zero exit must be isError:false, got %+v", shape)
	}
	if got := resultText(t, shape); got != "" {
		t.Errorf("a zero exit with no output must be exactly \"\" (marker must not over-fire), got %q", got)
	}
}

// writeHostFile creates a file the executing control-mock can read/edit (the mock runs
// the projected script on the test host, so the tool's `path` is a host temp path).
func writeHostFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// jsonField JSON-encodes s for embedding in an arguments literal (paths may contain
// characters that must be escaped in JSON).
func jsonField(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// @L4 @str_replace @happy — a single unambiguous replacement succeeds THROUGH the
// forward: not an error, the success message, and the file actually now holds the new
// text (the script really edited it, over the wire).
func TestL4StrReplaceHappyEditsFile(t *testing.T) {
	path := writeHostFile(t, "a.txt", "alpha BRAVO charlie")
	args := `{"path":` + jsonField(path) + `,"old_str":"BRAVO","new_str":"DELTA"}`
	shape, _ := forwardToolL4(t, "str_replace", args)

	if shape.IsError {
		t.Errorf("a valid str_replace must not be an error, got %+v", shape.Content)
	}
	if len(shape.Content) == 0 || !strings.Contains(shape.Content[0].Text, "Successfully replaced") {
		t.Errorf("str_replace must report success, got %+v", shape.Content)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "alpha DELTA charlie" {
		t.Errorf("str_replace must have edited the file over the wire, got %q", got)
	}
}

// @L4 @str_replace @error — THE composition this level exists for: the script's three
// error semantics (exit-1) COMPOSED with isError:true THROUGH the forward. L3 proved the
// script; L2 proved the projection; nothing proved them TOGETHER. Each case asserts
// isError:true, the message class in content, AND the file left unchanged.
func TestL4StrReplaceErrorsComposeToIsError(t *testing.T) {
	const original = "keep dup dup keep"
	cases := []struct {
		name    string
		oldStr  string
		newStr  string
		message string
	}{
		{"identical", "keep", "keep", "identical"},
		{"not found", "absent", "x", "not found"},
		{"more than one occurrence", "dup", "x", "occurrences"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writeHostFile(t, "s.txt", original)
			args := `{"path":` + jsonField(path) + `,"old_str":` + jsonField(c.oldStr) + `,"new_str":` + jsonField(c.newStr) + `}`
			shape, _ := forwardToolL4(t, "str_replace", args)

			if !shape.IsError {
				t.Errorf("a %s str_replace must project isError:true, got %+v", c.name, shape)
			}
			if len(shape.Content) == 0 || !strings.Contains(shape.Content[0].Text, c.message) {
				t.Errorf("a %s error must carry %q, got %+v", c.name, c.message, shape.Content)
			}
			// The file must be UNCHANGED on any error (no partial edit).
			got, _ := os.ReadFile(path)
			if string(got) != original {
				t.Errorf("a %s error must leave the file unchanged, got %q", c.name, got)
			}
		})
	}
}

// @L4 @create_file @happy — create_file writes the body and creates missing parents,
// through the forward: not an error, the success message, and the file exists with the
// body under a nested path.
func TestL4CreateFileWritesWithParents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "a.txt")
	args := `{"path":` + jsonField(path) + `,"file_text":"hello"}`
	shape, _ := forwardToolL4(t, "create_file", args)

	if shape.IsError {
		t.Errorf("create_file happy path must not be an error, got %+v", shape.Content)
	}
	if len(shape.Content) == 0 || !strings.Contains(shape.Content[0].Text, "Successfully created") {
		t.Errorf("create_file must report success, got %+v", shape.Content)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("create_file must have created the file (with parents) over the wire: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("create_file wrote %q, want %q", got, "hello")
	}
}

// @L4 @create_file @overwrite — create_file OVERWRITES an existing file without a
// guard (open(path,'w')). TOTAL GAP before: the overwrite behaviour existed but was
// untested at any level. The PoC gives no overwrite warning; this pins the fleet
// matches — a plain success and the new body.
func TestL4CreateFileOverwritesExisting(t *testing.T) {
	path := writeHostFile(t, "c.txt", "OLD")
	args := `{"path":` + jsonField(path) + `,"file_text":"NEW"}`
	shape, _ := forwardToolL4(t, "create_file", args)

	if shape.IsError {
		t.Errorf("create_file overwrite must not be an error, got %+v", shape.Content)
	}
	if len(shape.Content) == 0 || !strings.Contains(shape.Content[0].Text, "Successfully created") {
		t.Errorf("create_file overwrite must report success (no overwrite warning), got %+v", shape.Content)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "NEW" {
		t.Errorf("create_file must have overwritten the file, got %q, want %q", got, "NEW")
	}
}

// @L4 @create_file @error — create_file into a read-only directory errors with no
// partial write, THROUGH the forward: isError:true, the write failure in content, and
// nothing written at the target. This raises task #123's L3 script pin to the
// exec-contract level (the full projection + exit->isError composition).
func TestL4CreateFileReadOnlyDirErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses 0555 dir perms; the write-failure path is real where the exec child is unprivileged")
	}
	dir := t.TempDir()
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o755) })

	target := filepath.Join(roDir, "denied.txt")
	args := `{"path":` + jsonField(target) + `,"file_text":"x"}`
	shape, _ := forwardToolL4(t, "create_file", args)

	if !shape.IsError {
		t.Errorf("create_file into a read-only dir must project isError:true, got %+v", shape)
	}
	if len(shape.Content) == 0 || !strings.Contains(shape.Content[0].Text, "Error") {
		t.Errorf("the write failure must be surfaced in content, got %+v", shape.Content)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("a failed create_file must write NOTHING; os.Stat(%q) err = %v, want IsNotExist", target, err)
	}
}
