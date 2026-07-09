// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/projection"
)

// A full-cycle exec e2e for the file tools: it drives the REAL forward create+exec
// sequence and, in the control-mock's exec handler, decodes stdin_b64 and RUNS the
// projected interpreter script with that stdin against a temp file — so the test
// proves the file tool actually EXECUTES (creates/reads the file), not merely that the
// argv shape is right. This is the guard the browser-only gap missed: argv-shape unit
// tests prove wiring; this proves the projection, carried over the wire with its stdin
// payload, does the file operation end to end.

// runProjectedExec decodes the exec body's argv + stdin_b64 and executes the argv on
// the test host, feeding the decoded stdin. It returns a control execResponse
// modelling exactly what a guest would do: run argv, pump stdin, capture exit AND the
// stdout/stderr streams SEPARATELY into their own fields. The streams are captured with
// two distinct buffers (cmd.Stdout / cmd.Stderr), NOT CombinedOutput — a mock that
// fused the streams would make every stderr assertion vacuous, so the separation is
// load-bearing (proven by the three-way distinguishability probe). python3-bearing
// hosts only (the argv[0] interpreter must be on PATH; skipped otherwise).
func runProjectedExec(t *testing.T) func(http.ResponseWriter, controlExecBody) {
	t.Helper()
	return func(w http.ResponseWriter, body controlExecBody) {
		stdin, decErr := base64.StdEncoding.DecodeString(body.StdinB64)
		if decErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body.Argv) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Resolve the interpreter (argv[0]); if it is not on the host PATH, signal the
		// test to skip via a sentinel exit rather than failing spuriously.
		interp, err := exec.LookPath(body.Argv[0])
		if err != nil {
			// Fall back to a bare-name lookup (e.g. "python3" when argv[0] is an absolute
			// guest path not present on the host).
			base := body.Argv[0]
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			interp, err = exec.LookPath(base)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(controlExecResponse{
					ExitCode:  254,
					StderrB64: base64.StdEncoding.EncodeToString([]byte("NO_INTERPRETER")),
				})
				return
			}
		}
		cmd := exec.Command(interp, body.Argv[1:]...)
		cmd.Stdin = strings.NewReader(string(stdin))
		// SEPARATE stdout/stderr buffers — the D2 fix. CombinedOutput would fuse them.
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		var exitCode uint8
		if runErr := cmd.Run(); runErr != nil {
			var ee *exec.ExitError
			if errors.As(runErr, &ee) {
				exitCode = uint8(ee.ExitCode())
			} else {
				exitCode = 255
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(controlExecResponse{
			ExitCode:  exitCode,
			StdoutB64: base64.StdEncoding.EncodeToString(stdout.Bytes()),
			StderrB64: base64.StdEncoding.EncodeToString(stderr.Bytes()),
		})
	}
}

// TestExecMockSeparatesStdoutStderrAndExit is THE anti-fake-green guard: a three-way
// distinguishability probe on the control-mock. It runs one command that prints
// "OUT-<marker>" to stdout, "ERR-<marker>" to stderr, and exits 7, then asserts the
// mock captured them into DISTINCT fields: exit==7, StdoutB64 has OUT and NOT ERR,
// StderrB64 has ERR and NOT OUT. A mock that fused the streams (CombinedOutput — the
// D2 defect) fails this instantly: OUT and ERR would both appear in StdoutB64 and
// StderrB64 would be empty. This red is what makes every downstream stream/exit
// assertion in the e2e non-vacuous — without it, a stderr assertion could pass on a
// mock that never separated the streams.
func TestExecMockSeparatesStdoutStderrAndExit(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("/bin/sh not on the test host")
	}
	const marker = "M7k9"
	// A shell command writing distinct content to each stream and exiting 7. This is a
	// bash_tool-shaped argv (/bin/sh -c), the same the projection builds for bash_tool.
	argv, _ := projection.Project("bash_tool",
		[]byte(`{"command":"printf 'OUT-`+marker+`'; printf 'ERR-`+marker+`' 1>&2; exit 7"}`))

	handler := runProjectedExec(t)
	rec := httptest.NewRecorder()
	handler(rec, controlExecBody{Argv: argv})

	var resp controlExecResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("mock response must decode as an execResponse, got %q (%v)", rec.Body.String(), err)
	}
	if resp.ExitCode == 254 {
		t.Skip("interpreter not on host (sentinel exit)")
	}
	if resp.ExitCode != 7 {
		t.Errorf("exit code must be 7, got %d", resp.ExitCode)
	}
	stdout, _ := base64.StdEncoding.DecodeString(resp.StdoutB64)
	stderr, _ := base64.StdEncoding.DecodeString(resp.StderrB64)
	// stdout field: OUT present, ERR absent.
	if !strings.Contains(string(stdout), "OUT-"+marker) {
		t.Errorf("stdout field must contain OUT-%s, got %q", marker, stdout)
	}
	if strings.Contains(string(stdout), "ERR-"+marker) {
		t.Errorf("stdout field must NOT contain ERR-%s (streams fused — CombinedOutput?), got %q", marker, stdout)
	}
	// stderr field: ERR present, OUT absent.
	if !strings.Contains(string(stderr), "ERR-"+marker) {
		t.Errorf("stderr field must contain ERR-%s, got %q", marker, stderr)
	}
	if strings.Contains(string(stderr), "OUT-"+marker) {
		t.Errorf("stderr field must NOT contain OUT-%s (streams fused?), got %q", marker, stderr)
	}
}

// TestFileToolExecE2ECreatesFile is the full-cycle keystone: a create_file tool-call
// drives create+exec; the control-mock decodes stdin_b64, runs the interpreter script
// with it, and the file is actually written. The projected CallToolResult carries the
// success line — proving the tool EXECUTED end to end, over the wire, with its stdin.
func TestFileToolExecE2ECreatesFile(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on the test host; the guest runs the script")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "e2e", "created.txt")

	// Build the create_file projection from the REAL projection package — the same
	// argv+stdin production sends. No inlined script copy: the projection and its guest
	// scripts are the single source of truth, so this e2e proves exactly what ships.
	argsJSON := `{"path":"` + target + `","file_text":"e2e-body"}`
	argv, stdin := projection.Project("create_file", []byte(argsJSON))

	pki := newMTLSTestPKI(t)
	ctl := &twoHopControl{}
	srv := ctl.serveWith(t, pki, runProjectedExec(t))
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)
	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-e2e",
		ToolCall: ToolCall{
			Name:  "create_file",
			Argv:  argv,
			Stdin: stdin,
		},
	})
	if err != nil {
		t.Fatalf("create_file e2e must succeed, got %v", err)
	}

	// The exec body must have carried the stdin payload (the arguments JSON) base64'd.
	if ctl.gotExec.StdinB64 == "" {
		t.Fatal("the exec body must carry stdin_b64 (the file tool's arguments); it was empty")
	}
	decoded, _ := base64.StdEncoding.DecodeString(ctl.gotExec.StdinB64)
	if string(decoded) != argsJSON {
		t.Errorf("stdin must be the arguments JSON verbatim over the wire.\n got: %s\nwant: %s", decoded, argsJSON)
	}

	// The file must actually exist with the body — the tool EXECUTED.
	got, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("create_file must have written the file end-to-end: %v", readErr)
	}
	if string(got) != "e2e-body" {
		t.Errorf("create_file wrote %q, want %q", got, "e2e-body")
	}

	// The projected result carries the success line (isError:false).
	var shape callToolResultShape
	if err := json.Unmarshal(resp.Result, &shape); err != nil {
		t.Fatalf("resp.Result must be a CallToolResult, got %q (%v)", resp.Result, err)
	}
	if shape.IsError {
		t.Errorf("a successful create_file must be isError:false, got the error result %+v", shape.Content)
	}
	if len(shape.Content) == 0 || !strings.Contains(shape.Content[0].Text, "Successfully created") {
		t.Errorf("the result must carry the guest success line, got %+v", shape.Content)
	}
}
