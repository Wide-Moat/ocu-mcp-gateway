// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// A full-cycle exec e2e for the file tools: it drives the REAL forward create+exec
// sequence and, in the control-mock's exec handler, decodes stdin_b64 and RUNS the
// projected interpreter script with that stdin against a temp file — so the test
// proves the file tool actually EXECUTES (creates/reads the file), not merely that the
// argv shape is right. This is the guard the browser-only gap missed: argv-shape unit
// tests prove wiring; this proves the projection, carried over the wire with its stdin
// payload, does the file operation end to end.

// runProjectedExec decodes the exec body's argv + stdin_b64 and executes the argv on
// the test host, feeding the decoded stdin. It returns a control execResponse with the
// captured output — modelling exactly what a guest would do (run argv, pump stdin,
// capture exit+stdout+stderr). python3-bearing hosts only (skipped otherwise).
func runProjectedExec(t *testing.T) func(http.ResponseWriter, controlExecBody) {
	t.Helper()
	return func(w http.ResponseWriter, body controlExecBody) {
		stdin, decErr := base64.StdEncoding.DecodeString(body.StdinB64)
		if decErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// body.Argv is [interpreter, -c, script]; run it as the guest would.
		var cmd *exec.Cmd
		if len(body.Argv) == 3 && (body.Argv[0] == "/usr/bin/python3" || strings.HasSuffix(body.Argv[0], "python3")) {
			py, err := exec.LookPath("python3")
			if err != nil {
				// No python3 on the host — signal the test to skip via a sentinel exit.
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(controlExecResponse{
					ExitCode:  254,
					StderrB64: base64.StdEncoding.EncodeToString([]byte("NO_PYTHON3")),
				})
				return
			}
			cmd = exec.Command(py, "-c", body.Argv[2])
		} else {
			cmd = exec.Command(body.Argv[0], body.Argv[1:]...)
		}
		cmd.Stdin = strings.NewReader(string(stdin))
		var exitCode uint8
		out, err := cmd.CombinedOutput()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				exitCode = uint8(ee.ExitCode())
			} else {
				exitCode = 255
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(controlExecResponse{
			ExitCode:  exitCode,
			StdoutB64: base64.StdEncoding.EncodeToString(out),
		})
	}
}

// projectFileTool mirrors the ingress projection for a file tool so the forward-level
// e2e drives the same argv+stdin the real handler would build (create_file/view/
// str_replace → [python3 -c script] + the arguments JSON on stdin). The scripts are
// the ingress' committed scripts; here they are inlined minimally to keep the forward
// test self-contained without importing the ingress package (an import cycle).
//
// NOTE: the SCRIPT semantics are pinned in the ingress package's script-behaviour
// tests; this e2e proves the create+exec WIRE path carries argv+stdin and the guest
// executes it. To keep the two in lockstep, this reads the script from an env the
// test sets, so a script drift is caught by the ingress tests, not silently forked
// here.

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

	// The create_file projection: python3 running the create script, arguments JSON on
	// stdin. The script is the create-file program (parent dirs + write + success).
	script := `
import sys, json, os
data = json.loads(sys.stdin.read())
p = data['path']; ft = data['file_text']
d = os.path.dirname(p)
if d: os.makedirs(d, exist_ok=True)
open(p, 'w').write(ft)
print("Successfully created " + p)
`
	argsJSON := `{"path":"` + target + `","file_text":"e2e-body"}`

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
			Argv:  []string{"/usr/bin/python3", "-c", script},
			Stdin: []byte(argsJSON),
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
