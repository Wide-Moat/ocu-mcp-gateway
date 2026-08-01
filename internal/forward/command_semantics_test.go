// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// D8 (deploy/PARITY-LEDGER-147.md): the PoC translates benign non-zero exits from a
// small set of commands (grep/rg/find/diff/test/[) into model-friendly text instead of
// surfacing a bare non-zero exit the model may loop on. The fleet gateway BUILDS the
// bash argv itself (["/bin/sh","-c",command] in projection.Project), so the command is
// argv[2] VERBATIM - extraction runs on the exact command, not a guess. These keystones
// pin the semantics application in projectCallToolResult.

// semanticsResult drives projectCallToolResult directly with an execResponseWire and the
// gateway-built argv, decoding the CallToolResult it projects.
func semanticsResult(t *testing.T, exitCode uint8, stdout, stderr string, argv []string) callToolResultShape {
	t.Helper()
	blob, err := projectCallToolResult(execResponseWire{
		ExitCode:  exitCode,
		StdoutB64: base64.StdEncoding.EncodeToString([]byte(stdout)),
		StderrB64: base64.StdEncoding.EncodeToString([]byte(stderr)),
	}, argv)
	if err != nil {
		t.Fatalf("projectCallToolResult: %v", err)
	}
	var shape callToolResultShape
	if uerr := json.Unmarshal(blob, &shape); uerr != nil {
		t.Fatalf("result must be a CallToolResult, got %q (%v)", blob, uerr)
	}
	return shape
}

// (a) grep exit 1 with empty streams: the semantics table fires - isError:false, the
// table message "No matches found", and NO "[Exit code: N]" marker.
func TestCommandSemanticsGrepNoMatchesIsNotError(t *testing.T) {
	shape := semanticsResult(t, 1, "", "", []string{"/bin/sh", "-c", "grep foo /missing"})
	if shape.IsError {
		t.Errorf("grep exit 1 (no matches) must project isError:false, got isError:true %+v", shape.Content)
	}
	if len(shape.Content) == 0 || shape.Content[0].Text != "No matches found" {
		t.Errorf("grep exit 1 empty streams must carry the table message %q, got %+v", "No matches found", shape.Content)
	}
}

// (b) find exit 1 with stdout "partial": the semantics table fires (find threshold 2) -
// isError:false, and because stdout is non-empty the STDOUT is relayed, not the table
// message (PoC: "output if output else message").
func TestCommandSemanticsFindWithOutputRelaysStdout(t *testing.T) {
	shape := semanticsResult(t, 1, "partial", "", []string{"/bin/sh", "-c", "find / -name x"})
	if shape.IsError {
		t.Errorf("find exit 1 (partial access) must project isError:false, got isError:true %+v", shape.Content)
	}
	if len(shape.Content) == 0 || shape.Content[0].Text != "partial" {
		t.Errorf("find exit 1 with stdout must relay the stdout %q, got %+v", "partial", shape.Content)
	}
}

// (c) grep exit 2 (a real error, at/above threshold): the semantics table does NOT
// fire - isError:true, the raw error surfaces.
func TestCommandSemanticsGrepExitTwoStaysError(t *testing.T) {
	shape := semanticsResult(t, 2, "", "grep: invalid option", []string{"/bin/sh", "-c", "grep -Z foo"})
	if !shape.IsError {
		t.Errorf("grep exit 2 (real error, >= threshold) must stay isError:true, got isError:false %+v", shape.Content)
	}
}

// (d) a file-tool argv (interpreter -c, NOT the ["/bin/sh","-c",cmd] shape) exit 1: the
// argv is not the bash shape, so firstCommandFromArgv returns "" and the semantics never
// fire - the result is unchanged (isError:true).
func TestCommandSemanticsNonBashArgvUnchanged(t *testing.T) {
	shape := semanticsResult(t, 1, "", "Error: old_str not found", []string{"/usr/bin/python3", "-c", "print('x')"})
	if !shape.IsError {
		t.Errorf("a non-bash argv (file tool) exit 1 must be unchanged isError:true, got isError:false %+v", shape.Content)
	}
}

// (e) a bash argv whose command leads with an env assignment (LC_ALL=C grep x y): the
// tokenizer skips VAR=value and finds grep, so the semantics still fire on exit 1.
func TestCommandSemanticsEnvPrefixStillFires(t *testing.T) {
	shape := semanticsResult(t, 1, "", "", []string{"/bin/sh", "-c", "LC_ALL=C grep x y"})
	if shape.IsError {
		t.Errorf("an env-prefixed grep (LC_ALL=C grep) exit 1 must fire the semantics (isError:false), got isError:true %+v", shape.Content)
	}
	if len(shape.Content) == 0 || shape.Content[0].Text != "No matches found" {
		t.Errorf("env-prefixed grep exit 1 empty streams must carry %q, got %+v", "No matches found", shape.Content)
	}
}

// A signal-derived exit (137) with empty streams on a bash argv whose command is NOT in
// the table must stay the raw "[Exit code: 137]" marker - the semantics only cover the
// small benign-exit table, never a signal exit.
func TestCommandSemanticsSignalExitStaysMarker(t *testing.T) {
	shape := semanticsResult(t, 137, "", "", []string{"/bin/sh", "-c", "sleep 100"})
	if !shape.IsError {
		t.Errorf("exit 137 (signal) must stay isError:true, got isError:false %+v", shape.Content)
	}
	if len(shape.Content) == 0 || shape.Content[0].Text != "[Exit code: 137]" {
		t.Errorf("exit 137 empty streams must keep the raw marker %q, got %+v", "[Exit code: 137]", shape.Content)
	}
}

// A COMPOUND command whose FIRST token is a table command but whose exit comes from a
// TRAILING command (grep -q foo f; false) must NOT have the semantics remap applied:
// the `false` genuinely failed, so isError MUST stay true. Without the single-simple-
// command guard, firstCommandFromArgv returns grep and 1 < grep-threshold flips a real
// failure to success -- masking the error the model needs to see. This is the
// regression this guard exists to prevent.
func TestCommandSemanticsCompoundTrailingFailureStaysError(t *testing.T) {
	cases := []string{
		"grep -q foo f; false",   // sequence: trailing false owns exit 1
		"grep -q foo f && false", // and-chain: trailing false owns exit 1
		"grep foo f | wc -l",     // pipe: pipeline exit is the last stage
		"[ -f x ] || deploy",     // or-chain with a table command lead ([)
	}
	for _, cmd := range cases {
		shape := semanticsResult(t, 1, "", "", []string{"/bin/sh", "-c", cmd})
		if !shape.IsError {
			t.Errorf("compound command %q exit 1 must stay isError:true (a trailing command failed), got isError:false %+v", cmd, shape.Content)
		}
	}
}

// The guard must NOT over-block: a genuinely SINGLE simple grep with a quoted argument
// that CONTAINS a control-operator character (grep ';' f) is still one command, so the
// semantics remap still fires on its exit 1. A naive substring check for ';' would
// wrongly disqualify it; the quote-aware scan keeps it eligible.
func TestCommandSemanticsSingleGrepWithQuotedOperatorStillFires(t *testing.T) {
	shape := semanticsResult(t, 1, "", "", []string{"/bin/sh", "-c", "grep ';' f"})
	if shape.IsError {
		t.Errorf("a single grep whose quoted arg contains ';' exit 1 must still fire the semantics (isError:false), got isError:true %+v", shape.Content)
	}
}
