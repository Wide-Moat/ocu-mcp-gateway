// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/projection"
)

// The file-tool projections carry their behaviour in the guest SCRIPT, not the Go
// code — the argv-shape tests prove the projection wires up, but the SCRIPT is what
// actually creates/edits/reads. These tests RUN each projected script through the
// interpreter with a stdin payload against a temp file, so the canonical file-edit
// semantics — parent-dir creation, single-unambiguous replace, and the three
// str_replace error messages — are pinned as real behaviour, not just asserted in a
// comment. The script is run byte-identical to what the guest runs; only the temp
// path differs.

// runScript runs a projected file-tool script through python3 with the given stdin
// payload and returns (stdout+stderr combined, exitCode). It skips if python3 is not
// on the test host (the behaviour is guest-side; the argv-shape tests cover the wiring
// unconditionally).
func runScript(t *testing.T, script, stdin string) (string, int) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on the test host; the guest runs the script — argv-shape tests cover the wiring")
	}
	cmd := exec.Command(py, "-c", script)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running script: %v", err)
		}
	}
	return string(out), code
}

// TestCreateFileScriptWritesWithParents pins create_file: it makes missing parent
// directories and writes the file body verbatim, printing a success line (exit 0).
func TestCreateFileScriptWritesWithParents(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "deep", "a.txt")
	payload := `{"path":` + jsonStr(target) + `,"file_text":"hello\nworld"}`

	out, code := runScript(t, projection.CreateFileScript, payload)
	if code != 0 {
		t.Fatalf("create_file should succeed, got exit %d, out=%q", code, out)
	}
	if !strings.Contains(out, "Successfully created") {
		t.Errorf("create_file should print a success line, got %q", out)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("create_file did not write the file (parent dirs not created?): %v", err)
	}
	if string(got) != "hello\nworld" {
		t.Errorf("create_file wrote %q, want %q", got, "hello\nworld")
	}
}

// TestCreateFileScriptWriteFailureErrors pins create_file's FAILURE contract: a write
// the guest cannot perform (here, a target inside a read-only directory) is a Tier-2
// tool error — the script prints "Error: <cause>" and exits non-zero, and CRUCIALLY
// writes NOTHING (no partial/empty file left behind). This mirrors a real live case
// (create_file into a non-writable path returned "[Errno 13] Permission denied" and
// created no file). It is a coverage pin on behaviour that already exists; the value
// is the pinned regression and the no-partial-write assertion.
func TestCreateFileScriptWriteFailureErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		// Root bypasses a 0555 directory's write bit, so the failure would not trigger
		// and the test would be vacuous. The guest exec child is unprivileged, which is
		// where this path is real; CI runners are non-root, so this only skips a
		// root-local run.
		t.Skip("root bypasses 0555 dir perms; the guest write-failure path is exercised where the exec child is unprivileged")
	}
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0o555); err != nil {
		t.Fatal(err)
	}
	// Restore write so t.TempDir's cleanup can remove the tree.
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o755) })

	target := filepath.Join(roDir, "demo.py")
	payload := `{"path":` + jsonStr(target) + `,"file_text":"x"}`

	out, code := runScript(t, projection.CreateFileScript, payload)
	if code == 0 {
		t.Fatalf("a write into a read-only dir must fail non-zero, got 0 (out=%q)", out)
	}
	if !strings.Contains(out, "Error") {
		t.Errorf("a write failure must surface an \"Error: <cause>\" the caller sees, got %q", out)
	}
	// The load-bearing assertion: NOTHING is written on failure (no partial/empty file).
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("a failed create_file must write NOTHING; os.Stat(%q) err = %v, want IsNotExist", target, err)
	}
}

// TestStrReplaceScriptSingleReplace pins the happy path: a single unambiguous
// occurrence is replaced and the file is rewritten.
func TestStrReplaceScriptSingleReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(target, []byte("alpha BRAVO charlie"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload := `{"path":` + jsonStr(target) + `,"old_str":"BRAVO","new_str":"DELTA"}`

	out, code := runScript(t, projection.StrReplaceScript, payload)
	if code != 0 {
		t.Fatalf("str_replace should succeed, got exit %d, out=%q", code, out)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "alpha DELTA charlie" {
		t.Errorf("str_replace produced %q, want %q", got, "alpha DELTA charlie")
	}
}

// TestStrReplaceScriptErrorSemantics pins the THREE canonical error semantics, each
// exiting non-zero with the exact message class: identical old/new, old_str not
// found, and more than one occurrence (ambiguous — refused with a request for
// context). These are the load-bearing edit-safety guarantees.
func TestStrReplaceScriptErrorSemantics(t *testing.T) {
	dir := t.TempDir()

	t.Run("identical old and new", func(t *testing.T) {
		target := filepath.Join(dir, "id.txt")
		_ = os.WriteFile(target, []byte("xx same yy"), 0o600)
		payload := `{"path":` + jsonStr(target) + `,"old_str":"same","new_str":"same"}`
		out, code := runScript(t, projection.StrReplaceScript, payload)
		if code == 0 {
			t.Fatalf("identical old/new must fail non-zero, got 0 (out=%q)", out)
		}
		if !strings.Contains(out, "identical") {
			t.Errorf("identical old/new error must say so, got %q", out)
		}
	})

	t.Run("old_str not found", func(t *testing.T) {
		target := filepath.Join(dir, "nf.txt")
		_ = os.WriteFile(target, []byte("content here"), 0o600)
		payload := `{"path":` + jsonStr(target) + `,"old_str":"absent","new_str":"x"}`
		out, code := runScript(t, projection.StrReplaceScript, payload)
		if code == 0 {
			t.Fatalf("not-found must fail non-zero, got 0 (out=%q)", out)
		}
		if !strings.Contains(out, "not found") {
			t.Errorf("not-found error must say so, got %q", out)
		}
	})

	t.Run("multiple occurrences ambiguous", func(t *testing.T) {
		target := filepath.Join(dir, "multi.txt")
		_ = os.WriteFile(target, []byte("dup dup dup"), 0o600)
		payload := `{"path":` + jsonStr(target) + `,"old_str":"dup","new_str":"x"}`
		out, code := runScript(t, projection.StrReplaceScript, payload)
		if code == 0 {
			t.Fatalf("ambiguous (>1 match) must fail non-zero, got 0 (out=%q)", out)
		}
		if !strings.Contains(out, "occurrences") || !strings.Contains(out, "context") {
			t.Errorf("ambiguous error must report the count and ask for context, got %q", out)
		}
		// The file must be UNCHANGED (no partial edit on an ambiguous match).
		got, _ := os.ReadFile(target)
		if string(got) != "dup dup dup" {
			t.Errorf("an ambiguous match must not edit the file; got %q", got)
		}
	})
}

// TestViewScriptNumbersLinesAndListsDirs pins view: a text file is shown with line
// numbers; a directory is listed; a missing path errors non-zero.
func TestViewScriptNumbersLinesAndListsDirs(t *testing.T) {
	dir := t.TempDir()

	t.Run("text file numbered", func(t *testing.T) {
		target := filepath.Join(dir, "v.txt")
		_ = os.WriteFile(target, []byte("first\nsecond\n"), 0o600)
		out, code := runScript(t, projection.ViewScript, `{"path":`+jsonStr(target)+`}`)
		if code != 0 {
			t.Fatalf("view of a text file should succeed, got exit %d out=%q", code, out)
		}
		if !strings.Contains(out, "first") || !strings.Contains(out, "second") {
			t.Errorf("view should show the file contents, got %q", out)
		}
		if !strings.Contains(out, "1") || !strings.Contains(out, "2") {
			t.Errorf("view should number the lines, got %q", out)
		}
	})

	t.Run("directory listed", func(t *testing.T) {
		sub := filepath.Join(dir, "d")
		_ = os.MkdirAll(sub, 0o755)
		_ = os.WriteFile(filepath.Join(sub, "child.txt"), []byte("x"), 0o600)
		out, code := runScript(t, projection.ViewScript, `{"path":`+jsonStr(sub)+`}`)
		if code != 0 {
			t.Fatalf("view of a directory should succeed, got exit %d out=%q", code, out)
		}
		if !strings.Contains(out, "child.txt") {
			t.Errorf("view of a dir should list entries, got %q", out)
		}
	})

	t.Run("missing path errors", func(t *testing.T) {
		out, code := runScript(t, projection.ViewScript, `{"path":"/no/such/path/here"}`)
		if code == 0 {
			t.Fatalf("view of a missing path must fail non-zero, got 0 (out=%q)", out)
		}
		if !strings.Contains(out, "not found") {
			t.Errorf("missing-path error must say so, got %q", out)
		}
	})
}

// TestFileToolScriptStdinInjectionSafe pins the injection-safety guarantee: a path
// containing shell metacharacters, quotes, and newlines is handled as literal DATA
// (the file is created at that exact path), never interpreted. This is the whole
// reason the arguments ride on stdin rather than in argv.
func TestFileToolScriptStdinInjectionSafe(t *testing.T) {
	dir := t.TempDir()
	// A filename with characters that WOULD be dangerous if interpolated into a shell.
	nasty := filepath.Join(dir, "a'; rm -rf $HOME; echo \"x\".txt")
	payload := `{"path":` + jsonStr(nasty) + `,"file_text":"safe"}`

	out, code := runScript(t, projection.CreateFileScript, payload)
	if code != 0 {
		t.Fatalf("create_file with a metacharacter path should still succeed as literal data, got exit %d out=%q", code, out)
	}
	got, err := os.ReadFile(nasty)
	if err != nil {
		t.Fatalf("the file must be created at the LITERAL path (chars treated as data): %v", err)
	}
	if string(got) != "safe" {
		t.Errorf("wrote %q, want %q", got, "safe")
	}
}

// jsonStr JSON-encodes a string for embedding in a payload literal (so a temp path
// with special characters is a valid JSON string).
func jsonStr(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\n':
			b = append(b, '\\', 'n')
		case '\t':
			b = append(b, '\\', 't')
		default:
			b = append(b, string(r)...)
		}
	}
	b = append(b, '"')
	return string(b)
}
