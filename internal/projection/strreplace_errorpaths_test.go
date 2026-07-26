// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package projection

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runStrReplace executes the embedded StrReplaceScript through python3 with the
// given {path, old_str, new_str} on stdin, returning its combined stdout+stderr
// and whether it exited non-zero. It is the same execution shape the gateway
// projects (python3 -c <script>, opaque JSON on stdin), so a green here proves
// the SHIPPED script's error semantics, not a re-implementation.
func runStrReplace(t *testing.T, path, oldStr, newStr string) (string, bool) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH; the str_replace error-path coverage needs the real interpreter")
	}
	in, err := json.Marshal(map[string]string{"path": path, "old_str": oldStr, "new_str": newStr})
	if err != nil {
		t.Fatalf("marshal stdin: %v", err)
	}
	cmd := exec.Command(py, "-c", StrReplaceScript)
	cmd.Stdin = bytes.NewReader(in)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	failed := false
	if runErr != nil {
		if _, ok := runErr.(*exec.ExitError); ok {
			failed = true
		} else {
			t.Fatalf("run StrReplaceScript: %v", runErr)
		}
	}
	return out.String(), failed
}

// TestStrReplaceScript_ErrorPaths pins the three canonical str_replace error
// semantics (identical / not-found / more-than-one-occurrence) that the gateway
// keeps EXACT (#190.3): each refuses with a specific message, exits non-zero, and
// leaves the file unchanged. The success path is included as the positive control
// so a probe that breaks a refusal cannot pass by breaking the success arm too.
func TestStrReplaceScript_ErrorPaths(t *testing.T) {
	t.Run("identical old_str/new_str is refused before any file touch", func(t *testing.T) {
		// A nonexistent path proves the identical check runs BEFORE the open.
		out, failed := runStrReplace(t, "/no/such/path/deliberately-absent", "abc", "abc")
		if !failed {
			t.Fatalf("identical old/new must exit non-zero; got success, output=%q", out)
		}
		if !strings.Contains(out, "identical") {
			t.Fatalf("identical refusal message missing; output=%q", out)
		}
	})

	t.Run("old_str not found is refused and leaves the file unchanged", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "target.txt")
		const original = "the quick brown fox\n"
		if err := os.WriteFile(f, []byte(original), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		out, failed := runStrReplace(t, f, "ABSENT-NEEDLE", "REPLACEMENT")
		if !failed {
			t.Fatalf("not-found must exit non-zero; output=%q", out)
		}
		if !strings.Contains(out, "not found") {
			t.Fatalf("not-found refusal message missing; output=%q", out)
		}
		got, _ := os.ReadFile(f)
		if string(got) != original {
			t.Fatalf("file mutated on a refused edit: %q, want %q", got, original)
		}
	})

	t.Run("more than one occurrence is refused with a count and unchanged file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "dup.txt")
		const original = "foo bar foo baz foo\n" // 3 occurrences of "foo"
		if err := os.WriteFile(f, []byte(original), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		out, failed := runStrReplace(t, f, "foo", "QUX")
		if !failed {
			t.Fatalf(">1 occurrence must exit non-zero; output=%q", out)
		}
		if !strings.Contains(out, "occurrences") {
			t.Fatalf("multi-occurrence refusal message missing; output=%q", out)
		}
		if !strings.Contains(out, "3") {
			t.Fatalf("multi-occurrence message must carry the count 3; output=%q", out)
		}
		got, _ := os.ReadFile(f)
		if string(got) != original {
			t.Fatalf("file mutated on a refused ambiguous edit: %q, want %q", got, original)
		}
	})

	t.Run("positive control: a unique single occurrence is replaced exactly once", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "ok.txt")
		if err := os.WriteFile(f, []byte("alpha UNIQUE omega\n"), 0o600); err != nil {
			t.Fatalf("seed file: %v", err)
		}
		out, failed := runStrReplace(t, f, "UNIQUE", "REPLACED")
		if failed {
			t.Fatalf("a unique single replacement must succeed; output=%q", out)
		}
		got, _ := os.ReadFile(f)
		if want := "alpha REPLACED omega\n"; string(got) != want {
			t.Fatalf("replacement result = %q, want %q", got, want)
		}
	})
}
