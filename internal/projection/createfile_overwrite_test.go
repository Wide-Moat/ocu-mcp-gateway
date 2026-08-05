// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package projection

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runCreateFile executes the embedded CreateFileScript through python3 with the
// given {path, file_text} on stdin, in the same shape the gateway projects
// (python3 -c <script>, opaque JSON on stdin), so a green here binds the SHIPPED
// script rather than a re-implementation of it.
func runCreateFile(t *testing.T, path, text string) (string, bool) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH; the create_file overwrite coverage needs the real interpreter")
	}
	in, err := json.Marshal(map[string]string{"path": path, "file_text": text})
	if err != nil {
		t.Fatalf("marshal stdin: %v", err)
	}
	cmd := exec.Command(py, "-c", CreateFileScript)
	cmd.Stdin = bytes.NewReader(in)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	failed := false
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			failed = true
		} else {
			t.Fatalf("run CreateFileScript: %v", runErr)
		}
	}
	return out.String(), failed
}

// codeOf returns the script with its comment lines removed, so a guard scanning
// for a forbidden idiom cannot fire on the prose that explains why the idiom is
// forbidden. A guard that reddens on its own documentation teaches the next
// person to delete the documentation.
func codeOf(t *testing.T, name, script string) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	out := b.String()
	// Anti-vacuity: if the filter ever ate the code, every check on the result
	// would pass on an empty string.
	if len(strings.TrimSpace(out)) < 100 {
		t.Fatalf("%s stripped to %d bytes; the comment filter has eaten the code and every "+
			"check against it is vacuous", name, len(strings.TrimSpace(out)))
	}
	return out
}

// TestWriteScriptsDoNotOpenWithTruncation pins the constraint the storage mount
// imposes on every script that rewrites a file.
//
// The outputs mount refuses an open carrying O_TRUNC with EIO. Creating a new
// file works there and appending works there; only truncation AT OPEN fails. A
// rewrite therefore fails on the mount while passing every test on a local
// filesystem, because tmpfs and ext4 serve O_TRUNC perfectly well. That is why
// this assertion is STRUCTURAL: no behavioural test running on a normal
// filesystem can reproduce the failure, so a behavioural test alone would stay
// green with the defect present.
//
// Both write scripts are covered. They acquired the constraint at different
// times, and a guard that watched only one would let the other regress.
func TestWriteScriptsDoNotOpenWithTruncation(t *testing.T) {
	scripts := map[string]string{
		"CreateFileScript": CreateFileScript,
		"StrReplaceScript": StrReplaceScript,
	}
	for name, script := range scripts {
		body := codeOf(t, name, script)
		for _, banned := range []string{
			`open(path, 'w')`,
			`open(path, "w")`,
			`open(path, 'w+')`,
			`open(path, "w+")`,
			`O_TRUNC`,
		} {
			if strings.Contains(body, banned) {
				t.Errorf("%s code contains %q: that asks the kernel to truncate at open, which "+
					"the outputs mount answers with EIO, losing the write on an existing path", name, banned)
			}
		}
	}
	// The positive half for the creating script: it must still ask for creation,
	// or a genuinely new path would fail instead.
	if !strings.Contains(codeOf(t, "CreateFileScript", CreateFileScript), "O_CREAT") {
		t.Error("CreateFileScript no longer requests O_CREAT; a new path would fail to be created")
	}
}

// TestCreateFileScriptOverwritesWithoutLeavingATail pins that replacing longer
// content with shorter content leaves NOTHING of the old bytes behind.
//
// This is the failure mode the fix itself can introduce: opening without
// truncation and forgetting to cut leaves the old tail past the new content, and
// the file then reads as the new text followed by garbage. It reddens on a normal
// filesystem, which the structural test above cannot, so the two legs cover
// different halves and neither is redundant.
func TestCreateFileScriptOverwritesWithoutLeavingATail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "over.txt")

	const long = "LONG-ORIGINAL-CONTENT-THAT-MUST-NOT-SURVIVE"
	const short = "SHORT"

	if out, failed := runCreateFile(t, path, long); failed {
		t.Fatalf("seeding create failed: %s", out)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != long {
		t.Fatalf("seed readback = %q, %v; want %q", got, err, long)
	}

	out, failed := runCreateFile(t, path, short)
	if failed {
		t.Fatalf("create over an existing path failed: %s", out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if string(got) != short {
		t.Errorf("file = %q; want exactly %q — anything longer means the old tail survived "+
			"the rewrite and the file now reads as new content followed by stale bytes", got, short)
	}
}
