// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileSinkPublishAppendsDurableLine asserts a Publish writes exactly one
// newline-delimited JSON line to the file and returns nil — the durable success
// path that lets a forward ack. The payload arrives already serialized (the
// Emitter marshals the OCSF envelope); the sink renders it as one line.
func TestFileSinkPublishAppendsDurableLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	defer sink.Close()

	payload := []byte(`{"activity_id":1,"seq":0}`)
	if err := sink.Publish(context.Background(), "audit.ocsf", payload); err != nil {
		t.Fatalf("Publish returned error, want nil (durable write): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back audit file: %v", err)
	}
	if string(got) != string(payload)+"\n" {
		t.Fatalf("audit file = %q, want the payload followed by exactly one newline (%q)", string(got), string(payload)+"\n")
	}
}

// TestFileSinkPublishAppendsNotTruncates asserts a second Publish APPENDS a second
// line rather than truncating the first — the append-only spine a restart or a
// second action must preserve.
func TestFileSinkPublishAppendsNotTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	defer sink.Close()

	if err := sink.Publish(context.Background(), "audit.ocsf", []byte(`{"seq":0}`)); err != nil {
		t.Fatalf("first Publish: %v", err)
	}
	if err := sink.Publish(context.Background(), "audit.ocsf", []byte(`{"seq":1}`)); err != nil {
		t.Fatalf("second Publish: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(got), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit file has %d lines, want 2 (append-only, no truncation): %q", len(lines), string(got))
	}
	if lines[0] != `{"seq":0}` || lines[1] != `{"seq":1}` {
		t.Fatalf("audit lines = %q, want the two records in order", lines)
	}
}

// TestFileSinkOpenFailsClosedOnBadPath asserts opening a sink under an
// unwritable/nonexistent directory is a construction error, so the daemon aborts
// at boot rather than booting with a discarded audit trail.
func TestFileSinkOpenFailsClosedOnBadPath(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "no-such-dir", "audit.ocsf.jsonl")
	if _, err := OpenFileSink(bad); err == nil {
		t.Fatal("OpenFileSink under a nonexistent directory returned nil error, want a fail-closed open error")
	}
}

// TestFileSinkOpenFailsClosedOnEmptyPath asserts an empty path is refused (a
// misconfiguration, not a silent no-op sink).
func TestFileSinkOpenFailsClosedOnEmptyPath(t *testing.T) {
	if _, err := OpenFileSink(""); err == nil {
		t.Fatal("OpenFileSink(\"\") returned nil error, want a fail-closed error")
	}
}

// TestFileSinkPublishFailsClosedAfterClose asserts a Publish after Close is a
// non-nil error — an envelope that races shutdown is denied (the forward
// fail-closes), never silently dropped.
func TestFileSinkPublishFailsClosedAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	sink, err := OpenFileSink(path)
	if err != nil {
		t.Fatalf("OpenFileSink: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sink.Publish(context.Background(), "audit.ocsf", []byte(`{"seq":0}`)); err == nil {
		t.Fatal("Publish after Close returned nil, want a fail-closed error (no silent drop)")
	}
}

// TestFileSinkSatisfiesSink is a compile-time assertion that *FileSink is a Sink,
// so it slots in behind the Emitter with no call-site change.
func TestFileSinkSatisfiesSink(t *testing.T) {
	var _ Sink = (*FileSink)(nil)
}

// faultingFile is a syncWriteCloser that fails a chosen durability step, so the
// short-write and fsync-failure deny branches are driven deterministically (a real
// os.File on a regular file does not fault those on demand).
type faultingFile struct {
	shortWrite bool
	syncErr    error
}

func (f *faultingFile) Write(p []byte) (int, error) {
	if f.shortWrite {
		return len(p) - 1, nil // one byte short, no error: the short-write branch
	}
	return len(p), nil
}
func (f *faultingFile) Sync() error  { return f.syncErr }
func (f *faultingFile) Close() error { return nil }

// TestFileSinkPublishFailsClosedOnShortWrite asserts a short write (the whole
// record did not land) is a non-nil error — the durability deny that keeps the
// forward fail-closed (NFR-SEC-03 is not weakened by adding the success path).
func TestFileSinkPublishFailsClosedOnShortWrite(t *testing.T) {
	s := &FileSink{f: &faultingFile{shortWrite: true}}
	if err := s.Publish(context.Background(), "audit.ocsf", []byte(`{"seq":0}`)); err == nil {
		t.Fatal("Publish with a short write returned nil, want a fail-closed error")
	}
}

// TestFileSinkPublishFailsClosedOnFsyncError asserts an fsync failure (bytes not on
// stable storage) is a non-nil error — the emit-before-DURABLE-ack property.
func TestFileSinkPublishFailsClosedOnFsyncError(t *testing.T) {
	s := &FileSink{f: &faultingFile{syncErr: errors.New("disk gone")}}
	if err := s.Publish(context.Background(), "audit.ocsf", []byte(`{"seq":0}`)); err == nil {
		t.Fatal("Publish with an fsync failure returned nil, want a fail-closed error")
	}
}
