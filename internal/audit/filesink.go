// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// fileSinkPerm is the 0600 mode the audit file is created with: owner read/write
// only. The OCSF spine carries no credential, but it is a tamper-evidence record
// of every terminated request, so no other host user may read or append to it.
// This mirrors the ocu-control audit file sink so the fleet has one audit posture.
const fileSinkPerm = 0o600

// ErrFileSinkClosed is the fail-closed verdict for a Publish that races shutdown:
// an envelope arriving after the sink is closed is denied rather than silently
// dropped, so the forward fail-closes.
var ErrFileSinkClosed = errors.New("audit: file sink is closed")

// FileSink is the durable, single-writer Sink that backs -audit-sink with a real
// append-only newline-delimited JSON file. Each already-serialized OCSF payload is
// appended as exactly one line and fsync'd BEFORE Publish returns — so the request
// that triggered the emit is not acknowledged until its event is on durable
// storage (emit-before-ack, NFR-SEC-03). A write or fsync failure returns a
// non-nil error, which the Emitter wraps as ErrAuditWriteFailed and the caller's
// fail-closed branch treats as a hard deny. This is what makes "every terminated
// request is durably audited before ack, or it is denied" reachable — the parallel
// to control's OCSF file spine, aligned on the same \n-delimited JSON format.
//
// It is single-writer safe: a mutex serializes concurrent appends so two requests
// never interleave their bytes and the file's line order is the order the Emitter
// assigned each monotonic sequence.
type FileSink struct {
	mu     sync.Mutex
	f      syncWriteCloser
	closed bool
}

// syncWriteCloser is the narrow durable-file contract FileSink drives: append
// bytes, flush them to stable storage, and close. *os.File satisfies it in
// production; a test substitutes a faulting implementation to drive the
// short-write and fsync-failure deny branches deterministically.
type syncWriteCloser interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// Compile-time proof FileSink is a Sink (so it slots in behind the Emitter with no
// call-site change) and that *os.File satisfies the durable-file contract.
var (
	_ Sink            = (*FileSink)(nil)
	_ syncWriteCloser = (*os.File)(nil)
)

// OpenFileSink opens (or creates) path as an append-only audit file with 0600
// permissions. The file is opened O_APPEND|O_CREATE|O_WRONLY so existing lines are
// preserved and every write lands at the end — a restart continues the prior spine
// rather than truncating it. An empty path or an open failure (e.g. an unwritable
// directory) is returned so the daemon aborts at boot rather than booting with a
// discarded audit trail.
func OpenFileSink(path string) (*FileSink, error) {
	if path == "" {
		return nil, errors.New("audit: file sink path is empty (fail-closed)")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileSinkPerm)
	if err != nil {
		return nil, fmt.Errorf("audit: open file sink %q: %w", path, err)
	}
	// Durably commit the FILE's CREATION by fsyncing the PARENT DIRECTORY. An fsync
	// on the file alone does not flush the directory entry (POSIX), so a crash
	// right after create could lose a brand-new audit file — an unacceptable gap
	// for the durable-first audit spine (NFR-SEC-03). A restart re-opens an
	// existing file, where this is a no-op, but the first create is made durable.
	// If the parent cannot be synced the sink is refused at construction (fail
	// closed), and the just-opened file is closed so it is not leaked.
	if err := syncParentDir(path); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit: fsync parent dir of file sink %q: %w", path, err)
	}
	return &FileSink{f: f}, nil
}

// syncParentDir fsyncs the directory that contains path, so a newly created file's
// directory entry is durably on stable storage. It is a POSIX requirement that a
// file-level fsync does not cover; ext4/xfs may handle it implicitly, but relying
// on that is not portable or crash-safe.
func syncParentDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Publish appends payload as one newline-delimited JSON line and fsyncs the file
// before returning nil. It returns a non-nil error on a short write, a write
// failure, or an fsync failure (or after Close), so the Emitter's fail-closed
// branch denies the request rather than acking an event that did not reach durable
// storage. The payload arrives already serialized (the Emitter marshals the OCSF
// envelope); the sink renders exactly one line per envelope. The mutex makes the
// append + fsync atomic with respect to other Publishes.
func (s *FileSink) Publish(ctx context.Context, channel string, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("audit: file sink publish (channel %q): context: %w", channel, err)
	}

	line := make([]byte, 0, len(payload)+1)
	line = append(line, payload...)
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrFileSinkClosed
	}

	n, err := s.f.Write(line)
	if err != nil {
		// A write error may have appended a partial record; SEAL the sink so no
		// later Publish appends after a truncated tail (which would corrupt the
		// JSONL spine). Every subsequent Publish then fails closed.
		s.closed = true
		return fmt.Errorf("audit: append to file sink (channel %q): %w", channel, err)
	}
	if n != len(line) {
		// A short write left a truncated record on the tail. SEAL the sink: a later
		// append after a partial line yields an unparseable spine, so no further
		// write is permitted once durability was breached.
		s.closed = true
		return fmt.Errorf("audit: short write to file sink (channel %q): wrote %d of %d bytes", channel, n, len(line))
	}
	if err := s.f.Sync(); err != nil {
		// The bytes are not confirmed on stable storage. SEAL the sink: continuing
		// to append past an unconfirmed record risks an unrecoverable spine. Fail
		// closed here and on every subsequent Publish.
		s.closed = true
		return fmt.Errorf("audit: fsync file sink (channel %q): %w", channel, err)
	}
	return nil
}

// Close closes the underlying file. After Close every Publish fails closed. Close
// is idempotent: a second Close is a no-op returning nil.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.f.Close()
}
