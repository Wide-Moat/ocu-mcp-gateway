// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package boot

import (
	"context"
	"errors"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// fakeLoader is a test KeySetLoader: it returns a fixed set or a fixed error.
type fakeLoader struct {
	set auth.KeySet
	err error
}

func (f fakeLoader) Load(context.Context) (auth.KeySet, error) { return f.set, f.err }

func TestSequencerNotReadyBeforeLoad(t *testing.T) {
	seq, err := NewSequencer(fakeLoader{set: auth.NewStaticKeySet(nil, nil)})
	if err != nil {
		t.Fatalf("NewSequencer: %v", err)
	}
	if seq.Ready() {
		t.Fatal("sequencer must not be ready before Load")
	}
	if _, err := seq.KeySet(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("KeySet before Load must be ErrNotReady, got %v", err)
	}
}

func TestSequencerReadyAfterLoad(t *testing.T) {
	seq, _ := NewSequencer(fakeLoader{set: auth.NewStaticKeySet(nil, nil)})
	if err := seq.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !seq.Ready() {
		t.Fatal("sequencer must be ready after a successful Load")
	}
	if _, err := seq.KeySet(); err != nil {
		t.Fatalf("KeySet after Load: %v", err)
	}
}

func TestSequencerLoadFailureStaysNotReady(t *testing.T) {
	seq, _ := NewSequencer(fakeLoader{err: errors.New("store down")})
	err := seq.Load(context.Background())
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("a load failure must wrap ErrNotReady, got %v", err)
	}
	if seq.Ready() {
		t.Fatal("sequencer must stay not-ready after a load failure (fail-closed)")
	}
}

func TestSequencerNilSetIsNotReady(t *testing.T) {
	seq, _ := NewSequencer(fakeLoader{set: nil, err: nil})
	if err := seq.Load(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("a nil key set must be ErrNotReady, got %v", err)
	}
	if seq.Ready() {
		t.Fatal("a nil key set must leave the sequencer not-ready")
	}
}

func TestNewSequencerNilLoaderFailsClosed(t *testing.T) {
	if _, err := NewSequencer(nil); err == nil {
		t.Fatal("NewSequencer(nil) must fail closed")
	}
}
