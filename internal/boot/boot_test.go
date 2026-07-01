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
	seq, err := NewSequencer(fakeLoader{set: auth.NewStaticKeySet(nil, "", nil)})
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
	seq, _ := NewSequencer(fakeLoader{set: auth.NewStaticKeySet(nil, "", nil)})
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

// mutableLoader returns a set/error that a test can change between calls, to model
// Control re-rendering the boot-set (a revoke) or a transient load failure.
type mutableLoader struct {
	set auth.KeySet
	err error
}

func (m *mutableLoader) Load(context.Context) (auth.KeySet, error) { return m.set, m.err }

// TestRefreshSwapsInNewSet — a successful Refresh atomically swaps the set, and
// the live provider returns the NEW set immediately (the path a revoke takes to
// stop authenticating within the window). We identify the set by pointer identity
// through the provider.
func TestRefreshSwapsInNewSet(t *testing.T) {
	set1 := auth.NewStaticKeySet(nil, "d", nil)
	set2 := auth.NewStaticKeySet(nil, "d", nil)
	ml := &mutableLoader{set: set1}
	seq, _ := NewSequencer(ml)
	if err := seq.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	live := seq.LiveKeySet()
	if live() != set1 {
		t.Fatal("live provider must return the initially-loaded set")
	}
	// Control re-renders: the loader now yields set2.
	ml.set = set2
	if err := seq.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if live() != set2 {
		t.Fatal("after a successful Refresh, the live provider must return the NEW set")
	}
}

// TestRefreshFailureKeepsLastGoodSet — a Refresh whose load fails keeps the
// previously-loaded set (fail-safe: never blank auth, never fail open). Readiness
// is unchanged.
func TestRefreshFailureKeepsLastGoodSet(t *testing.T) {
	set1 := auth.NewStaticKeySet(nil, "d", nil)
	ml := &mutableLoader{set: set1}
	seq, _ := NewSequencer(ml)
	if err := seq.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	live := seq.LiveKeySet()
	// The next load fails (transient store outage / mis-render).
	ml.set = nil
	ml.err = errors.New("store down")
	if err := seq.Refresh(context.Background()); err == nil {
		t.Fatal("a failing Refresh must return an error")
	}
	if !seq.Ready() {
		t.Fatal("a failing Refresh must not flip readiness off (fail-safe)")
	}
	if live() != set1 {
		t.Fatal("a failing Refresh must keep the last-good set, not blank it")
	}
}

// TestRefreshBeforeLoadFailsClosed — Refresh before the initial Load is a
// fail-closed error (it must not fabricate readiness).
func TestRefreshBeforeLoadFailsClosed(t *testing.T) {
	seq, _ := NewSequencer(&mutableLoader{set: auth.NewStaticKeySet(nil, "d", nil)})
	if err := seq.Refresh(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Refresh before Load must be ErrNotReady, got %v", err)
	}
}
