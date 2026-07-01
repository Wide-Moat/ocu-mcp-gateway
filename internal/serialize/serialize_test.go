// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package serialize

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// TestFIFOOrderPerSession proves calls of one session run in ARRIVAL order: with
// the first slot held, later arrivals queue and, on release, proceed strictly in
// the order they enqueued (NFR-IC-05 sequential default). The arrivals are
// enqueued one at a time (each confirmed waiting before the next starts) so the
// FIFO ticket order is deterministic, not a race.
func TestFIFOOrderPerSession(t *testing.T) {
	s := NewSerializer(16, nil)

	// Hold the session's first slot so everything after it must queue.
	rel0, err := s.Acquire("sess", "tool")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	const n = 5
	var order []int
	var mu sync.Mutex
	started := make([]chan struct{}, n)
	done := make([]chan struct{}, n)
	for i := 0; i < n; i++ {
		started[i] = make(chan struct{})
		done[i] = make(chan struct{})
		go func(idx int) {
			close(started[idx]) // signal "goroutine running, about to Acquire"
			rel, aerr := s.Acquire("sess", "tool")
			if aerr != nil {
				t.Errorf("queued acquire %d: %v", idx, aerr)
				close(done[idx])
				return
			}
			mu.Lock()
			order = append(order, idx)
			mu.Unlock()
			rel()
			close(done[idx])
		}(i)
		// Enqueue arrivals one at a time in index order: wait for the goroutine to
		// start, then give it a beat to reach the ticket line before the next.
		<-started[i]
		time.Sleep(5 * time.Millisecond)
	}

	// Release the held slot; the queue now drains in FIFO order.
	rel0()
	for i := 0; i < n; i++ {
		select {
		case <-done[i]:
		case <-time.After(2 * time.Second):
			t.Fatalf("queued call %d did not complete (deadlock?)", i)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < n; i++ {
		if order[i] != i {
			t.Fatalf("FIFO order violated: got %v, want [0 1 2 3 4]", order)
		}
	}
}

// TestSelfCleaningDrainsToZero is the self-cleaning guard (architect requirement
// 1): once all calls of all sessions drain, the serializer holds NO gates — the
// map does not retain an entry per session ever seen. This is the property whose
// red-probe (neuter the delete-at-zero) must go RED.
func TestSelfCleaningDrainsToZero(t *testing.T) {
	s := NewSerializer(16, nil)

	// Exercise several sessions with overlapping in-flight calls.
	var wg sync.WaitGroup
	for _, hint := range []string{"a", "b", "c", "a", "b"} {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			rel, err := s.Acquire(h, "tool")
			if err != nil {
				t.Errorf("acquire %q: %v", h, err)
				return
			}
			time.Sleep(5 * time.Millisecond)
			rel()
		}(hint)
	}
	wg.Wait()

	if c := s.Contended(); c != 0 {
		t.Fatalf("serializer must self-clean to zero gates after drain, got %d (leaked gates)", c)
	}
}

// TestBoundedRefusesOverflow is the DoS guard (architect requirement 3): a session
// queue at its bound refuses excess with ErrSerializerFull rather than parking
// unboundedly. With the bound saturated by held slots, the next acquire is
// refused, not blocked.
func TestBoundedRefusesOverflow(t *testing.T) {
	const bound = 3
	s := NewSerializer(bound, nil)

	// Fill the bound: one running + (bound-1) queued so depth==bound.
	rel0, err := s.Acquire("sess", "tool") // running (depth 1)
	if err != nil {
		t.Fatalf("acquire 0: %v", err)
	}

	// Enqueue (bound-1) waiters so depth reaches the bound.
	ready := make(chan struct{}, bound)
	for i := 1; i < bound; i++ {
		go func() {
			rel, aerr := s.Acquire("sess", "tool")
			if aerr != nil {
				t.Errorf("queued acquire: %v", aerr)
				ready <- struct{}{}
				return
			}
			ready <- struct{}{}
			rel()
		}()
	}
	// Give the waiters time to enqueue (reach depth==bound).
	time.Sleep(50 * time.Millisecond)

	// The next acquire must be REFUSED (depth already at bound), not blocked.
	rel, aerr := s.Acquire("sess", "tool")
	if !errors.Is(aerr, ErrSerializerFull) {
		if rel != nil {
			rel()
		}
		t.Fatalf("an acquire beyond the bound must be refused with ErrSerializerFull, got %v", aerr)
	}

	// Drain: release the running slot; the waiters proceed and finish.
	rel0()
	for i := 1; i < bound; i++ {
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatal("waiter did not proceed after drain")
		}
	}
}

// TestParallelOptInBypassesSerialization is the per-skill opt-in (architect
// requirement 4): when the deployment predicate marks a tool parallel-safe, calls
// do NOT serialize — two acquire the same session concurrently without one waiting
// on the other. The predicate is a deployment seam, never the caller.
func TestParallelOptInBypassesSerialization(t *testing.T) {
	parallelSafe := func(tool string) bool { return tool == "parallel-tool" }
	s := NewSerializer(16, parallelSafe)

	// Hold a parallel-safe slot; a second parallel-safe acquire must NOT block on it.
	rel0, err := s.Acquire("sess", "parallel-tool")
	if err != nil {
		t.Fatalf("acquire 0: %v", err)
	}
	defer rel0()

	got := make(chan struct{})
	go func() {
		rel, aerr := s.Acquire("sess", "parallel-tool")
		if aerr == nil {
			rel()
		}
		close(got)
	}()
	select {
	case <-got:
		// Good: the parallel-safe call did not wait on the held slot.
	case <-time.After(1 * time.Second):
		t.Fatal("a parallel-opted-in tool must not serialize behind another call")
	}

	// And a sequential (non-opted) tool on the same session DOES serialize: with a
	// slot held, a sequential acquire blocks until release.
	relSeq, err := s.Acquire("sess", "sequential-tool")
	if err != nil {
		t.Fatalf("seq acquire 0: %v", err)
	}
	blocked := make(chan struct{})
	go func() {
		rel, aerr := s.Acquire("sess", "sequential-tool")
		if aerr == nil {
			rel()
		}
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("a sequential tool must serialize behind a held slot, but it did not block")
	case <-time.After(100 * time.Millisecond):
		// Good: it is blocked as expected.
	}
	relSeq() // release; the blocked sequential call now proceeds
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("the sequential call did not proceed after release")
	}
}

// TestDifferentSessionsDoNotBlockEachOther — serialization is PER session: a held
// slot on session A must not delay a call on session B.
func TestDifferentSessionsDoNotBlockEachOther(t *testing.T) {
	s := NewSerializer(16, nil)
	relA, err := s.Acquire("A", "tool")
	if err != nil {
		t.Fatalf("acquire A: %v", err)
	}
	defer relA()

	done := make(chan struct{})
	go func() {
		rel, aerr := s.Acquire("B", "tool")
		if aerr == nil {
			rel()
		}
		close(done)
	}()
	select {
	case <-done:
		// Good: session B proceeded despite A being held.
	case <-time.After(1 * time.Second):
		t.Fatal("a call on session B must not block on a held slot of session A")
	}
}
