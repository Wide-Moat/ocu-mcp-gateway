// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package quota

import (
	"errors"
	"sync"
	"testing"
)

func TestCeilingRefusesAtLimit(t *testing.T) {
	c := NewCeiling(2)
	r1, err := c.Acquire("caller")
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	r2, err := c.Acquire("caller")
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	// Third must be refused — not queued.
	if _, err := c.Acquire("caller"); !errors.Is(err, ErrCeilingExceeded) {
		t.Fatalf("third acquire must be refused, got %v", err)
	}
	// Releasing one frees a slot.
	r1()
	r3, err := c.Acquire("caller")
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	r2()
	r3()
	if got := c.InFlight("caller"); got != 0 {
		t.Fatalf("in-flight should be 0 after all releases, got %d", got)
	}
}

func TestCeilingIsPerCaller(t *testing.T) {
	c := NewCeiling(1)
	rA, err := c.Acquire("A")
	if err != nil {
		t.Fatalf("A acquire: %v", err)
	}
	defer rA()
	// A is saturated, but B has its own slot.
	rB, err := c.Acquire("B")
	if err != nil {
		t.Fatalf("B must have its own ceiling, got %v", err)
	}
	defer rB()
	if _, err := c.Acquire("A"); !errors.Is(err, ErrCeilingExceeded) {
		t.Fatalf("A is saturated, second A must be refused, got %v", err)
	}
}

func TestCeilingDisabledWhenNonPositive(t *testing.T) {
	c := NewCeiling(0)
	for i := 0; i < 100; i++ {
		if _, err := c.Acquire("x"); err != nil {
			t.Fatalf("a disabled ceiling must admit all, got %v at %d", err, i)
		}
	}
}

func TestCeilingDoubleReleaseSafe(t *testing.T) {
	c := NewCeiling(1)
	r, err := c.Acquire("x")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	r()
	r() // double release must not underflow the count
	if got := c.InFlight("x"); got != 0 {
		t.Fatalf("double release corrupted count: %d", got)
	}
	// A fresh acquire still works.
	if _, err := c.Acquire("x"); err != nil {
		t.Fatalf("acquire after double release: %v", err)
	}
}

// TestCeilingConcurrentAcquireRespectsLimit drives concurrent acquires that HOLD
// their slot until released, so the ceiling is genuinely under pressure (CR fix:
// the earlier version acquired→incremented→decremented→released under one lock,
// so slots freed instantly and maxObserved was ~1 — a vacuous test that passed
// even with a broken ceiling). Here the goroutines block on a barrier while
// holding, so EXACTLY `limit` acquire and the rest are refused; only after the
// holders are counted does the test release them. This presses the ceiling for
// real: defeating the limit lets more than `limit` acquire concurrently → RED.
func TestCeilingConcurrentAcquireRespectsLimit(t *testing.T) {
	const limit = 4
	const racers = 50
	c := NewCeiling(limit)

	var mu sync.Mutex
	holders := 0                             // currently-holding goroutines
	maxObserved := 0                         // peak concurrent holders
	refused := 0                             // goroutines the ceiling refused
	hold := make(chan struct{})              // closed to release all holders
	attempted := make(chan struct{}, racers) // one per goroutine that finished its Acquire attempt

	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.Acquire("hot")
			attempted <- struct{}{} // signal the attempt resolved (admit OR refuse)
			if err != nil {
				mu.Lock()
				refused++
				mu.Unlock()
				return
			}
			mu.Lock()
			holders++
			if holders > maxObserved {
				maxObserved = holders
			}
			mu.Unlock()
			<-hold // HOLD the slot until EVERY racer has attempted
			mu.Lock()
			holders--
			mu.Unlock()
			r()
		}()
	}

	// Wait until EVERY racer has resolved its Acquire (admitted holders are still
	// holding, the rest are refused) BEFORE releasing the barrier. This guarantees
	// the `limit` holders are concurrent and the refusals already happened, so a
	// defeated ceiling (which would let >limit hold at once) is caught.
	for i := 0; i < racers; i++ {
		<-attempted
	}
	close(hold)
	wg.Wait()

	if maxObserved != limit {
		t.Fatalf("peak concurrent holders = %d, want exactly the ceiling %d", maxObserved, limit)
	}
	if refused != racers-limit {
		t.Fatalf("expected %d refusals (racers - limit), got %d", racers-limit, refused)
	}
}
