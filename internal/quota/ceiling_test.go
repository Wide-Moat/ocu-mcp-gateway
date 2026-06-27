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

// TestCeilingConcurrentAcquireRespectsLimit drives concurrent acquires and
// asserts no more than `limit` ever hold a slot at once (the check-and-increment
// is atomic under the lock).
func TestCeilingConcurrentAcquireRespectsLimit(t *testing.T) {
	const limit = 4
	c := NewCeiling(limit)
	var wg sync.WaitGroup
	var mu sync.Mutex
	maxObserved := 0
	current := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := c.Acquire("hot")
			if err != nil {
				return // refused — correct under saturation
			}
			mu.Lock()
			current++
			if current > maxObserved {
				maxObserved = current
			}
			mu.Unlock()
			// hold briefly
			mu.Lock()
			current--
			mu.Unlock()
			r()
		}()
	}
	wg.Wait()
	if maxObserved > limit {
		t.Fatalf("observed %d concurrent holders, exceeds ceiling %d", maxObserved, limit)
	}
}
