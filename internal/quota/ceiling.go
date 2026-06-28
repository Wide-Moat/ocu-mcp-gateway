// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package quota enforces the per-caller connection ceiling (invariant #8,
// NFR-SEC-53): at most a configured number of concurrent in-flight requests per
// audience-validated caller, with excess REFUSED — never queued — so one caller
// cannot exhaust the listener's fd table and starve the others. The ceiling is
// keyed on the RESOLVED caller identity (the auth seam's KeyID), so it runs after
// authentication: an unauthenticated flood is already refused at the auth
// boundary, and the ceiling fairness applies among authenticated callers.
package quota

import (
	"errors"
	"sync"
)

// ErrCeilingExceeded is the refusal returned when a caller is already at its
// concurrent-connection ceiling. It is a REFUSAL, not a queue signal: the caller
// is rejected immediately (mapped to HTTP 429) rather than parked, so excess load
// cannot consume an fd slot or a goroutine (NFR-SEC-53).
var ErrCeilingExceeded = errors.New("quota: per-caller connection ceiling exceeded, refused (not queued)")

// Ceiling tracks concurrent in-flight requests per caller key and refuses a
// caller that is already at its limit. It is safe for concurrent use. The count
// is decremented when a request releases, so a caller's slots free as its
// requests complete — the ceiling bounds CONCURRENCY, not lifetime request count.
type Ceiling struct {
	// limit is the max concurrent in-flight requests per caller. A non-positive
	// limit disables the ceiling (every acquire succeeds) — used only when an
	// operator explicitly opts out; the default is a positive configured value.
	limit int

	mu     sync.Mutex
	counts map[string]int
}

// NewCeiling builds a per-caller ceiling with the given concurrent limit. A
// non-positive limit is treated as "ceiling disabled" rather than "admit nothing"
// — a zero limit must not lock out every caller; an operator disables the ceiling
// deliberately, and the fail-closed posture lives at the auth boundary, not here.
func NewCeiling(limit int) *Ceiling {
	return &Ceiling{limit: limit, counts: make(map[string]int)}
}

// Acquire reserves one in-flight slot for callerKey, or returns
// ErrCeilingExceeded if the caller is already at the limit. On success the caller
// MUST call the returned release exactly once (defer it) to free the slot. The
// check-and-increment is atomic under the lock, so two concurrent acquires for
// the same caller cannot both slip past the limit.
func (c *Ceiling) Acquire(callerKey string) (release func(), err error) {
	if c.limit <= 0 {
		// Ceiling disabled: admit, with a no-op release.
		return func() {}, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[callerKey] >= c.limit {
		// Refuse — do NOT queue. The caller is at its ceiling; excess is rejected
		// immediately so it consumes no fd slot.
		return nil, ErrCeilingExceeded
	}
	c.counts[callerKey]++
	released := false
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if released {
			// Guard against a double release corrupting the count.
			return
		}
		released = true
		c.counts[callerKey]--
		if c.counts[callerKey] <= 0 {
			// Drop the entry at zero so the map does not grow unbounded with
			// one entry per caller ever seen (a slow memory-exhaustion vector).
			delete(c.counts, callerKey)
		}
	}, nil
}

// InFlight returns the current in-flight count for callerKey. It is exposed for
// the chaos-test and a diagnostic gauge; it takes the lock so it is a consistent
// read.
func (c *Ceiling) InFlight(callerKey string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[callerKey]
}
