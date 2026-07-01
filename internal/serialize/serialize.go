// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package serialize enforces the per-session tool-call ordering contract
// (NFR-IC-05): tool execution is serialized per session by default — the calls
// of one logical session run in arrival order, one settled before the next
// starts — and parallelism is an explicit opt-in per skill, decided by a
// deployment predicate, never by the caller.
//
// It is a self-cleaning, request-scoped concurrency primitive, NOT a session
// registry: the only state is the set of CURRENTLY-CONTENDED sessions, and an
// entry's lifetime is strictly within the union of its overlapping in-flight
// requests — the last release deletes it, and nothing survives a restart. This
// holds the component-01 "no state that outlives a request" invariant (the
// invariant targets a durable session store / caller data between requests, not
// an ephemeral in-memory serializer; architect ruling P3-A).
//
// The queue per session is BOUNDED: the key is the caller-influenced session
// hint, so an unbounded queue on a caller-supplied key would be a memory-
// exhaustion (DoS) vector. Overflow is a fail-closed REFUSAL with a stable
// reason, not an unbounded park. The serializer sits BEHIND the per-caller
// connection ceiling (quota.Ceiling) in the handler, so total in-flight is
// already bounded before a session queue forms.
package serialize

import (
	"errors"
	"sync"
)

// ErrSerializerFull is the fail-closed refusal when a session's serialization
// queue is at its bound. It is a REFUSAL, not an unbounded park: a caller cannot
// grow a session queue without limit on a caller-supplied key (a memory-
// exhaustion vector), so excess depth is rejected with a stable reason (mapped to
// a leak-free deny at the handler), never queued unboundedly.
var ErrSerializerFull = errors.New("serialize: per-session queue is at its bound, refused (not queued)")

// ParallelPredicate decides whether a given tool-call may run in parallel within
// its session (the per-skill opt-in of NFR-IC-05). It is a DEPLOYMENT/policy seam,
// never the caller: the decision is made from server-side inputs (e.g. a config
// allow-list of parallel-safe tool names), NOT from the request body. The default
// is sequential — a nil predicate serializes everything.
//
// It deliberately invents no skill-manifest format (a skill registry is out of
// v1 scope): it is just a predicate over the tool name the deployment supplies.
type ParallelPredicate func(toolName string) bool

// Serializer serializes tool-calls per session hint. It is safe for concurrent
// use. Each contended session has a gate holding a FIFO ticket line; the gate is
// deleted when its last in-flight/waiting caller releases (self-cleaning), so the
// map holds only currently-contended sessions.
type Serializer struct {
	// maxDepth is the bound on a single session's queue (waiting + in-flight). A
	// non-positive maxDepth disables the bound (used only if an operator opts out);
	// the default is a positive configured value. Serialization order still holds
	// when unbounded — only the refuse-on-overflow guard is disabled.
	maxDepth int

	// parallel is the per-skill parallel opt-in predicate (deployment policy). A
	// nil predicate means "always sequential" — the safe default.
	parallel ParallelPredicate

	mu    sync.Mutex
	gates map[string]*gate
}

// gate is one session's FIFO ticket line. tickets counts total tickets ever
// issued (the next ticket number); serving is the ticket currently allowed to
// proceed; depth is the current waiting+in-flight count (for the bound and for
// self-cleaning). cond signals when serving advances.
type gate struct {
	cond    *sync.Cond
	tickets uint64
	serving uint64
	depth   int
}

// NewSerializer builds a per-session serializer with the given per-session queue
// bound and parallel opt-in predicate. A non-positive maxDepth disables the bound
// (order still holds); a nil predicate serializes everything (the safe default).
func NewSerializer(maxDepth int, parallel ParallelPredicate) *Serializer {
	return &Serializer{
		maxDepth: maxDepth,
		parallel: parallel,
		gates:    make(map[string]*gate),
	}
}

// Acquire reserves the caller's ordered turn for the given session hint and tool
// name, blocking until it is this caller's turn, then returns a release the caller
// MUST call exactly once (defer it) once the call is SETTLED (forwarded, audited,
// and its ack decided — the serializer wraps forward+emit+ack so call N+1 of a
// session cannot overtake the durable record of call N).
//
// If the tool is parallel-opted-in for this deployment (the predicate returns
// true), Acquire admits immediately with a no-op release — no ordering is imposed.
// If the session's queue is already at its bound, Acquire returns ErrSerializerFull
// (fail-closed refusal), never an unbounded park.
func (s *Serializer) Acquire(sessionHint, toolName string) (release func(), err error) {
	// Parallel opt-in (per-skill, deployment policy): bypass serialization.
	if s.parallel != nil && s.parallel(toolName) {
		return func() {}, nil
	}

	s.mu.Lock()
	g := s.gates[sessionHint]
	if g == nil {
		g = &gate{}
		g.cond = sync.NewCond(&s.mu) // shares the Serializer mutex as its locker
		s.gates[sessionHint] = g
	}
	// Bound the queue depth on the caller-supplied key (DoS guard). Overflow is a
	// refusal, not an unbounded park.
	if s.maxDepth > 0 && g.depth >= s.maxDepth {
		// If we just created an empty gate for a refused acquire, drop it so the
		// map does not retain a zero-depth gate.
		if g.depth == 0 {
			delete(s.gates, sessionHint)
		}
		s.mu.Unlock()
		return nil, ErrSerializerFull
	}
	// Take a FIFO ticket and join the line.
	myTicket := g.tickets
	g.tickets++
	g.depth++

	// Wait until it is our ticket's turn. cond.Wait releases and re-acquires s.mu.
	for g.serving != myTicket {
		g.cond.Wait()
	}
	s.mu.Unlock()

	released := false
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if released {
			// Guard against a double release corrupting the line.
			return
		}
		released = true
		// Advance the line and wake the next waiter.
		g.serving++
		g.depth--
		g.cond.Broadcast()
		if g.depth == 0 {
			// Self-clean: no waiting or in-flight caller remains for this session,
			// so drop the gate. The map holds only currently-contended sessions;
			// nothing outlives the union of overlapping in-flight requests.
			delete(s.gates, sessionHint)
		}
	}, nil
}

// Contended returns the number of sessions with a live gate (waiting or in-flight
// callers). It is exposed for the self-cleaning red-probe and a diagnostic gauge;
// a correctly self-cleaning serializer returns to zero once all calls drain.
func (s *Serializer) Contended() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.gates)
}
