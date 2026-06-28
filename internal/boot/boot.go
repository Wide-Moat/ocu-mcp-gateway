// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package boot is the load-before-bind sequencer for ocu-mcp-gatewayd. It owns
// the one boot ordering invariant the gateway must never violate: the
// authentication material (the Control-owned boot-set) and the constraint-profile
// validator are loaded and ready BEFORE any listener binds, and a material that
// cannot be loaded at boot is fail-closed — the daemon stays not-ready, binds
// nothing, and admits no request (invariant #9, NFR-SEC-04).
//
// Why this is load-bearing: the gateway authenticates every caller in-process
// against boot-loaded material (never a per-request Control lookup). If a
// listener could bind before that material loaded, a request arriving in the
// gap would face an empty key set — which must refuse fail-closed, never
// admit-all. Binding strictly after the material is ready makes the
// "no request before the gate is up" property an ordering fact, not a per-handler
// race. The sequencer binds nothing itself; the bind hook runs inside the
// readiness callback, wired in cmd/ocu-mcp-gatewayd.
//
// The sequencer is a thin policy layer over the auth.KeySetLoader seam: it opens
// no socket and reads no clock directly. Its collaborator is injected
// already-built from cmd/, so a unit test exercises it with a fake loader.
package boot

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// ErrNotReady is the fail-closed boot abort: the authentication material could
// not be loaded (the boot-set was unreadable or empty at boot), so the daemon
// must not bind a listener and must not admit a request. Callers match it with
// errors.Is (invariant #9).
var ErrNotReady = errors.New("boot: authentication material not loaded; gateway not ready (fail-closed)")

// Sequencer orders the load-before-bind boot. It holds the loaded key set behind
// a ready flag; Ready reports false until Load succeeds, and the cmd bind hook
// gates on Ready so a socket is reachable only after the material is loaded.
type Sequencer struct {
	loader auth.KeySetLoader
	keys   atomic.Pointer[auth.KeySet]
	ready  atomic.Bool
}

// NewSequencer builds the sequencer over the boot-set loader. A nil loader is a
// construction error: the gateway cannot authenticate without a material source,
// and a nil loader would be an admit-nothing-or-everything ambiguity at boot.
func NewSequencer(loader auth.KeySetLoader) (*Sequencer, error) {
	if loader == nil {
		return nil, errors.New("boot: NewSequencer requires a non-nil KeySetLoader (fail-closed)")
	}
	return &Sequencer{loader: loader}, nil
}

// Load loads the boot-set and flips readiness. On a loader error it returns
// ErrNotReady (wrapping the cause) and leaves readiness false, so the caller
// aborts boot before binding any listener. It is the single transition from
// not-ready to ready; the bind hook must run only after it returns nil.
func (s *Sequencer) Load(ctx context.Context) error {
	ks, err := s.loader.Load(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotReady, err)
	}
	if ks == nil {
		return fmt.Errorf("%w: loader returned a nil key set", ErrNotReady)
	}
	s.keys.Store(&ks)
	s.ready.Store(true)
	return nil
}

// Ready reports whether the boot-set has been loaded. The cmd bind hook gates on
// it: a listener binds only when Ready is true, so no socket is reachable in the
// pre-load window.
func (s *Sequencer) Ready() bool {
	return s.ready.Load()
}

// KeySet returns the loaded boot-set, or an error if called before a successful
// Load. The authenticator the handler uses is built from this set; requesting it
// before readiness is a fail-closed error, never a nil-set admit.
func (s *Sequencer) KeySet() (auth.KeySet, error) {
	if !s.ready.Load() {
		return nil, ErrNotReady
	}
	p := s.keys.Load()
	if p == nil {
		return nil, ErrNotReady
	}
	return *p, nil
}
