// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package ingress is the MCP gateway's inbound edge (F1): the listener that
// terminates MCP tool-calls from external callers, authenticates the caller as a
// relying party, validates the tool-call against the OCU constraint profile, and
// hands a validated session request to the forward leg (F5). It mounts ONLY the
// MCP surface — there is no operator/lifecycle/kill-switch route here, and this
// package has no import path to one (invariant #4, code half, enforced by
// importgraph_test.go).
//
// The bounded-read posture (header/read/idle timeouts + a pre-auth body cap)
// mirrors the sibling control plane's gateway ingress: the request surface is
// DoS-bounded BEFORE auth (invariant #8 / NFR-SEC-53 and the Slowloris guard),
// so an oversized or slow body is refused without being read whole into memory
// and before any identity check runs.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	// readHeaderTimeout bounds how long the server waits for request headers,
	// closing a connection that dribbles them (a Slowloris guard).
	readHeaderTimeout = 10 * time.Second
	// readTimeout bounds the whole-request read (headers + body), defeating a
	// slow body that dribbles under the header timeout. The MCP surface is small
	// JSON-RPC, not bulk data.
	readTimeout = 30 * time.Second
	// idleTimeout reaps a parked keep-alive connection rather than holding it
	// open indefinitely.
	idleTimeout = 120 * time.Second
	// maxBodyBytes caps the request body the decoder admits before refusal — a
	// pre-auth memory / slow-body guard (invariant #8). It must be at least the
	// largest profile-permitted message (maxToolArgumentsBytes is 256KiB) plus
	// JSON-RPC envelope overhead, so a legitimate maximal tool-call is not cut
	// off at the transport before the profile validator can size-check it. The
	// profile validator applies the tighter per-kind ceiling after decode; this
	// is the coarse pre-auth transport bound.
	maxBodyBytes = 512 << 10 // 512KiB
)

// channelKey is the unexported context key marking that a request arrived on the
// MCP gateway ingress. A distinct unexported type means no other package can
// collide with or read the key.
type channelKey struct{}

// Server runs the MCP gateway HTTP transport on a bound listener until its
// context is cancelled. It is constructed by the boot wiring AFTER the auth
// boot-set and profile validator are loaded, and only from the readiness hook,
// so the socket exists strictly after the gateway can fail-closed-validate every
// request (invariant #9). It mounts no operator route.
type Server struct {
	handler http.Handler
	ln      net.Listener
}

// NewServer builds the gateway server over a bound listener and request handler.
// The bounded read/idle posture is applied in httpServer at Serve time so the
// bound listener is owned in one place.
func NewServer(ln net.Listener, handler http.Handler) *Server {
	return &Server{handler: handler, ln: ln}
}

// httpServer constructs the *http.Server with the bounded posture. It is split
// from Serve so a unit test can assert ReadHeaderTimeout/ReadTimeout/IdleTimeout
// are all non-zero on the returned server (the bounded-read posture is
// load-bearing, not incidental).
func (s *Server) httpServer(ctx context.Context) *http.Server {
	return &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		ConnContext: func(connCtx context.Context, _ net.Conn) context.Context {
			return context.WithValue(connCtx, channelKey{}, true)
		},
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
}

// Serve runs the bound listener until ctx is cancelled. It returns nil on a
// clean ctx-driven shutdown and the server error otherwise.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("ingress: Serve called without a bound listener")
	}
	srv := s.httpServer(ctx)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ingress: serve: %w", err)
	}
	return nil
}
