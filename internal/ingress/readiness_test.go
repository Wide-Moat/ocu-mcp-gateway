// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestHealthzReflectsReadiness asserts /healthz answers 503 while the readiness
// predicate is false and 200 once it flips true — the honest readiness gate a
// container `depends_on: service_healthy` relies on. A liveness-only "always 200"
// would let a dependent service start before the gateway can accept traffic, the
// exact start race this closes.
func TestHealthzReflectsReadiness(t *testing.T) {
	var ready atomic.Bool // starts false: boot-set not loaded yet
	mux := NewReadinessMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("/healthz must not fall through to the MCP handler")
	}), ready.Load)

	// Not ready → 503.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz before ready = %d, want 503", rec.Code)
	}

	// Flip ready → 200.
	ready.Store(true)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz after ready = %d, want 200", rec.Code)
	}
}

// TestHealthzIsUnauthenticated asserts the probe path needs no caller credential:
// a bare GET /healthz (no Authorization, no MCP-Protocol-Version) is served by the
// readiness gate, never routed into the authenticating MCP handler. A probe has no
// sk-ocu- key, so requiring one would make readiness unprobeable.
func TestHealthzIsUnauthenticated(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	reachedMCP := false
	mux := NewReadinessMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reachedMCP = true
	}), ready.Load)

	rec := httptest.NewRecorder()
	// No Authorization header, no protocol-version header — a raw orchestrator probe.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if reachedMCP {
		t.Fatal("/healthz was routed into the MCP handler; the probe path must be unauthenticated and never reach auth")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz (ready, no creds) = %d, want 200", rec.Code)
	}
}

// TestNonHealthzRoutesToMCPHandler asserts every non-/healthz path still reaches
// the wrapped MCP handler unchanged — the readiness mux adds a probe path, it does
// not shadow or alter the tool-call surface.
func TestNonHealthzRoutesToMCPHandler(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	reachedMCP := false
	mux := NewReadinessMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reachedMCP = true
		w.WriteHeader(http.StatusTeapot) // a sentinel the readiness gate would never write
	}), ready.Load)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if !reachedMCP {
		t.Fatal("a non-/healthz request did not reach the wrapped MCP handler")
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("wrapped MCP handler response = %d, want the sentinel 418 (mux altered the tool-call surface)", rec.Code)
	}
}

// TestNewReadinessMuxFailsClosedOnNilSeams asserts construction refuses a nil MCP
// handler or a nil readiness predicate rather than silently building a mux that
// would panic or report a fixed readiness — fail-closed at composition.
func TestNewReadinessMuxFailsClosedOnNilSeams(t *testing.T) {
	if NewReadinessMux(nil, func() bool { return true }) != nil {
		t.Fatal("NewReadinessMux(nil handler) must return nil (fail-closed)")
	}
	if NewReadinessMux(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil) != nil {
		t.Fatal("NewReadinessMux(nil predicate) must return nil (fail-closed)")
	}
}
