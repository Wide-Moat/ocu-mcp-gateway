// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// GET /health is the LIVENESS preflight the upstream monolith served
// (computer-use-server app.py: @app.get("/health") -> {"status":"healthy"}) and
// the OpenWebUI tool probes FIRST, before POST /mcp initialize. A drop-in gateway
// must answer it so the tool's preflight passes without a tool-code change (the
// owner's drop-in requirement). It is DISTINCT from /healthz: /health is
// unconditional liveness (the process is up, so it answers 200 even before the
// boot-set loads), while /healthz is readiness (200 iff seq.Ready()). Both are
// unauthenticated (a preflight carries no key) and neither is forwarded.

// TestHealthIsLivenessAlways200 asserts GET /health returns 200 with the
// status:healthy body EVEN WHEN the gateway is not yet ready — it is a liveness
// probe (the process is up), not readiness. The upstream server answered it
// unconditionally; the tool only needs "container up / URL right" here.
func TestHealthIsLivenessAlways200(t *testing.T) {
	var ready atomic.Bool // NOT ready — boot-set not loaded
	mux := NewReadinessMux(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatalf("/health must not fall through to the MCP handler")
	}), ready.Load)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/health = %d, want 200 (liveness is unconditional, unlike readiness)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"healthy"`) {
		t.Fatalf("/health body = %q, want it to contain {\"status\":\"healthy\"} (mirrors the upstream server)", rec.Body.String())
	}
}

// TestHealthIsUnauthenticated asserts GET /health needs no caller credential — the
// tool's preflight runs before any key and must never be routed into the
// authenticating MCP handler.
func TestHealthIsUnauthenticated(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	reachedMCP := false
	mux := NewReadinessMux(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reachedMCP = true
	}), ready.Load)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if reachedMCP {
		t.Fatal("/health was routed into the MCP handler; the preflight path must be unauthenticated")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("/health (no creds) = %d, want 200", rec.Code)
	}
}

// TestHealthzStillReadiness asserts adding /health did not change /healthz: it is
// still readiness (503 while not ready, 200 once ready) — the two paths keep their
// distinct semantics.
func TestHealthzStillReadiness(t *testing.T) {
	var ready atomic.Bool // not ready
	mux := NewReadinessMux(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), ready.Load)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz before ready = %d, want 503 (still readiness, not liveness)", rec.Code)
	}

	ready.Store(true)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz after ready = %d, want 200", rec.Code)
	}
}
