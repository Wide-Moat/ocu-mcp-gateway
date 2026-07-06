// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHealthCheckProbeGreenOn200 asserts the probe returns nil (exit 0) when the
// daemon's /healthz answers 200 — a ready gateway.
func TestHealthCheckProbeGreenOn200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("probe hit %q, want /healthz", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := healthCheckProbe(context.Background(), strings.TrimPrefix(srv.URL, "http://")); err != nil {
		t.Fatalf("probe against a 200 /healthz returned error, want nil (healthy): %v", err)
	}
}

// TestHealthCheckProbeRedOn503 asserts the probe returns a non-nil error (non-zero
// exit) when /healthz answers 503 — a not-ready gateway (boot-set not loaded).
// This is the readiness red an orchestrator must see; a liveness-only probe that
// ignored the status would fake-green here.
func TestHealthCheckProbeRedOn503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if err := healthCheckProbe(context.Background(), strings.TrimPrefix(srv.URL, "http://")); err == nil {
		t.Fatal("probe against a 503 /healthz returned nil, want a non-nil error (not-ready is unhealthy)")
	}
}

// TestHealthCheckProbeRedOnRefused asserts a refused dial (no daemon bound yet) is
// unhealthy — the fresh-container case before the listener is up.
func TestHealthCheckProbeRedOnRefused(t *testing.T) {
	// 127.0.0.1:1 refuses immediately (no listener).
	if err := healthCheckProbe(context.Background(), "127.0.0.1:1"); err == nil {
		t.Fatal("probe against a refused dial returned nil, want a non-nil error (daemon not bound)")
	}
}

// TestHealthCheckProbeRequiresListen asserts an empty listen address is a
// non-nil error: the probe must dial the SAME address the daemon serves, so the
// invocation has to name it (the compose/Dockerfile probe passes -listen).
func TestHealthCheckProbeRequiresListen(t *testing.T) {
	if err := healthCheckProbe(context.Background(), ""); err == nil {
		t.Fatal("probe with an empty listen address returned nil, want a non-nil error (no address to dial)")
	}
}
