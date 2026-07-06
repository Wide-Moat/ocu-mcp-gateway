// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// The -health-check sub-command: a thin client that dials the already-running
// daemon's /healthz over the SAME MCP listener the serving path binds, and exits 0
// iff the daemon reports ready. It reuses the daemon binary as its own probe, so a
// distroless image (no shell, no curl) still has a container/compose/k8s probe.
// This mirrors the ocu-control health-check (which dials an operator Unix socket);
// the gateway's MCP listener is a TCP address, so the probe dials TCP.
//
// It is a CLIENT only: it constructs no boot state, no listener, no forwarder — it
// opens one connection to the address the serving daemon already bound and reads
// one response. A refused dial (no daemon, or the listener not yet up), a non-200
// (the readiness enum has not flipped — boot-set not loaded), or a timeout is a
// non-nil error the caller maps to a non-zero exit: exactly the red a readiness
// probe must surface.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// healthCheckTimeout bounds the whole probe — dial, request, and response read. A
// healthy daemon answers /healthz from an in-memory readiness flag essentially
// instantly; a probe that cannot get an answer in this window is reporting an
// unhealthy daemon. The orchestrator's own probe timeout (compose timeout: 3s)
// sits at or above this.
const healthCheckTimeout = 3 * time.Second

// errHealthCheckNoListen is returned when -listen was not supplied to the
// health-check invocation, so there is no address to dial. Every shipped probe
// passes -listen alongside -health-check precisely so the probe dials the SAME
// address the serving container bound.
var errHealthCheckNoListen = errors.New("health-check: -listen is required so the probe dials the same address the daemon serves")

// healthCheckProbe dials the daemon's /healthz over TCP at the listen address (the
// SAME flag the serving path binds) and returns nil iff the daemon answers 200. It
// boots nothing: it is a one-connection HTTP client. A missing address, a
// refused/failed dial, a non-200, or a timeout is a non-nil error the caller turns
// into a non-zero exit.
func healthCheckProbe(ctx context.Context, listenAddr string) error {
	if listenAddr == "" {
		return errHealthCheckNoListen
	}

	probeCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
	}

	url := "http://" + listenAddr + "/healthz"
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("health-check: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Connection refused (no daemon / listener not yet up), a dial timeout, or
		// any transport failure is an unhealthy verdict.
		return fmt.Errorf("health-check: dial /healthz at %q: %w", listenAddr, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		// A non-200 is the readiness handler reporting not-ready (503): a red probe,
		// not a daemon-absent error.
		return fmt.Errorf("health-check: /healthz returned %d, want 200", resp.StatusCode)
	}
	return nil
}
