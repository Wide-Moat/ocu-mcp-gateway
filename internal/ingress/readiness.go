// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import "net/http"

// healthzPath is the readiness probe path. It is served OPEN (no caller
// credential): an orchestrator probe has no sk-ocu- key, so requiring one would
// make readiness unprobeable. It carries no session data and mutates nothing.
const healthzPath = "/healthz"

// healthPath is the LIVENESS preflight path the MCP client probes before
// initialize (the upstream monolith served GET /health -> {"status":"healthy"}).
// It is unconditional liveness (not readiness) and unauthenticated, so a drop-in
// gateway answers the client's preflight with no tool-code change.
const healthPath = "/health"

// ReadinessMux wraps the authenticating MCP handler with an unauthenticated
// /healthz readiness gate. Every path other than /healthz falls through to the
// wrapped handler unchanged, so the tool-call surface is untouched; /healthz
// answers 200 iff the readiness predicate reports ready, else 503.
//
// The predicate is the boot Sequencer's readiness (boot-set loaded AND the
// listener bound), so a container `depends_on: service_healthy` becomes an honest
// gate: a dependent service starts only once this gateway can actually accept
// traffic, closing the liveness-only start race.
type ReadinessMux struct {
	mcp   http.Handler
	ready func() bool
}

// NewReadinessMux builds the mux from the wrapped MCP handler and the readiness
// predicate. A nil handler or a nil predicate is a fail-closed construction error
// (returns nil) rather than a mux that would panic on a request or report a fixed
// readiness — the composition root checks for nil.
func NewReadinessMux(mcp http.Handler, ready func() bool) *ReadinessMux {
	if mcp == nil || ready == nil {
		return nil
	}
	return &ReadinessMux{mcp: mcp, ready: ready}
}

// ServeHTTP serves /healthz from the readiness predicate and routes everything
// else to the wrapped MCP handler.
func (m *ReadinessMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == healthPath {
		// LIVENESS preflight — the upstream monolith served GET /health ->
		// {"status":"healthy"}, and the MCP client (e.g. the OpenWebUI tool) probes
		// it FIRST, before initialize. It is UNCONDITIONAL (the process is up, so it
		// answers 200 even before the boot-set loads — that is liveness, not
		// readiness) and UNAUTHENTICATED (the preflight carries no key). It surfaces
		// only a static status token: no tool list, no server version, no boot state,
		// so it is not a reconnaissance surface. Served gateway-local, never
		// forwarded. A drop-in gateway must answer it so the client's preflight
		// passes with no tool-code change.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}` + "\n"))
		return
	}
	if r.URL.Path == healthzPath {
		if m.ready() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready\n"))
			return
		}
		// Not ready: the boot-set has not loaded or the listener is not up. A 503
		// is the readiness handler reporting not-ready, which the probe turns into
		// a non-zero exit (unhealthy).
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
		return
	}
	m.mcp.ServeHTTP(w, r)
}
