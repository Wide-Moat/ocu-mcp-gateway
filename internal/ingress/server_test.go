// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

// TestHTTPServerBoundedPosture asserts every read/idle bound is non-zero on the
// constructed server (the bounded-read posture is load-bearing, not incidental).
func TestHTTPServerBoundedPosture(t *testing.T) {
	s := NewServer(nil, http.NewServeMux())
	srv := s.httpServer(context.Background())
	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout must be non-zero (Slowloris guard)")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout must be non-zero (slow-body guard)")
	}
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout must be non-zero (parked-conn reaper)")
	}
}

func TestServeWithoutListenerFails(t *testing.T) {
	s := NewServer(nil, http.NewServeMux())
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("Serve with no bound listener must error")
	}
}

// TestServeServesAndShutsDown binds a loopback listener, serves through a real
// handler, hits it once, then cancels the context and asserts a clean shutdown.
func TestServeServesAndShutsDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h, err := NewHandler(
		acceptAuth{caller: auth.Caller{KeyID: "k1"}},
		newValidator(t),
		&recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}},
		quota.NewCeiling(64),
		NewOriginPolicy(nil),
		newEmitter(t),
		newSerializer(t),
	)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	srv := NewServer(ln, h)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	// Give the server a moment to start, then make a request.
	addr := ln.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		// An AUTHENTICATED tools/call with NO protocol-version header. Auth is the
		// outermost boundary, so the bearer is required to reach the version pin at
		// all (a no-bearer request 401s first). This asserts the load-bearing
		// invariant — a forwarded method with no negotiated version is refused 400,
		// never silently downgraded — rather than the pre-auth ordering accident the
		// old assertion encoded (initialize is version-exempt; tools/call is not).
		req, rerr := http.NewRequest(http.MethodPost, "http://"+addr+"/",
			body(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}}`))
		if rerr != nil {
			t.Fatalf("build request: %v", rerr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer sk-ocu-test")
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	// Authenticated tools/call, no protocol-version header → 400 (the version pin
	// fires for every forwarded method; only initialize is exempt).
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("authenticated tools/call with missing version should be 400, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error on clean shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancel")
	}
}

// CR fix: Serve with a nil handler is refused (would fall back to DefaultServeMux).
func TestServeNilHandlerFailsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	s := NewServer(ln, nil)
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("Serve with a nil handler must fail closed (no DefaultServeMux fallback)")
	}
}
