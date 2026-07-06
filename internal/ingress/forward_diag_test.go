// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// A forward refusal returns a leak-free 502 to the caller, but the OPERATOR needs
// the exact cause. In a distroless image with no other logging, a 502 "forward
// refused" with an empty log is unactionable — an observability gap that has bitten
// the live stack more than once (a mount-scope admission fail, a wire drift, a dial
// error all surface identically). The handler logs the exact forward error to the
// diagnostic writer on a forward failure, so a single run reveals the real cause,
// while the CALLER-facing response stays leak-free.

// TestForwardFailIsLogged asserts that when the forwarder fails, the exact error
// is written to the diagnostic sink — so the operator sees WHY the 502 happened,
// not just that it did.
func TestForwardFailIsLogged(t *testing.T) {
	var buf bytes.Buffer
	restore := swapForwardDiag(&buf)
	defer restore()

	// A forwarder that fails with a specific, cause-bearing error (as the real one
	// does: it wraps ErrForwardFailed with the endpoint/path/status/admission cause).
	fwd := &recordingForwarder{err: forward.ErrForwardFailed}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", validToolCall)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("a forward failure must still be a 502 to the caller, got %d", rec.Code)
	}
	logged := buf.String()
	if logged == "" {
		t.Fatal("a forward failure logged NOTHING to the diagnostic sink; the operator cannot tell why the 502 happened (observability gap)")
	}
	if !strings.Contains(logged, "forward") {
		t.Fatalf("the diagnostic log does not carry the forward error cause; got %q", logged)
	}
}

// TestForwardDiagIsLeakFree asserts the diagnostic log NEVER contains the caller's
// sk-ocu- bearer or the service token — the operator log is not a credential leak.
// The handler must log the forward ERROR (which carries no secret), never the
// request headers or the credential.
func TestForwardDiagIsLeakFree(t *testing.T) {
	var buf bytes.Buffer
	restore := swapForwardDiag(&buf)
	defer restore()

	fwd := &recordingForwarder{err: forward.ErrForwardFailed}
	h := acceptingHandler(t, fwd, nil)

	// The caller presents a distinctive bearer; it must NOT appear in the diag log.
	_ = post(h, pinnedProtocolVersion, "sk-ocu-SECRET-CALLER-KEY-123456789012", validToolCall)

	logged := buf.String()
	if strings.Contains(logged, "sk-ocu-SECRET-CALLER-KEY-123456789012") {
		t.Fatalf("the diagnostic log leaked the caller bearer: %q", logged)
	}
	if strings.Contains(strings.ToLower(logged), "authorization") || strings.Contains(strings.ToLower(logged), "bearer ") {
		t.Fatalf("the diagnostic log carries an Authorization/bearer field: %q", logged)
	}
}

// TestForwardSuccessLogsNothing asserts a SUCCESSFUL forward writes nothing to the
// diagnostic sink — the diag log is for failures only, not per-request noise.
func TestForwardSuccessLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	restore := swapForwardDiag(&buf)
	defer restore()

	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", validToolCall)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid forward must succeed, got %d", rec.Code)
	}
	if buf.Len() != 0 {
		t.Fatalf("a successful forward wrote to the diagnostic sink (%q); the diag log is failures-only", buf.String())
	}
}
