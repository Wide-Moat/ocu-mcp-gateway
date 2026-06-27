// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

// TestMethodNotAllowed covers the non-POST rejection path.
func TestMethodNotAllowed(t *testing.T) {
	h := acceptingHandler(t, &recordingForwarder{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET must be 405, got %d", rec.Code)
	}
}

// TestHappyPath200 covers the success path (writeResult) end-to-end through the
// handler: auth → ceiling → validate → forward → 200 with the result relayed.
func TestHappyPath200(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{
		Correlation: "corr-123",
		Result:      []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[]}}`),
	}}
	h := acceptingHandler(t, fwd, nil)
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", validToolCall)
	if rec.Code != http.StatusOK {
		t.Fatalf("happy path must be 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("MCP-Correlation-Id"); got != "corr-123" {
		t.Errorf("correlation id should be relayed, got %q", got)
	}
	if !strings.Contains(rec.Body.String(), `"result"`) {
		t.Errorf("result should be relayed, got %q", rec.Body.String())
	}
}

// TestHappyPath200EmptyResult covers writeResult's empty-result branch.
func TestHappyPath200EmptyResult(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{}}
	h := acceptingHandler(t, fwd, nil)
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", validToolCall)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty-result happy path must be 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"jsonrpc"`) {
		t.Errorf("an empty result should still relay a JSON-RPC envelope, got %q", rec.Body.String())
	}
}

// TestOversizeBody413 covers the readBounded oversize path → writeDecodeError 413.
func TestOversizeBody413(t *testing.T) {
	h := acceptingHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, quota.NewCeiling(64))
	// A body larger than maxBodyBytes triggers the MaxBytesReader cap.
	huge := strings.Repeat("a", maxBodyBytes+1024)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"pad":"` + huge + `"}}}`
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body must be 413, got %d", rec.Code)
	}
}

// TestProfileInvalidArguments covers a profile-invalid body (over-size arguments)
// hitting writeProfileDeny's over-size branch via the validator.
func TestProfileDenyMalformed(t *testing.T) {
	h := acceptingHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, nil)
	// Well-formed envelope but a body that fails the base structural pass (no
	// method) → profile deny → 400.
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", `{"jsonrpc":"2.0","id":1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a structurally-invalid tool-call must be 400, got %d", rec.Code)
	}
}
