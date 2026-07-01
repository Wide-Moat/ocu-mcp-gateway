// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

// handlerWithOrigin wires a handler with the given Origin allowlist for the
// DNS-rebinding tests.
func handlerWithOrigin(t *testing.T, allowed []string) *Handler {
	t.Helper()
	h, err := NewHandler(
		acceptAuth{caller: auth.Caller{KeyID: "k1"}},
		newValidator(t),
		&recordingForwarder{err: forward.ErrForwardFailed},
		quota.NewCeiling(64),
		NewOriginPolicy(allowed),
		newEmitter(t),
		newSerializer(t),
	)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return h
}

func TestOriginPolicyAllows(t *testing.T) {
	p := NewOriginPolicy([]string{"https://app.example.com"})
	cases := map[string]bool{
		"":                             true,  // originless (CLI/non-browser) is allowed
		"https://app.example.com":      true,  // allowlisted
		"https://evil.example.com":     false, // present but not allowlisted → refused
		"http://app.example.com":       false, // scheme mismatch → refused
		"https://app.example.com:8080": false, // port mismatch → refused
	}
	for origin, want := range cases {
		if got := p.Allowed(origin); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", origin, got, want)
		}
	}
}

func TestOriginPolicyEmptyAllowlistRefusesAnyOrigin(t *testing.T) {
	p := NewOriginPolicy(nil)
	if !p.Allowed("") {
		t.Error("an originless request must be allowed even with an empty allowlist")
	}
	if p.Allowed("https://anything.example.com") {
		t.Error("with an empty allowlist, any present Origin must be refused (DNS-rebinding fail-closed)")
	}
}

// TestHandlerRejectsDisallowedOrigin proves the DNS-rebinding guard fires at the
// handler: a request carrying a disallowed Origin is refused 403 before auth.
func TestHandlerRejectsDisallowedOrigin(t *testing.T) {
	h := handlerWithOrigin(t, []string{"https://allowed.example.com"})
	req := httptest.NewRequest(http.MethodPost, "/", body(validToolCall))
	req.Header.Set(protocolVersionHeader, pinnedProtocolVersion)
	req.Header.Set("Authorization", "Bearer sk-ocu-x")
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a disallowed Origin must be refused 403, got %d", rec.Code)
	}
}

// TestHandlerAllowsOriginlessRequest proves a CLI/non-browser caller (no Origin)
// passes the DNS-rebinding guard (it then fails later at the fail-closed forward,
// NOT at the Origin guard).
func TestHandlerAllowsOriginlessRequest(t *testing.T) {
	h := handlerWithOrigin(t, []string{"https://allowed.example.com"})
	rec := post(h, pinnedProtocolVersion, "sk-ocu-x", validToolCall) // no Origin header
	if rec.Code == http.StatusForbidden {
		t.Fatal("an originless request must NOT be refused by the Origin guard")
	}
}
