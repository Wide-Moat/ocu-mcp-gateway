// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// The session_hint the gateway sends must be PER-CHAT, not per-tenant. Control's
// mintHandle is deterministic in the (identity, hint) pair, so a tenant-only hint
// collapses every tool-call of a tenant onto one reservation — the second concurrent
// create 409s. Keying the hint on the chat scope (the X-Chat-Id the client sends,
// carried on SessionRequest.SessionHint) gives each chat its own stable hint: the
// tool-calls of one chat REUSE one guest session (the agent's /workspace state
// persists across bash -> str_replace -> view), while a different chat gets a
// different session.

// captureHint spins up a control-shaped mTLS server that records the session_hint
// the gateway sends, and returns a forwarder pointed at it plus a pointer to the
// captured hint.
func captureHint(t *testing.T) (*ControlForwarder, *string) {
	t.Helper()
	pki := newMTLSTestPKI(t)
	got := new(string)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body controlCreateBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		*got = body.SessionHint
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(controlSessionResponse{Key: "k", State: 2})
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)

	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: srv.URL, TLS: pki.clientTLSConfig()},
		staticCred{token: "service-tok", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	return f, got
}

// TestSessionHintKeyedOnChatScope asserts the session_hint on the wire incorporates
// the request's chat scope, so it is stable per-chat and DIFFERS across chats — the
// property that stops the per-tenant 409 collision.
func TestSessionHintKeyedOnChatScope(t *testing.T) {
	f, got := captureHint(t)
	ctx := context.Background()

	// Two calls, same tenant, DIFFERENT chat scope → DIFFERENT hints.
	if _, err := f.Forward(ctx, SessionRequest{Principal: auth.Caller{Tenant: "tenant-a"}, SessionHint: "chat-1"}); err != nil {
		t.Fatalf("forward chat-1: %v", err)
	}
	hint1 := *got
	if _, err := f.Forward(ctx, SessionRequest{Principal: auth.Caller{Tenant: "tenant-a"}, SessionHint: "chat-2"}); err != nil {
		t.Fatalf("forward chat-2: %v", err)
	}
	hint2 := *got

	if hint1 == hint2 {
		t.Fatalf("two DIFFERENT chats of the same tenant produced the SAME session_hint %q — the per-tenant collision is not fixed", hint1)
	}
}

// TestSessionHintStablePerChat asserts the SAME chat scope produces the SAME
// session_hint across calls — so the tool-calls of one chat address one reusable
// guest session (control resumes it), not a fresh session each step.
func TestSessionHintStablePerChat(t *testing.T) {
	f, got := captureHint(t)
	ctx := context.Background()

	if _, err := f.Forward(ctx, SessionRequest{Principal: auth.Caller{Tenant: "tenant-a"}, SessionHint: "chat-1"}); err != nil {
		t.Fatalf("forward A: %v", err)
	}
	first := *got
	if _, err := f.Forward(ctx, SessionRequest{Principal: auth.Caller{Tenant: "tenant-a"}, SessionHint: "chat-1"}); err != nil {
		t.Fatalf("forward B: %v", err)
	}
	second := *got

	if first != second {
		t.Fatalf("the SAME chat produced DIFFERENT session_hints %q vs %q — a chat's tool-calls must address one reusable session", first, second)
	}
}

// TestSessionHintFallsBackToTenantWithoutChat asserts that when no chat scope is
// supplied (a non-OpenWebUI caller), the hint falls back to the tenant handle — the
// prior behaviour, a safe default that does not break existing callers.
func TestSessionHintFallsBackToTenantWithoutChat(t *testing.T) {
	f, got := captureHint(t)
	if _, err := f.Forward(context.Background(), SessionRequest{Principal: auth.Caller{Tenant: "tenant-a"}}); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if *got == "" {
		t.Fatal("with no chat scope the session_hint must fall back to a non-empty tenant handle, got empty")
	}
}
