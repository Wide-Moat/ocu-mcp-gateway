// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// controlStatusBody mirrors ocu-control's gateway-ingress status body: a single
// session_hint that ADDRESSES the caller's own row (the same one create just
// ensured). Control decodes it DisallowUnknownFields, so an over-rich body is a
// control 400 - the mock decodes the same way so a drift reds the test loudly.
type controlStatusBody struct {
	SessionHint string `json:"session_hint"`
}

// controlStatusResponse mirrors ocu-control's status reply on the mTLS gateway
// plane: the host-derived key, the numeric lifecycle state, and the audience-scoped
// effective_scope the D5 client needs to key its per-chat storage.
type controlStatusResponse struct {
	Key            string `json:"key"`
	State          int    `json:"state"`
	EffectiveScope string `json:"effective_scope"`
}

// scopeHopControl is a control-shaped httptest mux for the resolve_scope leg: it
// routes BOTH POST /v1alpha/sessions (create -> {key,state}) AND POST
// /v1alpha/sessions/status (status -> {key,state,effective_scope}). The status
// handler answers a per-hint effective_scope so two distinct hints (two chats)
// yield two distinct scopes - the audience-scoping the keystone pins. Each body is
// decoded DisallowUnknownFields, exactly as control does.
type scopeHopControl struct {
	gotStatus    controlStatusBody
	statusDecErr error
	sawStatus    bool
	// scopeFor maps a session_hint to the effective_scope control returns; a hint
	// with no entry gets an empty scope (the derive-off/no-scope case).
	scopeFor map[string]string
	// statusStatusCode lets a test force a non-2xx on the status route (the
	// fail-closed probe); 0 means 200 OK.
	statusStatusCode int
}

func (c *scopeHopControl) serve(t *testing.T, pki *mTLSTestPKI) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1alpha/sessions":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(controlSessionResponse{Key: "sess-host-derived-key", State: 2})
		case "/v1alpha/sessions/status":
			c.sawStatus = true
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			c.statusDecErr = dec.Decode(&c.gotStatus)
			if c.statusStatusCode != 0 {
				w.WriteHeader(c.statusStatusCode)
				_, _ = w.Write([]byte("status route refused"))
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(controlStatusResponse{
				Key:            "sess-host-derived-key",
				State:          2,
				EffectiveScope: c.scopeFor[c.gotStatus.SessionHint],
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	return srv
}

// scopeResultShape decodes the single text content block resolve_scope projects:
// a JSON document {"effective_scope":"<scope>"}.
type scopeResultShape struct {
	EffectiveScope string `json:"effective_scope"`
}

// scopeFromResult decodes the resp.Result CallToolResult, asserts a single non-error
// text block, and returns the effective_scope the block's JSON carries.
func scopeFromResult(t *testing.T, result []byte) string {
	t.Helper()
	var got callToolResultShape
	if err := json.Unmarshal(result, &got); err != nil {
		t.Fatalf("resp.Result must be a JSON CallToolResult, got %q (%v)", result, err)
	}
	if got.IsError {
		t.Error("a resolve_scope result is not a tool error (isError must be false)")
	}
	if len(got.Content) != 1 || got.Content[0].Type != "text" {
		t.Fatalf("resolve_scope must project exactly one text content block, got %+v", got.Content)
	}
	var scope scopeResultShape
	if err := json.Unmarshal([]byte(got.Content[0].Text), &scope); err != nil {
		t.Fatalf("the text block must be JSON {\"effective_scope\":...}, got %q (%v)", got.Content[0].Text, err)
	}
	return scope.EffectiveScope
}

// TestResolveScopeForwardsAndProjectsEffectiveScope is the D5 keystone: a
// tools/call named "resolve_scope" makes the gateway create/ensure the per-chat
// session then hit POST /v1alpha/sessions/status, and project the audience-scoped
// effective_scope control returns into a CallToolResult the D5 client reads. Two
// distinct X-Chat-Id values (chat-a vs chat-b) build two distinct session_hints
// (tenant-a/chat-a vs tenant-a/chat-b), so control returns two distinct scopes -
// pinning that a forged/other chat id lands under the caller's OWN tenant prefix
// and gets its own scope, never another chat's.
//
// Red-probe: neuter the status hop (skip the status call and project the create
// reply key as the scope) and the effective_scope the client sees is empty/wrong -
// this reds on the missing scope. Restoring the status hop greens it.
func TestResolveScopeForwardsAndProjectsEffectiveScope(t *testing.T) {
	pki := newMTLSTestPKI(t)
	ctl := &scopeHopControl{scopeFor: map[string]string{
		"tenant-a/chat-a": "fs-fleet-tenant-a-chat-a",
		"tenant-a/chat-b": "fs-fleet-tenant-a-chat-b",
	}}
	srv := ctl.serve(t, pki)
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)

	respA, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{KeyID: "k1", Tenant: "tenant-a"},
		SessionHint: "chat-a",
		ToolCall:    ToolCall{Name: "resolve_scope"},
	})
	if err != nil {
		t.Fatalf("resolve_scope must succeed, got %v", err)
	}
	if !ctl.sawStatus {
		t.Fatal("the gateway must drive the status hop (POST /v1alpha/sessions/status); it did not")
	}
	if ctl.statusDecErr != nil {
		t.Errorf("control decodes status DisallowUnknownFields; the gateway sent an over-rich status body: %v", ctl.statusDecErr)
	}
	// The status hop must address the SAME session create ensured, by its per-chat
	// hint (tenant + chat scope), never a raw chat id or the reply key.
	if ctl.gotStatus.SessionHint != "tenant-a/chat-a" {
		t.Errorf("status must address the session by its per-chat hint %q, got %q", "tenant-a/chat-a", ctl.gotStatus.SessionHint)
	}
	if got := scopeFromResult(t, respA.Result); got != "fs-fleet-tenant-a-chat-a" {
		t.Errorf("chat-a must resolve to its own scope %q, got %q", "fs-fleet-tenant-a-chat-a", got)
	}

	// A DIFFERENT chat id under the SAME tenant builds a distinct hint -> distinct scope.
	respB, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{KeyID: "k1", Tenant: "tenant-a"},
		SessionHint: "chat-b",
		ToolCall:    ToolCall{Name: "resolve_scope"},
	})
	if err != nil {
		t.Fatalf("resolve_scope (chat-b) must succeed, got %v", err)
	}
	if got := scopeFromResult(t, respB.Result); got != "fs-fleet-tenant-a-chat-b" {
		t.Errorf("chat-b must resolve to its OWN distinct scope %q, got %q", "fs-fleet-tenant-a-chat-b", got)
	}
}

// TestResolveScopeEmptyScopeDegradesNotFabricates pins the derive-off/no-scope
// case: control returns a 200 status with an EMPTY effective_scope, and the gateway
// projects {"effective_scope":""} so the D5 client degrades to base by its own
// choice. The gateway must NOT fabricate a base scope of its own here (that would
// hide a real derive-off from the client); it relays exactly what control returned.
func TestResolveScopeEmptyScopeDegradesNotFabricates(t *testing.T) {
	pki := newMTLSTestPKI(t)
	// scopeFor has no entry for the hint, so control returns an empty scope.
	ctl := &scopeHopControl{scopeFor: map[string]string{}}
	srv := ctl.serve(t, pki)
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)

	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-x",
		ToolCall:    ToolCall{Name: "resolve_scope"},
	})
	if err != nil {
		t.Fatalf("an empty scope is a legitimate 200, not a forward failure; got %v", err)
	}
	if got := scopeFromResult(t, resp.Result); got != "" {
		t.Errorf("an empty control scope must project an empty effective_scope (client degrades), got %q", got)
	}
}

// TestResolveScopeFailsClosedWhenStatusRouteDown is the fail-closed keystone
// (invariant #9): if the status route refuses (503), resolve_scope is a fail-closed
// ErrForwardFailed, NOT a fabricated {"effective_scope":""}. A non-2xx status means
// the scope is UNKNOWN, not empty - fabricating an empty scope would silently
// degrade the client to base on a transient control fault (the degrade-fake-green
// this guard kills).
func TestResolveScopeFailsClosedWhenStatusRouteDown(t *testing.T) {
	pki := newMTLSTestPKI(t)
	ctl := &scopeHopControl{scopeFor: map[string]string{}, statusStatusCode: http.StatusServiceUnavailable}
	srv := ctl.serve(t, pki)
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)

	_, ferr := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-1",
		ToolCall:    ToolCall{Name: "resolve_scope"},
	})
	if !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("a down status route must fail resolve_scope closed (ErrForwardFailed), not a fabricated empty scope; got %v", ferr)
	}
}
