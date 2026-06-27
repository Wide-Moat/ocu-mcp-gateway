// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/profile"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

// body wraps a JSON string as an io.Reader for an HTTP POST.
func body(s string) io.Reader { return strings.NewReader(s) }

// durableSink is a test audit Sink that durably accepts every event (returns
// nil). It models a healthy audit bus so handler tests reach the post-audit
// path; tests that exercise the fail-closed audit path use failingSink.
type durableSink struct{ count int }

func (s *durableSink) Publish(context.Context, string, []byte) error {
	s.count++
	return nil
}

// failingSink is a test audit Sink whose durable write always fails, so a handler
// test can drive the audit-write-failure-is-refusal path.
type failingSink struct{}

func (failingSink) Publish(context.Context, string, []byte) error {
	return context.DeadlineExceeded
}

// capturingSink durably accepts events and records the payloads so a test can
// assert what was emitted (e.g. that the actor is host-attested).
type capturingSink struct{ payloads [][]byte }

func (s *capturingSink) Publish(_ context.Context, _ string, payload []byte) error {
	s.payloads = append(s.payloads, payload)
	return nil
}

// newEmitter builds a durable test emitter for handler wiring.
func newEmitter(t *testing.T) *audit.Emitter {
	t.Helper()
	em, err := audit.NewEmitter(&durableSink{})
	if err != nil {
		t.Fatalf("build emitter: %v", err)
	}
	return em
}

// rejectAllAuth is a test authenticator that refuses every credential. It models
// the fail-closed auth boundary so a test can drive the 401 path.
type rejectAllAuth struct{}

func (rejectAllAuth) Authenticate(context.Context, auth.TransportCredential) (auth.Caller, error) {
	return auth.Caller{}, auth.ErrUnauthenticated
}

// acceptAuth is a test authenticator that resolves a fixed caller for any
// non-empty bearer, so a test can drive the post-auth path (ceiling, validate,
// forward) without standing up a real key set.
type acceptAuth struct {
	caller auth.Caller
}

func (a acceptAuth) Authenticate(_ context.Context, cred auth.TransportCredential) (auth.Caller, error) {
	if cred.Bearer == "" {
		return auth.Caller{}, auth.ErrUnauthenticated
	}
	return a.caller, nil
}

// recordingForwarder captures the SessionRequest it was handed, so a test can
// assert what the F5 forward carried (e.g. that no credential rode it). It
// returns a fixed response.
type recordingForwarder struct {
	got  *forward.SessionRequest
	resp forward.SessionResponse
	err  error
}

func (f *recordingForwarder) Forward(_ context.Context, req forward.SessionRequest) (forward.SessionResponse, error) {
	cp := req
	f.got = &cp
	return f.resp, f.err
}

// newValidator builds a real profile validator (structural base + OCU overlay)
// for handler tests, so validation behaves as in production.
func newValidator(t *testing.T) *profile.Validator {
	t.Helper()
	v, err := profile.NewValidator(profile.NewJSONRPCBaseValidator(), profile.DefaultLimits())
	if err != nil {
		t.Fatalf("build validator: %v", err)
	}
	return v
}

// newTestHandler builds a Handler with the given authenticator, a real validator,
// a fail-closed forwarder, and a generous ceiling. It is the default wiring for
// boundary-order tests that only vary the auth outcome.
func newTestHandler(t *testing.T, authn auth.CallerAuthenticator) *Handler {
	t.Helper()
	h, err := NewHandler(authn, newValidator(t), &recordingForwarder{err: forward.ErrForwardFailed}, quota.NewCeiling(64), newEmitter(t))
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h
}
