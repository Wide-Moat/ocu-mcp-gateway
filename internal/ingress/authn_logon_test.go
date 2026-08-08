// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

// errAuditPublishTest simulates a dead sink for the fail-open assertions.
var errAuditPublishTest = errAuditTestFault{}

type errAuditTestFault struct{}

func (errAuditTestFault) Error() string { return "audit sink down (test)" }

// The caller-key logon trail (ocu-control#118, contract 1.2.0). A failed
// sk-ocu- key is observable nowhere but the gateway, so the 401 path must
// emit a 3002 failure; a successful key emits one logon per connection.

// logonSink captures every published payload for assertion.
type logonSink struct {
	mu      sync.Mutex
	events  []map[string]any
	failNow bool
}

func (s *logonSink) Publish(_ context.Context, _ string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNow {
		return errAuditPublishTest
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err == nil {
		s.events = append(s.events, doc)
	}
	return nil
}

func (s *logonSink) logons() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, e := range s.events {
		if e["class_uid"] == float64(3002) {
			out = append(out, e)
		}
	}
	return out
}

func newLogonHandler(t *testing.T, authn auth.CallerAuthenticator, sink *logonSink) *Handler {
	t.Helper()
	em, err := audit.NewEmitter(sink)
	if err != nil {
		t.Fatalf("emitter: %v", err)
	}
	h, err := NewHandler(authn, newValidator(t), &recordingForwarder{},
		quota.NewCeiling(64), NewOriginPolicy(nil), NewResolveOnlyPolicy(""), em, newSerializer(t))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return h.WithPolicy(testPolicy(t))
}

// TestFailedKeyEmitsAFailureLogon is the reason this exists: a rejected caller
// key produces a 3002 failure at the gateway, the only place it can be seen.
func TestFailedKeyEmitsAFailureLogon(t *testing.T) {
	sink := &logonSink{}
	h := newLogonHandler(t, rejectAllAuth{}, sink)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, logonRequest(t, "sk-ocu-badkey00000000"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got := sink.logons()
	if len(got) != 1 {
		t.Fatalf("a rejected key emitted %d logon(s), want 1", len(got))
	}
	if got[0]["status_id"] != float64(2) {
		t.Errorf("the logon reports status_id %v, want 2 (failure)", got[0]["status_id"])
	}
	// The presented key never reaches the trail.
	raw, _ := json.Marshal(got[0])
	if strings.Contains(string(raw), "sk-ocu-") {
		t.Error("the failure logon carries the presented key")
	}
}

// TestLeakyAuthStillYieldsAKeyFreeFailureLogon pins the degrade-not-drop rule.
// A future authenticator could wrap the bearer into its error, but authnCause
// maps to a stable class rather than forwarding the raw error — so the failure
// logon is still RECORDED (every failure with its cause, NFR-SEC-88), and it
// carries no key material. The render guard stays the fail-closed net behind
// this; the two together mean neither a leak NOR a silent loss.
func TestLeakyAuthStillYieldsAKeyFreeFailureLogon(t *testing.T) {
	sink := &logonSink{}
	h := newLogonHandler(t, leakyAuth{}, sink)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, logonRequest(t, "sk-ocu-secretkey12345"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	got := sink.logons()
	if len(got) != 1 {
		t.Fatalf("a leaky-auth failure emitted %d logon(s), want 1 — the cause is "+
			"degraded, not dropped", len(got))
	}
	if got[0]["status_detail"] == "" {
		t.Error("the degraded failure carries no cause")
	}
	for _, e := range sink.events {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "sk-ocu-") {
			t.Fatal("a record carrying key material reached the trail")
		}
	}
}

// leakyAuth models a future authenticator that wraps the bearer into its error.
type leakyAuth struct{}

func (leakyAuth) Authenticate(_ context.Context, cred auth.TransportCredential) (auth.Caller, error) {
	return auth.Caller{}, &leakyErr{bearer: cred.Bearer}
}

type leakyErr struct{ bearer string }

func (e *leakyErr) Error() string { return "rejected key " + e.bearer }

// TestAcceptedKeyEmitsOneLogonPerConnection pins the once-per-connection latch
// on the real request path: two requests on one connection add one logon.
func TestAcceptedKeyEmitsOneLogonPerConnection(t *testing.T) {
	sink := &logonSink{}
	h := newLogonHandler(t, acceptAuth{caller: auth.Caller{KeyID: "tenant-9/portal-a", Tenant: "tenant-9"}}, sink)

	// One connection: the ConnContext latch rides a shared base context.
	base := withAuthnLatch(context.Background())
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := logonRequest(t, "sk-ocu-goodkey0000000").WithContext(base)
		h.ServeHTTP(rec, req)
	}

	got := sink.logons()
	if len(got) != 1 {
		t.Fatalf("3 requests on one connection emitted %d success logon(s), want 1", len(got))
	}
	if got[0]["status_id"] != float64(1) {
		t.Errorf("status_id = %v, want 1 (success)", got[0]["status_id"])
	}
	user, _ := got[0]["user"].(map[string]any)
	if user == nil || user["uid"] != "tenant-9/portal-a" {
		t.Errorf("the logon names user %v, want the resolved caller", got[0]["user"])
	}
}

// TestSecondConnectionEmitsASecondLogon keeps the latch per-connection.
func TestSecondConnectionEmitsASecondLogon(t *testing.T) {
	sink := &logonSink{}
	h := newLogonHandler(t, acceptAuth{caller: auth.Caller{KeyID: "c", Tenant: "t"}}, sink)

	for range 2 {
		rec := httptest.NewRecorder()
		req := logonRequest(t, "sk-ocu-goodkey0000000").WithContext(withAuthnLatch(context.Background()))
		h.ServeHTTP(rec, req)
	}
	if got := len(sink.logons()); got != 2 {
		t.Errorf("two connections emitted %d success logons, want 2", got)
	}
}

// TestFailedKeyIsNotLatched keeps every failed attempt visible: failures do not
// consume the latch, so three bad requests on one connection are three records.
func TestFailedKeyIsNotLatched(t *testing.T) {
	sink := &logonSink{}
	h := newLogonHandler(t, rejectAllAuth{}, sink)

	base := withAuthnLatch(context.Background())
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, logonRequest(t, "sk-ocu-bad").WithContext(base))
	}
	if got := len(sink.logons()); got != 3 {
		t.Errorf("3 failed attempts emitted %d logons, want 3 — failures must not latch", got)
	}
}

// TestLogonEmitFailureDoesNotDenyTheRequest is the fail-open posture: a dead
// audit sink must not turn a 401 into a 500 or a valid request into a failure.
// The request's own outcome is unchanged; only the trail loses a record.
func TestLogonEmitFailureDoesNotDenyTheRequest(t *testing.T) {
	sink := &logonSink{failNow: true}
	h := newLogonHandler(t, rejectAllAuth{}, sink)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, logonRequest(t, "sk-ocu-bad"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a failed logon EMIT changed the status to %d; the request outcome "+
			"must not depend on whether its logon recorded", rec.Code)
	}
}

// TestFailedSuccessEmitRetriesNextRequest is defect-1: a success logon whose
// emit was refused must NOT hold the connection latch, or the connection's only
// logon is lost the moment the disk hiccups. The trail must have the record once
// the sink recovers.
func TestFailedSuccessEmitRetriesNextRequest(t *testing.T) {
	sink := &logonSink{failNow: true}
	h := newLogonHandler(t, acceptAuth{caller: auth.Caller{KeyID: "c", Tenant: "t"}}, sink)

	base := withAuthnLatch(context.Background())
	// First request: emit refused, latch must NOT be held.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, logonRequest(t, "sk-ocu-good").WithContext(base))
	if h.LogonsDropped() != 1 {
		t.Errorf("a refused logon emit was not counted: dropped=%d, want 1", h.LogonsDropped())
	}

	// The disk recovers; the next request on the SAME connection must land the
	// logon that was lost.
	sink.mu.Lock()
	sink.failNow = false
	sink.mu.Unlock()
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, logonRequest(t, "sk-ocu-good").WithContext(base))

	if got := len(sink.logons()); got != 1 {
		t.Errorf("after a recovered emit the trail holds %d logons, want 1 — a failed "+
			"emit latched as if it had recorded", got)
	}
}

func logonRequest(t *testing.T, bearer string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	return req
}
