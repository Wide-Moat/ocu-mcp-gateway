// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// controlExecBody mirrors ocu-control's gateway-ingress execBody (serve.go:251),
// decoded there with DisallowUnknownFields. The gateway's exec-hop must send
// EXACTLY these fields; an over-rich body would be a control 400. session_hint
// ADDRESSES the caller's own row (the same one create just made), argv is the
// command vector, and timeout_s is the deployment-policy ceiling. No credential
// field exists — the Storage-JWT rides F7, never an exec body.
type controlExecBody struct {
	SessionHint string            `json:"session_hint"`
	Argv        []string          `json:"argv"`
	Env         map[string]string `json:"env"`
	Cwd         string            `json:"cwd"`
	StdinB64    string            `json:"stdin_b64"`
	TimeoutS    uint32            `json:"timeout_s"`
}

// controlExecResponse mirrors ocu-control's execResponse (serve.go:289): the
// guest child's exit code and the base64 captured output with truncation flags.
type controlExecResponse struct {
	ExitCode        uint8  `json:"exit_code"`
	StdoutB64       string `json:"stdout_b64"`
	StderrB64       string `json:"stderr_b64"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

// twoHopControl is a control-shaped httptest mux that routes BOTH F5 legs the
// live Forward now drives: POST /v1alpha/sessions (create → {key,state}) AND POST
// /v1alpha/sessions/exec (exec → execResponse). It is the real two-route surface
// ocu-control's gateway-ingress mounts (serve.go), so the gateway's create-then-
// exec sequence hits the correct handler for each hop. The exec handler is
// supplied by the caller so each test drives a specific guest outcome (success,
// tool-fail, route-down). It decodes each body DisallowUnknownFields, exactly as
// control does, so an over-rich body reds the test loudly.
type twoHopControl struct {
	gotExec    controlExecBody
	execDecErr error
	sawExec    bool
}

// serveWith builds the httptest.Server over the mTLS PKI. execHandler is invoked
// for the exec route with the decoded body; it writes control's exec reply (or a
// non-2xx to simulate a route-down / refusal).
func (c *twoHopControl) serveWith(t *testing.T, pki *mTLSTestPKI, execHandler func(w http.ResponseWriter, body controlExecBody)) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1alpha/sessions":
			// Create hop: reply with the host-derived key + state, exactly as control.
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(controlSessionResponse{Key: "sess-host-derived-key", State: 2})
		case "/v1alpha/sessions/exec":
			c.sawExec = true
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			c.execDecErr = dec.Decode(&c.gotExec)
			execHandler(w, c.gotExec)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	return srv
}

// execOK writes a control exec success reply with the given stdout/stderr and
// exit code.
func execOK(exitCode uint8, stdout, stderr string) func(http.ResponseWriter, controlExecBody) {
	return func(w http.ResponseWriter, _ controlExecBody) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(controlExecResponse{
			ExitCode:  exitCode,
			StdoutB64: base64.StdEncoding.EncodeToString([]byte(stdout)),
			StderrB64: base64.StdEncoding.EncodeToString([]byte(stderr)),
		})
	}
}

// execRouteDown writes a 503 for the exec route, simulating the exec channel being
// unavailable (the guest not up, the driver down). It is the fail-closed probe:
// the whole tool-call must refuse, never a fabricated empty success.
func execRouteDown() func(http.ResponseWriter, controlExecBody) {
	return func(w http.ResponseWriter, _ controlExecBody) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("exec channel unavailable"))
	}
}

// newExecForwarder builds a live forwarder over the given control server.
func newExecForwarder(t *testing.T, pki *mTLSTestPKI, url string) *ControlForwarder {
	t.Helper()
	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: url, TLS: pki.clientTLSConfig()},
		staticCred{token: "service-tok", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	return f
}

// TestExecHopForwardsCommandAndProjectsStdout is the G2 keystone: a live
// create-then-exec sequence. The gateway creates the session, then drives the
// SECOND hop — POST /v1alpha/sessions/exec carrying the caller's argv under the
// SAME session_hint create used — and projects the guest child's stdout into a
// CallToolResult the caller can read. This proves the command is actually EXECUTED
// (the fake-green root: create-only returned an empty body, no stdout).
//
// Red-probe: with a create-only Forward (no exec hop) resp.Result is empty and no
// exec request is ever seen — this reds. The neuter (exec route ALIVE) greens it.
func TestExecHopForwardsCommandAndProjectsStdout(t *testing.T) {
	pki := newMTLSTestPKI(t)
	ctl := &twoHopControl{}
	srv := ctl.serveWith(t, pki, execOK(0, "hi\n", ""))
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)

	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{KeyID: "k1", Tenant: "tenant-a"},
		SessionHint: "chat-7",
		ToolCall:    ToolCall{Name: "bash_tool", Argv: []string{"bash", "-lc", "echo hi"}},
	})
	if err != nil {
		t.Fatalf("live create+exec must succeed, got %v", err)
	}

	// The exec hop must have fired at all (the whole point — command executed).
	if !ctl.sawExec {
		t.Fatal("the gateway must drive the exec hop (POST /v1alpha/sessions/exec); it did not")
	}
	if ctl.execDecErr != nil {
		t.Errorf("control decodes exec DisallowUnknownFields; the gateway sent an over-rich exec body: %v", ctl.execDecErr)
	}
	// The exec must address the SAME session create made (session_hint = the built
	// create hint, "tenant-a/chat-7"), NOT the reply Key (a host-derived correlation
	// that is not an addressable hint).
	if ctl.gotExec.SessionHint != "tenant-a/chat-7" {
		t.Errorf("exec must address the created session by its hint %q, got %q", "tenant-a/chat-7", ctl.gotExec.SessionHint)
	}
	// The caller's argv must ride the exec body verbatim.
	if len(ctl.gotExec.Argv) != 3 || ctl.gotExec.Argv[2] != "echo hi" {
		t.Errorf("exec argv must carry the caller command, got %v", ctl.gotExec.Argv)
	}
	// The deployment timeout ceiling must be sent (default 30, clamped), never 0
	// (which control/guest would read as unbounded).
	if ctl.gotExec.TimeoutS == 0 {
		t.Error("exec must send a non-zero timeout_s from the deployment policy (a 0 is an unbounded DoS vector)")
	}

	// The projected result must be a CallToolResult carrying the guest stdout, so
	// the caller (the model) actually sees "hi".
	var got callToolResultShape
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("resp.Result must be a JSON CallToolResult, got %q (%v)", resp.Result, err)
	}
	if len(got.Content) == 0 || got.Content[0].Text != "hi\n" {
		t.Errorf("the projected result must carry the guest stdout %q, got %+v", "hi\n", got.Content)
	}
	if got.IsError {
		t.Error("a zero exit code must project isError:false")
	}
}

// TestExecHopFailsClosedWhenExecRouteDown is the fail-closed keystone (invariant
// #9): if the exec route refuses (503 — guest not up, driver down), the whole
// tool-call is a fail-closed ErrForwardFailed, NOT a fabricated empty 200. The
// create succeeded but the command did NOT run, so returning success would be a
// silent lie to the caller (the fake-green failure mode, made impossible here).
//
// Red-probe soundness: TODAY (create-only Forward) there is no exec hop, so a
// 503-on-exec changes nothing and this cannot pass — it reds until the hop exists
// AND propagates the exec failure. Neuter (exec route ALIVE) → success, no error.
func TestExecHopFailsClosedWhenExecRouteDown(t *testing.T) {
	pki := newMTLSTestPKI(t)
	ctl := &twoHopControl{}
	srv := ctl.serveWith(t, pki, execRouteDown())
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)

	_, ferr := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-1",
		ToolCall:    ToolCall{Name: "bash_tool", Argv: []string{"bash", "-lc", "echo hi"}},
	})
	if !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("a down exec route must fail the whole tool-call closed (ErrForwardFailed), got %v", ferr)
	}
}

// TestExecHopToolFailIsTierTwoNotTransportFail is the two-tier error keystone: a
// guest command that EXITS NON-ZERO (a tool-execution failure) is a Tier-2 error —
// a 200 CallToolResult{isError:true} carrying the sanitized stderr — NOT a
// transport-level ErrForwardFailed. The exec hop itself was a healthy 200 from
// control; the child's non-zero exit is a legitimate tool outcome the model must
// see, not a gateway refusal (x-ocu-error-model tier-2, NFR-SEC-51).
//
// Red-probe: create-only Forward returns no result at all, so this reds; a hop
// that (wrongly) treated exit!=0 as ErrForwardFailed would ALSO red here — pinning
// the tier boundary. Neuter (exit 0) → isError:false.
func TestExecHopToolFailIsTierTwoNotTransportFail(t *testing.T) {
	pki := newMTLSTestPKI(t)
	ctl := &twoHopControl{}
	srv := ctl.serveWith(t, pki, execOK(1, "", "bash: nope: command not found\n"))
	defer srv.Close()

	f := newExecForwarder(t, pki, srv.URL)

	resp, ferr := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-2",
		ToolCall:    ToolCall{Name: "bash_tool", Argv: []string{"bash", "-lc", "nope"}},
	})
	// A non-zero guest exit is NOT a transport failure — the forward itself succeeded.
	if ferr != nil {
		t.Fatalf("a non-zero guest exit is a Tier-2 tool error, not a transport fail; got %v", ferr)
	}
	var got callToolResultShape
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("resp.Result must be a JSON CallToolResult, got %q (%v)", resp.Result, err)
	}
	if !got.IsError {
		t.Error("a non-zero exit code must project isError:true (Tier-2 tool error)")
	}
	if len(got.Content) == 0 || got.Content[0].Text == "" {
		t.Error("a tool-fail result must carry the sanitized stderr as content so the model sees the failure")
	}
}

// callToolResultShape is the minimal decode of the projected MCP CallToolResult
// the tests assert against — the content text blocks and the isError flag.
type callToolResultShape struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}
