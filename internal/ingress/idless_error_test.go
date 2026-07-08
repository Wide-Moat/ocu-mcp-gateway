// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The id-less-error-frame invariant (fast-follow to #37, tracking issue #38): once
// the JSON-RPC request id has been parsed, EVERY error the handler writes MUST echo
// that id. A strict MCP SDK correlates responses by id, so an id-less error on a
// status whose body it parses is rejected the same way the empty create-only body
// was — and the client hangs. Pre-parse transport-faults (a bad method, an
// unparseable/oversized body, a failed origin/auth check) are legitimately id-less
// BUT are served on a non-2xx HTTP status, which the SDK catches at the transport
// layer (HTTPStatusError), never hanging on a body it did not parse.

// TestProfileDenyEchoesRequestID is the fast-follow keystone: a well-formed-envelope
// tools/call that FAILS profile validation (a schema-invalid body, e.g. arguments
// that are an array not an object) is denied AFTER its id is parsed, so the denial
// MUST echo the request id. This is the one genuine remaining hang-risk member — the
// profile-deny returns 400, a 4xx the SDK parses the body of.
//
// Red-probe: the pre-fix writeProfileDeny wrote an id-less error (writeRPCError with
// no id), so the id-echo assertion reds today. Restoring the id-carrying deny greens
// it.
func TestProfileDenyEchoesRequestID(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	// A single-message JSON-RPC tools/call with a parseable id whose params.arguments
	// is an ARRAY (not the required object) — passes the single-message envelope,
	// reaches the profile deny, and is refused there.
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":123,"method":"tools/call","params":{"name":"bash_tool","arguments":[1,2,3]}}`)

	// A profile deny is a 4xx (not a 2xx success) — the SDK parses this body, so it
	// must be a well-formed JSON-RPC error that echoes the id.
	if rec.Code == http.StatusOK {
		t.Fatalf("a schema-invalid tools/call must be denied, not 200; body=%s", rec.Body.String())
	}
	var resp jsonRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("a profile deny must be a JSON-RPC response object, got %q (%v)", rec.Body.String(), err)
	}
	if resp.Error == nil {
		t.Fatalf("a profile deny must carry a JSON-RPC error, got %s", rec.Body.String())
	}
	if len(resp.ID) == 0 || string(resp.ID) == "null" {
		t.Errorf("a post-parse deny MUST echo the request id 123, got id=%q (body=%s)", resp.ID, rec.Body.String())
	} else if string(resp.ID) != "123" {
		t.Errorf("a post-parse deny must echo the request id 123, got %s", resp.ID)
	}
}

// TestForwardRefusedEchoesRequestID pins the invariant on the forward-refused site:
// a forward failure (502) is a post-parse error, so it echoes the id. It is served
// non-2xx (the SDK catches it on the transport and would not hang), but the
// invariant is uniform — any error after the id is parsed echoes it.
//
// Red-probe: the pre-fix forward-refused wrote an id-less error, so the id-echo
// assertion reds.
func TestForwardRefusedEchoesRequestID(t *testing.T) {
	fwd := &recordingForwarder{err: forward.ErrForwardFailed}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":456,"method":"tools/call","params":{"name":"bash_tool","arguments":{"command":"echo hi"}}}`)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("a forward failure must be 502, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp jsonRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("a forward refusal must be a JSON-RPC response object, got %q (%v)", rec.Body.String(), err)
	}
	if string(resp.ID) != "456" {
		t.Errorf("a post-parse forward refusal MUST echo the request id 456, got %s (body=%s)", resp.ID, rec.Body.String())
	}
}

// TestTransportFaultWriterCannotEmitIdlessOn2xx is the STRUCTURAL keystone: the
// id-less writer (writeRPCError, the transport-fault writer) cannot emit an id-less
// body on a 2xx status. An id-less body on a status the SDK parses is the exact frame
// that hung the client, so the writer coerces any 2xx to a non-2xx — making the
// hang-inducing frame unconstructible through the only id-less path. Every id-known
// site uses writeRPCErrorWithID instead.
//
// Red-probe: removing the coercion (letting writeRPCError honour a 2xx) reds this.
func TestTransportFaultWriterCannotEmitIdlessOn2xx(t *testing.T) {
	rec := httptest.NewRecorder()
	// A caller (mistakenly) asks the id-less writer for a 200 — the class of bug the
	// coupling prevents.
	writeRPCError(rec, http.StatusOK, rpcInternalError, "should not be a 200")
	if rec.Code >= 200 && rec.Code < 300 {
		t.Errorf("the id-less transport-fault writer must never emit a 2xx (an id-less 2xx body hangs the SDK); got %d", rec.Code)
	}
}

// TestPreParseFaultsAreNon2xx is the structural guard Fable asked to verify: a
// pre-parse transport-fault (an unparseable body, an over-size body) is served on a
// non-2xx HTTP status. That is what makes an id-less pre-parse error SAFE — the SDK
// catches it at the transport layer rather than parsing a body with no id and
// hanging. An id-less error on a 2xx is the failure mode; this pins that pre-parse
// faults never land there.
//
// Red-probe: making any of these paths write a 200 reds this.
func TestPreParseFaultsAreNon2xx(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	cases := map[string]string{
		// Unparseable body — a decode fault before any id is known.
		"unparseable body": `{"jsonrpc":"2.0","id":1,`,
		// Batched array — rejected pre-buffer as a single-message-envelope fault.
		"batched array": `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bash_tool","arguments":{}}}]`,
	}
	for name, reqBody := range cases {
		t.Run(name, func(t *testing.T) {
			rec := post(h, pinnedProtocolVersion, "sk-ocu-good", reqBody)
			if rec.Code >= 200 && rec.Code < 300 {
				t.Errorf("%s is a pre-parse transport-fault and MUST be non-2xx (so an id-less body is transport-caught), got %d", name, rec.Code)
			}
		})
	}
}
