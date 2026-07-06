// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The gateway speaks the stateless streamable-HTTP transport the official MCP SDK
// (streamablehttp_client) needs. Confirmed firsthand from both the SDK and the
// upstream FastMCP server: a plain application/json response is valid (the SDK's
// _handle_json_response branch), no Mcp-Session-Id is required (each POST is
// independent, stateless), and the ONE missing piece is JSON-RPC notifications: a
// notification (no id, or a notifications/* method) is fire-and-forget and MUST be
// acknowledged 202 Accepted with an EMPTY body — never a JSON-RPC result and never
// a -32601 deny. The gateway used to -32601 the notifications/initialized the SDK
// sends right after initialize, which closed the SDK transport
// (BrokenResourceError) on the next request (list_tools). This closes that.

// TestNotificationInitializedIsAccepted202 is the keystone: notifications/initialized
// (the exact message the SDK sends post-initialize) is 202 with an empty body and
// never reaches the forwarder. Answering it -32601 (the old behaviour) reds this —
// and, firsthand, breaks the real SDK on the next request.
func TestNotificationInitializedIsAccepted202(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("notifications/initialized returned %d, want 202 Accepted (a notification is fire-and-forget)", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Fatalf("a notification 202 must carry an empty body, got %q", body)
	}
	if fwd.got != nil {
		t.Fatal("a notification must never reach the forwarder")
	}
}

// TestAnyNotificationIsAccepted202 asserts the 202 rule is generic across
// notifications/* (cancelled, progress), not special-cased to initialized — a
// notification by definition takes no response body.
func TestAnyNotificationIsAccepted202(t *testing.T) {
	for _, m := range []string{"notifications/cancelled", "notifications/progress", "notifications/roots/list_changed"} {
		fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
		h := acceptingHandler(t, fwd, nil)
		rec := post(h, pinnedProtocolVersion, "sk-ocu-good", `{"jsonrpc":"2.0","method":"`+m+`","params":{}}`)
		if rec.Code != http.StatusAccepted {
			t.Errorf("%s returned %d, want 202", m, rec.Code)
		}
		if fwd.got != nil {
			t.Errorf("%s reached the forwarder", m)
		}
	}
}

// TestIdlessRequestIsNotification asserts a message with NO id is treated as a
// notification (202), even if its method is not under notifications/* — a JSON-RPC
// message without an id IS a notification by definition, so it takes no response.
func TestIdlessRequestIsNotification(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)
	// No "id" field → a notification per JSON-RPC.
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", `{"jsonrpc":"2.0","method":"tools/list"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("an id-less message must be treated as a notification (202), got %d", rec.Code)
	}
}

// TestIdBearingRequestsStillAnswered asserts an id-bearing request is NOT swallowed
// as a notification: initialize (id present) still returns a 200 result, so the
// notification rule keys on the ABSENCE of an id, not merely the presence of a
// method.
func TestIdBearingRequestsStillAnswered(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("an id-bearing initialize must still return a 200 result, got %d", rec.Code)
	}
}
