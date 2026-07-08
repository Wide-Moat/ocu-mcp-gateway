// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The gateway grows the MCP handshake so the official client SDK works as a
// drop-in: initialize and tools/list are answered GATEWAY-LOCAL (never forwarded),
// and only tools/call forwards. The load-bearing security property is that the two
// handshake methods NEVER reach the forwarder — recreating the method-confusion
// hole (a non-tools/call method riding the F5 forward) would be a regression.

// TestHandshakeMethodsAreNotForwarded is the security keystone: initialize and
// tools/list are answered locally with a 200 and the recording forwarder is NEVER
// called. If the local-answer guard were removed they would fall through to the
// forward (or be denied) — either way fwd.got would change or the code would not
// be 200, reddening this test.
func TestHandshakeMethodsAreNotForwarded(t *testing.T) {
	cases := map[string]string{
		"initialize": `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`,
		"tools/list": `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
	}
	for name, reqBody := range cases {
		t.Run(name, func(t *testing.T) {
			fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
			h := acceptingHandler(t, fwd, nil)

			rec := post(h, pinnedProtocolVersion, "sk-ocu-good", reqBody)

			if rec.Code != http.StatusOK {
				t.Fatalf("%s must be answered gateway-local with 200, got %d (body %q)", name, rec.Code, rec.Body.String())
			}
			if fwd.got != nil {
				t.Fatalf("%s reached the F5 forward; a handshake method must be answered locally and NEVER forwarded (method-confusion hole)", name)
			}
		})
	}
}

// TestInitializeIsVersionHeaderExempt is the drop-in keystone for the real SDK.
// The MCP streamable-HTTP spec requires the MCP-Protocol-Version header on every
// request AFTER initialization, but NOT on initialize itself — the client learns
// the version from the initialize RESULT, so it cannot send it on the initialize
// request. A conforming SDK (mcp-python streamablehttp_client) therefore POSTs
// initialize with NO version header. If the version pin gated initialize, the
// handshake would deadlock: the client can never learn the version it would need.
// Here initialize is sent with NO version header (post version="") and MUST be
// answered 200 gateway-local. tools/call with no version header still 400s
// (TestInvariant6), so the pin is not weakened for the forwarded path — only the
// spec-mandated initialize exemption is carved out.
func TestInitializeIsVersionHeaderExempt(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	// version="" → no MCP-Protocol-Version header, exactly what the SDK sends.
	rec := post(h, "", "sk-ocu-good", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize with no version header must be answered 200 (spec exempts initialize from the version pin), got %d (body %q)", rec.Code, rec.Body.String())
	}
	if fwd.got != nil {
		t.Fatalf("initialize reached the F5 forward; it must be answered gateway-local")
	}
}

// TestInitializeResultShape asserts the initialize response is a well-formed MCP
// InitializeResult the SDK can consume: a JSON-RPC result carrying the pinned
// protocolVersion, a capabilities object, and a serverInfo with a name. A
// mismatched protocolVersion makes the SDK abort the handshake, so it is pinned.
func TestInitializeResultShape(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize returned %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	var env struct {
		JSONRPC string `json:"jsonrpc"`
		Result  struct {
			ProtocolVersion string                     `json:"protocolVersion"`
			Capabilities    map[string]json.RawMessage `json:"capabilities"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("initialize response is not a JSON-RPC result: %v (body %q)", err, rec.Body.String())
	}
	if env.JSONRPC != "2.0" {
		t.Errorf("initialize result jsonrpc = %q, want 2.0", env.JSONRPC)
	}
	if env.Result.ProtocolVersion != pinnedProtocolVersion {
		t.Errorf("initialize result protocolVersion = %q, want the pinned %q", env.Result.ProtocolVersion, pinnedProtocolVersion)
	}
	if env.Result.Capabilities == nil {
		t.Error("initialize result has no capabilities object")
	}
	if env.Result.ServerInfo.Name == "" {
		t.Error("initialize result serverInfo.name is empty; the SDK needs a named server")
	}
}

// TestToolsListReturnsToolArray asserts tools/list returns a JSON-RPC result with
// a tools array (each entry naming a tool), so the SDK sees the callable tools. An
// empty or missing tools array would leave the SDK unable to call any tool.
func TestToolsListReturnsToolArray(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list returned %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("tools/list response is not a JSON-RPC result: %v (body %q)", err, rec.Body.String())
	}
	if len(env.Result.Tools) == 0 {
		t.Fatal("tools/list returned an empty tools array; the SDK must see at least one callable tool")
	}
	for i, tool := range env.Result.Tools {
		if tool.Name == "" {
			t.Errorf("tools/list tool[%d] has an empty name", i)
		}
	}
}

// TestOffSurfaceMethodStillDenied asserts the allowlist still refuses a genuinely
// off-surface method (an invented hostile one, or a real MCP method the gateway
// does not implement) with -32601 and never forwards it — growing the handshake
// did not open the allowlist to everything.
func TestOffSurfaceMethodStillDenied(t *testing.T) {
	cases := map[string]string{
		"invented hostile":     `{"jsonrpc":"2.0","id":1,"method":"evil/pwn","params":{"name":"echo","arguments":{}}}`,
		"unimplemented method": `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{}}`,
	}
	for name, reqBody := range cases {
		t.Run(name, func(t *testing.T) {
			fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
			h := acceptingHandler(t, fwd, nil)

			rec := post(h, pinnedProtocolVersion, "sk-ocu-good", reqBody)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s must be denied 400, got %d", name, rec.Code)
			}
			var env struct {
				Error struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &env)
			if env.Error.Code != rpcMethodNotAllowed {
				t.Errorf("%s must map to -32601, got %d", name, env.Error.Code)
			}
			if fwd.got != nil {
				t.Errorf("%s reached the forward; an off-surface method must be denied before it", name)
			}
		})
	}
}
