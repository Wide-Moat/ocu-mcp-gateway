// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// A tools/call whose tool has NO exec projection reaches the forward's create-only
// path, so the relayed SessionResponse.Result is empty. The response the gateway
// writes for that arm MUST still be a well-formed JSON-RPC response object: it MUST
// echo the request id and carry EITHER a result OR an error (never neither). The
// prior behaviour wrote a bare {"jsonrpc":"2.0"} with no id and no result/error —
// not a valid JSON-RPC response (JSON-RPC 2.0 §5), which a strict SDK rejects with a
// pydantic ValidationError and then HANGS (the call never returns). These tests pin
// the well-formedness so an id-less/result-less frame can never be written once the
// id is known.

// jsonRPCResponse is a strict decode of a JSON-RPC response object. id and the
// result/error presence are inspected so the well-formedness invariant can assert
// "echoes id AND (result XOR error)".
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// TestToolCallResponseIsWellFormedJSONRPC is the well-formedness keystone: a
// create-only forward (empty Result — a tool with no exec projection, e.g.
// create_file) must NOT produce an id-less, result-less body. The response must
// parse as a JSON-RPC response object that echoes the request id and carries a
// result XOR an error.
//
// Red-probe: the prior create-only arm wrote {"jsonrpc":"2.0"} (no id, no
// result/error), so the id-echo assertion and the result-XOR-error assertion both
// red. Restoring the id-carrying error frame greens them.
func TestToolCallResponseIsWellFormedJSONRPC(t *testing.T) {
	// A forward that returns an empty Result (the create-only path a tool with no
	// exec projection takes). create_file is such a tool today.
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"create_file","arguments":{"description":"d","file_text":"x","path":"/tmp/a"}}}`)

	var resp jsonRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body must be a JSON-RPC response object, got %q (%v)", rec.Body.String(), err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("response must be jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	// MUST echo the request id — a response with no id cannot be correlated by the
	// SDK (this is the half that hung the client).
	if len(resp.ID) == 0 || string(resp.ID) == "null" {
		t.Errorf("response MUST echo the request id 77, got id=%q (body=%s)", resp.ID, rec.Body.String())
	} else if string(resp.ID) != "77" {
		t.Errorf("response must echo the request id 77, got %s", resp.ID)
	}
	// MUST carry result XOR error — never neither, never both.
	hasResult := len(resp.Result) > 0
	hasError := resp.Error != nil
	if hasResult == hasError {
		t.Errorf("response MUST carry result XOR error (never neither, never both); hasResult=%v hasError=%v body=%s", hasResult, hasError, rec.Body.String())
	}
}

// TestUnimplementedToolIsWellFormedError pins the RULED shape of the create-only
// arm: an unimplemented tool (no exec projection) is answered with a well-formed
// JSON-RPC ERROR, code -32602, with the echoed id — NOT a lying empty
// CallToolResult "success" (a false "file created" is worse than the hang). The
// gateway must never claim a file op succeeded when it forwarded nothing.
//
// Red-probe: the prior arm wrote a no-error {"jsonrpc":"2.0"}, so the error/code
// assertions red.
func TestUnimplementedToolIsWellFormedError(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good",
		`{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"view","arguments":{"description":"d","path":"/tmp/a"}}}`)

	var resp jsonRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response must be a JSON-RPC response object, got %q (%v)", rec.Body.String(), err)
	}
	if string(resp.ID) != `"abc"` {
		t.Errorf("error response MUST echo the request id \"abc\", got %s", resp.ID)
	}
	if resp.Error == nil {
		t.Fatalf("an unimplemented tool must be a JSON-RPC error, not an empty success; body=%s", rec.Body.String())
	}
	if resp.Error.Code != rpcInvalidParams {
		t.Errorf("unimplemented tool error code must be -32602, got %d", resp.Error.Code)
	}
	if resp.Result != nil {
		t.Errorf("an error response must NOT also carry a result (lying success), got result=%s", resp.Result)
	}
}
