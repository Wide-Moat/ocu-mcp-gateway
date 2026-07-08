// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	_ "embed"
	"encoding/json"
	"net/http"
)

// The gateway answers the MCP lifecycle handshake (initialize, tools/list)
// GATEWAY-LOCAL so the official client SDK works against it as a drop-in for the
// old endpoint — no tool-code change, only the connection Valves. These two
// methods are the client-side handshake the SDK runs before it can call a tool;
// they are answered here and NEVER forwarded on F5 (only tools/call forwards),
// so the method-confusion guard (invariant #17) is preserved: a handshake method
// cannot ride the forward.

// serverInfoName mirrors the upstream MCP server name (FastMCP name
// "computer-use-mcp") so the SDK sees the same server identity across the
// endpoint swap — the owner's drop-in requirement. The gateway is a transparent
// front for the same tool surface, not a differently-named server.
const serverInfoName = "computer-use-mcp"

// serverInfoVersion is the advertised server version. The gateway carries no
// semver of its own (its revision is the MCP date string, NFR-IC-04); this is the
// server-identity version the SDK records, distinct from the protocol version.
const serverInfoVersion = "1.0.0"

//go:embed tools_list.json
var toolsListJSON []byte

// jsonRPCID is a raw JSON-RPC id echoed back verbatim (it may be a string, a
// number, or null per the JSON-RPC spec, so it is carried as RawMessage).
type jsonRPCID = json.RawMessage

// initializeResult is the MCP InitializeResult the gateway returns for
// initialize: the pinned protocol version, the capability set, and the mirrored
// server identity. A mismatched protocolVersion makes the SDK abort the
// handshake, so it is the same pinned value the transport header enforces.
type initializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      serverInfo             `json:"serverInfo"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// rpcResultBody is a JSON-RPC success envelope carrying an arbitrary result and
// echoing the request id.
//
// ID has NO omitempty: a success frame is only ever written on a path where the id
// is known (initialize/tools/list/a projected tools/call result), and JSON-RPC 2.0
// §5 requires a result response to echo the id. Dropping a known id silently (the
// omitempty foot-gun) produced an un-correlatable frame the SDK could not match,
// which HUNG the client — so the id is always serialized on a result frame. A
// genuinely absent id (a message that should not have reached here) serializes as
// JSON `null`, still a valid — and visibly wrong — response, never a silently
// id-less body.
type rpcResultBody struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      jsonRPCID       `json:"id"`
	Result  json.RawMessage `json:"result"`
}

// idFrom extracts the JSON-RPC id from the validated raw body so the response can
// echo it (the SDK matches responses to requests by id). A missing id yields nil,
// which is omitted from the envelope.
func idFrom(raw []byte) jsonRPCID {
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(raw, &msg)
	return msg.ID
}

// writeInitializeResult answers initialize gateway-local with a well-formed MCP
// InitializeResult. capabilities declares tools (the only surface the gateway
// fronts); listChanged is false because the gateway's tool set is static.
func writeInitializeResult(w http.ResponseWriter, raw []byte) {
	result := initializeResult{
		ProtocolVersion: pinnedProtocolVersion,
		Capabilities: map[string]interface{}{
			"tools": map[string]interface{}{"listChanged": false},
		},
		ServerInfo: serverInfo{Name: serverInfoName, Version: serverInfoVersion},
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		// The result is a fixed shape; a marshal failure is not expected, but keep
		// the boundary fail-closed rather than writing a partial body.
		writeRPCError(w, http.StatusInternalServerError, rpcInternalError, "internal error")
		return
	}
	writeRPCSuccess(w, raw, resultJSON)
}

// writeToolsList answers tools/list gateway-local with the static tool set the
// gateway fronts (the exact FastMCP-generated schemas of the upstream tools). The
// SDK needs to SEE these to allow a call_tool; the actual invocation still forwards
// as a tools/call. The embedded JSON is a `{"tools":[...]}` object, which is
// exactly the ListToolsResult shape, so it is the result verbatim.
func writeToolsList(w http.ResponseWriter, raw []byte) {
	writeRPCSuccess(w, raw, toolsListJSON)
}

// writeRPCSuccess writes a JSON-RPC success envelope with the given result and the
// request's echoed id.
func writeRPCSuccess(w http.ResponseWriter, raw, result []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rpcResultBody{
		JSONRPC: "2.0",
		ID:      idFrom(raw),
		Result:  result,
	})
}
