// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/profile"
)

// JSON-RPC error codes (the closed set the OCU profile's boundedError permits).
// No internal-range codes are invented; -32602 covers unknown tool, invalid
// arguments, and unsupported protocol version.
const (
	rpcParseError       = -32700
	rpcInvalidRequest   = -32600
	rpcMethodNotAllowed = -32601
	rpcInvalidParams    = -32602
	rpcInternalError    = -32603
)

// rpcErrorBody is the leak-free JSON-RPC error envelope written to the caller. It
// carries a stable reason class (a short, enumerable message) and NOTHING
// caller- or topology-derived: no session id, container_name, internal
// host/route, or stack detail (invariant #5, NFR-SEC-51). The message is a fixed
// string chosen at the call site from a closed set, never interpolated from a
// caller value or an internal error cause.
type rpcErrorBody struct {
	JSONRPC string      `json:"jsonrpc"`
	Error   rpcErrorObj `json:"error"`
}

type rpcErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// writeRPCError writes a bounded, leak-free JSON-RPC error with the given HTTP
// status and JSON-RPC code. The message is a stable reason class supplied by the
// call site; it MUST NOT carry caller data or an internal cause. The body is
// small by construction (a fixed message), satisfying the size bound.
func writeRPCError(w http.ResponseWriter, httpStatus, rpcCode int, reason string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(rpcErrorBody{
		JSONRPC: "2.0",
		Error:   rpcErrorObj{Code: rpcCode, Message: reason},
	})
}

// writeProfileDeny maps a profile *Deny onto a leak-free JSON-RPC error. It reads
// ONLY the deny's stable Reason class (never any caller payload), so a validation
// rejection cannot become an information-leak side channel (invariant #5). A
// non-Deny error maps to a generic internal error without detail.
func writeProfileDeny(w http.ResponseWriter, err error) {
	var d *profile.Deny
	if !errors.As(err, &d) {
		writeRPCError(w, http.StatusBadRequest, rpcInvalidRequest, "invalid request")
		return
	}
	switch d.Reason {
	case profile.ReasonBatching:
		writeRPCError(w, http.StatusBadRequest, rpcInvalidRequest, d.Reason.String())
	case profile.ReasonOverSize:
		writeRPCError(w, http.StatusRequestEntityTooLarge, rpcInvalidParams, d.Reason.String())
	case profile.ReasonBaseSchema, profile.ReasonProfileSchema:
		writeRPCError(w, http.StatusBadRequest, rpcInvalidParams, d.Reason.String())
	default:
		writeRPCError(w, http.StatusBadRequest, rpcInvalidRequest, "invalid request")
	}
}

// writeDecodeError maps a transport-level read error onto an HTTP status. An
// oversized body is the honest 413; any other read failure is a generic 400 with
// no internal detail (invariant #5).
func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeRPCError(w, http.StatusRequestEntityTooLarge, rpcInvalidParams, "request body too large")
		return
	}
	writeRPCError(w, http.StatusBadRequest, rpcParseError, "invalid request body")
}

// writeResult relays the forwarded result to the caller. Only the bounded result
// payload and the stable correlation id reach the wire; the gateway has already
// identifier-minimized the upstream response (no session id / container_name /
// internal route) before it reaches here (invariant #5). The correlation id is a
// stable handle, NOT a session id.
func writeResult(w http.ResponseWriter, resp forward.SessionResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if resp.Correlation != "" {
		// A stable, leak-free correlation handle for the caller to reference; it
		// is not a session id and carries no internal topology.
		w.Header().Set("MCP-Correlation-Id", resp.Correlation)
	}
	w.WriteHeader(http.StatusOK)
	// resp.Result is the bounded, validated result payload to relay verbatim.
	if len(resp.Result) > 0 {
		_, _ = w.Write(resp.Result)
		return
	}
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0"}`))
}
