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
	case profile.ReasonMethodNotFound:
		// An off-allowlist inbound method is "method not found" (-32601), not a
		// malformed body: the surface is exactly tools/call, and a request naming
		// any other method is refused here, never forwarded (method-confusion guard).
		writeRPCError(w, http.StatusBadRequest, rpcMethodNotAllowed, d.Reason.String())
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

// writeToolResult relays the forwarded CallToolResult to the caller, VALIDATED
// OUTBOUND and framed into the JSON-RPC result envelope with the echoed request id.
//
//   - Outbound validation (invariant #5, NFR-SEC-51): resp.Result is the projected
//     MCP CallToolResult from the exec hop. Before it reaches the caller it is
//     validated against KindCallToolResult — a control/guest/projection bug that
//     produced a malformed or oversized result is a FAIL-CLOSED 500, never a
//     malformed body handed to the caller. This is the outbound counterpart of the
//     inbound profile gate; the response path was previously unvalidated.
//   - JSON-RPC framing: a validated result is wrapped {"jsonrpc":"2.0","id":<echoed>,
//     "result":<CallToolResult>} so the SDK correlates the response to its request.
//   - Create-only path: a forward with no exec projection (resp.Result empty — a
//     non-bash tool, or a bare create) keeps the minimal {"jsonrpc":"2.0"} body with
//     the correlation in the header (the prior stateless-create behaviour).
//
// The gateway has already identifier-minimized the upstream response before here;
// the correlation id is a stable handle, NOT a session id.
func (h *Handler) writeToolResult(w http.ResponseWriter, resp forward.SessionResponse, id json.RawMessage) {
	// Create-only (no exec projection): preserve the minimal body + correlation
	// header. Nothing to validate — there is no result payload.
	if len(resp.Result) == 0 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if resp.Correlation != "" {
			w.Header().Set("MCP-Correlation-Id", resp.Correlation)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0"}`))
		return
	}

	// Outbound validation: a result that is not a well-formed, bounded
	// CallToolResult must never be relayed as a success (fail-closed, leak-free).
	if err := h.validator.Validate(profile.KindCallToolResult, resp.Result); err != nil {
		writeRPCError(w, http.StatusInternalServerError, rpcInternalError, "invalid upstream result")
		return
	}

	// Frame the validated result into the JSON-RPC envelope with the echoed id,
	// reusing the handshake path's rpcResultBody so the framing is identical across
	// gateway-local and forwarded results. The result is already-valid JSON
	// (RawMessage), carried verbatim.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if resp.Correlation != "" {
		// A stable, leak-free correlation handle for the caller to reference; it
		// is not a session id and carries no internal topology.
		w.Header().Set("MCP-Correlation-Id", resp.Correlation)
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rpcResultBody{
		JSONRPC: "2.0",
		ID:      id,
		Result:  json.RawMessage(resp.Result),
	})
}
