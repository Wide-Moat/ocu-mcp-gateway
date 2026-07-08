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
//
// ID is the echoed JSON-RPC request id and is OMITTED (omitempty) ONLY when the id
// is not known at the error site — the pre-parse/transport errors (a bad method, an
// unparseable body) have no id to echo, and JSON-RPC 2.0 §5 permits a null id there.
// Once the id IS known (a parsed tools/call), the id-carrying writer below MUST be
// used so no error frame is ever written id-less to a client that will correlate by
// id (the hang the create-only arm caused).
type rpcErrorBody struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      jsonRPCID   `json:"id,omitempty"`
	Error   rpcErrorObj `json:"error"`
}

type rpcErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// writeRPCError writes a bounded, leak-free JSON-RPC error with NO echoed id. It is
// the TRANSPORT-FAULT writer: for the pre-parse boundary where the request id is not
// yet known (a bad method, an unparseable/oversized body, an origin/auth/ceiling
// refusal before the body is read). Such a fault is served on a NON-2XX status, which
// a strict SDK catches at the transport layer (an HTTPStatusError) instead of parsing
// the body — so an id-less body is safe here and only here.
//
// It STRUCTURALLY couples id-less to non-2xx: a 2xx status is a programming error
// (an id-less body on a 2xx is the exact frame that hung the client — issue #38), so
// it is coerced to a 500. That makes an id-less body on a 2xx UNCONSTRUCTIBLE through
// this writer; every id-known path uses writeRPCErrorWithID instead. The message is a
// stable reason class supplied by the call site; it MUST NOT carry caller data or an
// internal cause (invariant #5). The body is small by construction.
func writeRPCError(w http.ResponseWriter, httpStatus, rpcCode int, reason string) {
	if httpStatus >= 200 && httpStatus < 300 {
		// An id-less error on a success status is never legitimate — the SDK would
		// parse it and hang on the missing id. Fail closed to a 500 rather than emit
		// the hang-inducing frame.
		httpStatus = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(rpcErrorBody{
		JSONRPC: "2.0",
		Error:   rpcErrorObj{Code: rpcCode, Message: reason},
	})
}

// writeRPCErrorWithID writes the same bounded, leak-free JSON-RPC error but ECHOES
// the request id. It is the id-carrying variant the serializer invariant requires:
// once the id is known (a parsed tools/call reaching the response path), a response
// frame — success OR error — is NEVER written without echoing it, so a client that
// correlates responses by id can always match the reply and never hangs waiting for
// one that never comes. The message stays a fixed reason class (invariant #5).
func writeRPCErrorWithID(w http.ResponseWriter, id jsonRPCID, httpStatus, rpcCode int, reason string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(rpcErrorBody{
		JSONRPC: "2.0",
		ID:      id,
		Error:   rpcErrorObj{Code: rpcCode, Message: reason},
	})
}

// writeProfileDeny maps a profile *Deny onto a leak-free JSON-RPC error, ECHOING the
// request id. It reads ONLY the deny's stable Reason class (never any caller
// payload), so a validation rejection cannot become an information-leak side channel
// (invariant #5). A non-Deny error maps to a generic internal error without detail.
//
// The id is echoed because a profile deny of a well-formed-envelope tools/call fires
// AFTER the request id has been parsed: an id-less deny on the 400/413 status the SDK
// parses the body of is rejected the same way an empty body is, and the client hangs
// (the id-less-error class, issue #38). The id-carrying writer keeps the deny
// correlatable. The caller passes the id from the (envelope-validated) raw body; a
// body so malformed that no id could be parsed yields a nil id, which serializes as
// the JSON-RPC null id — still a well-formed error on its non-2xx status.
func writeProfileDeny(w http.ResponseWriter, id jsonRPCID, err error) {
	var d *profile.Deny
	if !errors.As(err, &d) {
		writeRPCErrorWithID(w, id, http.StatusBadRequest, rpcInvalidRequest, "invalid request")
		return
	}
	switch d.Reason {
	case profile.ReasonBatching:
		writeRPCErrorWithID(w, id, http.StatusBadRequest, rpcInvalidRequest, d.Reason.String())
	case profile.ReasonOverSize:
		writeRPCErrorWithID(w, id, http.StatusRequestEntityTooLarge, rpcInvalidParams, d.Reason.String())
	case profile.ReasonMethodNotFound:
		// An off-allowlist inbound method is "method not found" (-32601), not a
		// malformed body: the surface is exactly tools/call, and a request naming
		// any other method is refused here, never forwarded (method-confusion guard).
		writeRPCErrorWithID(w, id, http.StatusBadRequest, rpcMethodNotAllowed, d.Reason.String())
	case profile.ReasonBaseSchema, profile.ReasonProfileSchema:
		writeRPCErrorWithID(w, id, http.StatusBadRequest, rpcInvalidParams, d.Reason.String())
	default:
		writeRPCErrorWithID(w, id, http.StatusBadRequest, rpcInvalidRequest, "invalid request")
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
//     produced a malformed or oversized result is a FAIL-CLOSED 500 (id echoed),
//     never a malformed body handed to the caller. This is the outbound counterpart
//     of the inbound profile gate; the response path was previously unvalidated.
//   - JSON-RPC framing: a validated result is wrapped {"jsonrpc":"2.0","id":<echoed>,
//     "result":<CallToolResult>} so the SDK correlates the response to its request.
//   - Create-only path (unimplemented tool): a forward with NO exec projection
//     (resp.Result empty) means the named tool has no gateway projection, so nothing
//     was executed. This is answered with a WELL-FORMED JSON-RPC ERROR (-32602,
//     echoed id), NOT a bare {"jsonrpc":"2.0"} and NOT a lying empty CallToolResult
//     "success". The old id-less body was not a valid JSON-RPC response object
//     (JSON-RPC 2.0 §5 requires result XOR error and an echoed id), which a strict
//     SDK rejects and then HANGS on. A false "it worked" is worse than an honest
//     error, so an unimplemented tool is an error, never a fabricated success.
//
// The serializer invariant this method upholds: once the id is known (a parsed
// tools/call always carries one — notifications never reach here), NO response frame,
// success or error, is written without echoing it.
//
// The gateway has already identifier-minimized the upstream response before here;
// the correlation id is a stable handle, NOT a session id.
func (h *Handler) writeToolResult(w http.ResponseWriter, resp forward.SessionResponse, id json.RawMessage) {
	// Create-only (no exec projection): the named tool is not implemented at this
	// gateway (only tools with an argv projection execute). Answer a well-formed
	// JSON-RPC error with the echoed id — never an id-less frame, never a fabricated
	// success. The correlation still rides the header for operator correlation.
	if len(resp.Result) == 0 {
		if resp.Correlation != "" {
			w.Header().Set("MCP-Correlation-Id", resp.Correlation)
		}
		writeRPCErrorWithID(w, id, http.StatusOK, rpcInvalidParams, "unimplemented tool")
		return
	}

	// Outbound validation: a result that is not a well-formed, bounded
	// CallToolResult must never be relayed as a success (fail-closed, leak-free).
	// The id is echoed so even the fail-closed refusal is a correlatable JSON-RPC
	// response, not a hang.
	if err := h.validator.Validate(profile.KindCallToolResult, resp.Result); err != nil {
		writeRPCErrorWithID(w, id, http.StatusInternalServerError, rpcInternalError, "invalid upstream result")
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
