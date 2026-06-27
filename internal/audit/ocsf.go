// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import "encoding/json"

// OCSF ApiActivity class constants (OCSF 1.5.0, the version the audit-fanin
// contract pins via metadata.version). The gateway emits only this class on its
// channel.
const (
	// ocsfClassUID is the OCSF API Activity class uid (6003).
	ocsfClassUID = 6003
	// ocsfCategoryUID is the Application Activity category (6).
	ocsfCategoryUID = 6
	// ocsfVersion is the pinned OCSF schema version (matches the contract's
	// payload $ref https://schema.ocsf.io/api/1.5.0/...).
	ocsfVersion = "1.5.0"
)

// OCSF activity_id / status_id enums used by the gateway. activity_id is defined
// by the ApiActivity class; the gateway's ingress is a "Create"-shaped API call
// (a tool-call request entering the surface). status_id aligns the envelope
// Outcome.
const (
	activityIDCreate = 1  // ApiActivity activity_id: Create
	statusIDSuccess  = 1  // OCSF status_id: Success
	statusIDFailure  = 2  // OCSF status_id: Failure
	statusIDOther    = 99 // OCSF status_id: Other (maps Outcome unknown)
)

// statusID maps the envelope Outcome to the OCSF status_id.
func statusID(o Outcome) int {
	switch o {
	case OutcomeSuccess:
		return statusIDSuccess
	case OutcomeFailure:
		return statusIDFailure
	default:
		return statusIDOther
	}
}

// ToApiActivity renders an Envelope as an OCSF ApiActivity (class 6003) JSON
// object — the payload shape the audit-fanin contract references by $ref (never
// inlined in the contract, materialised here at emit). The OCU mandatory
// envelope fields ride the OCSF object: actor_id → actor, sequence →
// metadata.sequence, trace_id → metadata.correlation_uid, outcome → status_id.
// The pipeline authors the hash-chain at ingest; this payload carries only the
// monotonic sequence the chain order is derived from.
//
// The Envelope MUST be Validated before this is called (Emit does so); rendering
// an invalid envelope would publish an out-of-contract event.
func (e Envelope) ToApiActivity() ([]byte, error) {
	obj := map[string]any{
		"class_uid":    ocsfClassUID,
		"category_uid": ocsfCategoryUID,
		"activity_id":  activityIDCreate,
		"status_id":    statusID(e.Outcome),
		// actor carries the host-attested caller identity (NFR-SEC-09).
		"actor": map[string]any{
			"user": map[string]any{
				"uid": e.ActorID,
			},
		},
		// api names the target resource of the tool-call ingress.
		"api": map[string]any{
			"operation": e.Action,
			"resource":  e.Resource,
		},
		// metadata carries the OCSF version, the per-source monotonic sequence
		// (the chain-order input), and the cross-surface correlation id.
		"metadata": map[string]any{
			"version":         ocsfVersion,
			"sequence":        e.Sequence,
			"correlation_uid": e.TraceID,
			"product": map[string]any{
				"name":   "ocu-mcp-gateway",
				"vendor": "Open Computer Use",
			},
		},
		// The session/container binding correlation handle.
		"session_uid": e.SessionID,
	}
	return json.Marshal(obj)
}
