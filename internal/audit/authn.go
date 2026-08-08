// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Caller-key authentication events (OCSF 3002) — the emitter half of the
// audit-fanin 1.2.0 addition. The sk-ocu- key is validated at the gateway
// (ADR-0027); Control only ever sees the gateway's own mTLS identity, so a
// failed caller key is observable nowhere but here.
//
// The channel states the discipline (NFR-SEC-88): one logon per accepted
// connection, every failure with its cause, fail-open with counted loss. The
// fail-open half belongs to the caller (the authn decorator counts a refused
// emit and continues); this emit stays honest about errors so the caller can.

const (
	// authnClassUID is the OCSF Authentication class uid (IAM 3, class 002).
	authnClassUID = 3002
	// authnCategoryUID is the IAM category the class belongs to.
	authnCategoryUID = 3
	// authnActivityLogon is activity 1: a caller authenticated to the gateway.
	authnActivityLogon = 1
	// authnProtocol names the mechanism. Deliberately NOT "mtls-x509" or
	// "unix-peercred" — the caller key is neither, and reusing another surface's
	// label would hide which one is under attack. Deliberately not carrying the
	// "sk-ocu-" prefix either: the record-level key-material guard scans for that
	// prefix, and a label embedding it would be indistinguishable from a leak.
	authnProtocol = "ocu-api-key"
)

// AuthnEnvelope is one caller-key authentication act, success or failure.
// It never carries key material: the key is the credential under test, and a
// trail that stored it would be a credential store.
type AuthnEnvelope struct {
	// TraceID is the cross-surface correlation id.
	TraceID string
	// ConnID is the host-assigned connection identity the once-per-connection
	// latch keys on; empty for a request that arrived through no listener hook.
	ConnID string
	// ActorID is the resolved caller on success; empty on failure (a refused
	// key resolves no caller, and inventing a sketch would put attacker-chosen
	// bytes in the actor field).
	ActorID string
	// Outcome aligns the OCSF status_id.
	Outcome Outcome
	// FailureDetail names WHY a failed act failed. Empty on success.
	FailureDetail string
	// sequence is assigned by EmitAuthn from the emitter's own counter, so both
	// event kinds share one per-source monotonic space. Unexported: only the
	// emitter sets it.
	sequence uint64
}

// validate fails closed on a malformed record — including one that would leak
// key material through the failure detail, an easy mistake when wrapping a
// validator error verbatim.
func (e AuthnEnvelope) validate() error {
	if !e.Outcome.valid() {
		return fmt.Errorf("%w: outcome %q", ErrInvalidEnvelope, e.Outcome)
	}
	if e.Outcome == OutcomeSuccess && e.ActorID == "" {
		return fmt.Errorf("%w: a successful logon names no caller", ErrInvalidEnvelope)
	}
	if strings.Contains(e.FailureDetail, "sk-ocu-") {
		return fmt.Errorf("%w: failure detail carries key material", ErrInvalidEnvelope)
	}
	return nil
}

// ToAuthentication renders the act as an OCSF Authentication (3002) JSON
// object: the class's own required objects (user; service, since this
// transport names no dst_endpoint), the protocol discriminator, and the
// failure cause.
func (e AuthnEnvelope) ToAuthentication() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}

	obj := map[string]any{
		"class_uid":     authnClassUID,
		"category_uid":  authnCategoryUID,
		"activity_id":   authnActivityLogon,
		"status_id":     statusID(e.Outcome),
		"auth_protocol": authnProtocol,
		"user": map[string]any{
			"uid": e.ActorID,
		},
		"service": map[string]any{
			"name": "ocu-mcp-gateway",
		},
		"metadata": map[string]any{
			"version":         ocsfVersion,
			"sequence":        e.sequence,
			"correlation_uid": e.TraceID,
			"product": map[string]any{
				"name":   "ocu-mcp-gateway",
				"vendor": "Open Computer Use",
			},
		},
	}
	if e.FailureDetail != "" {
		obj["status_detail"] = e.FailureDetail
	}
	if e.ConnID != "" {
		obj["session"] = map[string]any{"uid": e.ConnID}
	}
	return json.Marshal(obj)
}

// EmitAuthn publishes one authentication event on the gateway's own fan-in
// channel — the same address as every other gateway event, because the
// contract binds the source to the channel identity.
//
// Unlike Emit it is NOT wrapped in the fail-closed refusal contract: the
// fail-open/counted-loss decision belongs to the authn decorator, which needs
// the raw error to count.
func (e *Emitter) EmitAuthn(ctx context.Context, env AuthnEnvelope) error {
	env.sequence = e.seq.Add(1) - 1

	payload, err := env.ToAuthentication()
	if err != nil {
		return err
	}
	if err := e.sink.Publish(ctx, channelAddress, payload); err != nil {
		return errors.Join(ErrAuditWriteFailed, err)
	}
	return nil
}
