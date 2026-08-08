// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Caller-key authentication events (OCSF 3002) — the emitter half of the
// contract's 1.2.0 addition. The sk-ocu- key is validated AT THE GATEWAY;
// Control only ever sees the gateway's own mTLS identity, so a failed caller
// key is observable nowhere but here.
//
// The emission discipline is stated on the channel (NFR-SEC-88): one logon per
// accepted connection, every failure with its cause, fail-open with counted
// loss — the fail-open is the DECORATOR's job; this file is the record and its
// emit, which stays honest about errors so the caller can count them.

func testLogon() AuthnEnvelope {
	return AuthnEnvelope{
		TraceID: "trace-1",
		ConnID:  "conn-1",
		ActorID: "tenant-9/portal-a",
		Outcome: OutcomeSuccess,
	}
}

// TestAuthnRenderCarriesTheClassRequiredObjects is the conformance keystone,
// the same bar the control-plane emitter cleared: a 3002 without user and
// service is not Authentication.
func TestAuthnRenderCarriesTheClassRequiredObjects(t *testing.T) {
	payload, err := testLogon().ToAuthentication()
	if err != nil {
		t.Fatalf("ToAuthentication: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := doc["class_uid"]; got != float64(3002) {
		t.Fatalf("class_uid = %v, want 3002", got)
	}
	if got := doc["category_uid"]; got != float64(3) {
		t.Errorf("category_uid = %v, want 3 (IAM)", got)
	}
	if got := doc["activity_id"]; got != float64(1) {
		t.Errorf("activity_id = %v, want 1 (Logon)", got)
	}
	user, _ := doc["user"].(map[string]any)
	if user == nil || user["uid"] != "tenant-9/portal-a" {
		t.Errorf("user = %v; 3002 requires the authenticating user at top level", doc["user"])
	}
	svc, _ := doc["service"].(map[string]any)
	if svc == nil || svc["name"] == "" {
		t.Errorf("service = %v; at_least_one(service, dst_endpoint) and this "+
			"transport names no dst_endpoint", doc["service"])
	}
	if got := doc["auth_protocol"]; got != "ocu-api-key" {
		t.Errorf("auth_protocol = %v; the caller key is neither mTLS nor a socket "+
			"peer, and reusing their labels would hide which surface is under attack", got)
	}
	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil || meta["correlation_uid"] != "trace-1" {
		t.Errorf("metadata.correlation_uid = %v", doc["metadata"])
	}
}

// TestAuthnFailureCarriesCauseNeverKeyMaterial pins both halves of the failure
// record: the cause is present, and no fragment of the presented key ever
// reaches the trail — an audit record carrying key material would turn the
// trail into a credential store.
func TestAuthnFailureCarriesCauseNeverKeyMaterial(t *testing.T) {
	env := testLogon()
	env.Outcome = OutcomeFailure
	env.FailureDetail = "key not in the boot-loaded set"
	env.ActorID = "" // a failed key resolves no caller

	payload, err := env.ToAuthentication()
	if err != nil {
		t.Fatalf("ToAuthentication: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := doc["status_id"]; got != float64(2) {
		t.Errorf("status_id = %v, want 2 (failure)", got)
	}
	if got := doc["status_detail"]; got != "key not in the boot-loaded set" {
		t.Errorf("status_detail = %v; the cause is gone", got)
	}
	if strings.Contains(string(payload), "sk-ocu-") {
		t.Error("the rendered record contains key material")
	}
}

// TestAuthnEnvelopeRefusesKeyMaterial fails closed at construction: a
// FailureDetail that embeds the presented key (an easy mistake when wrapping a
// validator error) is refused rather than rendered.
func TestAuthnEnvelopeRefusesKeyMaterial(t *testing.T) {
	env := testLogon()
	env.Outcome = OutcomeFailure
	env.FailureDetail = `unknown key "sk-ocu-abcdef0123456789"`

	if _, err := env.ToAuthentication(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("a failure detail carrying key material rendered (err=%v); the trail "+
			"would become a credential store", err)
	}
}

// TestAuthnSuccessWithoutACallerIsRefused fails closed at construction: a
// successful logon that names nobody is a trail entry saying "someone got in"
// — it satisfies every counting check while answering none of the questions a
// reviewer asks of it.
func TestAuthnSuccessWithoutACallerIsRefused(t *testing.T) {
	env := testLogon()
	env.ActorID = ""
	if _, err := env.ToAuthentication(); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("a success naming no caller rendered (err=%v)", err)
	}
}

// TestAuthnEmitRidesTheGatewayChannel proves the record publishes to the same
// per-source channel as every other gateway event — the contract binds the
// source to the channel identity, and a second address would file these under
// another source.
func TestAuthnEmitRidesTheGatewayChannel(t *testing.T) {
	sink := &captureSink{}
	em, err := NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}

	if err := em.EmitAuthn(context.Background(), testLogon()); err != nil {
		t.Fatalf("EmitAuthn: %v", err)
	}
	if sink.channel != "audit.ingest.mcp-gateway" {
		t.Errorf("the logon published to %q; the contract binds this source to its "+
			"own channel", sink.channel)
	}
	var doc map[string]any
	if err := json.Unmarshal(sink.payload, &doc); err != nil {
		t.Fatalf("unmarshal published payload: %v", err)
	}
	if doc["class_uid"] != float64(3002) {
		t.Errorf("published class_uid = %v", doc["class_uid"])
	}
}

// TestAuthnEmitSharesTheSequenceSpace keeps one monotonic sequence per source.
// A parallel counter for authn events would let two events share a sequence,
// and chain order at the ingest would be ambiguous.
func TestAuthnEmitSharesTheSequenceSpace(t *testing.T) {
	sink := &captureSink{}
	em, err := NewEmitter(sink)
	if err != nil {
		t.Fatalf("NewEmitter: %v", err)
	}

	if err := em.EmitAuthn(context.Background(), testLogon()); err != nil {
		t.Fatalf("EmitAuthn: %v", err)
	}
	env := Envelope{
		TraceID: "t2", SessionID: "s", ActorID: "a", Resource: "r",
		Action: "tools/call", Outcome: OutcomeSuccess,
	}
	if err := em.Emit(context.Background(), env); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(sink.payload, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	meta := doc["metadata"].(map[string]any)
	if meta["sequence"] != float64(1) {
		t.Errorf("the api-activity event after one logon carries sequence %v, want 1 — "+
			"the two kinds are not sharing the per-source sequence space", meta["sequence"])
	}
}

// captureSink records the last publish.
type captureSink struct {
	channel string
	payload []byte
}

func (c *captureSink) Publish(_ context.Context, channel string, payload []byte) error {
	c.channel = channel
	c.payload = payload
	return nil
}
