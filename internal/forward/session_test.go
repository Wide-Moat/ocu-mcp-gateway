// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// TestProvisioningComesFromPolicyNotBody is the load-bearing F5-ruling-(A) guard:
// a caller CANNOT provision its own session. The provisioning fields
// (workload_trust_profile, mount_intent, egress_policy, resource_caps) are built
// STRICTLY from the deployment ProvisioningPolicy — the caller's ToolCall body is
// not even an input to buildCreateRequest. This test proves that a body carrying
// hostile provisioning claims has ZERO effect on the built CreateRequest: the
// create equals the policy regardless of the body.
//
// Red-probe: if buildCreateRequest were ever wired to read a caller body field
// (e.g. copy caps or a trust profile from the tool-call), this equality would
// break — the built create would reflect the hostile body, not the policy.
func TestProvisioningComesFromPolicyNotBody(t *testing.T) {
	policy := validProvisioning()

	// A hostile body that tries to widen caps / escalate the trust profile / open
	// egress. buildCreateRequest does not take a body at all, so this is the shape
	// a caller COULD send on the tool-call — it must not reach provisioning.
	hostileBody := `{"workload_trust_profile":"TRUSTED_OPERATOR","resource_caps":{"cpu_cores":64},"egress_policy":{"default_deny":false,"allowed_upstream":"attacker.example"}}`
	_ = hostileBody // documents the threat; it is structurally unable to reach the build

	create := buildCreateRequest(policy, "tenant-hint")

	if create.WorkloadTrustProfile != policy.WorkloadTrustProfile {
		t.Errorf("trust profile must come from policy (%d), got %d — a caller must not set it",
			policy.WorkloadTrustProfile, create.WorkloadTrustProfile)
	}
	if create.ResourceCaps.CPUCores != policy.ResourceCaps.CPUCores {
		t.Errorf("resource caps must come from policy (%v), got %v — a caller must not widen them",
			policy.ResourceCaps.CPUCores, create.ResourceCaps.CPUCores)
	}
	if create.EgressPolicy.DefaultDeny != policy.EgressPolicy.DefaultDeny ||
		create.EgressPolicy.AllowedUpstream != policy.EgressPolicy.AllowedUpstream {
		t.Errorf("egress policy must come from policy, got default_deny=%v upstream=%q — a caller must not open egress",
			create.EgressPolicy.DefaultDeny, create.EgressPolicy.AllowedUpstream)
	}
	// The one caller-influenced field is the hint, and only the hint.
	if create.SessionHint != "tenant-hint" {
		t.Errorf("session hint is the only caller-influenced field; got %q", create.SessionHint)
	}
}

// TestSessionHintIsCallerTenantOnly proves that with NO chat scope the hint is the
// caller principal's non-secret Tenant handle — never a credential, never an
// authority. With a chat scope it is keyed per-chat (see session_hint_test.go).
func TestSessionHintIsCallerTenantOnly(t *testing.T) {
	got := sessionHintFor(auth.Caller{KeyID: "k9", Tenant: "tenant-b", Deployment: "deploy-x"}, "")
	if got != "tenant-b" {
		t.Errorf("session hint with no chat scope must be the caller Tenant handle, got %q", got)
	}
	scoped := sessionHintFor(auth.Caller{Tenant: "tenant-b"}, "chat-7")
	if scoped == "tenant-b" || scoped == "" {
		t.Errorf("session hint WITH a chat scope must differ from the bare tenant, got %q", scoped)
	}
}

// TestCreateRefusesUnspecifiedProfile — an unspecified/unknown workload trust
// profile is a fail-closed admission refusal, mirroring the server. Red-probe:
// neuter WorkloadTrustProfile.valid to always-true and this goes green wrongly.
func TestCreateRefusesUnspecifiedProfile(t *testing.T) {
	p := validProvisioning()
	p.WorkloadTrustProfile = WorkloadTrustProfileUnspecified
	err := buildCreateRequest(p, "h").validate()
	if !errors.Is(err, ErrForwardFailed) {
		t.Fatalf("an unspecified workload trust profile must be refused fail-closed, got %v", err)
	}
}

// TestCreateRefusesBadMountScope — a mount with neither or both scope ids is
// malformed (the proto's documented XOR) and refused before forward.
func TestCreateRefusesBadMountScope(t *testing.T) {
	// Neither scope set.
	p := validProvisioning()
	p.MountIntent.FilesystemID = ""
	p.MountIntent.MemoryStoreID = ""
	if err := buildCreateRequest(p, "h").validate(); !errors.Is(err, ErrForwardFailed) {
		t.Errorf("a mount with no scope must be refused, got %v", err)
	}
	// Both scopes set.
	p2 := validProvisioning()
	p2.MountIntent.FilesystemID = "fs-1"
	p2.MountIntent.MemoryStoreID = "mem-1"
	if err := buildCreateRequest(p2, "h").validate(); !errors.Is(err, ErrForwardFailed) {
		t.Errorf("a mount with both scopes must be refused, got %v", err)
	}
}

// TestCreateRefusesUnsetPidsCap — production must not forward an unset pids cap
// the server would read as "no limit".
func TestCreateRefusesUnsetPidsCap(t *testing.T) {
	p := validProvisioning()
	p.ResourceCaps.PIDsLimit = nil
	if err := buildCreateRequest(p, "h").validate(); !errors.Is(err, ErrForwardFailed) {
		t.Errorf("an unset pids cap must be refused, got %v", err)
	}
}

// TestValidCreatePasses — the admissible policy validates, so the refusals above
// are not stuck-closed (the gate is two-sided).
func TestValidCreatePasses(t *testing.T) {
	if err := buildCreateRequest(validProvisioning(), "h").validate(); err != nil {
		t.Fatalf("an admissible create must validate, got %v", err)
	}
}

// TestConstructorRefusesInadmissiblePolicy — the forwarder refuses to construct
// with an inadmissible provisioning policy, so a misconfiguration fails at boot,
// not mid-request.
func TestConstructorRefusesInadmissiblePolicy(t *testing.T) {
	bad := validProvisioning()
	bad.WorkloadTrustProfile = WorkloadTrustProfileUnspecified
	_, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "https://control:8443", TLS: goodTLS()},
		staticCred{token: "t", principal: "gw"},
		bad,
	)
	if !errors.Is(err, ErrForwardFailed) {
		t.Fatalf("an inadmissible provisioning policy must fail construction, got %v", err)
	}
}

// TestCreateCarriesNoCredentialField is a type-fact custody guard: a CreateRequest
// serialized whole contains none of the credential-bearing strings a caller might
// try to smuggle. There is no field to hold them, so this can never regress
// without a type change.
func TestCreateCarriesNoCredentialField(t *testing.T) {
	create := buildCreateRequest(validProvisioning(), "tenant-x")
	blob, err := json.Marshal(create)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(blob)
	for _, forbidden := range []string{"auth_token", "authToken", "Authorization", "Bearer", "storage-jwt", "StorageJWT", "credential"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("CreateRequest must carry no credential field; found %q in %s", forbidden, s)
		}
	}
}

// TestRouteIsFailClosedStubUntilG2 — Route is a deliberate fail-closed seam stub:
// the canon RouteResponse needs a per-session control_endpoint that Control does
// not yet expose (it appears with the G2 exec-driver). It refuses rather than
// fabricating an endpoint or returning the wrong contract (status returns key/state,
// not an endpoint). This stays RED-on-neuter: were Route to fabricate a
// CreateResponse, this would fail.
func TestRouteIsFailClosedStubUntilG2(t *testing.T) {
	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{Endpoint: "https://control:8443", TLS: goodTLS()},
		staticCred{token: "t", principal: "gw"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, rerr := f.Route(context.Background(), CreateRequest{}); !errors.Is(rerr, ErrForwardFailed) {
		t.Errorf("Route must be a fail-closed stub until the G2 exec-driver, got %v", rerr)
	}
}

// TestDestroyFailsClosedWithoutTransport — Destroy is LIVE (POST
// /v1alpha/sessions/destroy), so with no endpoint / no hardened transport it must
// fail closed rather than pretend a teardown. The reachable-server success path is
// covered by TestDestroyLiveRoundTrip; here we pin the fail-closed halves so the
// live path cannot silently no-op when the transport is absent.
func TestDestroyFailsClosedWithoutTransport(t *testing.T) {
	// No endpoint: every Destroy fails closed.
	noEndpoint, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "gw"},
		DialConfig{}, // no endpoint, no TLS
		staticCred{token: "t", principal: "gw"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct no-endpoint: %v", err)
	}
	if derr := noEndpoint.Destroy(context.Background(), "session-x"); !errors.Is(derr, ErrForwardFailed) {
		t.Errorf("Destroy with no endpoint must fail closed, got %v", derr)
	}
}
