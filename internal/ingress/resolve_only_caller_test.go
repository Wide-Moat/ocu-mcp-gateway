// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

// A deployment can hand an embedding portal a gateway credential whose ONLY
// purpose is to learn which storage scope a chat belongs to. That purpose does
// not include running guest code, so -resolve-only-key-ids confines the named
// credential to the synthetic resolve_scope tool: bash_tool, create_file,
// str_replace and view are refused for it, before the per-session serializer and
// before the F5 forward, so Control materializes no session for a call the
// deployment forbids.
//
// Keystone: the recording forwarder must NEVER be invoked for a confined caller's
// non-resolve tool-call — the same observable proxy for "no session exists" the
// tool-name allowlist tests use. The two known-positive controls below (an
// UNRESTRICTED caller, and an EMPTY restriction list) are what make the keystone
// discriminating: a check that refused every tool-call, or a policy accidentally
// restricting everyone, would satisfy the refusal assertion alone.

// resolveScopeCall is a well-formed tools/call naming the synthetic D5 scope tool.
const resolveScopeCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"resolve_scope","arguments":{}}}`

// resolveOnlyHandler wires a handler whose authenticator resolves a caller with
// the given KeyID, under the given comma-separated resolve-only list. Every other
// seam is the default accepting wiring, so the only variable across these tests is
// the pairing of the resolved KeyID with the deployment policy.
func resolveOnlyHandler(t *testing.T, fwd forward.Forwarder, keyID, restrictedKeyIDs string) *Handler {
	t.Helper()
	h, err := NewHandler(
		acceptAuth{caller: auth.Caller{KeyID: keyID, Tenant: "t1", Deployment: "a1"}},
		newValidator(t),
		fwd,
		quota.NewCeiling(64),
		NewOriginPolicy(nil),
		NewResolveOnlyPolicy(restrictedKeyIDs),
		newEmitter(t),
		newSerializer(t),
	)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	return h
}

// TestResolveOnlyCallerRefusedForExecutingTool is the keystone: a confined
// credential naming an executing tool is refused, and the refusal happens before
// the forward, so no session is provisioned for it. Red-probe: make the
// restricted-set lookup always report "not restricted" and every subtest goes RED
// (the call reaches the forwarder with a 200/502 instead of the 403).
func TestResolveOnlyCallerRefusedForExecutingTool(t *testing.T) {
	for _, name := range []string{"bash_tool", "create_file", "str_replace", "view"} {
		t.Run(name, func(t *testing.T) {
			fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
			h := resolveOnlyHandler(t, fwd, "portal-key", "portal-key")

			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
			rec := post(h, pinnedProtocolVersion, "sk-ocu-portal", body)

			if fwd.got != nil {
				t.Errorf("a resolve-only caller's %q call reached the F5 forward — Control provisions a session for a tool the deployment forbids this credential", name)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("a resolve-only caller's %q call must be refused 403 (the policy-refusal status the Origin guard already uses), got %d (body %q)", name, rec.Code, rec.Body.String())
			}
			var env struct {
				ID    json.RawMessage `json:"id"`
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("refusal is not a JSON-RPC envelope: %v (body %q)", err, rec.Body.String())
			}
			if env.Error.Code != rpcInvalidRequest {
				t.Errorf("a policy refusal must map to JSON-RPC %d, got %d", rpcInvalidRequest, env.Error.Code)
			}
			// Post-parse refusals echo the id; an id-less error frame hangs a client
			// that correlates by id (issue #38).
			if string(env.ID) != "1" {
				t.Errorf("a post-parse refusal must echo the request id, got %q", string(env.ID))
			}
			// Leak-free (invariant #5): the reason is a stable class, never a
			// caller- or deployment-derived identifier.
			if strings.Contains(rec.Body.String(), "portal-key") {
				t.Errorf("the refusal leaked the caller KeyID: %q", rec.Body.String())
			}
		})
	}
}

// TestResolveOnlyCallerMayCallResolveScope proves the confinement is a
// restriction, not a revocation: the one call the credential exists to make still
// reaches the forward. Without this the guard could be refusing the confined
// caller outright, which would break the portal it is meant to serve.
func TestResolveOnlyCallerMayCallResolveScope(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := resolveOnlyHandler(t, fwd, "portal-key", "portal-key")

	rec := post(h, pinnedProtocolVersion, "sk-ocu-portal", resolveScopeCall)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("a resolve-only caller must still be allowed to call resolve_scope, got 403 (body %q)", rec.Body.String())
	}
	if fwd.got == nil {
		t.Fatal("a resolve-only caller's resolve_scope call must reach the F5 forward — the scope lookup is the whole purpose of the credential")
	}
	if fwd.got.ToolCall.Name != resolveScopeToolName {
		t.Errorf("the forwarded tool-call must be %q, got %q", resolveScopeToolName, fwd.got.ToolCall.Name)
	}
}

// TestUnrestrictedCallerStillExecutesTools is a KNOWN-POSITIVE CONTROL: with a
// restriction list that names a DIFFERENT credential, an ordinary caller's
// bash_tool still forwards. A guard that refused every tool-call would satisfy the
// keystone above and fail here.
func TestUnrestrictedCallerStillExecutesTools(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := resolveOnlyHandler(t, fwd, "agent-key", "portal-key")

	rec := post(h, pinnedProtocolVersion, "sk-ocu-agent", validToolCall)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("a caller absent from the resolve-only list must not be confined, got 403 (body %q)", rec.Body.String())
	}
	if fwd.got == nil {
		t.Fatal("a caller absent from the resolve-only list must still reach the F5 forward for bash_tool")
	}
}

// TestEmptyResolveOnlyListConfinesNobody is the second KNOWN-POSITIVE CONTROL:
// with the knob unset, the same credential that the keystone confines executes
// bash_tool normally. Without it, the keystone could be passing because the policy
// was non-empty by accident (a default that silently strips tools from every
// deployment).
func TestEmptyResolveOnlyListConfinesNobody(t *testing.T) {
	for _, list := range []string{"", "   ", ",,"} {
		t.Run("list="+strings.ReplaceAll(list, " ", "_"), func(t *testing.T) {
			fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
			h := resolveOnlyHandler(t, fwd, "portal-key", list)

			rec := post(h, pinnedProtocolVersion, "sk-ocu-portal", validToolCall)

			if rec.Code == http.StatusForbidden {
				t.Fatalf("an empty resolve-only list must confine nobody, got 403 (body %q)", rec.Body.String())
			}
			if fwd.got == nil {
				t.Fatal("with no resolve-only list configured, bash_tool must still reach the F5 forward")
			}
		})
	}
}

// TestResolveOnlyPolicyParsesDeploymentList pins the configured SYNTAX: a
// comma-separated list of key ids, whitespace-tolerant, with empty entries
// dropped. The dropped-empty case is load-bearing — an entry for the empty key id
// would confine every caller whose record resolved without one, turning a stray
// trailing comma into a fleet-wide tool outage.
func TestResolveOnlyPolicyParsesDeploymentList(t *testing.T) {
	p := NewResolveOnlyPolicy(" portal-a , portal-b ,")
	for _, id := range []string{"portal-a", "portal-b"} {
		if !p.Restricted(id) {
			t.Errorf("key id %q is listed and must be confined to resolve_scope", id)
		}
	}
	if p.Restricted("agent-key") {
		t.Error("an unlisted key id must not be confined")
	}
	if p.Restricted("") {
		t.Error("the empty key id must never be confined (a trailing comma must not restrict every caller)")
	}
	if (ResolveOnlyPolicy{}).Restricted("portal-a") {
		t.Error("the zero-value policy must confine nobody")
	}
}
