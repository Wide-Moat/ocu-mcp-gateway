// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import "strings"

// ResolveOnlyPolicy names the caller credentials this deployment confines to the
// synthetic resolve_scope tool.
//
// An embedding portal needs exactly one answer from the gateway — which storage
// scope a chat belongs to, so it can render that chat's files. It needs no tool
// execution at all. A credential that can ALSO reach bash_tool, create_file,
// str_replace or view turns a leak of the portal's configuration into guest code
// execution, so a deployment binds such a credential to the one call it needs and
// refuses the rest. A restricted caller still crosses every other boundary
// unchanged (auth, ceiling, profile validation, audit); it loses only the ability
// to name an executing tool.
//
// The restriction keys on Caller.KeyID — the stable, non-secret identifier of the
// RESOLVED credential record — and lives in DEPLOYMENT CONFIGURATION, never in the
// key record. A record that carried its own privilege field would be authority the
// credential asserts about itself, the shape this gateway's authentication
// deliberately refuses (NFR-SEC-09: a looked-up record outranks a self-asserted
// claim), and the key-set contract is frozen against exactly that addition.
// Configuration also lets an operator widen or narrow the confinement without
// re-minting and re-distributing a key.
//
// The zero value restricts NOBODY. An unset knob must not silently strip tools
// from every caller; a caller this policy does not name keeps the surface the
// tool-name allowlist already governs.
type ResolveOnlyPolicy struct {
	restricted map[string]bool
}

// NewResolveOnlyPolicy builds the policy from a comma-separated list of key ids
// ("portal-a,portal-b"). Entries are trimmed and empty ones dropped, so a
// trailing comma or a line-wrapped deployment value cannot mint a restriction on
// the empty key id — an entry that would otherwise confine every caller whose
// record resolved without one. An empty or whitespace-only list yields the zero
// policy: no caller is restricted.
func NewResolveOnlyPolicy(keyIDs string) ResolveOnlyPolicy {
	set := make(map[string]bool)
	for _, id := range strings.Split(keyIDs, ",") {
		if id = strings.TrimSpace(id); id != "" {
			set[id] = true
		}
	}
	return ResolveOnlyPolicy{restricted: set}
}

// Restricted reports whether the resolved caller is confined to resolve_scope.
// It is asked with the KeyID the authenticator resolved, never with a
// caller-supplied value, so the answer cannot be steered from the wire.
func (p ResolveOnlyPolicy) Restricted(keyID string) bool {
	return p.restricted[keyID]
}
