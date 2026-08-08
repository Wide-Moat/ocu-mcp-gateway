// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"strings"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/authz"
)

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

// Restricted reports whether the deployment list names this caller. The request
// path no longer consults it — CompileResolveOnly folds the list into the
// authorization policy (ADR-0041), so the confinement is decided by the one
// evaluator. It remains as the accessor the list-parsing test asserts against.
func (p ResolveOnlyPolicy) Restricted(keyID string) bool {
	return p.restricted[keyID]
}

// resolveOnlyProfileName is the profile a compiled resolve-only binding points
// at. It is added only when the deployment names at least one caller, so a
// policy carries no profile nothing references.
const resolveOnlyProfileName = "resolve-only"

// CompileResolveOnly folds the -resolve-only-key-ids list into an authorization
// policy as caller bindings (ADR-0041), superseding the hand-rolled confinement
// this file used to enforce in the request path.
//
// The flag survives as SUGAR, not as a second mechanism: an operator keeping it
// gets the same confinement through the general evaluator, so there is one place
// where a caller's surface is decided and one place to audit.
//
// A caller the POLICY already binds is left alone. Naming a caller in both the
// document and the flag expresses the binding twice, and the document is what an
// operator wrote down — silently overruling it would make the flag a hidden
// override of the file it is meant to abbreviate.
func CompileResolveOnly(p authz.Policy, r ResolveOnlyPolicy) authz.Policy {
	if len(r.restricted) == 0 {
		return p
	}

	// Copy before mutating: the caller's policy may be shared, and a compile that
	// edited it in place would confine callers in every other holder of it too.
	out := p
	out.Profiles = make(map[string]authz.Profile, len(p.Profiles)+1)
	for k, v := range p.Profiles {
		out.Profiles[k] = v
	}
	out.Callers = make(map[string]string, len(p.Callers)+len(r.restricted))
	for k, v := range p.Callers {
		out.Callers[k] = v
	}

	if _, ok := out.Profiles[resolveOnlyProfileName]; !ok {
		out.Profiles[resolveOnlyProfileName] = authz.Profile{
			Tools: map[string]authz.ToolRule{resolveScopeToolName: {}},
		}
	}
	for id := range r.restricted {
		if _, alreadyBound := out.Callers[id]; alreadyBound {
			continue
		}
		out.Callers[id] = resolveOnlyProfileName
	}
	return out
}
