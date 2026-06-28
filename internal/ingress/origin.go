// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

// OriginPolicy validates the request Origin header against DNS-rebinding
// (x-ocu-authz: "Origin header MUST be validated (DNS-rebinding)"). A
// DNS-rebinding attack tricks a browser into sending a request to the gateway's
// local bind from an attacker-controlled page; rejecting a disallowed Origin
// blocks it.
//
// Policy: a request with NO Origin header (a non-browser/CLI client — the common
// MCP caller) is allowed, because DNS-rebinding is a browser-only attack and a
// CLI sets no Origin. A request WITH an Origin header is allowed ONLY if that
// Origin is in the configured allowlist; an Origin present but not allowed is
// refused. With an empty allowlist, any present Origin is refused (fail-closed
// for the browser case), so a misconfigured allowlist denies browser callers
// rather than admitting a rebinding attacker.
type OriginPolicy struct {
	allowed map[string]bool
}

// NewOriginPolicy builds an Origin policy from an allowlist of exact origins
// (e.g. "https://app.example.com"). A nil/empty list yields a policy that admits
// only originless (non-browser) requests — the safe DNS-rebinding default.
func NewOriginPolicy(allowed []string) OriginPolicy {
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		if o != "" {
			set[o] = true
		}
	}
	return OriginPolicy{allowed: set}
}

// Allowed reports whether a request carrying the given Origin header may proceed.
// An empty origin (no header) is allowed (non-browser caller). A present origin
// must be in the allowlist.
func (p OriginPolicy) Allowed(origin string) bool {
	if origin == "" {
		return true
	}
	return p.allowed[origin]
}
