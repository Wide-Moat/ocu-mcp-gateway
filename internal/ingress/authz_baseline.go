// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import _ "embed"

// BaselineAuthzPolicy is the committed default policy (ADR-0041). A deployment
// that configures none runs today's surface under an auditable rule set rather
// than under an absence.
//
// It is permissive and explicit, which is the shape ADR-0041 requires: a
// deny-all default would ship a gateway that answers nothing and break the
// one-click install, while an allow-all default would be the pre-policy hole
// wearing a file. Deny-by-default is a property of the evaluator, not of this
// document — every tool omitted here is refused, and the prefixes bound the
// file verbs to the workspace the guest actually mounts.
//
//go:embed authz_baseline.json
var BaselineAuthzPolicy []byte

// AdvertisedToolNames is the served tool set, derived from the same embedded
// tool list the name allowlist is built from. The policy loader cross-checks
// every rule against it, so a rule naming a tool the gateway does not serve
// fails boot rather than granting nothing silently.
func AdvertisedToolNames() []string {
	out := make([]string, 0, len(allowedToolNames))
	for name := range allowedToolNames {
		out = append(out, name)
	}
	return out
}
