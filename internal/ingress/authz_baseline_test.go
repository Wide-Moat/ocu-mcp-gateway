// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/authz"
)

// TestBaselineAuthzPolicyLoads is what stands between a typo in the committed
// baseline and a gateway that will not boot. The boot path loads this exact
// document when a deployment configures no policy of its own, and Load is
// deliberately strict — an unserved tool name or a prefix missing its trailing
// separator is a boot failure, which is correct at runtime and unhelpful as the
// first sign of a bad edit.
func TestBaselineAuthzPolicyLoads(t *testing.T) {
	p, err := authz.Load(BaselineAuthzPolicy, AdvertisedToolNames())
	if err != nil {
		t.Fatalf("the committed baseline does not load: %v", err)
	}

	// The baseline must grant the advertised surface: it exists to reproduce
	// today's behaviour as an auditable rule set, so a tool the gateway serves
	// but the baseline omits would be a silent narrowing on upgrade.
	for _, tool := range AdvertisedToolNames() {
		if err := p.Decide("any-caller", tool, argsForBaselineProbe(tool)); err != nil {
			t.Errorf("the baseline denies advertised tool %q: %v — an operator who "+
				"configures nothing would lose a tool that worked before", tool, err)
		}
	}
}

// argsForBaselineProbe supplies an argument set each tool's rule can evaluate.
// A file verb probed with no path would be denied for a reason unrelated to what
// this test asks.
func argsForBaselineProbe(tool string) map[string]any {
	switch tool {
	case "bash_tool", "resolve_scope":
		return nil
	default:
		return map[string]any{"path": "/home/assistant/probe"}
	}
}
