// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authz

import (
	"errors"
	"strings"
	"testing"
)

// The loader's whole job is refusing a policy it cannot trust. ADR-0041 makes a
// configured-but-unusable policy a BOOT failure rather than a runtime fallback,
// because a gateway that silently ran a default while an operator believed their
// file was in force is the worst of both postures.

const baseline = `{
  "version": 1,
  "profiles": {
    "full": {
      "tools": {
        "bash_tool": {},
        "view": {"path_prefixes": ["/home/assistant/"]}
      }
    },
    "resolve-only": {"tools": {"resolve_scope": {}}}
  },
  "callers": {"portal-a": "resolve-only"},
  "default_profile": "full"
}`

func TestLoadAcceptsAConformingPolicy(t *testing.T) {
	p, err := Load([]byte(baseline), []string{"bash_tool", "view", "resolve_scope"})
	if err != nil {
		t.Fatalf("a conforming policy was refused: %v", err)
	}
	if p.DefaultProfile != "full" {
		t.Errorf("default_profile = %q, want %q", p.DefaultProfile, "full")
	}
	if got := p.ProfileFor("portal-a"); got != "resolve-only" {
		t.Errorf("bound caller resolved to %q, want %q", got, "resolve-only")
	}
	if got := p.ProfileFor("someone-else"); got != "full" {
		t.Errorf("unbound caller resolved to %q, want the default %q", got, "full")
	}
}

// TestLoadRefusesAMalformedPolicy covers every way a document must fail to load.
// Each is a boot failure: the alternative is a gateway serving a surface nobody
// declared.
func TestLoadRefusesAMalformedPolicy(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{name: "not JSON", doc: `{`},
		{name: "empty document", doc: ``},
		{
			name: "schema violation: regex smuggled into a rule",
			doc:  `{"version":1,"profiles":{"f":{"tools":{"view":{"path_regex":".*"}}}},"default_profile":"f"}`,
		},
		{
			name: "schema violation: prefix without a trailing separator",
			doc:  `{"version":1,"profiles":{"f":{"tools":{"view":{"path_prefixes":["/home/assistant"]}}}},"default_profile":"f"}`,
		},
		{
			name: "schema violation: empty prefix list",
			doc:  `{"version":1,"profiles":{"f":{"tools":{"view":{"path_prefixes":[]}}}},"default_profile":"f"}`,
		},
		{
			name: "default_profile names no declared profile",
			doc:  `{"version":1,"profiles":{"f":{"tools":{}}},"default_profile":"nonexistent"}`,
		},
		{
			name: "a caller binds to no declared profile",
			doc:  `{"version":1,"profiles":{"f":{"tools":{}}},"callers":{"a":"ghost"},"default_profile":"f"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load([]byte(tc.doc), []string{"view", "resolve_scope"}); err == nil {
				t.Errorf("Load accepted %s — a policy the gateway cannot trust would "+
					"take effect at the first call instead of failing boot", tc.name)
			}
		})
	}
}

// TestLoadRefusesARuleForAnUnservedTool is the no-drift arm ADR-0041 names. A
// rule for a tool nobody serves is one no audit of the served surface can check,
// and it usually means a typo silently granting nothing.
func TestLoadRefusesARuleForAnUnservedTool(t *testing.T) {
	doc := `{"version":1,"profiles":{"f":{"tools":{"bash_toool":{}}}},"default_profile":"f"}`
	_, err := Load([]byte(doc), []string{"bash_tool", "view"})
	if err == nil {
		t.Fatal("Load accepted a rule for a tool the gateway does not advertise")
	}
	if !errors.Is(err, ErrUnservedTool) {
		t.Errorf("error %v does not wrap ErrUnservedTool", err)
	}
	if !strings.Contains(err.Error(), "bash_toool") {
		t.Errorf("the error does not name the offending tool: %v", err)
	}
}

// TestLoadRefusesAnEmptyAdvertisedSet fails closed on the cross-check INPUT,
// which is a different defect from the cross-check itself failing.
//
// The policy used here grants no tools at all, so the unserved-tool check has
// nothing to complain about and cannot mask the guard. A policy that did name
// tools would be refused either way, and the assertion would not be bound to
// the guard it names — removing the guard would leave such a test green.
func TestLoadRefusesAnEmptyAdvertisedSet(t *testing.T) {
	grantsNothing := `{"version":1,"profiles":{"f":{"tools":{}}},"default_profile":"f"}`

	// Control: with a non-empty advertised set the same document loads, so the
	// refusal below is attributable to the empty set and nothing else.
	if _, err := Load([]byte(grantsNothing), []string{"view"}); err != nil {
		t.Fatalf("the control policy was refused for an unrelated reason: %v", err)
	}

	if _, err := Load([]byte(grantsNothing), nil); err == nil {
		t.Error("Load accepted a policy with no advertised tools to check against; " +
			"a caller passing none is a wiring bug, and every rule would then be " +
			"validated against an empty set")
	}
}
