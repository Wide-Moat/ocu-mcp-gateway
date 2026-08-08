// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/authz"
)

// ADR-0041 supersedes the hand-rolled resolve-only check with a resolve_scope-
// only PROFILE, and keeps the -resolve-only-key-ids syntax as sugar that
// compiles to a caller binding. These tests pin the compilation, so an operator
// keeping the flag gets the same confinement through the general mechanism
// rather than through a second, quieter one.

func TestResolveOnlyListCompilesToCallerBindings(t *testing.T) {
	base, err := authz.Load(BaselineAuthzPolicy, AdvertisedToolNames())
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	got := CompileResolveOnly(base, NewResolveOnlyPolicy("portal-a,portal-b"))

	for _, id := range []string{"portal-a", "portal-b"} {
		if name := got.ProfileFor(id); name != resolveOnlyProfileName {
			t.Errorf("caller %q bound to profile %q, want %q", id, name, resolveOnlyProfileName)
		}
	}
	// An unnamed caller keeps the surface the baseline gives it. Widening or
	// narrowing every other caller would make the flag mean something it never
	// meant.
	if name := got.ProfileFor("someone-else"); name != base.DefaultProfile {
		t.Errorf("an unnamed caller resolved to %q, want the baseline default %q",
			name, base.DefaultProfile)
	}
}

// TestCompiledConfinementRefusesAnExecutingTool is the keystone the hand-rolled
// check carried: a confined credential reaching for a tool it may not call is
// refused. It now runs through the general evaluator.
func TestCompiledConfinementRefusesAnExecutingTool(t *testing.T) {
	base, err := authz.Load(BaselineAuthzPolicy, AdvertisedToolNames())
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	p := CompileResolveOnly(base, NewResolveOnlyPolicy("portal-a"))

	if err := p.Decide("portal-a", "bash_tool", map[string]any{"command": "id"}); err == nil {
		t.Error("a confined caller reached bash_tool; a leak of the portal's " +
			"configuration would then buy an attacker a guest shell rather than a " +
			"scope lookup")
	}
	if err := p.Decide("portal-a", "resolve_scope", nil); err != nil {
		t.Errorf("a confined caller was refused the one tool it exists to call: %v", err)
	}
}

// TestEmptyResolveOnlyListLeavesThePolicyUnchanged pins the zero value. An unset
// knob must not silently confine anybody, and must not silently ADD a profile
// nothing references either.
func TestEmptyResolveOnlyListLeavesThePolicyUnchanged(t *testing.T) {
	base, err := authz.Load(BaselineAuthzPolicy, AdvertisedToolNames())
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	got := CompileResolveOnly(base, NewResolveOnlyPolicy(""))

	if len(got.Callers) != len(base.Callers) {
		t.Errorf("an empty list changed the caller bindings (%d -> %d)",
			len(base.Callers), len(got.Callers))
	}
	if err := got.Decide("anyone", "bash_tool", nil); err != nil {
		t.Errorf("an empty list confined a caller: %v", err)
	}
}

// TestEmptyResolveOnlyListAddsNoProfile is separate, and uses a policy that does
// NOT already declare the confining profile.
//
// Asserting this against the shipped baseline is unfalsifiable: the baseline
// declares "resolve-only" itself, so "the compile did not add it" holds no
// matter what the compile does. Mutation testing is what exposed that — removing
// the empty-list short-circuit left the assertion green.
func TestEmptyResolveOnlyListAddsNoProfile(t *testing.T) {
	const doc = `{
	  "version": 1,
	  "profiles": {"full": {"tools": {"bash_tool": {}, "resolve_scope": {}}}},
	  "default_profile": "full"
	}`
	base, err := authz.Load([]byte(doc), AdvertisedToolNames())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if _, present := base.Profiles[resolveOnlyProfileName]; present {
		t.Fatalf("the fixture already declares %q, so this test cannot detect an "+
			"addition", resolveOnlyProfileName)
	}

	got := CompileResolveOnly(base, NewResolveOnlyPolicy(""))
	if _, added := got.Profiles[resolveOnlyProfileName]; added {
		t.Errorf("an empty list added the %q profile; an unset knob that quietly grew "+
			"the policy would make the shipped rule set differ from the document an "+
			"operator reads", resolveOnlyProfileName)
	}
}

// TestCompileDoesNotMutateTheInputPolicy pins the copy. A Policy value shares
// its maps, so a compile that edited in place would confine callers in every
// other holder of that policy — including, at boot, the baseline a second
// deployment path might reuse.
func TestCompileDoesNotMutateTheInputPolicy(t *testing.T) {
	// The fixture MUST already carry a caller binding. The shipped baseline has
	// none, so its Callers map is nil and an in-place compile would allocate a
	// fresh map anyway — leaving nothing to alias and the assertion unfalsifiable.
	// Mutation testing surfaced that: the in-place mutant stayed green against the
	// baseline.
	const doc = `{
	  "version": 1,
	  "profiles": {
	    "full": {"tools": {"bash_tool": {}, "resolve_scope": {}}},
	    "other": {"tools": {"resolve_scope": {}}}
	  },
	  "callers": {"existing": "other"},
	  "default_profile": "full"
	}`
	base, err := authz.Load([]byte(doc), AdvertisedToolNames())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	before := len(base.Callers)

	_ = CompileResolveOnly(base, NewResolveOnlyPolicy("portal-a"))

	if len(base.Callers) != before {
		t.Errorf("CompileResolveOnly mutated its input (callers %d -> %d)", before, len(base.Callers))
	}
	if err := base.Decide("portal-a", "bash_tool", map[string]any{"command": "id"}); err != nil {
		t.Errorf("the INPUT policy now confines portal-a: %v — the compile leaked its "+
			"binding into a policy the caller still holds", err)
	}
}

// TestCompiledBindingDoesNotClobberAnExplicitPolicy keeps the sugar subordinate
// to the document. A deployment that names a caller in its own policy AND in the
// flag has expressed the binding twice; the policy file is the source of truth,
// so the flag must not silently overrule what an operator wrote down.
func TestCompiledBindingDoesNotClobberAnExplicitPolicy(t *testing.T) {
	const doc = `{
	  "version": 1,
	  "profiles": {
	    "full": {"tools": {"bash_tool": {}, "resolve_scope": {}}},
	    "custom": {"tools": {"bash_tool": {}}}
	  },
	  "callers": {"portal-a": "custom"},
	  "default_profile": "full"
	}`
	base, err := authz.Load([]byte(doc), AdvertisedToolNames())
	if err != nil {
		t.Fatalf("policy: %v", err)
	}

	got := CompileResolveOnly(base, NewResolveOnlyPolicy("portal-a"))
	if name := got.ProfileFor("portal-a"); name != "custom" {
		t.Errorf("the flag overrode an explicit policy binding (%q -> %q); the "+
			"document an operator wrote is the source of truth", "custom", name)
	}
}
