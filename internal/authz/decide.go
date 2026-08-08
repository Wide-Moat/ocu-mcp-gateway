// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package authz

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// ErrDenied reports a call the policy refuses. It carries no caller-derived
// value in its message beyond the tool name and the profile, both of which the
// deployment already declared — a deny reason must not echo an agent-supplied
// path back onto a surface an operator reads.
var ErrDenied = errors.New("authz: denied by policy")

// The reasons a call is denied. Each is a distinct sentinel wrapping ErrDenied,
// so a test can bind an assertion to the guard it names rather than to whichever
// guard happens to fire first. Every one of these guards is shadowed by the next
// — remove any single one and a later check still denies — so a test asserting
// only "some error" would leave each of them free to delete.
//
// They are also what an operator reads: "no policy loaded" is a deployment
// fault, "profile does not grant" is a policy decision, and "outside the
// declared prefixes" is an argument-scoped refusal. Collapsing them would make
// a wiring bug indistinguishable from a working denial.
var (
	ErrNoPolicy        = errors.New("authz: no policy is loaded")
	ErrUnknownProfile  = errors.New("authz: bound profile is not declared")
	ErrToolNotGranted  = errors.New("authz: profile does not grant this tool")
	ErrPathUnevaluable = errors.New("authz: tool carries a path predicate but the call names no readable path")
	ErrPathOutOfScope  = errors.New("authz: path lies outside every declared prefix")
)

// Decide reports whether callerID may invoke tool with args, per the policy
// (ADR-0041, NFR-SEC-49).
//
// Deny-by-default is a property of THIS function, not of any shipped rule set: a
// tool the bound profile does not name is denied, and a path outside every
// listed prefix is denied. The baseline policy a deployment gets is permissive
// and explicit; the evaluator is what makes the omissions mean something.
//
// A zero Policy denies everything. A wiring bug that leaves the evaluator
// unloaded must refuse calls rather than serve them unchecked.
func (p Policy) Decide(callerID, tool string, args map[string]any) error {
	if len(p.Profiles) == 0 {
		return fmt.Errorf("%w: %w", ErrDenied, ErrNoPolicy)
	}

	profileName := p.ProfileFor(callerID)
	profile, ok := p.Profiles[profileName]
	if !ok {
		// Load refuses a policy whose bindings do not resolve, so reaching here
		// means the Policy was assembled without Load. Deny rather than trust it.
		return fmt.Errorf("%w: %w: %q", ErrDenied, ErrUnknownProfile, profileName)
	}

	rule, granted := profile.Tools[tool]
	if !granted {
		return fmt.Errorf("%w: %w: profile %q, tool %q", ErrDenied, ErrToolNotGranted, profileName, tool)
	}
	if len(rule.PathPrefixes) == 0 {
		// The tool is granted as a class with no argument predicate. This is the
		// whole decision for a shell-class tool: its command content carries no
		// rule, because a command-pattern deny cannot meet NFR-SEC-49's own
		// zero-red-team-pass criterion, and its effects are confined by the
		// sandbox boundary instead.
		return nil
	}

	raw, ok := args["path"].(string)
	if !ok || raw == "" {
		// The rule carries a path predicate and the call names no path the
		// evaluator can read. Allowing would skip the predicate entirely, which
		// is the one outcome a deny-by-default evaluator must not produce.
		return fmt.Errorf("%w: %w: tool %q", ErrDenied, ErrPathUnevaluable, tool)
	}
	if !pathUnderAnyPrefix(raw, rule.PathPrefixes) {
		return fmt.Errorf("%w: %w: profile %q, tool %q", ErrDenied, ErrPathOutOfScope, profileName, tool)
	}
	return nil
}

// pathUnderAnyPrefix reports whether p normalizes to an absolute path lying
// under one of the prefixes.
//
// The comparison happens AFTER normalization, so a traversal cannot walk out of
// a granted prefix, and a path that walks up and back down is judged on where it
// lands rather than on the characters it contains. A relative path is refused
// outright: its meaning depends on a working directory the gateway does not have
// and the guest may not share.
//
// The predicate is lexical. Symlink and mount semantics are enforced by the
// sandbox mount plan, not here, and both halves are required (ADR-0041).
// A relative path needs no separate guard: path.Clean leaves it relative
// ("./home/x" cleans to "home/x"), and every declared prefix is absolute, so the
// comparison below cannot match one. An explicit HasPrefix(p, "/") check was
// written here first and removed — mutation testing showed deleting it changed
// no outcome, which makes it a line that reads like a control while enforcing
// nothing.
func pathUnderAnyPrefix(p string, prefixes []string) bool {
	clean := path.Clean(p)
	for _, prefix := range prefixes {
		// The schema requires a trailing separator on every prefix, which is what
		// makes the boundary decidable: comparing against the cleaned prefix plus
		// "/" means /home/assistant/ never admits /home/assistant2, while a plain
		// HasPrefix would.
		cleanPrefix := path.Clean(prefix)
		if clean == cleanPrefix || strings.HasPrefix(clean, cleanPrefix+"/") {
			return true
		}
	}
	return false
}
