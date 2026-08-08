// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package authz loads and evaluates the deployment-supplied per-action
// authorization policy (ADR-0041, NFR-SEC-49).
//
// The policy is boot-loaded configuration on the same config plane that carries
// the boot credential set. It is never fetched from the Control plane at request
// time: the gateway-to-Control read edge stays forbidden, and a request-time
// lookup would put the authorization decision behind a network hop that can
// fail.
//
// A configured policy the gateway cannot trust is a BOOT failure, never a
// fallback to a default. A gateway silently running its own default while an
// operator believes their file is in force is worse than either posture alone.
package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/Wide-Moat/ocu-mcp-gateway/contracts"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaURL = "https://schemas.open-computer-use.dev/authz/gateway-authz-policy.schema.json"

// ErrUnservedTool reports a policy rule naming a tool the gateway does not
// advertise. It is a distinct sentinel because the operator response differs
// from a shape error: a rule for an unserved tool is nearly always a typo that
// would otherwise grant nothing, silently.
var ErrUnservedTool = errors.New("authz: policy names a tool the gateway does not serve")

// ToolRule is what a profile grants for one tool. An empty rule grants the tool
// class with no argument predicate — the only correct shape for a shell-class
// tool, whose command content carries no predicate (ADR-0041).
type ToolRule struct {
	// PathPrefixes are the allowed absolute prefixes for this tool's path
	// argument. Empty means the tool takes no path predicate, NOT that every
	// path is denied: the schema forbids an empty list precisely so the two
	// cannot be confused.
	PathPrefixes []string `json:"path_prefixes,omitempty"`
}

// Profile is a named grant set. A tool absent from Tools is denied for every
// caller bound to this profile — deny-by-default expressed as omission, so a
// tool added to the advertised set is denied until a policy grants it.
type Profile struct {
	Tools map[string]ToolRule `json:"tools"`
}

// Policy is a validated policy document.
type Policy struct {
	Version        int                `json:"version"`
	Profiles       map[string]Profile `json:"profiles"`
	Callers        map[string]string  `json:"callers,omitempty"`
	DefaultProfile string             `json:"default_profile"`
}

// ProfileFor reports the profile name bound to a caller, falling back to the
// default. Both are guaranteed to name a declared profile: Load refuses a
// document where either does not.
func (p Policy) ProfileFor(callerID string) string {
	if name, ok := p.Callers[callerID]; ok {
		return name
	}
	return p.DefaultProfile
}

var (
	compileOnce sync.Once
	compiled    *jsonschema.Schema
	compileErr  error
)

// compile builds the validator from the embedded vendored schema exactly once. A
// compile failure is a build or vendoring error, surfaced to every Load so the
// loader fails closed rather than skipping validation.
func compile() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		var raw any
		if err := json.Unmarshal(contracts.GatewayAuthzPolicySchema, &raw); err != nil {
			compileErr = fmt.Errorf("authz: parse embedded policy schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(schemaURL, raw); err != nil {
			compileErr = fmt.Errorf("authz: add embedded policy schema resource: %w", err)
			return
		}
		sch, err := c.Compile(schemaURL)
		if err != nil {
			compileErr = fmt.Errorf("authz: compile embedded policy schema: %w", err)
			return
		}
		compiled = sch
	})
	return compiled, compileErr
}

// Load validates a policy document and returns it, or reports why it cannot be
// trusted. advertised is the tool set the gateway serves; every tool a profile
// names must be a member.
//
// Three checks run, in this order: the frozen schema (shape), the referential
// checks the schema cannot express (a profile name must resolve), and the
// no-drift cross-check against the advertised set. Shape first, because a
// referential check over a malformed document reports confusing errors about
// the wrong thing.
func Load(raw []byte, advertised []string) (Policy, error) {
	// The advertised set is checked first: an empty one would make every rule
	// look unserved, so a caller passing none is a wiring bug, not a policy the
	// gateway should reason about.
	if len(advertised) == 0 {
		return Policy{}, errors.New("authz: no advertised tools supplied; the no-drift " +
			"cross-check would compare every policy rule against an empty set")
	}

	sch, err := compile()
	if err != nil {
		return Policy{}, err
	}
	var inst any
	if err := json.Unmarshal(raw, &inst); err != nil {
		return Policy{}, fmt.Errorf("authz: policy is not valid JSON: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return Policy{}, fmt.Errorf("authz: policy violates the frozen schema: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, fmt.Errorf("authz: decode policy: %w", err)
	}

	// Referential integrity. The schema constrains a profile NAME's shape but
	// cannot check that it resolves, so an unresolvable default would leave every
	// unbound caller's surface undefined at the first call rather than at boot.
	if _, ok := p.Profiles[p.DefaultProfile]; !ok {
		return Policy{}, fmt.Errorf("authz: default_profile %q names no declared profile", p.DefaultProfile)
	}
	for caller, profile := range p.Callers {
		if _, ok := p.Profiles[profile]; !ok {
			return Policy{}, fmt.Errorf("authz: caller %q binds to profile %q, which is not declared", caller, profile)
		}
	}

	// No-drift: every tool a rule names must be one the gateway advertises. The
	// offenders are reported together and in a stable order, so an operator
	// fixing a policy sees the whole list once instead of one name per boot.
	served := make(map[string]bool, len(advertised))
	for _, t := range advertised {
		served[t] = true
	}
	var unserved []string
	for name, prof := range p.Profiles {
		for tool := range prof.Tools {
			if !served[tool] {
				unserved = append(unserved, fmt.Sprintf("%s/%s", name, tool))
			}
		}
	}
	if len(unserved) > 0 {
		sort.Strings(unserved)
		return Policy{}, fmt.Errorf("%w: %v", ErrUnservedTool, unserved)
	}

	return p, nil
}
