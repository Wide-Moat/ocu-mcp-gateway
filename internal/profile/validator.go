// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Limits are the OCU-side size bounds (x-ocu-limits). They are RETUNABLE
// operator defaults within the NFR-SEC-46/51 floor, NOT frozen contract values,
// so they live as configurable fields rather than hard-coded constants. The
// counts are byte ceilings the gateway measures PRE-BUFFER (the schema's
// maxLength keywords count code points; the authoritative ceiling is the byte
// measurement here, taken before the body is decoded whole). The defaults below
// mirror the vendored contract's x-ocu-limits values.
type Limits struct {
	MaxErrorMessageBytes    int // x-ocu-limits.maxErrorMessageBytes (NFR-SEC-51)
	MaxErrorDataBytes       int // x-ocu-limits.maxErrorDataBytes (NFR-SEC-51)
	MaxToolDescriptionBytes int // x-ocu-limits.maxToolDescriptionBytes (NFR-SEC-51)
	MaxInstructionsBytes    int // x-ocu-limits.maxInstructionsBytes (NFR-SEC-51)
	MaxCallToolResultBytes  int // x-ocu-limits.maxCallToolResultBytes (NFR-SEC-46)
	MaxContentBlocks        int // x-ocu-limits.maxContentBlocks (NFR-SEC-46)
	MaxToolArgumentsBytes   int // x-ocu-limits.maxToolArgumentsBytes (NFR-SEC-46/51)
}

// DefaultLimits returns the operational defaults mirroring the vendored
// contract's x-ocu-limits block. An operator may retune any value within the
// NFR-SEC-46/51 floor; these are the enforced defaults, not a frozen contract.
func DefaultLimits() Limits {
	return Limits{
		MaxErrorMessageBytes:    1024,
		MaxErrorDataBytes:       4096,
		MaxToolDescriptionBytes: 8192,
		MaxInstructionsBytes:    8192,
		MaxCallToolResultBytes:  1048576,
		MaxContentBlocks:        256,
		MaxToolArgumentsBytes:   262144,
	}
}

// Validator applies the two-pass MCP-base-then-OCU-profile check, dispatching
// each message kind to its bound overlay $def. It is constructed once at boot
// (the embedded overlay is compiled into per-$def schemas) and is safe for
// concurrent use: it holds only compiled schemas and immutable limits.
type Validator struct {
	base   BaseValidator
	limits Limits
	// defs holds the compiled overlay schema for each bound $def name, resolved
	// from the embedded constraint profile via its $id + JSON-pointer fragment.
	defs map[string]*jsonschema.Schema
}

// NewValidator compiles the embedded OCU constraint profile and returns a
// Validator. The base pass is REQUIRED: a nil base is a fail-closed construction
// error, because skipping the base pass would let a structurally-malformed
// message reach the profile pass. The limits default to DefaultLimits when the
// zero value is passed (a zero MaxCallToolResultBytes would otherwise reject
// every result as over-size — a zero ceiling is treated as "use the default",
// never as "permit nothing", at construction; an operator who truly wants a
// tighter bound sets a positive value).
func NewValidator(base BaseValidator, limits Limits) (*Validator, error) {
	if base == nil {
		return nil, fmt.Errorf("profile: NewValidator requires a non-nil BaseValidator (the base pass is load-bearing; fail-closed)")
	}
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}

	c := jsonschema.NewCompiler()
	const profileURL = "https://schemas.open-computer-use.dev/mcp/2025-06-18/ocu-constraints.schema.json"

	var raw any
	if err := json.Unmarshal(constraintProfileJSON, &raw); err != nil {
		return nil, fmt.Errorf("profile: parse embedded constraint profile: %w", err)
	}
	if err := c.AddResource(profileURL, raw); err != nil {
		return nil, fmt.Errorf("profile: add embedded constraint profile resource: %w", err)
	}

	// Compile each bound $def by its JSON-pointer fragment. The overlay is
	// non-self-executing (no root type), so we compile the $defs individually —
	// each is the schema a message of the corresponding Kind is checked against.
	defNames := []string{
		"jsonRpcSingleMessage",
		"boundedError",
		"boundedTool",
		"boundedCallToolResult",
		"boundedInitializeResult",
	}
	defs := make(map[string]*jsonschema.Schema, len(defNames))
	for _, name := range defNames {
		sch, err := c.Compile(profileURL + "#/$defs/" + name)
		if err != nil {
			return nil, fmt.Errorf("profile: compile $def %q: %w", name, err)
		}
		defs[name] = sch
	}

	return &Validator{base: base, limits: limits, defs: defs}, nil
}

// ValidateSingleMessageEnvelope enforces jsonRpcSingleMessage: an HTTP body MUST
// be a single JSON object, never an array (batching was removed in MCP revision
// 2025-06-18). It is the FIRST check on any inbound body, before the body is
// decoded into a typed message, so a batched array is rejected pre-buffer.
func (v *Validator) ValidateSingleMessageEnvelope(raw []byte) error {
	// A leading '[' after optional whitespace is a JSON array — reject without a
	// full parse so an oversized batched body is short-circuited.
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return &Deny{Kind: KindInvalid, Reason: ReasonBatching}
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return &Deny{Kind: KindInvalid, Reason: ReasonBaseSchema}
	}
	if err := v.defs["jsonRpcSingleMessage"].Validate(doc); err != nil {
		return &Deny{Kind: KindInvalid, Reason: ReasonBatching}
	}
	return nil
}

// Validate runs the two-pass check for a message of the given kind: the MCP
// base-schema pass FIRST, then the OCU profile pass. It returns nil on accept
// and a *Deny (wrapping ErrDenied) on reject. The deny carries only a stable
// reason class and the kind — no caller-derived data (invariant #5). For an
// inbound message this is called PRE-BUFFER on the decoded body; a reject means
// nothing downstream ran.
func (v *Validator) Validate(kind Kind, raw []byte) error {
	if kind == KindInvalid {
		// A zero/unknown kind is a dispatch error: fail closed.
		return &Deny{Kind: KindInvalid, Reason: ReasonProfileSchema}
	}

	// Per-kind size ceilings, measured on the serialized bytes before any schema
	// work, so an over-size payload is rejected without being parsed or staged.
	// These run on the already-bounded bytes the ingress read under its 512KiB
	// MaxBytesReader cap (the transport-level DoS guard); this is the tighter
	// per-kind ceiling (e.g. arguments ≤256KiB), not the transport cap.
	if err := v.enforceSize(kind, raw); err != nil {
		return err
	}

	// Pass 1 — MCP base schema (structural conformance; OCU does not restate it).
	// An off-allowlist method surfaces as ReasonMethodNotFound (-32601), distinct
	// from a malformed-body base-schema violation, so a method-confusion attempt is
	// refused as "method not found" rather than mislabelled.
	if err := v.base.ValidateBase(kind, raw); err != nil {
		if errors.Is(err, errMethodNotFound) {
			return &Deny{Kind: kind, Reason: ReasonMethodNotFound}
		}
		return &Deny{Kind: kind, Reason: ReasonBaseSchema}
	}

	// Pass 2 — OCU profile overlay, dispatched to the bound $def. A kind with no
	// dedicated $def (CallToolRequest) is fully covered by the size ceiling plus
	// the base pass, so it has no overlay step.
	defName := kind.defName()
	if defName == "" {
		return nil
	}
	sch, ok := v.defs[defName]
	if !ok {
		// A bound kind whose $def did not compile is a construction bug; fail
		// closed rather than admit unchecked.
		return &Deny{Kind: kind, Reason: ReasonProfileSchema}
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return &Deny{Kind: kind, Reason: ReasonBaseSchema}
	}
	if err := sch.Validate(doc); err != nil {
		return &Deny{Kind: kind, Reason: ReasonProfileSchema}
	}
	return nil
}

// enforceSize applies the per-kind serialized-byte ceiling from Limits. It is
// the authoritative byte bound (the schema's maxLength keywords are code-point
// counts; this byte measurement is the gateway's per-kind size ceiling,
// NFR-SEC-46), applied before the schema passes so an over-size payload is not
// parsed. A zero or negative limit for a kind means "no byte ceiling configured
// for this kind" and is skipped — the schema keyword still applies in pass 2.
func (v *Validator) enforceSize(kind Kind, raw []byte) error {
	var ceiling int
	switch kind {
	case KindCallToolRequest:
		ceiling = v.limits.MaxToolArgumentsBytes
	case KindCallToolResult:
		ceiling = v.limits.MaxCallToolResultBytes
	case KindError:
		// The whole error object is bounded by message+data; the per-field
		// schema bounds catch the individual fields in pass 2. Here we bound the
		// total to the sum so an enormous error object is rejected pre-buffer.
		ceiling = v.limits.MaxErrorMessageBytes + v.limits.MaxErrorDataBytes
	case KindInitializeResult:
		ceiling = v.limits.MaxInstructionsBytes
	case KindTool:
		ceiling = v.limits.MaxToolDescriptionBytes
	}
	if ceiling > 0 && len(raw) > ceiling {
		return &Deny{Kind: kind, Reason: ReasonOverSize}
	}
	return nil
}
