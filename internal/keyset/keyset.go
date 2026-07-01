// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package keyset validates a Control-delivered MCP hashed-key boot-set against
// the frozen canon schema (contracts/mcp/mcp-key-set.schema.json, ADR-0027,
// vendored byte-identical). It is the boot-load fail-closed gate: a set that
// violates the frozen shape — an empty records array, a non-"active" status, an
// unsalted-looking or malformed hash, a short salt, or an extra field smuggling a
// secret past additionalProperties:false — is refused here before it is mapped,
// so a bad render never reaches the authenticator.
//
// The schema validates SHAPE only. The peer invariants — omit-before-render,
// boot-refresh-within-5-min (NFR-SEC-04), deployment homogeneity, and
// constant-time comparison — are enforced in the loader and the authenticator,
// not the schema (they are not JSON-Schema-expressible).
package keyset

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Wide-Moat/ocu-mcp-gateway/contracts"
)

// schemaURL is the $id of the vendored key-set schema; the compiler keys the
// resource on it.
const schemaURL = "https://schemas.open-computer-use.dev/mcp/mcp-key-set.schema.json"

var (
	compileOnce sync.Once
	compiled    *jsonschema.Schema
	compileErr  error
)

// compile builds the validator from the embedded vendored schema exactly once. A
// compile failure is a build/vendoring error (the embedded schema is malformed),
// surfaced to every Validate call so the loader fails closed rather than skipping
// validation.
func compile() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		var raw any
		if err := json.Unmarshal(contracts.MCPKeySetSchema, &raw); err != nil {
			compileErr = fmt.Errorf("keyset: parse embedded key-set schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(schemaURL, raw); err != nil {
			compileErr = fmt.Errorf("keyset: add embedded key-set schema resource: %w", err)
			return
		}
		sch, err := c.Compile(schemaURL)
		if err != nil {
			compileErr = fmt.Errorf("keyset: compile embedded key-set schema: %w", err)
			return
		}
		compiled = sch
	})
	return compiled, compileErr
}

// Validate checks a raw boot-set JSON document against the frozen key-set schema.
// It returns a non-nil error on any schema violation (or on a document that is
// not valid JSON), so the caller refuses the boot-set fail-closed. A nil return
// means the SHAPE is valid; the peer invariants are enforced elsewhere.
func Validate(raw []byte) error {
	sch, err := compile()
	if err != nil {
		return err
	}
	var inst any
	if err := json.Unmarshal(raw, &inst); err != nil {
		return fmt.Errorf("keyset: boot-set is not valid JSON: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("keyset: boot-set violates the mcp-key-set schema: %w", err)
	}
	return nil
}
