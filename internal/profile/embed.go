// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import _ "embed"

// constraintProfileJSON is the vendored OCU MCP constraint profile, embedded at
// build time so the validator carries its contract in the binary rather than
// reading it from disk at boot (a disk read would be a fail-open seam: a missing
// or truncated file must never silently relax validation). The source is the
// canon wire contract vendored byte-identical at contracts/mcp/2025-06-18/ — see
// VENDORED.md for its provenance (canon SHA 099d3d7, blob OID 23b28bd, the
// ADR-0027 two-shelf x-ocu-authz re-pin). vendored_drift_test.go pins that this
// copy stays byte-identical to contracts/mcp/2025-06-18/ — scripts/vendored_check.py
// only tracks the contracts/ path against canon, not this copy against contracts/,
// so a canon re-pin can otherwise leave this embed silently stale. The relative
// path is resolved from THIS package directory by go:embed.
//
//go:embed ocu-constraints.schema.json
var constraintProfileJSON []byte

// ProfileBytes returns the embedded constraint profile. It is exposed so a
// conformance test can assert the embedded bytes are byte-identical to the
// vendored file on disk — proving the binary validates against the same contract
// the repository vendored, with no drift.
func ProfileBytes() []byte {
	// Return a copy so a caller cannot mutate the embedded contract.
	out := make([]byte, len(constraintProfileJSON))
	copy(out, constraintProfileJSON)
	return out
}
