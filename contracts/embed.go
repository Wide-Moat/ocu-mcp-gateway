// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package contracts embeds the vendored canon contract artifacts so the gateway
// validates against the SAME bytes recorded in VENDORED.md — there is no second
// copy to drift. The files are vendored byte-identical from canon (blob OIDs in
// VENDORED.md, enforced by scripts/vendored_check.py); embedding them here means
// the running binary and the byte-equality gate check one and the same file.
package contracts

import _ "embed"

// MCPKeySetSchema is the frozen Control→gateway hashed-key-set JSON Schema
// (contracts/mcp/mcp-key-set.schema.json, ADR-0027, PR #318). The boot-set loader
// validates the delivered key set against this before mapping it.
//
//go:embed mcp/mcp-key-set.schema.json
var MCPKeySetSchema []byte
