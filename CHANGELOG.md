<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This component carries
no semver release yet; its MCP wire revision is the date string `2025-06-18`
negotiated on `initialize` (NFR-IC-04).

## [Unreleased]

### Added — initial scaffold

- The MCP gateway daemon (`cmd/ocu-mcp-gatewayd`): load-before-bind composition
  root that binds the MCP listener only after the Control-owned authentication
  material is loaded (fail-closed boot).
- The two-pass OCU constraint-profile validator (`internal/profile`): MCP base
  schema then the OCU overlay, dispatched per message kind, with pre-buffer size
  ceilings and a leak-free structured deny. Property-tested.
- The caller-authentication seam (`internal/auth`) abstracting the minimal-shelf
  static `sk-ocu-` validator (real salted SHA-256, constant-time compare,
  timing-neutral prefix check) and the full-shelf OAuth 2.1 RS path (ADR-0027,
  gated on PR #311).
- The F5 forward under the gateway's own service identity (`internal/forward`):
  the caller credential has no field on the forward shapes (a type fact).
- The MCP ingress (`internal/ingress`): bounded read posture, and the boundary
  order protocol-version-pin → auth (header-only) → connection-ceiling →
  bounded-decode → validate → forward → leak-free response.
- The per-caller connection ceiling (`internal/quota`): refuse-not-queue.
- Vendored, byte-identical OCU constraint profile under `contracts/mcp/2025-06-18/`
  with provenance in `VENDORED.md` (canon `62f5eeb`).
- `CONSTITUTION.md`: the load-bearing invariants, each mapped to a named enforcing
  test and proven RED-when-neutered.
- CI: `security.yml` (SHA-pinned actions, binary-pinned gitleaks/trufflehog,
  semgrep, trivy, a `sk-ocu-` gitleaks rule) and `go.yml` (fmt, vet, staticcheck,
  golangci-lint, test, race, ≥80% coverage floor, property tests).
- `deploy/` manifests (k8s NetworkPolicy + Compose) and the NFR-SEC-52
  IaC-policy gate (`scripts/iac_policy_check.py`) asserting no gateway→operator
  network route, with a two-sided self-test red-probe.
