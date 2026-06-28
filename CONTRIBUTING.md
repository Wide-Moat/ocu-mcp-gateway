<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Contributing

## Ground rules

- **Canon is the source of truth.** The contract this component implements lives
  in the architecture repo (`Wide-Moat/open-computer-use`), pinned by SHA in
  [`VENDORED.md`](VENDORED.md). Do not re-decide here what an ADR or the frozen
  wire contract already fixed; a behaviour change goes to the canon first.
- **Invariants are load-bearing.** Every property in
  [`CONSTITUTION.md`](CONSTITUTION.md) is enforced by a named test. A change that
  weakens one must update its enforcing test **in the same commit**, and a CI gate
  must be proven RED-when-neutered (a two-sided red-probe), not assumed.
- **Merge is owner-gated.** Push and open-PR are delegated; merging to `main` is
  not. Open a PR and let the owner merge.

## Before you open a PR

Run the gates locally:

```sh
gofmt -l .              # must be empty
go vet ./...
go test ./... -race
go test ./internal/profile/ -run 'NeverPanics' -rapid.checks=10000   # property tests
python3 scripts/iac_policy_check.py --self-test                      # IaC red-probe
python3 scripts/iac_policy_check.py                                  # IaC gate
```

Internal-package line coverage must stay **≥ 80%** (the `coverage` CI job
enforces it).

## Commit and PR conventions

- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, …). The PR
  title is linted against the same convention.
- Sign your commits (the security workflow expects signed, conventional commits).
- Keep `.planning/` out of commits (it is gitignored; it is local-only).
- All committed content is **English only**.

## What lives where

- `cmd/ocu-mcp-gatewayd/` — the daemon composition root (load-before-bind).
- `internal/auth/` — the caller-auth seam + the minimal-shelf `sk-ocu-` validator.
- `internal/profile/` — the two-pass OCU constraint-profile validator.
- `internal/ingress/` — the MCP listener + the boundary-order handler.
- `internal/forward/` — the F5 forward under the gateway service identity.
- `internal/quota/` — the per-caller connection ceiling.
- `internal/boot/`, `internal/config/` — boot sequencing and the boot-set loader.
- `contracts/mcp/2025-06-18/` — the vendored, byte-identical wire contract.
- `deploy/`, `scripts/iac_policy_check.py` — the rendered manifests + the
  NFR-SEC-52 network-policy gate.
