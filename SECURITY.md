<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via GitHub's **Report a vulnerability**
(Security ▸ Advisories) on this repository, not as a public issue. Include the
affected version/commit, a reproduction, and the impact you observed. We aim to
acknowledge within a few business days.

Please do **not** open a public issue, PR, or discussion for a suspected
vulnerability until a fix is released and coordinated.

## Scope and trust boundary

This component is the **MCP gateway** — the agent tool-call ingress in front of
the control plane. Its security posture is defined by the invariants in
[`CONSTITUTION.md`](CONSTITUTION.md), each mechanically enforced. The
highest-value properties:

- The caller credential is authenticated at the transport edge and **never**
  appears on the F5 forward leg or any path reaching the sandbox.
- The gateway has **no** route — in code or on the network — to the operator
  surface (kill-switch / denylist / lifecycle).
- Outbound errors are leak-free and size-bounded.
- Every authentication and forward boundary is fail-closed.

A report demonstrating a violation of any invariant in `CONSTITUTION.md` is
in-scope and high-priority.

## Caller keys

Caller keys use the `sk-ocu-` prefix specifically so a leaked key is
scanner-detectable; a gitleaks rule for it ships in `.gitleaks.toml`. Keys are
stored only as salted SHA-256 (never plaintext) and are minted exclusively by the
control plane. If you find a committed key, treat it as compromised and report it.

## Supply chain

CI pins all GitHub Actions by 40-char commit SHA and pins scanner binaries by
version (gitleaks, trufflehog). Dependencies are mirrored from the architecture
repo's vetted set. See `.github/workflows/`.
