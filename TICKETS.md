<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Deferred work (declared, not silent)

Items intentionally deferred from the scaffold, each with a reason and a landing
gate. Nothing here is a silent cap — a reviewer (and CI) can see what is owed.

## T1 — JSON-RPC `id` propagation through the F5 forward

**From:** CodeRabbit finding (handler.go — the JSON-RPC `id` is dropped before the
forward, so a response cannot correlate to its request).

**Why deferred:** the forward is a fail-closed stub today (it returns 502, no
response is built from a forward result), so there is no response to correlate
yet. The `id` belongs in the **frozen Control session-setup request shape (PR
#293)**, not an invented field in this repo — inventing a cross-component field is
the fail-open class the fleet avoids.

**Lands with:** the real F5 forward (P1), once #293's `session_setup` schema is
vendored. The `id` is threaded from the inbound request, carried on the forward,
and echoed on the response. Own enforcing test then (request `id` == response
`id`).

## T2 — Pin the semgrep scanner image by digest

**From:** CodeRabbit finding (`.github/workflows/security.yml` — the semgrep
container used the movable `semgrep/semgrep` tag).

**Status:** mitigated — pinned to the versioned tag `semgrep/semgrep:1.96.0`
(reproducible, no longer floating to latest) and added `persist-credentials:
false` to the job checkout.

**Why not fully closed:** a full digest pin (`semgrep/semgrep@sha256:...`) is the
stronger form but needs a verified pull to capture the digest. Lands when a
verified pull is available in CI. The sibling `ocu-control` uses the same
versioned-tag form, so this is at parity and stricter than the original movable
tag.

## T3 — Contract: `boundedError.data` has no JSON `type` (canon-owned)

**From:** CodeRabbit finding (`contracts/mcp/2025-06-18/ocu-constraints.schema.json`
— `boundedError.data` declares no `type`, so it accepts any JSON).

**Why not fixed here:** the wire contract is **vendored byte-identical from canon**
(blob OID recorded in `VENDORED.md`); this repo must not edit it. The `data`
field is intentionally typeless in the contract (it carries the optional
protocol-version negotiation hint, bounded by `maxErrorDataBytes` at the gateway).
If a tighter type is wanted it changes in the architecture canon first.

**Action:** raised with the architect as a canon-side observation; no gateway-side
change.
