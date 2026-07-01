<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# Vendored canon provenance

This repository (component-01, the MCP gateway) implements a contract owned by
the architecture canon in `Wide-Moat/open-computer-use`. The canon is pinned by
commit SHA; this file is the audit record of **what** was read and **what** was
copied, at **which** pinned revision.

Canon is **cited by name + SHA**, never linked as a cross-repo `../..` relative
path. Relative links across repositories resolve to nothing on GitHub and break
the link-checker (lychee) — every reference below is either a citation (read,
not copied) or an absolute, revision-pinned URL.

## Pinned canon revision

| Field | Value |
|---|---|
| Source repo | `Wide-Moat/open-computer-use` |
| Branch | `next/v1` |
| Pinned commit | `62f5eeb598f2f4e0370d3c35d5d70b8f204df7de` |
| Commit subject | `feat(contracts): freeze the admission tier-token vocabulary and pairing matrix (#296)` |
| Pinned date | 2026-06-22 |

To re-verify any row below against the pinned canon:

```sh
git -C <open-computer-use> rev-parse 62f5eeb598f2f4e0370d3c35d5d70b8f204df7de:<path>
# the printed git blob OID must equal the "Blob OID" column
```

## Read-only citations (not copied into this repo)

These artifacts are the contract this component implements. They are **read**,
not vendored as files — the gateway re-states facts in its own words
(`CONSTITUTION.md`, code comments) and cites the canon source here.

| Artifact | Path @ canon | Blob OID @ `62f5eeb` |
|---|---|---|
| Component-01 spec (the contract implemented) | `docs/architecture/components/01-mcp-gateway.md` | `9f401d328b48b32c1a844cf4f7bb09f1eb34357c` |
| Trust boundaries / token taxonomy §8 | `docs/architecture/02-trust-boundaries.md` | `21d44fae3df94bd2535c8580eaf31f330b637027` |
| Container / flow map (F1, F5, F10) §3–4 | `docs/architecture/05-c4-container.md` | `375ff211c6a1a9580c3663d6c2da2b97633f21e5` |
| Threat model (P1 rows mitigated) §3.2 | `docs/architecture/06-threat-model.md` | `d453378097ed253eaa3bb3bed65a0b9b6b23c70c` |
| NFRs governing this edge | `docs/architecture/manifesto/02-nfrs.md` | `f8429c55b248d3b2804fbfe45bfeaa6ee7286ff8` |

NFRs in force on this edge (read from the file above): NFR-SEC-09, -26, -46,
-51, -52, -53, NFR-SEC-04 (refresh window), NFR-IC-04, NFR-IC-05.

> The NFR path is `docs/architecture/manifesto/02-nfrs.md` (under
> `docs/architecture/`), corrected from an earlier truncated `manifesto/...`
> form in the builder brief.

## Vendored as a file (copied byte-identical)

The wire contract is **copied** because the gateway's schema validator loads it
as a frozen artifact, not as prose to be restated. The copy is byte-identical to
canon (the git blob OID matches), so its provenance is mechanically checkable.

| Artifact | Vendored path | Canon path @ `62f5eeb` | Blob OID (canon == local) |
|---|---|---|---|
| OCU MCP constraint profile (2025-06-18) | `contracts/mcp/2025-06-18/ocu-constraints.schema.json` | `contracts/mcp/2025-06-18/ocu-constraints.schema.json` | `fbada4ed9e7eae31d4810156e63297d323c6cba7` |
| OCU Audit fan-in (AsyncAPI 3.0.0) — F10 OCSF emit | `contracts/audit/audit-fanin.asyncapi.yaml` | `contracts/audit/audit-fanin.asyncapi.yaml` | `6beb0cab568c44572f0eec756f8028335cda2288` |

SHA-256 of the vendored copies:
- `ocu-constraints.schema.json`: `3efa305c1d5f573700d6d19d7eb1add9ff761a4cf5089b9031c7c820f339e77d`
- `audit-fanin.asyncapi.yaml`: `0c82d163b152ca3e5d8e31e89b892b012b9ccaf6a8170393bb875f5deb7e5114`

> The gateway emits ONLY on the `mcpGatewayAudit` channel
> (`audit.ingest.mcp-gateway`), payload OCSF **ApiActivity** (class 6003). The
> hash-chain linkage (`prev_hash`/`chain_hash`) is authored by the pipeline at
> ingest, NOT by the gateway — the gateway supplies the per-source monotonic
> `sequence` (NFR-SEC-48) and the pipeline derives chain order.

Verify the vendored copy is still byte-identical to its canon source:

```sh
git hash-object contracts/mcp/2025-06-18/ocu-constraints.schema.json
# must print fbada4ed9e7eae31d4810156e63297d323c6cba7
```

## Pending canon (NOT yet vendorable — gated on merge)

The caller-auth wire format and its floor NFR are **not** on the pinned canon
revision. They land with PR #311 (ADR-0027) merging to `next/v1`; this component
builds the caller-auth path as a **seam** until then, and re-pins canon forward
to vendor the frozen format once #311 merges.

| Pending artifact | Status | Lands with |
|---|---|---|
| ADR-0027 — MCP caller static API-key auth | architect-owned, proposed | PR #311 → `next/v1` |
| NFR-SEC-87 — caller-auth floor (entropy ≥256 bits, salted hash at rest, revoke ≤5 min) | architect-owned, proposed | PR #311 → `next/v1` |

> NFR-SEC-87, **not** -86: -86 is taken by ADR-0026 / #307 (renderer-egress);
> the auth floor was renumbered 86→87 in ADR-0027. The seam pins to **-87**.
