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
| Pinned commit | `26c67490a569e738a728e6db3b537a8f801e8dea` |
| Commit subject | `docs: add the step-by-step demo walkthrough (#314)` |
| Pinned date | 2026-06-28 |

> **Re-pinned forward** from `62f5eeb` (#296) to `26c6749` for P1-live: the frozen
> `session_setup.proto` (F5 wire, PR #293 @ `a6b48bd`) is NOT reachable from
> `62f5eeb` — that revision predates the proto landing on `next/v1`. Re-pinning to
> a revision that includes `a6b48bd` makes the vendored proto's provenance
> mechanically checkable. Three already-cited docs drifted between the two pins
> (`01-mcp-gateway.md`, `06-threat-model.md`, `02-nfrs.md`); their blob OIDs below
> are recomputed at the new pin. The two byte-copied contract files
> (`ocu-constraints`, `audit-fanin`) did NOT drift, so the local copies remain
> byte-identical.

To re-verify any row below against the pinned canon:

```sh
git -C <open-computer-use> rev-parse 26c67490a569e738a728e6db3b537a8f801e8dea:<path>
# the printed git blob OID must equal the "Blob OID" column
```

## Read-only citations (not copied into this repo)

These artifacts are the contract this component implements. They are **read**,
not vendored as files — the gateway re-states facts in its own words
(`CONSTITUTION.md`, code comments) and cites the canon source here.

| Artifact | Path @ canon | Blob OID @ `26c6749` |
|---|---|---|
| Component-01 spec (the contract implemented) | `docs/architecture/components/01-mcp-gateway.md` | `32b945b5a1097329f3319a061eee1aff84271e96` |
| Trust boundaries / token taxonomy §8 | `docs/architecture/02-trust-boundaries.md` | `21d44fae3df94bd2535c8580eaf31f330b637027` |
| Container / flow map (F1, F5, F10) §3–4 | `docs/architecture/05-c4-container.md` | `375ff211c6a1a9580c3663d6c2da2b97633f21e5` |
| Threat model (P1 rows mitigated) §3.2 | `docs/architecture/06-threat-model.md` | `83cf5395624c0790c2a42a37442219c736df6777` |
| NFRs governing this edge | `docs/architecture/manifesto/02-nfrs.md` | `f0d98c9aa613bac586207ca96a2563fe92de23b5` |

NFRs in force on this edge (read from the file above): NFR-SEC-09, -26, -46,
-51, -52, -53, NFR-SEC-04 (refresh window), NFR-IC-04, NFR-IC-05.

> The NFR path is `docs/architecture/manifesto/02-nfrs.md` (under
> `docs/architecture/`), corrected from an earlier truncated `manifesto/...`
> form in the builder brief.

## Vendored as a file (copied byte-identical)

The wire contract is **copied** because the gateway's schema validator loads it
as a frozen artifact, not as prose to be restated. The copy is byte-identical to
canon (the git blob OID matches), so its provenance is mechanically checkable.

| Artifact | Vendored path | Canon path @ `26c6749` | Blob OID (canon == local) |
|---|---|---|---|
| OCU MCP constraint profile (2025-06-18) | `contracts/mcp/2025-06-18/ocu-constraints.schema.json` | `contracts/mcp/2025-06-18/ocu-constraints.schema.json` | `fbada4ed9e7eae31d4810156e63297d323c6cba7` |
| OCU Audit fan-in (AsyncAPI 3.0.0) — F10 OCSF emit | `contracts/audit/audit-fanin.asyncapi.yaml` | `contracts/audit/audit-fanin.asyncapi.yaml` | `6beb0cab568c44572f0eec756f8028335cda2288` |
| F5 session-setup wire (proto3, gRPC) — Create/Route/Destroy | `contracts/proto/ocu/control/session/v1/session_setup.proto` | `contracts/proto/ocu/control/session/v1/session_setup.proto` | `3ebd2c93dc303a4dd47b39c5ef81f3cde959b73b` |

SHA-256 of the vendored copies:
- `ocu-constraints.schema.json`: `3efa305c1d5f573700d6d19d7eb1add9ff761a4cf5089b9031c7c820f339e77d`
- `audit-fanin.asyncapi.yaml`: `0c82d163b152ca3e5d8e31e89b892b012b9ccaf6a8170393bb875f5deb7e5114`
- `session_setup.proto`: `10d96e6a597a629aaddfbc3ff2c6f6adccc86acaa577dae63321cddf5d5c7dcc`

> The gateway emits ONLY on the `mcpGatewayAudit` channel
> (`audit.ingest.mcp-gateway`), payload OCSF **ApiActivity** (class 6003). The
> hash-chain linkage (`prev_hash`/`chain_hash`) is authored by the pipeline at
> ingest, NOT by the gateway — the gateway supplies the per-source monotonic
> `sequence` (NFR-SEC-48) and the pipeline derives chain order.

> The `session_setup.proto` is the F5 forward wire (gateway → Control, mTLS-SAN
> service identity), frozen by PR #293 @ `a6b48bd`. It exposes ONLY
> `Create`/`Route`/`Destroy` — deliberately incapable of force-kill /
> denylist-edit / quota-override (NFR-SEC-26 surface invariant, mirrors
> CONSTITUTION §IV). Custody holds on BOTH directions: no request or response
> body carries the minted Storage-JWT, the filestore credential, or any backend
> secret — `MountIntent` OMITS the auth token (server-minted on the mount-config
> plane). `CreateRequest.session_hint` is a HINT only (NFR-SEC-43); the host
> derives the real `session_id` binding from the attested caller identity.
> **`CreateRequest` field 6 is `reserved 6; reserved "image"`** — the in-process
> `image` ref is PIN-PENDING at the gatekeeper (#205 reconciliation); the gateway
> leaves that path UNSET and documented, never invents or silently drops it. See
> issue #3 for the architect's assessment.

Verify a vendored copy is still byte-identical to its canon source:

```sh
git hash-object contracts/mcp/2025-06-18/ocu-constraints.schema.json
# must print fbada4ed9e7eae31d4810156e63297d323c6cba7
git hash-object contracts/proto/ocu/control/session/v1/session_setup.proto
# must print 3ebd2c93dc303a4dd47b39c5ef81f3cde959b73b
```

## Caller-auth floor: landed as PROSE, no wire artifact to vendor

As of this pin (`26c6749`), the caller-auth ADR and its floor NFR **have landed**
on `next/v1` — but as prose, NOT as a vendorable wire contract. There is no
`contracts/` schema or proto for the `sk-ocu-` key to copy (verified firsthand:
`git ls-tree -r 26c6749 -- contracts/` names no caller/api-key artifact). P4
therefore pins the caller-auth path to the **NFR-SEC-87 prose floor**, not a blob
OID — the gateway's `internal/auth/skkey.go` already implements that floor
(salted SHA-256, per-record constant-time compare, reject-unsalted, fail-closed).

| Artifact | Status @ `26c6749` | Blob OID |
|---|---|---|
| ADR-0027 — MCP caller static API-key auth | `accepted` (ratified #313) | `6d57088c730ba3e4e71114060a16d65199841a1c` |
| NFR-SEC-87 — caller-auth floor (entropy ≥256 bits, salted hash at rest, revoke ≤5 min) | frozen NFR row in `docs/architecture/manifesto/02-nfrs.md` | (in `02-nfrs.md`, `f0d98c9…`) |

> NFR-SEC-87, **not** -86: -86 is taken by ADR-0026 / #307 (renderer-egress);
> the auth floor was renumbered 86→87 in ADR-0027. The floor citation is **-87**.
