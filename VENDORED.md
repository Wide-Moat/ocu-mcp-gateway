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
| Pinned commit | `099d3d76d6d8a8e5bec6f46b989c6b9a9246c375` |
| Commit subject | `feat(contracts): freeze the north Files-API bodies (ADR-0028, closes #304) (#323)` |
| Pinned date | 2026-07-01 |

> **Re-pinned forward** from `26c6749` (#314) to `099d3d7` for P4: the frozen
> `mcp-key-set.schema.json` (the ADR-0027 Control→gateway hashed-key boot-set, PR
> #318 @ `09b00fc`) is NOT reachable from `26c6749` — that revision predates the
> schema landing on `next/v1`. Re-pinning to `099d3d7` (the current `next/v1` tip)
> makes the vendored key-set schema's provenance mechanically checkable. One
> byte-copied file drifted between the two pins: `ocu-constraints.schema.json`
> (`fbada4ed`→`23b28bd`) — the ADR-0027 two-shelf `x-ocu-authz` update
> (`static-key`/`oauth2-rs` split, unconditional `WWW-Authenticate: Bearer`); the
> change is in the `x-ocu-authz` extension block, NOT the validation `$defs`, so
> the F1 validator is behaviourally unchanged. Its local copy is re-vendored
> byte-identical to the new pin. Nothing else drifted (the earlier P1-live re-pin
> recomputed the doc OIDs).

To re-verify any row below against the pinned canon:

```sh
git -C <open-computer-use> rev-parse 099d3d76d6d8a8e5bec6f46b989c6b9a9246c375:<path>
# the printed git blob OID must equal the "Blob OID" column
```

## Read-only citations (not copied into this repo)

These artifacts are the contract this component implements. They are **read**,
not vendored as files — the gateway re-states facts in its own words
(`CONSTITUTION.md`, code comments) and cites the canon source here.

| Artifact | Path @ canon | Blob OID @ `099d3d7` |
|---|---|---|
| Component-01 spec (the contract implemented) | `docs/architecture/components/01-mcp-gateway.md` | `32b945b5a1097329f3319a061eee1aff84271e96` |
| Trust boundaries / token taxonomy §8 | `docs/architecture/02-trust-boundaries.md` | `21d44fae3df94bd2535c8580eaf31f330b637027` |
| Container / flow map (F1, F5, F10) §3–4 | `docs/architecture/05-c4-container.md` | `375ff211c6a1a9580c3663d6c2da2b97633f21e5` |
| Threat model (P1 rows mitigated) §3.2 | `docs/architecture/06-threat-model.md` | `83cf5395624c0790c2a42a37442219c736df6777` |
| NFRs governing this edge | `docs/architecture/manifesto/02-nfrs.md` | `f0d98c9aa613bac586207ca96a2563fe92de23b5` |
| ADR-0027 — MCP caller static API-key auth | `docs/architecture/adr/0027-mcp-caller-static-api-key-auth.md` | `6d57088c730ba3e4e71114060a16d65199841a1c` |

NFRs in force on this edge (read from the file above): NFR-SEC-09, -26, -46,
-51, -52, -53, NFR-SEC-04 (refresh window), NFR-IC-04, NFR-IC-05.

> The NFR path is `docs/architecture/manifesto/02-nfrs.md` (under
> `docs/architecture/`), corrected from an earlier truncated `manifesto/...`
> form in the builder brief.

## Vendored as a file (copied byte-identical)

The wire contract is **copied** because the gateway's schema validator loads it
as a frozen artifact, not as prose to be restated. The copy is byte-identical to
canon (the git blob OID matches), so its provenance is mechanically checkable.

| Artifact | Vendored path | Canon path @ `099d3d7` | Blob OID (canon == local) |
|---|---|---|---|
| OCU MCP constraint profile (2025-06-18) | `contracts/mcp/2025-06-18/ocu-constraints.schema.json` | `contracts/mcp/2025-06-18/ocu-constraints.schema.json` | `23b28bda5acf347f925592701f770f39aa1b97ee` |
| OCU Audit fan-in (AsyncAPI 3.0.0) — F10 OCSF emit | `contracts/audit/audit-fanin.asyncapi.yaml` | `contracts/audit/audit-fanin.asyncapi.yaml` | `6beb0cab568c44572f0eec756f8028335cda2288` |
| F5 session-setup wire (proto3, gRPC) — Create/Route/Destroy | `contracts/proto/ocu/control/session/v1/session_setup.proto` | `contracts/proto/ocu/control/session/v1/session_setup.proto` | `3ebd2c93dc303a4dd47b39c5ef81f3cde959b73b` |
| MCP hashed-key-set (Control → gateway boot-set, ADR-0027) | `contracts/mcp/mcp-key-set.schema.json` | `contracts/mcp/mcp-key-set.schema.json` | `25329b0f572b049ed593d5bc7fe14f74980b0091` |

SHA-256 of the vendored copies:
- `ocu-constraints.schema.json`: `3ba7d9c2c4be1ccd4ffd0371c7b76db00b6d9a8cb0a1f7474966a7e0f2534c7e`
- `audit-fanin.asyncapi.yaml`: `0c82d163b152ca3e5d8e31e89b892b012b9ccaf6a8170393bb875f5deb7e5114`
- `session_setup.proto`: `10d96e6a597a629aaddfbc3ff2c6f6adccc86acaa577dae63321cddf5d5c7dcc`
- `mcp-key-set.schema.json`: `0672c4da86354a98bfead570a57c865d25d0c64ef1609420ad5ba214a1af621d`

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
# must print 23b28bda5acf347f925592701f770f39aa1b97ee
git hash-object contracts/proto/ocu/control/session/v1/session_setup.proto
# must print 3ebd2c93dc303a4dd47b39c5ef81f3cde959b73b
git hash-object contracts/mcp/mcp-key-set.schema.json
# must print 25329b0f572b049ed593d5bc7fe14f74980b0091
```

The `scripts/vendored_check.py` CI gate asserts each vendored file's
`git hash-object` still equals the blob OID declared above — a silent local
mutation of a vendored contract reds the gate. (Provenance against canon is
established at vendoring time and recorded here; the gate enforces the local copy
does not drift from what was recorded.)

## Caller-auth: the key-set wire contract has landed (P4)

The caller-auth wire contract is now a **vendorable artifact**, not just prose. As
of this pin (`099d3d7`), `contracts/mcp/mcp-key-set.schema.json` (PR #318 @
`09b00fc`) freezes the Control→gateway hashed-key boot-set: `{version: const 1,
records[]}` with each `HashedKeyRecord` = `{key_id, key_hash (^[0-9a-f]{64}$,
salted SHA-256), salt (^([0-9a-f]{2}){8,}$), tenant, deployment, status (const
"active"), created_at, expires_at?}`, `additionalProperties:false` at both levels,
`records` `minItems 1`. It is vendored byte-identical (row above) and the gateway
boot-loads + validates against it. The schema validates the SHAPE; the
omit-before-render, boot-refresh-within-5-min (NFR-SEC-04), and constant-time
comparison are peer invariants (NFR-SEC-87, ADR-0027) enforced in code, not the
schema. The `x-ocu-authz` block of the constraint profile (re-vendored this pin)
carries the two-shelf `static-key`/`oauth2-rs` rule split.

| Artifact | Status @ `099d3d7` | Blob OID |
|---|---|---|
| ADR-0027 — MCP caller static API-key auth | `accepted` (ratified #313) | `6d57088c730ba3e4e71114060a16d65199841a1c` |
| `mcp-key-set.schema.json` — hashed-key boot-set | frozen (PR #318 @ `09b00fc`), vendored | `25329b0f572b049ed593d5bc7fe14f74980b0091` |
| NFR-SEC-87 — caller-auth floor (entropy ≥256 bits, salted hash at rest, revoke ≤5 min) | frozen NFR row in `docs/architecture/manifesto/02-nfrs.md` | (in `02-nfrs.md`, `f0d98c9…`) |

> NFR-SEC-87, **not** -86: -86 is taken by ADR-0026 / #307 (renderer-egress);
> the auth floor was renumbered 86→87 in ADR-0027. The floor citation is **-87**.
