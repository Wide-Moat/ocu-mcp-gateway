<!-- SPDX-License-Identifier: FSL-1.1-Apache-2.0 -->
<!-- Copyright (c) 2025 Open Computer Use Contributors -->

# ocu-mcp-gateway — builder requirements

Component-01 of the OCU next/v1 architecture: the **MCP gateway**, the agent
tool-call ingress that sits **before** the Control plane. It authenticates the
MCP caller, validates the tool-call against the OCU profile, and forwards a
session request to the Control/operator API. It runs no agent loop and never
reaches the sandbox directly.

This is the scaffold brief for the peer who will build this repo. Read it, then
read the canon it pins, before writing any code.

## Canon (read first, pinned by SHA — do not copy, cite)

All canon lives on `next/v1` in `Wide-Moat/open-computer-use`, pinned at
`62f5eeb598f2f4e0370d3c35d5d70b8f204df7de`:

| Artifact | Path @ canon SHA |
|---|---|
| Component spec (the contract you implement) | `docs/architecture/components/01-mcp-gateway.md` |
| Wire contract (vendor this) | `contracts/mcp/2025-06-18/ocu-constraints.schema.json` |
| Trust boundaries / token taxonomy | `docs/architecture/02-trust-boundaries.md` §8 |
| Container/flow map (F1, F5, F10) | `docs/architecture/05-c4-container.md` §3–4 |
| Threat model (P1 rows you mitigate) | `docs/architecture/06-threat-model.md` §3.2 |
| Caller-auth ADR | **`docs/architecture/adr/0027-mcp-caller-static-api-key-auth.md` — architect drafting (decision frozen in "Auth" below)** |
| NFRs governing this edge | `docs/architecture/manifesto/02-nfrs.md` (NFR-SEC-09, -46, -51, -52, -53, -04, -26, NFR-IC-04, -05; NFR-SEC-87 lands with #311) |

Cite canon by name + SHA in `VENDORED.md`, never as a clickable `../..` path
(cross-repo relative links break CI — this bit a sibling repo already).

## What this component is

- **Language:** Go. Mirror the sibling `ocu-control` repo structure (CI gates,
  `CONSTITUTION.md`, canon-by-URL, vendored contracts, `.planning/` gitignored).
- **Position:** in front of Control. The agent/MCP client dials the gateway (F1);
  the gateway forwards a session request to Control/operator API (F5) carrying
  **its own service identity, never the caller's credential**; the gateway emits
  OCSF to the Audit pipeline (F10).
- **No agent loop, no model.** The calling client owns the loop and the model.
- **Holds no state that outlives a request.** No session registry (Control owns
  it), no caller token after the response, no upstream credential, no kill-switch
  route, no path to the operator ingress.

## Invariants the build MUST satisfy (from the component-01 spec — each is falsifiable)

1. Every inbound tool-call is validated against the MCP base schema **then** the
   OCU profile before any forward; an unknown field or out-of-bound payload is
   rejected **pre-buffer** with a structured deny, never partially acted on
   (schema-validation + property-test; NFR-SEC-51, -46).
2. The caller credential is authenticated at ingress; identity is **never** read
   from the request body (NFR-SEC-09). *(Mechanism = static sk- key — see Auth.)*
3. The caller credential **never** appears on the F5 forward leg, in a forwarded
   argument, or on any path reaching the sandbox; the forward carries only the
   gateway's own service identity (code-path audit + integration-test;
   NFR-SEC-09, -26).
4. **No** gateway code path resolves to a lifecycle, denylist, or kill-switch
   route; no rendered deploy manifest grants the gateway a network route to the
   operator ingress on either shelf (IaC-policy assertion; NFR-SEC-52).
5. Outbound errors/discovery responses are size-bounded and carry a stable reason
   class + correlation id only — never a session id, `container_name`, internal
   host/route, or stack detail (schema-validation + property-test; NFR-SEC-51).
6. The negotiated protocol revision is pinned per connection; a missing/
   unnegotiable `MCP-Protocol-Version` is rejected, never silently downgraded
   (NFR-IC-04).
7. Tool execution is serialized per session by default; parallelism opt-in per
   skill (NFR-IC-05).
8. At most a configured number of open connections per audience-validated caller;
   excess is **refused, not queued**; one caller cannot exhaust the listener fd
   table (chaos-test; NFR-SEC-53).
9. **Fail-closed** is the default on every authentication and forward boundary.

## Auth — caller authentication via static sk- API keys (ADR-0027, architect-decided)

MCP-caller auth on the **minimal shelf** is a **static `sk-` API key** (LiteLLM-style);
the **full shelf** keeps the customer-IdP relying-party flow. OAuth 2.1 RS is the
named full-shelf path, not a rejection — it is the other shelf. The deciding ADR is
`0027-mcp-caller-static-api-key-auth` (architect drafting; this section reflects its
frozen decision).

- **Key format:** `sk-ocu-<base62, 32 bytes (256-bit) CSPRNG>`. **Per-caller** (one
  key = one principal — never a single shared secret). Shown once at issuance, never
  stored in plaintext. The `sk-ocu-` prefix makes a leaked key scanner-detectable —
  wire a gitleaks/trufflehog rule for it.
- **Issuance:** the **Control plane**, via the `occ mcp-key create --tenant <T>`
  operator verb (Control is the single auditable mint point — ADR-0013/0019; this is
  the caller-edge analogue of ADR-0004's operator-edge two-shelf split). The gateway
  **never** issues keys and **never** owns a key DB.
- **Storage:** **salted SHA-256** (`sha256(salt‖secret)`, per-key salt) — adopt
  LiteLLM's hash-at-rest + return-once shape but **reject its unsalted SHA-256**
  (pass-the-hash advisory GHSA-69x8-hrgq-fjj8). Record =
  `{key_id, key_hash, salt, tenant, deployment/audience, expires_at, status, created_at}`.
  Postgres on the full shelf; a root-owned hashed-entries file on the minimal shelf.
  Plaintext never on disk.
- **Validation seam (the load-bearing call):** in-process, against **boot-loaded**
  material — **never a per-request Control lookup**. The gateway loads the
  Control-owned hashed-key set at boot (the same config plane that delivers its
  signing material), hashes the presented bearer, constant-time compares. This keeps
  the "no state that outlives a request" invariant literal (material is config, not
  request-derived state) and adds no second gateway→Control hot-path leg. **Rejected:**
  per-request read-API (a forbidden second edge that inverts the F5 invariant) and a
  gateway-maintained denylist (Control owns denylists).
- **Audience/tenant binding:** read from the **resolved record**, not from a claim in
  the key (an opaque key carries no claims). A key absent from *this* deployment's set
  fails to resolve → 401. The record's `tenant` is the tenant binding; the deployment
  scope is the audience-equivalent. This satisfies NFR-SEC-09 (a looked-up record is
  more authoritative than a self-asserted claim) — NFR-SEC-09 is **kept, not amended**.
- **Revocation + rotation:** `occ mcp-key revoke --id` flips `status`/deletes the
  record; Control re-pushes the boot set, gateway refreshes within NFR-SEC-04 (≤5 min).
  Rotation = issue-new + revoke-old with an optional grace window; no in-place mutation.
  Expiry = optional `expires_at` (absent ⇒ non-expiring, so the one-click path is not
  blocked).
- **Floor (NFR-SEC-87, new — lands with ADR-0027/#311; the number is 87 not 86, since 86 is held by ADR-0026/#307):** entropy ≥256 bits, salted-hash-at-rest, revoke ≤5 min.

**The auth wire format is now frozen by ADR-0027 — but scaffold the validator as a
seam anyway** (an interface the boot-set loader + constant-time comparator plug into),
so the full-shelf IdP path drops in beside it without a rewrite.

## CI gates (mirror ocu-control / security.yml — SHA-pin all actions)

Secrets scan (gitleaks + trufflehog, **pin the binary version, not just the action
SHA**), SAST/SCA (semgrep + CodeQL HIGH/CRITICAL block, Trivy/Grype CRITICAL),
signed SBOM, unit ≥80% patch coverage, property-tests on the schema validator,
conventional + signed commits, CODEOWNERS, license-allowlist, doc-lint. Every gate
that the sibling repos run; copy `security.yml` not the laggard `docs-lint.yml`
movable-tag pattern.

## In scope for the peer

- The MCP listener + the OCU-profile schema validator (the wire contract above).
- The F1→F5 forward with gateway **service identity** (not the caller key).
- The sk- validation **seam** (plug the frozen validator in once the ADR lands).
- F10 OCSF emit (fail-closed durable-first, per the audit contract).
- Per-caller connection ceilings + fd-table fairness.
- The full CI/CONSTITUTION/contract-vendoring package, mirroring ocu-control.

## Owned by the architect (not the peer — do not invent)

- The caller-auth ADR (key format, issuance command, storage shelf, validation
  seam, revocation model, NFR-SEC-09 reconciliation).
- Any amendment to the component-01 spec or NFR-SEC-09.
- The `occ mcp-key` CLI surface (lands in ocu-control, coordinated).

## Anti-patterns (the fleet learned these the hard way)

- Never claim a green you didn't witness firsthand; a "flaky" RED is a hypothesis
  that demands proof the test itself passed, not a default explanation.
- A CI gate must be proven to red **when neutered** (a two-sided red-probe), or it
  may be silently a no-op.
- Don't hold a key DB in the gateway — its no-state invariant is load-bearing for
  the trust boundary.
- Merge to `main` is owner-gated. Push + open-PR is delegated; merge is not.
