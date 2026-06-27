<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# ocu-mcp-gateway Constitution

These are the load-bearing invariants of the OCU MCP gateway (component-01), the
agent tool-call ingress that sits **before** the control plane. They are not
style preferences; each is a security or custody property the rest of the system
is allowed to assume holds. Every invariant below is mechanically enforced — by a
named test (a behavioural assertion, an AST/import-graph scan, a structural type
check, or a rendered-manifest policy gate) — not by reviewer vigilance alone, and
each is proven RED-when-neutered (a two-sided red-probe), so a gate that became a
no-op fails CI instead of passing silently.

A change that weakens one of these is not a normal change. It must update the
enforcing test in the same commit, and any behaviour an Architecture Decision
Record (ADR) or a frozen wire contract fixed must change in the architecture
canon first (`Wide-Moat/open-computer-use`, pinned in `VENDORED.md`). If you are
about to delete or relax a guard named here, stop and escalate instead.

The enforcing artefact is named for each invariant so the claim is checkable, not
asserted. If an enforcing file is renamed or moved, update this document in the
same change.

---

## I. Validate-then-forward; bounded-read then validate (NFR-SEC-51, NFR-SEC-46)

Every inbound tool-call is validated against the MCP base schema **then** the OCU
profile **before any forward**; an unknown field or out-of-bound payload is
rejected with a structured deny, never partially acted on or forwarded. The
transport DoS guard is a 512KiB `MaxBytesReader` cap that refuses an oversized or
slow body before it is read whole; the per-kind profile size-ceilings then run on
those bounded bytes, before the schema parse, so an over-size payload is rejected
without being parsed. The two-pass order (base first, then overlay) is the
validation mechanism; batching is rejected (the body must be a single object).

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestInvariant1_ValidateBeforeForward` — an invalid body is denied and the
  recording forwarder is never called) and
  `internal/profile/validator_smoke_test.go`
  (`TestOverSizeRejectedPreBuffer`, `TestBatchingRejected`,
  `TestInitializeResultRejectsExtraCapability`).

## II. Identity from the transport, never the body (NFR-SEC-09)

The caller credential is authenticated at ingress from transport-presented
material **only** (the `Authorization` header); identity is never read from the
JSON-RPC body or the URI query. Fail-closed: any non-success is a refusal.

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestInvariant2_IdentityFromTransportNotBody`) and the architect pin
  `internal/ingress/auth_header_only_test.go`
  (`TestAuthReadsTransportHeaderOnly` — the bearer-extraction path reads
  `r.Header` and never `r.Body`; planting a body read goes RED).

## III. The caller credential never rides the F5 forward (NFR-SEC-09, NFR-SEC-26)

The caller bearer never appears on the forward leg, in a forwarded argument, or
on any path reaching the sandbox; the forward carries only the gateway's own
service identity. This is a **type fact**: the forward shapes have no field that
could carry the credential.

The transport (P1 dial skeleton) presents the gateway's OWN service credential —
the host-side service-to-service "Generic internal token" (component-01:39, §8) —
over an mTLS-1.3 leg (NFR-SEC-37), never the caller's credential and never an
operator scope (P1-S2). A forward with no service credential is refused, never
sent anonymously (NFR-SEC-26). The session-request WIRE FIELDS are NOT invented in
this repo: they come from the frozen Control session-setup schema (PR #293) and
plug into the seam when vendored — so the dial path fails closed pending #293
rather than fabricating a cross-component body.

- **Enforcement:** `internal/forward/no_credential_test.go`
  (`TestForwardShapesCarryNoCredential` — a reflect pass over every forward shape
  plus an AST scan of the package source reject any credential-named field;
  planting a `Bearer` field goes RED on both) and
  `internal/ingress/invariants_test.go` (`TestInvariant3_NoCredentialOnForward` —
  the resolved principal rides the forward, the secret string does not). The P1
  transport seam: `internal/forward/dial_test.go`
  (`TestNewWithDialRequiresMTLSWhenEndpointSet` — a configured endpoint without
  mTLS fails NFR-SEC-37; `TestNewWithDialRequiresServiceCredential` — a nil
  service credential fails NFR-SEC-26; `TestDialForwardFailsClosedOnCredError` —
  a credential error refuses the forward; `TestDialForwardPendingFrozenSchema` —
  the dial path fails closed pending #293, never inventing the body).

## IV. No gateway route to the operator surface — code AND network (NFR-SEC-52)

No gateway code path resolves to a lifecycle, denylist, or kill-switch route, and
no rendered deploy manifest grants the gateway a network route to the operator
ingress on either shelf. This is **two** falsifiable halves, neither sufficient
alone.

- **Enforcement (code half):** `internal/ingress/importgraph_test.go`
  (`TestGatewayReachesNoOperatorRoute` — an AST scan rejects operator-route
  symbols and a `go list -deps ./...` check excludes any operator/lifecycle/
  kill-switch package; planting a `KillSwitch` symbol goes RED). Because the
  gateway is a separate module, the operator surface is not even importable.
- **Enforcement (network half):** `scripts/iac_policy_check.py` (structural YAML
  parse of `deploy/k8s/networkpolicy.yaml` and `deploy/compose/docker-compose.yaml`
  — deny-by-default; the operator ingress is absent from the k8s egress allowlist
  and the gateway service does not join the Compose operator network). The
  `--self-test` red-probe plants an operator route in each and asserts the gate
  goes RED; it runs in CI before the main gate.

## V. Leak-free, size-bounded outbound (NFR-SEC-51)

Outbound errors and discovery responses are size-bounded and carry a stable
reason class plus a correlation id only — never a session id, `container_name`,
internal host/route, or stack detail. The wire error envelope is built from a
closed set of reason classes, never interpolated from a caller value or an
internal cause.

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestInvariant5_LeakFreeOutbound` — a realistically-wrapped forward error is
  not relayed; planting `ferr.Error()` into the response goes RED) and
  `internal/profile/validator_property_test.go`
  (`TestValidatorNeverPanicsAndDenyIsLeakFree` — for any input, a deny exposes
  only a fixed, short reason-class string).

## VI. The protocol revision is pinned per connection (NFR-IC-04)

A request whose `MCP-Protocol-Version` is missing or unnegotiable is rejected,
never silently downgraded. The pinned revision is `2025-06-18`.

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestInvariant6_ProtocolVersionPinned` — missing and mismatched versions are
  both 400; the pinned version passes the gate).

## VII. Per-caller connection ceiling refuses, never queues (NFR-SEC-53)

The gateway holds at most a configured number of concurrent in-flight requests
per audience-validated caller; excess is **refused** (429), never queued, so a
single caller cannot exhaust the listener fd table. The ceiling is keyed on the
resolved caller identity, so it runs strictly after authentication.

- **Enforcement:** `internal/quota/ceiling_test.go`
  (`TestCeilingRefusesAtLimit`, `TestCeilingIsPerCaller`,
  `TestCeilingConcurrentAcquireRespectsLimit`) and
  `internal/ingress/invariants_test.go`
  (`TestInvariant8_ConnectionCeilingRefuses` — a saturated caller is 429;
  neutering the ceiling goes RED).

## VIII. Fail-closed on every authentication and forward boundary (invariant #9)

Fail-closed is the default. A forward that cannot complete is a refusal (502),
never a silent success; an authentication that does not explicitly succeed is a
401; a nil seam at construction is an error, not an admit-all.

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestInvariant9_FailClosedForward`, `TestNewHandlerFailsClosedOnNilSeam`) and
  the seam fail-closed tests `internal/forward/http_test.go`
  (`TestControlForwarderFailsClosedWithoutEndpoint`),
  `internal/auth/skkey_test.go` (`TestNewStaticAuthenticatorNilSetFailsClosed`).

## IX. Load-before-bind: no listener binds before the auth material is loaded (NFR-SEC-04)

The Control-owned authentication material is loaded and ready **before** any
listener binds; an unreadable boot-set is fail-closed — the daemon stays
not-ready, binds nothing, and admits no request. The bind hook gates on
readiness.

- **Enforcement:** `internal/boot/boot_test.go`
  (`TestSequencerNotReadyBeforeLoad`, `TestSequencerLoadFailureStaysNotReady`,
  `TestSequencerReadyAfterLoad`) and the composition root
  `cmd/ocu-mcp-gatewayd/main.go` (binds only after `seq.Ready()` and aborts on a
  load failure before any `net.Listen`).

## X. The caller-auth wire format is a seam (ADR-0027, gated on PR #311)

The minimal-shelf static `sk-ocu-` validator and the full-shelf OAuth 2.1 RS
validator are two shelves of one `CallerAuthenticator` interface. The minimal
shelf stores only salted SHA-256 (never plaintext, rejecting unsalted per
GHSA-69x8-hrgq-fjj8), compares constant-time, and validates against boot-loaded
material in-process — never a per-request Control lookup. The final wire format
lands when ADR-0027 (PR #311) merges to canon; the seam plugs it in without a
rewrite.

- **Enforcement:** `internal/auth/skkey_test.go` (the real salted-SHA-256 path:
  `TestStaticKeySetResolvesActiveKey`, `TestStaticKeySetRejectsWrongSecret`,
  `TestStaticKeySetRejectsRevoked`, `TestStaticKeySetRejectsExpired`,
  `TestHashForRecordRejectsPrefixlessSecret`) and the boot-set loader
  `internal/config/loader_test.go`.

## XI. F10 OCSF audit is emit-before-ack, fail-closed durable-first (NFR-SEC-03)

Every terminated request is recorded as an OCSF ApiActivity event on the
gateway's audit fan-in channel BEFORE the response is acknowledged; a durable
audit-write failure REFUSES the request, never acks it. A 200 therefore always
means the action took effect AND was durably recorded. The audit actor is the
host-attested caller principal (the resolved KeyID), never a body claim
(NFR-SEC-09). The per-source `sequence` is monotonic; the pipeline authors the
hash-chain at ingest (the gateway supplies only the sequence). The contract is
the vendored `contracts/audit/audit-fanin.asyncapi.yaml` (channel
`mcpGatewayAudit`, payload OCSF ApiActivity).

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestF10_AuditWriteFailureIsRefusal` — a forward that succeeds but whose audit
  write fails is refused 500, not acked 200; planting an ignored emit error goes
  RED) and (`TestF10_AuditActorIsHostAttested` — the emitted actor is the resolved
  KeyID, a body `caller` claim does not appear). The emitter's own fail-closed
  contract: `internal/audit/audit_test.go` (`TestEmitWriteFailureIsRefusal`,
  `TestSequenceMonotonicAndUnique`, `TestEmitInvalidEnvelopeRefused`).

---

## Deferred (declared, not yet enforced)

### Per-session tool-execution serialization (NFR-IC-05) — DEFERRED

The component-01 spec (line 51) requires tool execution to be **serialized per
session by default, with parallelism opt-in per skill** — a gateway behaviour
(spec Open Question 4 names it "a gateway behaviour with no wire field"), so it is
genuinely in this component's scope. It is **deferred, not covered**, and is
declared here rather than dissolved into the renumbering above (no silent caps).

Why deferred is correct today: the forward path is a fail-closed stub
(`ControlForwarder` returns `ErrForwardFailed` — "Control transport not yet
wired"), so **nothing executes to serialize**. A per-session serializer with no
execution behind it would be untestable scaffolding. It lands with the
Control-transport wiring and gets its own enforcing test then (a session-keyed
serializer asserting sequential-by-default execution with opt-in parallelism,
two-sided red-probed like the rest).

The vendored wire contract already documents the constraint
(`x-ocu-profile.concurrency`, `mode: sequential-default-per-session`,
NFR-IC-05); this entry records that the *gateway-side enforcement* is the
outstanding work.

---

## Read before changing any of the above

- The architecture and specifications are the source of truth and live in the
  `open-computer-use` canon, pinned by SHA in `VENDORED.md`. Do not re-decide
  here what an ADR already decided; if a decision must change, it changes in the
  architecture canon first.
- The frozen wire contract under `contracts/mcp/2025-06-18/` pins the OCU
  constraint profile (the bounded `$def`s, the numeric caps, the revision). The
  vendored copy is byte-identical to canon (its git blob OID is recorded in
  `VENDORED.md`).
- All committed content is English only. State facts in this project's own words;
  the specs, ADRs, and the frozen contract are the only citable sources for
  behaviour.
- Merge to `main` is owner-gated. Push and open-PR are delegated; merge is not.
