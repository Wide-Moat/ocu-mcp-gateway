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

A tools/call request — the main attack surface, which has no dedicated overlay
$def — is STRICT-validated at the base pass: `params.name` MUST be a non-empty
string and `params.arguments`, if present, MUST be a JSON object (never a scalar
or array). A weakly-validated request is the gap CodeRabbit surfaced; strict
validation closes it.

The inbound JSON-RPC **method** is checked against an explicit allowlist, not
merely for presence. A self-audit found method-confusion: the base pass checked
only that the `method` key existed, never its value, so a request whose method
was NOT `tools/call` (an invented `evil/pwn`, or a real-but-off-surface
`resources/list`) rode the tools/call path and was forwarded on F5 as a
tool-call. Only `tools/call` is ever forwarded on F5 (the `SessionRequest` can
carry only a `ToolCall`), so an off-surface method is refused with JSON-RPC
`-32601` "method not found" and forwarded nowhere.

The gateway ALSO answers the MCP lifecycle handshake — `initialize` and
`tools/list` — GATEWAY-LOCAL (behind auth), so the official client SDK works
against it as a drop-in for the upstream endpoint. These two methods are routed to
a local responder BEFORE the tools/call validation path and NEVER build a
`SessionRequest` or reach the forwarder — the load-bearing security property is
that a handshake method cannot ride the F5 leg, so growing the handshake does not
reopen the method-confusion hole. Every other method still falls through to the
allowlist deny. The allowlist / handshake set is named and extensible: a new
inbound method is a one-line add plus its own local-answer-or-forward decision and
test, never a rewrite.

A JSON-RPC **notification** — a message with no `id`, or a `notifications/*`
method — is fire-and-forget and is acknowledged `202 Accepted` with an EMPTY body
BEFORE the handshake/forward routing: it is never answered with a result or a
`-32601` deny and never reaches the forwarder. This is the stateless
streamable-HTTP transport the official SDK speaks (it sends
`notifications/initialized` right after `initialize`); answering that notification
with any body closed the SDK transport on the next request. Because a notification
is dropped before the forward, it too cannot ride the F5 leg.

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestInvariant1_ValidateBeforeForward` — an invalid body is denied and the
  recording forwarder is never called),
  `internal/profile/validator_smoke_test.go`
  (`TestOverSizeRejectedPreBuffer`, `TestBatchingRejected`,
  `TestInitializeResultRejectsExtraCapability`), and the strict tools/call check
  `internal/profile/coverage_test.go` (`TestBaseValidatorStructural` — a
  tools/call with no params.name, an empty name, array arguments, or scalar params
  all fail; neutering the strict check goes RED).
  The inbound method allowlist: `internal/profile/base_method_allowlist_test.go`
  (`TestBaseRejectsNonToolsCallMethod`, `TestBaseAdmitsToolsCallMethod`,
  `TestMethodAllowlistIsExactlyToolsCall`) and, at the shipped boundary,
  `internal/ingress/method_allowlist_test.go` (`TestUnknownMethodNotForwarded` —
  a genuinely off-surface method is denied -32601 and the recording forwarder is
  never called; `TestToolsCallStillForwards` — the one forwarded method still
  forwards). The MCP handshake routing: `internal/ingress/handshake_test.go`
  (`TestHandshakeMethodsAreNotForwarded` — initialize and tools/list are answered
  gateway-local 200 and the forwarder is NEVER called; removing the local routing
  reds it; `TestInitializeResultShape`, `TestToolsListReturnsToolArray` — the
  handshake responses are the shapes the SDK consumes; `TestOffSurfaceMethodStillDenied`
  — growing the handshake did not open the allowlist to everything). The
  notification 202 rule: `internal/ingress/streamable_test.go`
  (`TestNotificationInitializedIsAccepted202` — the notification the SDK sends
  post-initialize is 202 with an empty body and never forwarded; answering it
  -32601 reds it and breaks the real SDK; `TestAnyNotificationIsAccepted202`,
  `TestIdlessRequestIsNotification`, `TestIdBearingRequestsStillAnswered` — the
  rule keys on the absence of an id, not on swallowing id-bearing requests).
  Two-sided: replacing the allowlist guard with the old presence-only check, making
  the allowlist fail-open, forwarding a handshake method, or answering a
  notification with a body reds a named test.
  The transport bound itself: `internal/ingress/bounded_read_test.go`
  (`TestBoundedReadStopsAtTransportCap` — a self-audit found the cap fake-green:
  deleting the `MaxBytesReader` line left the old 413 assertion GREEN because the
  per-kind profile ceiling answers the SAME 413 — after buffering the whole body.
  The test counts the bytes the handler consumes from the wire (must stop at
  cap+ε) and asserts the refusal carries the TRANSPORT reason class
  ("request body too large"), not the ceiling's ("payload_over_size_bound");
  deleting the MaxBytesReader line goes RED on both prongs).

## II. Identity from the transport, never the body (NFR-SEC-09)

The caller credential is authenticated at ingress from transport-presented
material **only** (the `Authorization` header); identity is never read from the
JSON-RPC body or the URI query. Fail-closed: any non-success is a refusal.

The request Origin is validated as a DNS-rebinding guard (x-ocu-authz: "Origin
header MUST be validated"): a present Origin must be in the configured allowlist
or the request is refused 403 before auth; an originless (CLI/non-browser) caller
is allowed. With an empty allowlist any present Origin is refused (fail-closed for
the browser case).

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestInvariant2_IdentityFromTransportNotBody`), the architect pin
  `internal/ingress/auth_header_only_test.go`
  (`TestAuthReadsTransportHeaderOnly` — the bearer-extraction path reads
  `r.Header` and never `r.Body`; planting a body read goes RED), and the Origin
  DNS-rebinding guard `internal/ingress/origin_test.go`
  (`TestOriginPolicyAllows`, `TestHandlerRejectsDisallowedOrigin` — a disallowed
  Origin is 403; neutering the Origin check goes RED).

## III. The caller credential never rides the F5 forward (NFR-SEC-09, NFR-SEC-26)

The caller bearer never appears on the forward leg, in a forwarded argument, or
on any path reaching the sandbox; the forward carries only the gateway's own
service identity. This is a **type fact**: the forward shapes have no field that
could carry the credential.

The transport (the F5 dial) presents the gateway's OWN service credential — the
host-side service-to-service "Generic internal token" (component-01:39, §8) — over
an mTLS-1.3 leg (NFR-SEC-37), never the caller's credential and never an operator
scope (P1-S2). A forward with no service credential is refused, never sent
anonymously (NFR-SEC-26). The F5 wire is **HTTP/JSON over mTLS**, not gRPC: the
Control gateway-ingress mounts a minimal JSON service surface (`POST
/v1alpha/sessions[/destroy|/status]`, decoded with `DisallowUnknownFields`), and the
gRPC surface named in 08-contracts §1 is a future follow-up Control itself declares.
The FIELD SEMANTICS are NOT invented in this repo: they are the frozen Control
session-setup schema (`session_setup.proto`, PR #293), vendored byte-identical (see
`VENDORED.md`) and hand-mapped into the seam (`internal/forward/session.go`); the
JSON wire projection is exactly the three fields Control's `createBody` decodes
(`session_hint`, `image`, `control_pub_key`).

The F5 create is **stateless create-per-forward** (architect ruling A). The
session-provisioning fields (`workload_trust_profile`, `mount_intent`,
`egress_policy`, `resource_caps`) come STRICTLY from the deployment
`ProvisioningPolicy` injected at construction — NEVER from the caller's tool-call
body, so **a caller cannot provision its own session** (widen caps, escalate the
trust profile, or open egress). The only caller-influenced value is the
`session_hint`, and it is a HINT (NFR-SEC-43), sourced from the resolved,
non-secret principal handle. Custody holds as a type fact on both directions: the
mapped shapes have no field for the minted Storage-JWT / filestore credential
(`MountIntent` omits the auth token). The `image` ref is PIN-PENDING at the
gatekeeper (`reserved 6`/`"image"`, #205 / issue #3) and is left UNSET on the wire
(empty), never invented nor silently dropped; `control_pub_key` is likewise empty on
a bare create (the Ed25519 key is staged for the exec channel Control drives — the G2
exec-driver, ADR-0024). The create round-trip is LIVE: the dial builds and validates
an admissible create (fail-closed on an unspecified profile, an ill-formed mount
scope, or an unset pids cap), projects it to the JSON wire body, POSTs it over the
hardened mTLS transport, and maps the reply — failing closed on a transport error or
a non-2xx (never a fabricated success). `Destroy` is LIVE too (`POST
/v1alpha/sessions/destroy`, the cooperative teardown, never the operator force-kill).
`Route` is a deliberate fail-closed stub until Control exposes a per-session
`control_endpoint` (the G2 exec-driver, NFR-IC-05); resolving it through `/status`
would return the wrong contract (`{key,state}`, not an endpoint), so it refuses
rather than fabricate.

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
  a credential error refuses the forward; `TestDialForwardFailsClosedOnUnreachableControl`
  — the dial path builds+validates the create then fails closed when Control is
  unreachable, never a fabricated success). The provisioning guard:
  `internal/forward/session_test.go`
  (`TestProvisioningComesFromPolicyNotBody` — provisioning comes from the
  deployment policy, not the caller body, so a caller cannot provision;
  `TestCreateRefusesUnspecifiedProfile` / `TestConstructorRefusesInadmissiblePolicy`
  — fail-closed admission; `TestCreateCarriesNoCredentialField` — the mapped
  create carries no credential-named field; `TestRouteIsFailClosedStubUntilG2` — the
  Route stub refuses rather than fabricate a control_endpoint;
  `TestDestroyFailsClosedWithoutTransport` — live Destroy fails closed with no
  transport). The LIVE F5 round-trip: `internal/forward/roundtrip_test.go`
  (`TestForwardLiveRoundTrip` — a create POSTs exactly `{session_hint, image,
  control_pub_key}` over a verified mTLS handshake and maps the 201 `{key,state}`
  reply into a `SessionResponse` correlation; `TestForwardDoesNotLeakCallerCredential`
  — no caller `sk-ocu-` key rides F5 in header or body;
  `TestForwardFailsClosedOnControlError` / `TestDestroyFailsClosedOnControlError` — a
  non-2xx control reply is a fail-closed refusal, never a fabricated success;
  `TestDestroyLiveRoundTrip` — the cooperative teardown POSTs
  `/v1alpha/sessions/destroy`; both live paths go RED under a fabricate-success or
  no-op keystone neuter).
  The SHIPPED wiring (a self-audit found the composition root calling a legacy
  endpoint-only constructor AROUND these guards — the guarded path existed,
  production did not walk it): the legacy `NewControlForwarder` was REMOVED, so
  `NewControlForwarderWithDial` is the only construction path, and
  `cmd/ocu-mcp-gatewayd/wiring_test.go` pins the composition root
  (`TestShippedForwarderWiringUsesGuardedConstructor` — an AST scan of package
  main admits only the guarded constructor, so re-adding a bypass call goes RED;
  `TestServeRequiresServiceCredentialFile` / `TestServeRequiresProvisioningPolicy`
  / `TestServeRefusesEndpointWithoutMTLS` — the daemon refuses to BOOT, before any
  listener binds, on a configuration that cannot walk the guarded path). The
  material the guarded path consumes: `internal/forward/credential_test.go` (the
  file-backed Generic internal token fails closed at construction and per
  presentation, and re-reads the file so rotation needs no restart),
  `internal/forward/mtls_load_test.go` (partial or unparsable mTLS material is
  refused; the TLS-1.3 floor is pinned), and
  `internal/config/provisioning_test.go` (closed workload-trust-profile
  vocabulary — never defaulted; unknown-field smuggle guard; admissibility stays
  with the constructor as the single validation source).

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
  and the gateway service does not join the Compose operator network). The gate
  is **fail-closed on an empty/malformed manifest**: a positive structural
  assertion (`assert_k8s_wellformed`/`assert_compose_wellformed`) requires the
  manifest to actually carry the gateway policy shape, so a manifest that proves
  nothing fails CLOSED rather than passing by absence of an operator route (the
  CodeRabbit fail-open). The `--self-test` red-probe plants an operator route in
  every k8s selector form (matchLabels, matchExpressions In/Exists,
  namespaceSelector) AND plants 6 empty/malformed manifests, asserting the gate
  goes RED on each; it runs in CI before the main gate.

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

## X. The caller-auth wire format is ratified (ADR-0027, NFR-SEC-87 floor)

The minimal-shelf static `sk-ocu-` validator and the full-shelf OAuth 2.1 RS
validator are two shelves of one `CallerAuthenticator` interface. ADR-0027 is
**accepted**, and its wire contract is now a **vendored artifact**:
`contracts/mcp/mcp-key-set.schema.json` (the Control→gateway hashed-key boot-set,
byte-identical from canon, `VENDORED.md`).

The minimal shelf enforces the NFR-SEC-87 floor: it stores only salted SHA-256
(`sha256(salt‖secret)`, hex, never plaintext, rejecting the unsalted digest per
GHSA-69x8-hrgq-fjj8), compares **constant-time** (`subtle.ConstantTimeCompare`,
no early-exit), and validates against boot-loaded material in-process — never a
per-request Control lookup. The boot-set is **schema-validated at load, fail-closed**
(an empty records set, a non-`active` status, a malformed hash, a short salt, or an
extra field are all refused — the set is boot-rejected, never served with holes).
The `deployment` scope is guarded in **two layers**: (i) at boot, a set with any
record scoped to another deployment reds the WHOLE load (`-deployment` is required;
empty is boot-reject), and (ii) at resolve, a record whose deployment ≠ this
gateway's never authenticates — closing the confused-deputy foreign-set class. A
key absent from the set, a wrong secret, a revoked/expired (hence omitted) key, or
a deployment mismatch is refused with `401` and an unconditional `WWW-Authenticate:
Bearer` challenge. Revocation converges within the NFR-SEC-04 window: the boot-set
is **re-loaded periodically** (`-boot-set-refresh` < 5 min) with an atomic swap, so
a revoked key stops authenticating on the next resolve; a refresh failure keeps the
last-good set (fail-safe, never blanking auth). The plaintext `sk-ocu-` key is
NEVER logged or emitted to audit — the audit actor is the `key_id`, never the
secret.

- **Enforcement:** `internal/auth/skkey_test.go` (the real salted-SHA-256 path:
  `TestStaticKeySetResolvesActiveKey`, `…RejectsWrongSecret`, `…RejectsRevoked`,
  `…RejectsExpired`, `…RejectsForeignDeploymentRecord`) and the constant-time pin
  `internal/auth/constant_time_ast_test.go` (`TestResolveUsesConstantTimeCompare`
  — an AST inspection of Resolve's BODY, replacing a grep-mechanics version a
  self-audit proved vacuous: it requires a subtle.ConstantTimeCompare CALL inside
  Resolve, and forbids bytes.Equal, any ==/!= over a call or indexed value, and
  any `break` in the record loop, so a non-constant-time rewrite with a dead
  token reference goes RED); the schema gate `internal/keyset/`
  (`TestSchemaRejects` — empty-set / non-active / malformed-hash / extra-field all
  refused); the boot-set loader `internal/config/loader_test.go`
  (`TestFileLoaderForeignDeploymentBootRejects`, `…EmptyDeploymentFailsClosed`,
  `…NonActiveStatusFailsSchema`, `…ExtraFieldFailsSchema`); and the refresh path
  `internal/boot/boot_test.go` (`TestRefreshSwapsInNewSet`,
  `TestRefreshFailureKeepsLastGoodSet`). The vendored schema is byte-pinned by
  `scripts/vendored_check.py`.

## XI. F10 OCSF audit is emit-before-ack, fail-closed durable-first (NFR-SEC-03)

Every terminated request **with a validated identity** is recorded as an OCSF
ApiActivity event on the gateway's audit fan-in channel BEFORE the response is
acknowledged; a durable audit-write failure REFUSES the request, never acks it. A
200 therefore always means the action took effect AND was durably recorded. This
holds for the SUCCESS path AND for the post-auth REFUSAL paths — a ceiling
refusal (429) and a forward refusal (502) each emit an `OutcomeFailure` event
with the resolved actor, durable-first fail-closed and SYMMETRIC to success: a
refusal we could not durably record is a repudiation hole, so it becomes a 500,
never a silently-unrecorded rejection (§XI, canon spec lines 64/75).

The two PRE-AUTH refusals — a 401 auth-failure and a 403 origin rejection — fire
before any caller is resolved, so they carry no host-attested actor and are a
DELIBERATE transport-layer omission (a placeholder actor would be false
attribution in OCSF, worse than omission), NOT a gap. This is documented on the
audit package and pinned by a test so the exclusion cannot silently erode.

The audit actor is the host-attested caller principal (the resolved KeyID), never
a body claim (NFR-SEC-09). The per-source `sequence` is monotonic; the pipeline
authors the hash-chain at ingest (the gateway supplies only the sequence). The
contract is the vendored `contracts/audit/audit-fanin.asyncapi.yaml` (channel
`mcpGatewayAudit`, payload OCSF ApiActivity).

- **Enforcement:** `internal/ingress/invariants_test.go`
  (`TestF10_AuditWriteFailureIsRefusal` — a forward that succeeds but whose audit
  write fails is refused 500, not acked 200; planting an ignored emit error goes
  RED) and (`TestF10_AuditActorIsHostAttested` — the emitted actor is the resolved
  KeyID, a body `caller` claim does not appear). The emitter's own fail-closed
  contract: `internal/audit/audit_test.go` (`TestEmitWriteFailureIsRefusal`,
  `TestSequenceMonotonicAndUnique`, `TestEmitInvalidEnvelopeRefused`). The §XI
  refusal-recording: `internal/ingress/refusal_audit_test.go`
  (`TestForwardRefusalIsRecorded` / `TestCeilingRefusalIsRecorded` — a 502/429
  post-auth refusal records exactly one OutcomeFailure event with the resolved
  actor; removing either refusal emit goes RED; `TestRefusalAuditIsFailClosed` —
  a refusal whose audit write fails is 500, not the original refusal code;
  `TestPreAuthRefusalsDoNotEmit` — 401 and 403 emit nothing, the documented
  transport-layer omission).

---

## XII. Tool execution is serialized per session by default (NFR-IC-05)

The tool-calls of one logical session run in arrival order — one settled before
the next starts — and parallelism is an explicit per-skill opt-in decided by a
deployment predicate, NEVER by a caller body field. The serializer keys on the
session hint (a HINT, NFR-SEC-43), sits BEHIND the per-caller ceiling (total
in-flight is bounded first), and holds the session's slot across forward + emit
(the settled state), so call N+1 of a session cannot overtake the durable record
of call N — the per-session history is strictly executed → recorded → next.

It is an ephemeral, self-cleaning concurrency primitive, NOT a session registry:
a session's gate exists only while it is contended and is deleted at zero
in-flight, so nothing outlives the union of overlapping in-flight requests (the
component-01 no-state-outlives-a-request invariant holds; architect ruling P3-A).
The per-session queue is BOUNDED — the key is caller-influenced, so an unbounded
queue would be a DoS vector; overflow is a fail-closed refusal with a stable
reason, never an unbounded park.

- **Enforcement:** `internal/serialize/serialize_test.go`
  (`TestFIFOOrderPerSession` — queued calls of a session proceed in arrival order;
  `TestSelfCleaningDrainsToZero` — the gate map returns to zero after drain,
  neutering the delete-at-zero goes RED; `TestBoundedRefusesOverflow` — a session
  queue at its bound refuses with `ErrSerializerFull` rather than parking,
  neutering the bound goes RED; `TestParallelOptInBypassesSerialization` — a
  parallel-opted tool does not serialize while a sequential one does;
  `TestDifferentSessionsDoNotBlockEachOther` — serialization is per session). The
  handler wiring (slot spans forward + emit): `internal/ingress/handler.go` step
  4b. The parallel opt-in is a deployment predicate (`ParallelPredicate`), never a
  caller body field.

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
