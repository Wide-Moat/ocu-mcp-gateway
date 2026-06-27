// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package auth is the caller-authentication SEAM at the MCP gateway ingress.
//
// The gateway authenticates the inbound MCP caller as a relying party BEFORE
// any tool-call is acted on, and it does so from transport-presented material
// ONLY — never from the JSON-RPC body or the URI query (NFR-SEC-09). This
// package holds the transport-neutral seam (CallerAuthenticator), the value
// types that flow from it into dispatch (Caller), and the fail-closed refusal
// sentinel. The concrete authenticators live below this seam.
//
// Two-shelf design (ADR-0027, owner-merge-gated on PR #311). The seam abstracts
// BOTH shelves of the same authority decision, so the final wire format drops in
// without a rewrite:
//
//   - Minimal shelf — a static "sk-ocu-" opaque API key (per-caller, 256-bit
//     CSPRNG, salted-SHA-256 at rest). The key carries NO claims; the authority
//     record (tenant, audience-equivalent deployment scope) is read from the
//     resolved boot-set entry, never self-asserted by the key. A key absent from
//     THIS deployment's boot-loaded set fails to resolve → refuse.
//   - Full shelf — the customer-IdP relying-party flow: an OAuth 2.1 Resource
//     Server bearer that MUST name this MCP server in its RFC 8707 audience
//     claim, with the RFC 9728 resource-metadata challenge on refusal.
//
// The load-bearing seam call is in-process validation against BOOT-LOADED
// material — never a per-request lookup into the Control plane. Boot-set
// material is configuration (the same config plane that delivers the gateway's
// service-identity signing material), not request-derived state, so validating
// against it keeps the "no state that outlives a request" invariant literal and
// adds no second gateway→Control hot-path leg. A per-request Control read-API
// (a forbidden second edge that would invert the F5 invariant) and a
// gateway-maintained denylist (Control owns denylists) are both REJECTED.
//
// The credential authenticated here is NEVER forwarded: it does not appear on
// the F5 forward leg, in a forwarded argument, or on any path reaching the
// sandbox (NFR-SEC-09, NFR-SEC-26). The forward carries only the gateway's own
// service identity. Enforcement of that non-forwarding lives in the forward
// package; this package's job is to terminate the caller credential at ingress.
package auth

import (
	"context"
	"errors"
)

// ErrUnauthenticated is the fail-closed refusal returned when no valid caller
// credential is present: a missing, malformed, expired, revoked, or
// wrong-audience credential, or one absent from this deployment's boot-loaded
// set. It is returned BEFORE any tool-call is buffered or acted on and before
// any forward is formed, so an unauthenticated request reaches nothing. Callers
// match it with errors.Is. Fail-closed is the default on this boundary: any
// authenticator error that is not an explicit success is a refusal, never an
// admit.
var ErrUnauthenticated = errors.New("auth: caller credential not authenticated, refused (fail-closed)")

// TransportCredential is the material an authenticator inspects, carried on the
// transport, never in the JSON-RPC body or URI query (NFR-SEC-09). Exactly the
// fields an authenticator needs are populated; a body is never present here by
// construction, so an authenticator cannot read identity from a request payload
// even by mistake.
//
// The Bearer is the raw transport bearer (the "sk-ocu-..." key on the minimal
// shelf, or the OAuth 2.1 RS access token on the full shelf), taken from the
// Authorization header. Origin is the request Origin header, validated against
// DNS-rebinding before the credential is even consulted (x-ocu-authz, the local
// 127.0.0.1-not-0.0.0.0 bind is enforced at listener construction, not here).
type TransportCredential struct {
	// Bearer is the raw transport bearer credential. It is consumed by the
	// authenticator and never propagated past it. An empty Bearer is a
	// fail-closed refusal, not an anonymous admit.
	Bearer string
	// Origin is the request Origin header, for DNS-rebinding validation. An
	// authenticator MAY reject a disallowed Origin before consulting the
	// bearer; the allowed set is config.
	Origin string
}

// Caller is the authenticated principal an authenticator resolves from a
// TransportCredential. It is the ONLY caller identity dispatch acts on, and it
// is derived entirely from the RESOLVED authority record (the boot-set entry on
// the minimal shelf, the validated token's looked-up record on the full shelf),
// never from a self-asserted claim in an opaque key (NFR-SEC-09: a looked-up
// record is more authoritative than a self-asserted claim).
//
// The raw credential is NOT a field here: a Caller is what survives past
// authentication, and the credential is terminated at the seam. There is
// therefore no Caller field that could be forwarded onto F5 or into the sandbox.
type Caller struct {
	// KeyID is the stable, non-secret identifier of the resolved credential
	// record (the "key_id" of the boot-set entry, or the token's subject on the
	// full shelf). It is safe to log and to record in an audit event; it is NOT
	// the secret. It is the audit actor handle for NFR-SEC-03 attribution.
	KeyID string
	// Tenant is the tenant the resolved record binds the caller to. It comes
	// from the record, never from a body field or a key-embedded claim.
	Tenant string
	// Audience is the deployment-scope / audience-equivalent the resolved record
	// is scoped to. A credential absent from THIS deployment's set never
	// resolves, so a resolved Caller is audience-valid by construction.
	Audience string
}

// CallerAuthenticator is the caller-authentication seam. A concrete
// authenticator (the minimal-shelf sk-ocu- key validator, the full-shelf
// OAuth 2.1 RS validator) turns a transport credential into a Caller, or returns
// ErrUnauthenticated (or a wrapped cause) — it NEVER admits on an error.
//
// Implementations MUST:
//   - read identity ONLY from transport material, never from a request body;
//   - validate against BOOT-LOADED material in-process, never via a per-request
//     Control lookup;
//   - fail closed: any non-success outcome is a refusal;
//   - constant-time compare secret material (no early-exit on first-byte
//     mismatch) so a timing side-channel cannot probe the key set.
//
// The context is first per repo convention; an in-process validator performs no
// network I/O but still takes it so the seam is uniform and a future full-shelf
// validator (which may refresh metadata) fits the same shape.
type CallerAuthenticator interface {
	// Authenticate resolves cred to a Caller, or returns ErrUnauthenticated
	// (possibly wrapped) when the credential is missing, malformed, expired,
	// revoked, wrong-audience, or absent from this deployment's set. It MUST NOT
	// consult a request body and MUST NOT perform a per-request Control lookup.
	Authenticate(ctx context.Context, cred TransportCredential) (Caller, error)
}

// KeySetLoader is the boot-time material seam: it loads the Control-owned
// hashed-key set into the gateway at boot (and refreshes it within the
// NFR-SEC-04 window, ≤5 min, when Control re-pushes after a revoke/rotate).
// Control is the single auditable mint point (the gateway never issues keys and
// never owns a key DB); this seam only CONSUMES the set Control delivers on the
// config plane. The concrete loader (a root-owned hashed-entries file on the
// minimal shelf, a config-plane fetch on the full shelf) lives below the seam.
//
// The returned KeySet is what a sk-ocu- CallerAuthenticator validates against in
// process. Holding it is config, not request-derived state, so it does not
// violate the no-state-outlives-a-request invariant: it outlives requests the
// same way the service-identity signing key does.
type KeySetLoader interface {
	// Load returns the current boot-set, or an error. A loader that cannot
	// produce a set fails closed at boot: the gateway must not bind a listener
	// against an empty or unreadable key set on the minimal shelf, because that
	// would admit nothing OR (worse, if mis-handled) admit everything. Boot
	// ordering (load-before-bind) is the boot package's responsibility.
	Load(ctx context.Context) (KeySet, error)
}

// KeySet is the boot-loaded authority material a sk-ocu- authenticator resolves
// a presented bearer against. It is an opaque interface so the at-rest shape
// (salted-SHA-256 record set) is owned by the concrete minimal-shelf
// implementation below the seam, and the full-shelf OAuth path can satisfy the
// CallerAuthenticator seam without implementing this key-set shape at all.
//
// Record fields the concrete set custodies (per ADR-0027, frozen on PR #311):
// {key_id, key_hash, salt, tenant, deployment/audience, expires_at, status,
// created_at}. Plaintext is never on disk; only the salted hash is stored.
type KeySet interface {
	// Resolve hashes the presented bearer with each candidate record's salt and
	// constant-time compares against that record's stored hash, returning the
	// matched record's Caller binding on a hit. A miss (no record, expired,
	// revoked) returns ErrUnauthenticated. It performs no network I/O.
	Resolve(bearer string) (Caller, error)
}
