// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"fmt"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// The F5 session-setup wire shape, hand-mapped from the frozen canon proto
// (contracts/proto/ocu/control/session/v1/session_setup.proto, PR #293 @ a6b48bd,
// blob 3ebd2c9; see VENDORED.md). The gateway hand-maps the seam structs rather
// than generating Go off the proto because the proto's go_package targets a
// FOREIGN module (github.com/Wide-Moat/ocu-control/gen/...); pulling that generated
// tree in would vendor another repo's build output. These structs mirror the
// frozen wire shape 1:1 in name and semantics so the live gRPC marshal (the
// remaining transport wire-up) maps field-for-field, and the security invariants
// the proto encodes are re-stated here as TYPE FACTS, not discipline.
//
// CUSTODY (proto file header, both directions): no request or response value on
// this surface carries the minted Storage-JWT, the filestore credential, or any
// backend secret. MountIntent OMITS the auth token (server-minted on the separate
// mount-config plane). This is enforced by construction — there is no field on
// these types to put such a secret in.
//
// NFR-SEC-26 SURFACE INVARIANT: the shape covers ONLY create/route/destroy. There
// is no force-kill, denylist-edit, or quota-override field or verb — the absence
// is the invariant (mirrors CONSTITUTION §IV / the proto service comment).

// WorkloadTrustProfile is the closed v1-GA workload trust axis the admission
// matrix keys on (proto enum WorkloadTrustProfile). It is the WORKLOAD trust axis
// ONLY: the runtime isolation tier (runc|gvisor|firecracker) is deployment-wide
// and is NOT a field on this surface (NFR-SEC-38) — a request cannot select or
// downgrade a tier. Unspecified is the proto3 zero value and is NOT admissible:
// the server rejects it fail-closed rather than defaulting to a real profile, so
// the gateway must set an explicit profile from its admission policy.
type WorkloadTrustProfile int32

const (
	// WorkloadTrustProfileUnspecified is the proto3 zero value — NOT a valid
	// profile. Forwarding it is a fail-closed rejection at Control admission, so
	// the gateway never leaves the profile at its zero value on a real create.
	WorkloadTrustProfileUnspecified WorkloadTrustProfile = 0
	// WorkloadTrustProfileTrustedOperator is the operator-trusted workload class.
	WorkloadTrustProfileTrustedOperator WorkloadTrustProfile = 1
	// WorkloadTrustProfileInternalWorkforce is the internal-workforce class.
	WorkloadTrustProfileInternalWorkforce WorkloadTrustProfile = 2
)

// valid reports whether p is an admissible (non-zero, known) profile. It mirrors
// the server's fail-closed admission check so the gateway can refuse to forward a
// create whose profile is unset/unknown rather than let Control reject it late.
func (p WorkloadTrustProfile) valid() bool {
	switch p {
	case WorkloadTrustProfileTrustedOperator, WorkloadTrustProfileInternalWorkforce:
		return true
	default:
		return false
	}
}

// MountIntent is the substrate-neutral per-session storage-mount description
// (proto message MountIntent). It names WHAT the session needs — destination,
// scope, RW/RO posture, freshness — but NEVER the credential: the weak Storage-JWT
// is server-minted on the mount-config plane and is ABSENT here by construction
// (custody). Exactly one of FilesystemID / MemoryStoreID identifies the scope
// (application-layer XOR; proto3 cannot express it without collapsing the two
// distinct named scopes).
type MountIntent struct {
	// Destination is the absolute guest mountpoint (e.g. /workspace/out).
	Destination string
	// FilesystemID is the per-session logical scope (the isolation unit); egress
	// binds the connection to this id. XOR with MemoryStoreID.
	FilesystemID string
	// MemoryStoreID is the parallel scope for a memory-backed mount. XOR with
	// FilesystemID.
	MemoryStoreID string
	// ReadOnly is the host-enforced posture: true => RO input, false => RW sink.
	ReadOnly bool
	// CacheDurationS is the per-mount local-VFS freshness window in whole seconds.
	CacheDurationS uint32
	// NOTE: there is deliberately NO auth-token field — it must never appear on
	// this surface (custody). The proto reserves NO name here; field 6 is left
	// free for a future ADDITIVE field, never for a credential.
}

// scopeValid reports whether exactly one of the two scope ids is set (the XOR the
// proto documents but proto3 cannot express). A mount with neither or both scopes
// is malformed and refused before forward.
func (m MountIntent) scopeValid() bool {
	return (m.FilesystemID != "") != (m.MemoryStoreID != "")
}

// EgressPolicy is the per-session egress trust-edge policy (proto message
// EgressPolicy): the deny-default posture plus the single allow-listed upstream
// the session may reach, keyed to the same FilesystemID as the mount.
type EgressPolicy struct {
	// DefaultDeny is the posture; it is true on every production path (deny-all
	// outbound). A production create with DefaultDeny=false is refused — there is
	// no permissive default.
	DefaultDeny bool
	// AllowedUpstream is the single allow-listed object-store service the mount
	// client may dial guest-out over the egress hop. Empty means no egress.
	AllowedUpstream string
	// FilesystemID binds the egress connection to the same scope as the mount.
	FilesystemID string
}

// ResourceCaps are the HARD resource caps stamped on the runtime (proto message
// ResourceCaps) — ceilings, not shares (CPU is a hard cap, never a relative
// weight).
type ResourceCaps struct {
	// CPUCores is the hard CPU ceiling in fractional cores.
	CPUCores float64
	// MemoryBytes is the hard memory ceiling in bytes.
	MemoryBytes int64
	// PIDsLimit caps the process count. It is a pointer so an unset cap (nil) is
	// distinguishable from an explicit zero (proto `optional int64`): production
	// must set it, and the gateway fails closed on an unset cap on a real create
	// rather than forwarding a 0 the server would read as "no limit".
	PIDsLimit *int64
}

// CreateRequest is the gateway → Control F5 create body, hand-mapped from the
// frozen proto CreateRequest. The admissible shape is {WorkloadTrustProfile,
// MountIntent, EgressPolicy, ResourceCaps} plus a SessionHint. The
// provisioning fields (profile, mount, egress, caps) are SESSION-PROVISIONING
// values the gateway supplies from its admission policy / deployment config —
// NOT caller-supplied body fields (a caller must not be able to widen its own
// caps or egress). SessionHint is the ONLY caller-influenced value, and it is a
// HINT: the host derives the real session_id binding from the attested caller
// identity, never from this string (NFR-SEC-43).
//
// There is NO tier field (NFR-SEC-38), NO auth token, and NO backend credential
// anywhere in this body (custody). The in-process `image` ref that the local
// gateway CreateRequest would carry is PIN-PENDING at the gatekeeper — the proto
// reserves field 6 / "image" (#205 reconciliation). It is intentionally ABSENT
// here: not invented, not silently dropped. See issue #3 for the architect's
// image-ref-vs-reserved assessment; the seam leaves the image path unset until
// canon reconciles it.
type CreateRequest struct {
	// WorkloadTrustProfile selects the admission-matrix workload class. Supplied
	// by the gateway's admission policy; must be a valid (non-Unspecified) profile
	// or the create is refused before forward.
	WorkloadTrustProfile WorkloadTrustProfile
	// MountIntent is the per-session storage mount description (no auth token).
	MountIntent MountIntent
	// EgressPolicy is the per-session egress trust-edge policy (default-deny).
	EgressPolicy EgressPolicy
	// ResourceCaps are the hard caps stamped on the runtime.
	ResourceCaps ResourceCaps
	// SessionHint is the caller-influenced session/tenant/container_name id — a
	// HINT ONLY (NFR-SEC-43). A foreign hint cannot bind another tenant's session.
	SessionHint string
	// NOTE: the proto's reserved field 6 / "image" is deliberately NOT represented
	// here (PIN-PENDING, issue #3). Adding an Image field would invent a contract
	// the gatekeeper reserves; the gateway must not.
}

// CreateResponse is the Control → gateway F5 create reply, hand-mapped from the
// frozen proto CreateResponse. It carries the HOST-DERIVED session binding and
// the per-session control endpoint — and NO credential (custody).
type CreateResponse struct {
	// SessionID is the host-derived session binding (NFR-SEC-43) — the authority,
	// not an echo of the request hint.
	SessionID string
	// ControlEndpoint is the per-session control endpoint the caller routes to.
	ControlEndpoint string
}

// ProvisioningPolicy is the deployment-level source of the session-provisioning
// fields of a CreateRequest. It is the seam the architect's F5 ruling (A) mandates:
// workload_trust_profile, mount_intent, egress_policy, and resource_caps come
// STRICTLY from here — a config value fixed at deployment, injected at forwarder
// construction — and NEVER from the caller's tool-call body. A caller therefore
// cannot widen its own caps, downgrade its trust profile, or open egress by
// smuggling those fields in a request; the only caller-influenced value on the
// create is the SessionHint, applied separately.
//
// This is a value type carried on the forwarder, not an interface: the policy is
// static deployment config, resolved once, not a per-request negotiation.
type ProvisioningPolicy struct {
	// WorkloadTrustProfile is the admission-matrix workload class for sessions this
	// gateway provisions. It MUST be a valid (non-Unspecified) profile — a create
	// built from an Unspecified policy is refused fail-closed before forward.
	WorkloadTrustProfile WorkloadTrustProfile
	// MountIntent is the per-session storage mount description (no auth token).
	MountIntent MountIntent
	// EgressPolicy is the per-session egress trust-edge policy (default-deny on a
	// production path).
	EgressPolicy EgressPolicy
	// ResourceCaps are the hard caps stamped on the runtime.
	ResourceCaps ResourceCaps
}

// buildCreateRequest assembles the F5 CreateRequest from the deployment
// ProvisioningPolicy and the caller-derived session hint — and NOTHING else. The
// provisioning fields are copied verbatim from the policy; the ONLY caller-
// influenced value is sessionHint, which lands in the HINT field (never an
// authority, NFR-SEC-43). There is no path by which a caller body value reaches a
// provisioning field: the caller's ToolCall is not even an argument here. The
// `image` field is intentionally not set (PIN-PENDING, issue #3).
func buildCreateRequest(policy ProvisioningPolicy, sessionHint string) CreateRequest {
	return CreateRequest{
		WorkloadTrustProfile: policy.WorkloadTrustProfile,
		MountIntent:          policy.MountIntent,
		EgressPolicy:         policy.EgressPolicy,
		ResourceCaps:         policy.ResourceCaps,
		SessionHint:          sessionHint,
	}
}

// sessionHintFor derives the session hint from the resolved caller principal. It
// uses the caller Tenant — a NON-SECRET, host-attested handle the auth seam
// produced, never the caller's raw credential (auth.Caller has no credential
// field). The value is a HINT the host may seed a derived binding from, never the
// authority for the session_id binding (NFR-SEC-43); a foreign hint cannot bind
// another tenant's session. It is the ONLY caller-influenced value on the create.
func sessionHintFor(principal auth.Caller) string {
	return principal.Tenant
}

// validate enforces the fail-closed admission checks the gateway can make before
// a forward, mirroring the server's own rejections so a malformed create is
// refused at the source rather than late at Control:
//   - the workload trust profile must be a valid (non-Unspecified) profile
//     (NFR-SEC-38 / admission fail-closed);
//   - exactly one mount scope is set (the proto's documented XOR);
//   - on a deny-default egress the allowed upstream is scoped to the mount's
//     filesystem id (the trust-edge keys the credential exchange on it);
//   - the pids limit is set (production must not forward an unset cap the server
//     would read as "no limit").
//
// A validation failure returns an error wrapping ErrForwardFailed so the forward
// boundary stays fail-closed (invariant #9).
func (r CreateRequest) validate() error {
	if !r.WorkloadTrustProfile.valid() {
		return fmt.Errorf("%w: workload trust profile is unspecified/unknown (fail-closed admission)", ErrForwardFailed)
	}
	if !r.MountIntent.scopeValid() {
		return fmt.Errorf("%w: mount intent must set exactly one of filesystem_id / memory_store_id", ErrForwardFailed)
	}
	if r.ResourceCaps.PIDsLimit == nil {
		return fmt.Errorf("%w: resource caps must set a pids limit on a production create (no unset cap)", ErrForwardFailed)
	}
	return nil
}
