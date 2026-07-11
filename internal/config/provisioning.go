// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// LoadProvisioningPolicy loads the deployment ProvisioningPolicy from a JSON
// file. This file is DEPLOYMENT CONFIG owned by this component's operator surface
// (like the flag set) — it is NOT a canon wire contract; the field names simply
// mirror the vendored session_setup.proto vocabulary so there is one vocabulary,
// not two. It is the config-plane source the F5 ruling (A) mandates: the
// session-provisioning fields come STRICTLY from here, never from a caller body
// (CONSTITUTION §III).
//
// The loader is a MAPPER with a closed vocabulary: an unknown workload-trust-
// profile word, a missing profile (Unspecified is not admissible — never
// defaulted), or an UNKNOWN FIELD (the boot-set smuggle guard, applied here) reds
// the load. ADMISSIBILITY (mount XOR, set pids cap, non-Unspecified profile) is
// validated once, by the guarded forwarder constructor — the single validation
// source — so an absent pids_limit maps to nil and is refused THERE, at boot.
func LoadProvisioningPolicy(path string) (forward.ProvisioningPolicy, error) {
	if path == "" {
		return forward.ProvisioningPolicy{}, fmt.Errorf("config: provisioning policy path is empty (fail-closed)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return forward.ProvisioningPolicy{}, fmt.Errorf("config: read provisioning policy %q: %w", path, err)
	}

	var wire provisioningWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return forward.ProvisioningPolicy{}, fmt.Errorf("config: provisioning policy %q is not the expected shape: %w", path, err)
	}

	profile, err := profileFromWire(wire.WorkloadTrustProfile)
	if err != nil {
		return forward.ProvisioningPolicy{}, fmt.Errorf("config: provisioning policy %q: %w", path, err)
	}

	mounts, err := mountsFromWire(wire)
	if err != nil {
		return forward.ProvisioningPolicy{}, fmt.Errorf("config: provisioning policy %q: %w", path, err)
	}

	return forward.ProvisioningPolicy{
		WorkloadTrustProfile: profile,
		MountIntents:         mounts,
		EgressPolicy: forward.EgressPolicy{
			DefaultDeny:     wire.EgressPolicy.DefaultDeny,
			AllowedUpstream: wire.EgressPolicy.AllowedUpstream,
			FilesystemID:    wire.EgressPolicy.FilesystemID,
		},
		ResourceCaps: forward.ResourceCaps{
			CPUCores:    wire.ResourceCaps.CPUCores,
			MemoryBytes: wire.ResourceCaps.MemoryBytes,
			PIDsLimit:   wire.ResourceCaps.PIDsLimit,
		},
		ExecTimeoutSeconds: wire.ExecTimeoutSeconds,
	}, nil
}

// provisioningWire is the on-disk JSON shape of the deployment provisioning
// policy. Field names mirror the vendored proto vocabulary (snake_case). There is
// deliberately NO field for a credential, a token, an image ref (PIN-PENDING,
// issue #3), or a runtime tier (NFR-SEC-38) — and DisallowUnknownFields refuses
// any attempt to add one in config without a code change.
type provisioningWire struct {
	WorkloadTrustProfile string `json:"workload_trust_profile"`
	// MountIntent is the LEGACY singular shape: exactly one storage mount. It
	// maps to a one-element mount list. mount_intents supersedes it (the ADR-0029
	// two-mount layout: uploads RO + outputs RW); setting BOTH is a config error.
	MountIntent  *mountIntentEntry  `json:"mount_intent"`
	MountIntents []mountIntentEntry `json:"mount_intents"`
	EgressPolicy struct {
		DefaultDeny     bool   `json:"default_deny"`
		AllowedUpstream string `json:"allowed_upstream"`
		FilesystemID    string `json:"filesystem_id"`
	} `json:"egress_policy"`
	ResourceCaps struct {
		CPUCores    float64 `json:"cpu_cores"`
		MemoryBytes int64   `json:"memory_bytes"`
		PIDsLimit   *int64  `json:"pids_limit"`
	} `json:"resource_caps"`
	// ExecTimeoutSeconds is the deployment ceiling on a single exec (the G2
	// exec-driver hop), a DEPLOYMENT-policy value (never caller-controlled). It is
	// OPTIONAL: an absent field is 0, which the gateway resolves to the safe default
	// and clamps into [1,300] before forwarding, so a config need not set it.
	ExecTimeoutSeconds uint32 `json:"exec_timeout_seconds"`
}

// profileFromWire maps the closed wire vocabulary to the enum. Unknown or empty
// words are refused — the loader never defaults a trust class (Unspecified is a
// fail-closed rejection at Control admission, so defaulting here would only move
// the failure later and hide the misconfiguration).
func profileFromWire(s string) (forward.WorkloadTrustProfile, error) {
	switch s {
	case "trusted_operator":
		return forward.WorkloadTrustProfileTrustedOperator, nil
	case "internal_workforce":
		return forward.WorkloadTrustProfileInternalWorkforce, nil
	case "":
		return forward.WorkloadTrustProfileUnspecified, fmt.Errorf("workload_trust_profile is missing (never defaulted; Unspecified is not admissible)")
	default:
		return forward.WorkloadTrustProfileUnspecified, fmt.Errorf("workload_trust_profile %q is not in the closed vocabulary {trusted_operator, internal_workforce}", s)
	}
}

// mountIntentEntry is the on-disk shape of one storage mount (snake_case,
// mirroring the vendored proto vocabulary like the rest of the wire struct).
type mountIntentEntry struct {
	Destination    string `json:"destination"`
	FilesystemID   string `json:"filesystem_id"`
	MemoryStoreID  string `json:"memory_store_id"`
	ReadOnly       bool   `json:"read_only"`
	CacheDurationS uint32 `json:"cache_duration_s"`
}

// mountsFromWire resolves the singular-vs-plural mount fields into one list.
// The two fields are mutually exclusive: the singular is the legacy one-mount
// shape and maps to a one-element list; a config setting both is ambiguous and
// reds the load (fail-closed - this file is operator-authored deployment
// config). Per-entry admissibility (scope XOR, destination shape, uniqueness)
// is validated once by the guarded forwarder constructor, the single
// validation source, like every other policy field.
func mountsFromWire(wire provisioningWire) ([]forward.MountIntent, error) {
	if wire.MountIntent != nil && len(wire.MountIntents) > 0 {
		return nil, fmt.Errorf("mount_intent and mount_intents are mutually exclusive; use mount_intents")
	}
	entries := wire.MountIntents
	if wire.MountIntent != nil {
		entries = []mountIntentEntry{*wire.MountIntent}
	}
	mounts := make([]forward.MountIntent, 0, len(entries))
	for _, e := range entries {
		mounts = append(mounts, forward.MountIntent{
			Destination:    e.Destination,
			FilesystemID:   e.FilesystemID,
			MemoryStoreID:  e.MemoryStoreID,
			ReadOnly:       e.ReadOnly,
			CacheDurationS: e.CacheDurationS,
		})
	}
	return mounts, nil
}
