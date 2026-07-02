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

	return forward.ProvisioningPolicy{
		WorkloadTrustProfile: profile,
		MountIntent: forward.MountIntent{
			Destination:    wire.MountIntent.Destination,
			FilesystemID:   wire.MountIntent.FilesystemID,
			MemoryStoreID:  wire.MountIntent.MemoryStoreID,
			ReadOnly:       wire.MountIntent.ReadOnly,
			CacheDurationS: wire.MountIntent.CacheDurationS,
		},
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
	}, nil
}

// provisioningWire is the on-disk JSON shape of the deployment provisioning
// policy. Field names mirror the vendored proto vocabulary (snake_case). There is
// deliberately NO field for a credential, a token, an image ref (PIN-PENDING,
// issue #3), or a runtime tier (NFR-SEC-38) — and DisallowUnknownFields refuses
// any attempt to add one in config without a code change.
type provisioningWire struct {
	WorkloadTrustProfile string `json:"workload_trust_profile"`
	MountIntent          struct {
		Destination    string `json:"destination"`
		FilesystemID   string `json:"filesystem_id"`
		MemoryStoreID  string `json:"memory_store_id"`
		ReadOnly       bool   `json:"read_only"`
		CacheDurationS uint32 `json:"cache_duration_s"`
	} `json:"mount_intent"`
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
