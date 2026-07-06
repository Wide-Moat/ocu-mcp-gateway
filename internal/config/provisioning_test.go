// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// writePolicy writes a provisioning-policy JSON file and returns its path.
func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provisioning.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

const validPolicyJSON = `{
  "workload_trust_profile": "internal_workforce",
  "mount_intent": {"destination": "/workspace", "filesystem_id": "fs-1", "read_only": false, "cache_duration_s": 30},
  "egress_policy": {"default_deny": true, "allowed_upstream": "object-store", "filesystem_id": "fs-1"},
  "resource_caps": {"cpu_cores": 1.0, "memory_bytes": 536870912, "pids_limit": 512}
}`

func TestLoadProvisioningPolicyMapsWireShape(t *testing.T) {
	got, err := LoadProvisioningPolicy(writePolicy(t, validPolicyJSON))
	if err != nil {
		t.Fatalf("LoadProvisioningPolicy: %v", err)
	}
	if got.WorkloadTrustProfile != forward.WorkloadTrustProfileInternalWorkforce {
		t.Errorf("profile: got %d, want InternalWorkforce", got.WorkloadTrustProfile)
	}
	if got.MountIntent.Destination != "/workspace" || got.MountIntent.FilesystemID != "fs-1" ||
		got.MountIntent.MemoryStoreID != "" || got.MountIntent.ReadOnly || got.MountIntent.CacheDurationS != 30 {
		t.Errorf("mount intent mismapped: %+v", got.MountIntent)
	}
	if !got.EgressPolicy.DefaultDeny || got.EgressPolicy.AllowedUpstream != "object-store" || got.EgressPolicy.FilesystemID != "fs-1" {
		t.Errorf("egress policy mismapped: %+v", got.EgressPolicy)
	}
	if got.ResourceCaps.CPUCores != 1.0 || got.ResourceCaps.MemoryBytes != 536870912 {
		t.Errorf("resource caps mismapped: %+v", got.ResourceCaps)
	}
	if got.ResourceCaps.PIDsLimit == nil || *got.ResourceCaps.PIDsLimit != 512 {
		t.Errorf("pids limit must map to a set pointer (512), got %v", got.ResourceCaps.PIDsLimit)
	}
}

// TestLoadProvisioningPolicyRefusesUnknownProfile pins the closed vocabulary: the
// workload trust profile is a closed enum and the loader NEVER defaults or guesses
// — an unknown or missing profile is refused so a typo cannot silently land a
// session in the wrong admission class.
func TestLoadProvisioningPolicyRefusesUnknownProfile(t *testing.T) {
	bad := strings.Replace(validPolicyJSON, "internal_workforce", "root", 1)
	if _, err := LoadProvisioningPolicy(writePolicy(t, bad)); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("an unknown profile must be refused naming the value, got %v", err)
	}
	missing := strings.Replace(validPolicyJSON, `"workload_trust_profile": "internal_workforce",`, "", 1)
	if _, err := LoadProvisioningPolicy(writePolicy(t, missing)); err == nil {
		t.Error("a missing profile must be refused (never defaulted) — Unspecified is not admissible")
	}
}

// TestLoadProvisioningPolicyRefusesUnknownField mirrors the boot-set smuggle
// guard: an extra field (say, a credential someone tries to route through the
// provisioning file) reds the load rather than being silently dropped.
func TestLoadProvisioningPolicyRefusesUnknownField(t *testing.T) {
	smuggle := strings.Replace(validPolicyJSON, `"workload_trust_profile"`, `"auth_token": "sk-x", "workload_trust_profile"`, 1)
	if _, err := LoadProvisioningPolicy(writePolicy(t, smuggle)); err == nil {
		t.Error("an unknown field must red the load (smuggle guard), not be silently dropped")
	}
}

func TestLoadProvisioningPolicyFailsClosedOnFile(t *testing.T) {
	if _, err := LoadProvisioningPolicy(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing policy file must be refused")
	}
	if _, err := LoadProvisioningPolicy(writePolicy(t, `{not json`)); err == nil {
		t.Error("malformed JSON must be refused")
	}
	if _, err := LoadProvisioningPolicy(""); err == nil {
		t.Error("an empty path must be refused")
	}
}

// TestLoadProvisioningPolicyLeavesAbsentPidsNil pins the division of labor: the
// loader is a MAPPER — an absent pids_limit maps to a nil pointer (distinguishable
// from an explicit 0), and the ADMISSIBILITY refusal of an unset cap belongs to
// the guarded forwarder constructor, the single validation source.
func TestLoadProvisioningPolicyLeavesAbsentPidsNil(t *testing.T) {
	noPids := strings.Replace(validPolicyJSON, `, "pids_limit": 512`, "", 1)
	got, err := LoadProvisioningPolicy(writePolicy(t, noPids))
	if err != nil {
		t.Fatalf("LoadProvisioningPolicy: %v", err)
	}
	if got.ResourceCaps.PIDsLimit != nil {
		t.Errorf("absent pids_limit must map to nil (the constructor refuses it), got %v", *got.ResourceCaps.PIDsLimit)
	}
}

// TestLoadProvisioningPolicyMapsExecTimeout pins the deployment exec-timeout
// ceiling (the G2 exec-driver hop): a configured exec_timeout_seconds maps onto the
// policy, so a deployment can retune the interactive-command ceiling. It is a
// DEPLOYMENT-policy value (F5 ruling A), never caller-controlled. The gateway clamps
// it into [1,300] with a 30 default before forwarding, so an absent field (0) is the
// "use default" signal, validated at the forward, not here.
func TestLoadProvisioningPolicyMapsExecTimeout(t *testing.T) {
	withTimeout := strings.Replace(validPolicyJSON,
		`"resource_caps": {"cpu_cores": 1.0, "memory_bytes": 536870912, "pids_limit": 512}`,
		`"resource_caps": {"cpu_cores": 1.0, "memory_bytes": 536870912, "pids_limit": 512}, "exec_timeout_seconds": 45`,
		1)
	got, err := LoadProvisioningPolicy(writePolicy(t, withTimeout))
	if err != nil {
		t.Fatalf("LoadProvisioningPolicy: %v", err)
	}
	if got.ExecTimeoutSeconds != 45 {
		t.Errorf("exec_timeout_seconds must map onto the policy (45), got %d", got.ExecTimeoutSeconds)
	}

	// Absent → 0 (the "use default" signal the clamp resolves to 30 at forward time).
	got2, err := LoadProvisioningPolicy(writePolicy(t, validPolicyJSON))
	if err != nil {
		t.Fatalf("LoadProvisioningPolicy: %v", err)
	}
	if got2.ExecTimeoutSeconds != 0 {
		t.Errorf("an absent exec_timeout_seconds must map to 0 (use-default), got %d", got2.ExecTimeoutSeconds)
	}
}
