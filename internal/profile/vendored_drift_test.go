// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestEmbeddedProfileMatchesCanonVendoredCopy pins that the go:embed'd validator
// contract (this package's ocu-constraints.schema.json, the ONE the binary
// actually validates against) stays byte-identical to the canon-pinned copy at
// contracts/mcp/2025-06-18/ocu-constraints.schema.json. The two copies exist
// because the validator loads its contract via go:embed from THIS package
// directory (a disk read at boot would be a fail-open seam), while
// contracts/mcp/2025-06-18/ is the vendored-from-canon artifact VENDORED.md and
// scripts/vendored_check.py track. Nothing previously asserted the two stayed in
// lockstep — a canon re-pin that updates contracts/mcp/2025-06-18/ (as ADR-0027's
// two-shelf x-ocu-authz split did) can silently leave this package's copy on the
// OLD pin forever, because scripts/vendored_check.py only checks the
// contracts/mcp/2025-06-18/ path against ITS recorded blob OID — it has no entry
// for internal/profile/ocu-constraints.schema.json.
//
// Red-probe: this test was RED against the repository as found (the embedded
// copy was the pre-ADR-0027 pin, fbada4ed, while the canon copy had already
// re-vendored to 23b28bd — see VENDORED.md's re-pin note). Re-vendoring the
// embedded copy from the canon copy turns it green.
func TestEmbeddedProfileMatchesCanonVendoredCopy(t *testing.T) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	// This file lives at internal/profile/vendored_drift_test.go; the repo root
	// is two directories up.
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	canonPath := filepath.Join(repoRoot, "contracts", "mcp", "2025-06-18", "ocu-constraints.schema.json")

	canon, err := os.ReadFile(canonPath)
	if err != nil {
		t.Fatalf("read canon vendored copy %s: %v", canonPath, err)
	}

	embedded := ProfileBytes()

	if string(embedded) != string(canon) {
		t.Errorf("internal/profile/ocu-constraints.schema.json (go:embed'd, %d bytes) has DRIFTED from the canon-pinned copy at %s (%d bytes) — the validator is enforcing a stale contract; re-vendor the embedded copy from the canon copy and update embed.go's provenance comment + VENDORED.md",
			len(embedded), canonPath, len(canon))
	}
}
