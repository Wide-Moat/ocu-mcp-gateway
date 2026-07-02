// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestShippedForwarderWiringUsesGuardedConstructor pins CONSTITUTION §III at the
// COMPOSITION ROOT: the forwarder the daemon actually ships is built by the
// guarded constructor (NewControlForwarderWithDial — mTLS-1.3 policy validated at
// construction, NFR-SEC-37; a ServiceCredential required, NFR-SEC-26; the
// deployment ProvisioningPolicy admissibility-checked, ruling A) and NEVER by a
// bypass that skips those guards.
//
// A self-audit found the shipped main.go called the legacy endpoint-only
// constructor while every §III dial guard sat on the WithDial path — the classic
// "guarded path exists, production does not walk it": with -control-url set, the
// legacy construction booted an unguarded forwarder instead of refusing
// endpoint-without-mTLS at construction. The package tests stayed green because
// they exercised the guarded constructor, not the shipped wiring.
//
// Structural prong (this test): an AST scan of package main asserts the ONLY
// forward-package constructor called is NewControlForwarderWithDial. Red-probe:
// re-adding a legacy forward.NewControlForwarder call in main.go goes RED here
// even if every behavioral test still passes.
func TestShippedForwarderWiringUsesGuardedConstructor(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	path := filepath.Join(thisDir(t), "main.go")
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	guarded := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "forward" {
			return true
		}
		switch sel.Sel.Name {
		case "NewControlForwarderWithDial":
			guarded++
		case "NewControlForwarder":
			t.Errorf("main.go:%d calls the legacy forward.NewControlForwarder, bypassing the §III dial guards (mTLS NFR-SEC-37, ServiceCredential NFR-SEC-26, provisioning admissibility); the composition root must use NewControlForwarderWithDial", fset.Position(call.Pos()).Line)
		}
		return true
	})
	if guarded == 0 {
		t.Error("main.go never calls forward.NewControlForwarderWithDial; the shipped daemon must construct its forwarder through the guarded path (§III)")
	}
}

// The behavioral prong: serve() — the SHIPPED boot path — must refuse a
// configuration that cannot walk the guarded forwarder construction, and it must
// refuse it fail-closed at BOOT (before any listener binds), naming the missing
// knob. These tests drive serve() itself, not the forward package, so they bite
// the wiring the daemon actually ships.

func TestServeRequiresServiceCredentialFile(t *testing.T) {
	err := serve(context.Background(), options{
		bootSetPath:     "unused",
		deployment:      "d1",
		refreshInterval: time.Minute,
		// -service-credential-file deliberately absent
	})
	if err == nil || !strings.Contains(err.Error(), "-service-credential-file") {
		t.Fatalf("serve must refuse to boot without -service-credential-file (the F5 forward is never sent anonymously, NFR-SEC-26), got: %v", err)
	}
}

func TestServeRequiresProvisioningPolicy(t *testing.T) {
	err := serve(context.Background(), options{
		bootSetPath:           "unused",
		deployment:            "d1",
		refreshInterval:       time.Minute,
		serviceCredentialFile: writeTempFile(t, "token", "tok-svc"),
		// -provisioning-policy deliberately absent
	})
	if err == nil || !strings.Contains(err.Error(), "-provisioning-policy") {
		t.Fatalf("serve must refuse to boot without -provisioning-policy (F5 provisioning comes strictly from deployment config, §III), got: %v", err)
	}
}

func TestServeRefusesEndpointWithoutMTLS(t *testing.T) {
	err := serve(context.Background(), options{
		bootSetPath:           "unused",
		deployment:            "d1",
		refreshInterval:       time.Minute,
		serviceCredentialFile: writeTempFile(t, "token", "tok-svc"),
		provisioningPolicy:    writeTempFile(t, "policy.json", minimalPolicyJSON),
		controlURL:            "https://control:8443",
		// no -control-ca / -control-client-cert / -control-client-key
	})
	if err == nil || !strings.Contains(err.Error(), "mTLS") {
		t.Fatalf("serve must refuse a Control endpoint without mTLS material (the F5 leg is mTLS-1.3 only, NFR-SEC-37), got: %v", err)
	}
}

// minimalPolicyJSON is an admissible deployment provisioning policy for boot
// tests (mirrors internal/config's loader tests).
const minimalPolicyJSON = `{
  "workload_trust_profile": "internal_workforce",
  "mount_intent": {"destination": "/workspace", "filesystem_id": "fs-1", "read_only": false, "cache_duration_s": 30},
  "egress_policy": {"default_deny": true, "allowed_upstream": "object-store", "filesystem_id": "fs-1"},
  "resource_caps": {"cpu_cores": 1.0, "memory_bytes": 536870912, "pids_limit": 512}
}`

// writeTempFile writes a fixture file and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// thisDir resolves the directory of this test file, so the AST scan reads the
// same main.go that ships regardless of the working directory the test runs in.
func thisDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate package sources")
	}
	return filepath.Dir(file)
}
