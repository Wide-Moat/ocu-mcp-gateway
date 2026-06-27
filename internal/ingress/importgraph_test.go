// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gatewayModulePath is this module's import path. The gateway IS the whole
// module: unlike the sibling control plane (where the gateway is one in-binary
// adapter and the operator surface is a peer package to exclude), this component
// is a separate process whose module contains NO operator/lifecycle/kill-switch
// package at all. The code half of invariant #4 is therefore the stronger claim
// that no such package exists in the module to reach, plus a source scan that no
// gateway code names an operator-route symbol.
const gatewayModulePath = "github.com/Wide-Moat/ocu-mcp-gateway"

// forbiddenRouteSymbols are identifiers that would indicate a code path resolving
// to a lifecycle, denylist, or kill-switch route — the operator surface the
// gateway must never reach (invariant #4, code half; component-01 spec).
// Naming any of them in gateway source is the falsifying signal.
var forbiddenRouteSymbols = []string{
	"KillSwitch",
	"Killswitch",
	"Denylist",
	"DenyList",
	"RevokeAll",
	"RevokeOne",
	"ForceKill",
	"OperatorSeam",
	"OperatorScope",
	"Lifecycle",
}

// forbiddenImportFragments are import-path fragments that would indicate the
// module pulled in an operator/lifecycle/kill-switch package — none may appear in
// the module's transitive dependency closure.
var forbiddenImportFragments = []string{
	"/operator",
	"/killswitch",
	"/killSwitch",
	"/lifecycle",
	"/denylist",
}

// TestGatewayReachesNoOperatorRoute is the invariant #4 (code half) enforcing
// test. It proves (a) no internal source file names an operator-route symbol, and
// (b) the module's whole transitive dependency closure contains no operator/
// lifecycle/kill-switch package. Red-probe: add a `var KillSwitch struct{}` to
// any internal package, or import such a package, and this test goes RED.
func TestGatewayReachesNoOperatorRoute(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	// (a) Source scan over every internal package.
	scanInternalSourceForForbiddenSymbols(t, filepath.Join(root, "internal"))

	// (b) Transitive import-closure scan over the whole module.
	assertModuleDepsExcludeOperatorPath(t, root)
}

// moduleRoot walks up from this test file to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate the module root")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// scanInternalSourceForForbiddenSymbols parses every non-test .go file under dir
// (recursively) and fails on any identifier naming a forbidden operator-route
// symbol.
func scanInternalSourceForForbiddenSymbols(t *testing.T, dir string) {
	t.Helper()
	forbidden := map[string]bool{}
	for _, s := range forbiddenRouteSymbols {
		forbidden[s] = true
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, isIdent := n.(*ast.Ident); isIdent && forbidden[id.Name] {
				rel, _ := filepath.Rel(dir, path)
				t.Errorf("internal source %s names forbidden operator-route symbol %q at %s; "+
					"no gateway code path may resolve to a lifecycle/denylist/kill-switch route (invariant #4)",
					rel, id.Name, fset.Position(id.Pos()))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal source: %v", err)
	}
}

// assertModuleDepsExcludeOperatorPath shells out to `go list -deps ./...` for the
// whole module and fails if any dependency import path contains an operator/
// lifecycle/kill-switch fragment.
func assertModuleDepsExcludeOperatorPath(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "./...")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("`go list -deps ./...` failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dep := strings.TrimSpace(line)
		for _, frag := range forbiddenImportFragments {
			// Only flag fragments under this module's own path or an obvious
			// operator package — a third-party path coincidentally containing
			// "/lifecycle" is not an operator-surface reach. Scope to the module
			// path so the gate targets the gateway's own packages.
			if strings.Contains(dep, frag) && strings.HasPrefix(dep, gatewayModulePath) {
				t.Errorf("module dependency closure includes %q (operator-route fragment %q); "+
					"the gateway must reach no operator/lifecycle/kill-switch package (invariant #4)",
					dep, frag)
			}
		}
	}
}
