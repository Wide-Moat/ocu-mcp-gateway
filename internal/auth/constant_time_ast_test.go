// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package auth

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// TestResolveUsesConstantTimeCompare pins the constant-time property of the
// resolver STRUCTURALLY, in the body of Resolve itself (NFR-SEC-87, ADR-0027).
//
// A self-audit found the previous, grep-mechanics version of this test vacuous:
// it scanned the whole FILE for the token "subtle.ConstantTimeCompare" and two
// specific forbidden spellings. A careful neuter — Resolve rewritten as a
// non-constant-time byte loop with an early break, plus a DEAD file-level
// reference keeping the token present, avoiding both forbidden spellings —
// passed it, along with the entire auth suite. The AST version below goes RED
// under exactly that neuter (evidence in the audit-fix PR), because it inspects
// what Resolve DOES, not which tokens the file contains:
//
//  1. a subtle.ConstantTimeCompare CALL must appear inside Resolve's body — a
//     dead reference elsewhere no longer satisfies anything;
//  2. no bytes.Equal call inside Resolve — the classic non-CT digest equality;
//  3. no ==/!= comparison inside Resolve whose operand contains a call or an
//     index expression — this closes the conversion equalities
//     (string(want) == string(got), hex.EncodeToString(...) == ...) AND the
//     manual per-byte loop (want[i] != got[i]) in one rule; Resolve's
//     legitimate comparisons (status, deployment, err, eq == 1) touch only
//     plain identifiers, selectors and literals;
//  4. no `break` anywhere in Resolve — the comparison count must not depend on
//     WHERE in the set the match sat (the position-timing pin the architect
//     mandated; the public-attribute skips use `continue`, which stays legal).
func TestResolveUsesConstantTimeCompare(t *testing.T) {
	t.Parallel()

	fn := resolveFuncDecl(t)

	ctCalls := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if isSelectorCall(node, "subtle", "ConstantTimeCompare") {
				ctCalls++
			}
			if isSelectorCall(node, "bytes", "Equal") {
				t.Errorf("Resolve compares with bytes.Equal at %s — a non-constant-time digest equality (NFR-SEC-87)", pos(t, node))
			}
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				if operandContainsCallOrIndex(node.X) || operandContainsCallOrIndex(node.Y) {
					t.Errorf("Resolve has an ==/!= comparison over a call or indexed value at %s — digest material may only be compared with subtle.ConstantTimeCompare", pos(t, node))
				}
			}
		case *ast.BranchStmt:
			if node.Tok == token.BREAK {
				t.Errorf("Resolve breaks out of its record loop at %s — the comparison count must be independent of the match position (no position timing-leak)", pos(t, node))
			}
		}
		return true
	})
	if ctCalls == 0 {
		t.Error("Resolve's body never CALLS subtle.ConstantTimeCompare — the hash comparison is not provably constant-time (a dead token elsewhere does not count)")
	}
}

// resolveFuncDecl parses skkey.go and returns the staticKeySet.Resolve FuncDecl.
func resolveFuncDecl(t *testing.T) *ast.FuncDecl {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate package sources")
	}
	path := filepath.Join(filepath.Dir(thisFile), "skkey.go")
	astFset = token.NewFileSet()
	f, err := parser.ParseFile(astFset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse skkey.go: %v", err)
	}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "Resolve" || fd.Recv == nil || len(fd.Recv.List) != 1 {
			continue
		}
		if recvNames(fd) == "staticKeySet" {
			return fd
		}
	}
	t.Fatal("staticKeySet.Resolve not found in skkey.go; the constant-time pin has no anchor")
	return nil
}

// astFset carries positions for failure messages within this test file.
var astFset *token.FileSet

func pos(t *testing.T, n ast.Node) string {
	t.Helper()
	return fmt.Sprintf("%s", astFset.Position(n.Pos()))
}

// recvNames renders the receiver's base type name (star-stripped).
func recvNames(fd *ast.FuncDecl) string {
	expr := fd.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// isSelectorCall reports whether call is pkg.Fn(...).
func isSelectorCall(call *ast.CallExpr, pkg, fn string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == fn
}

// operandContainsCallOrIndex reports whether the expression subtree contains a
// call or an index expression — the two shapes every non-constant-time digest
// equality must take (a conversion/encode call, or a per-byte index).
func operandContainsCallOrIndex(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.CallExpr, *ast.IndexExpr:
			found = true
			return false
		}
		return true
	})
	return found
}
