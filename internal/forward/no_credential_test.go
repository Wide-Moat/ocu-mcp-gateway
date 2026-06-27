// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// credentialFieldNames are the field-name fragments that would indicate a
// credential-bearing field smuggled onto a forward shape. Invariant #3 forbids
// the caller credential on the F5 forward leg or in a forwarded argument; the
// non-forwarding property is a TYPE FACT, so it is falsifiable by scanning the
// forward shapes for any such field. A field whose name contains one of these
// (case-insensitive) trips the gate — the proof that the wire shape cannot carry
// the bearer is that no such field exists to put it in.
var credentialFieldNames = []string{
	"bearer",
	"token",
	"apikey",
	"secret",
	"credential",
	"password",
	"authorization",
	"skocu",
}

// forwardShapes are the value types this package forwards or relays. None may
// declare a credential-bearing field. auth.Caller is included because it is
// embedded in SessionRequest.Principal — if a credential field were added to
// Caller, it would ride the forward through Principal, so the scan must cover it.
//
// The reflect pass below asserts the COMPILED struct shapes carry no such field
// (catching an embedded/promoted field), and the AST pass asserts the SOURCE of
// this package declares none (catching a field on a type not listed here).
func forwardShapes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(forward.SessionRequest{}),
		reflect.TypeOf(forward.ToolCall{}),
		reflect.TypeOf(forward.SessionResponse{}),
		reflect.TypeOf(auth.Caller{}),
	}
}

// TestForwardShapesCarryNoCredential is the invariant #3 enforcing test. It
// proves the F5 forward shapes have no field that could carry the caller
// credential — neither directly (reflect over each struct, including promoted
// fields) nor anywhere in this package's source (AST scan over every struct
// field name). Red-probe: add a `Bearer string` field to SessionRequest and this
// test goes RED.
func TestForwardShapesCarryNoCredential(t *testing.T) {
	t.Parallel()

	// (a) Reflect pass: walk every field (recursively, so an embedded credential
	// field is caught) of each forward shape.
	for _, typ := range forwardShapes() {
		assertNoCredentialField(t, typ, typ.Name())
	}

	// (b) AST pass: every struct declared in this package's non-test source must
	// declare no credential-named field — this catches a credential field added
	// to a NEW forward type not yet in forwardShapes().
	assertPackageSourceDeclaresNoCredentialField(t)
}

// assertNoCredentialField fails if typ (or any struct it embeds) declares a field
// whose name matches a credential fragment.
func assertNoCredentialField(t *testing.T, typ reflect.Type, path string) {
	t.Helper()
	if typ.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		lower := strings.ToLower(f.Name)
		for _, frag := range credentialFieldNames {
			if strings.Contains(lower, frag) {
				t.Errorf("forward shape %s.%s is a credential-bearing field (matches %q); "+
					"the caller credential must never have a place on the F5 forward (invariant #3)",
					path, f.Name, frag)
			}
		}
		// Recurse into struct-typed and embedded fields so a nested credential
		// field cannot hide.
		ft := f.Type
		if ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft != typ {
			assertNoCredentialField(t, ft, path+"."+f.Name)
		}
	}
}

// assertPackageSourceDeclaresNoCredentialField parses this package's non-test Go
// source and fails on any struct field whose name matches a credential fragment.
func assertPackageSourceDeclaresNoCredentialField(t *testing.T) {
	t.Helper()
	dir := packageDir(t)
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", e.Name(), perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, field := range st.Fields.List {
				for _, name := range field.Names {
					lower := strings.ToLower(name.Name)
					for _, frag := range credentialFieldNames {
						if strings.Contains(lower, frag) {
							t.Errorf("%s declares credential-bearing struct field %q at %s (matches %q); "+
								"forward shapes must carry no caller credential (invariant #3)",
								e.Name(), name.Name, fset.Position(name.Pos()), frag)
						}
					}
				}
			}
			return true
		})
	}
}

// packageDir returns the directory of this test file (the forward package dir).
func packageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate the package dir")
	}
	return filepath.Dir(thisFile)
}
