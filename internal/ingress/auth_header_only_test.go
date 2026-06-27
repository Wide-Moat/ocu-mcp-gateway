// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestAuthReadsTransportHeaderOnly is the enforcing test for the architect pin:
// the caller authentication step reads the transport Authorization header ONLY
// and NEVER buffers the request body to extract the token (component-01 spec line
// 39 — the caller token rides the transport, never the JSON-RPC body or URI
// query). Buffering the body pre-auth would break the pre-buffer-reject invariant
// (#1, NFR-SEC-46/51) and open a DoS (an unauthenticated flood forces buffering).
//
// It is two-pronged so a future regress is caught from both directions:
//
//	(a) Behavioural: an OVER-SIZE body presented with a BAD bearer must be refused
//	    by the auth/header path (401) WITHOUT the body being read whole — i.e. the
//	    authenticator decides from the header alone, before any body buffering.
//	(b) Structural: bearerFromHeader's source reads r.Header, never r.Body — an AST
//	    scan asserts the bearer-extraction function never names the body reader.
//
// Red-probe: change bearerFromHeader to read r.Body, or make the handler buffer
// the body before Authenticate, and the structural prong goes RED.
func TestAuthReadsTransportHeaderOnly(t *testing.T) {
	t.Parallel()

	// (a) Behavioural: a bad bearer is rejected from the header before the body
	// matters. We send a body and a bad bearer; the response is 401 and the body
	// reader is left untouched by auth (the handler only reads it AFTER auth, which
	// never happens here).
	bodyRead := false
	h := newTestHandler(t, rejectAllAuth{})
	req := httptest.NewRequest(http.MethodPost, "/", &trackingReader{onRead: func() { bodyRead = true }})
	req.Header.Set(protocolVersionHeader, pinnedProtocolVersion)
	req.Header.Set("Authorization", "Bearer sk-ocu-bad")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad bearer must be 401, got %d", rec.Code)
	}
	if bodyRead {
		t.Error("auth path read the request body; the token must come from the transport header ONLY (architect pin)")
	}

	// (b) Structural: bearerFromHeader names r.Header and never r.Body.
	assertBearerExtractionReadsHeaderNotBody(t)
}

// assertBearerExtractionReadsHeaderNotBody parses handler.go and asserts the
// bearerFromHeader function body references the header accessor and never the body
// field, so the token-extraction path cannot read the body.
func assertBearerExtractionReadsHeaderNotBody(t *testing.T) {
	t.Helper()
	dir := thisDir(t)
	fset := token.NewFileSet()
	path := filepath.Join(dir, "handler.go")
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse handler.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "bearerFromHeader" {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatal("bearerFromHeader not found in handler.go; the auth-header-only pin has no anchor")
	}
	readsHeader := false
	ast.Inspect(fn, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Header":
			readsHeader = true
		case "Body":
			t.Errorf("bearerFromHeader references r.Body at %s; the caller token must be read from the transport header ONLY (architect pin)",
				fset.Position(sel.Pos()))
		}
		return true
	})
	if !readsHeader {
		t.Error("bearerFromHeader does not reference a Header accessor; it must extract the token from the transport header")
	}
}

// thisDir returns the directory of this test file (the ingress package dir).
func thisDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	return filepath.Dir(file)
}

// trackingReader is an io.ReadCloser that records when it is read, so the test can
// assert the auth path never touched the body.
type trackingReader struct {
	onRead func()
}

func (tr *trackingReader) Read(p []byte) (int, error) {
	tr.onRead()
	return 0, os.ErrClosed // any non-nil; the test only cares that Read was called
}
func (tr *trackingReader) Close() error { return nil }
