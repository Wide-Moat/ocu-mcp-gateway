// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"net/http"
	"testing"
)

// TestUnauthenticated401CarriesWWWAuthenticateChallenge pins the canon
// x-ocu-authz rule (contracts/mcp/2025-06-18/ocu-constraints.schema.json,
// "unconditional" rules): a 401 for a missing or invalid bearer MUST carry a
// WWW-Authenticate: Bearer challenge, unconditionally on both auth shelves. The
// gateway code sets this header (handler.go), but no test pinned it — a future
// edit could delete the header and no gate would catch it. Red-probe: comment
// out the w.Header().Set("WWW-Authenticate", ...) call in handler.go and this
// test reds (header absent).
func TestUnauthenticated401CarriesWWWAuthenticateChallenge(t *testing.T) {
	h := newTestHandler(t, rejectAllAuth{})

	rec := post(h, pinnedProtocolVersion, "sk-ocu-bad", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad bearer must be 401, got %d (body %q)", rec.Code, rec.Body.String())
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer realm="ocu-mcp-gateway"`
	if got != want {
		t.Errorf("401 must carry WWW-Authenticate: %q, got %q (canon x-ocu-authz unconditional rule)", want, got)
	}
}
