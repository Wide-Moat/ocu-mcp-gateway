// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// TestMountIntentsProjectVerbatimOntoTheWire pins the per-field content of the
// mount_intents projection, not just its presence. TestForwardLiveRoundTrip proves
// the list is non-empty and that every entry names exactly one scope; neither
// check would notice a projection that dropped read_only or transposed
// cache_duration_s between two mounts — control would then materialize a
// read-write mount where the deployment asked for read-only, which is a silent
// posture downgrade rather than a visible failure.
//
// The two mounts differ in EVERY field, and they differ from each other: a
// read-only filesystem-scoped mount with one cache window, and a read-write
// memory-scoped mount with another. A projection that loses a field, defaults it,
// or swaps entries cannot produce this exact pair.
func TestMountIntentsProjectVerbatimOntoTheWire(t *testing.T) {
	pki := newMTLSTestPKI(t)

	var gotBody controlCreateBody
	var decodeErr error

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		decodeErr = dec.Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(controlSessionResponse{Key: "sess-k", State: 2})
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	prov := validProvisioning()
	prov.MountIntents = []MountIntent{
		{Destination: "/workspace", FilesystemID: "fs-alpha", ReadOnly: true, CacheDurationS: 45},
		{Destination: "/mnt/user-data", MemoryStoreID: "mem-beta", ReadOnly: false, CacheDurationS: 7},
	}
	// Egress binds to the same scope as the filesystem-backed mount.
	prov.EgressPolicy = EgressPolicy{DefaultDeny: true, AllowedUpstream: "object-store", FilesystemID: "fs-alpha"}

	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: srv.URL, TLS: pki.clientTLSConfig()},
		staticCred{token: "service-tok", principal: "ocu-mcp-gateway"},
		prov,
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	if _, err := f.Forward(context.Background(), SessionRequest{
		Principal: auth.Caller{KeyID: "k1", Tenant: "tenant-a"},
		ToolCall:  ToolCall{Name: "run", Arguments: []byte(`{}`)},
	}); err != nil {
		t.Fatalf("forward must succeed over mTLS, got %v", err)
	}
	if decodeErr != nil {
		t.Fatalf("control decodes the create body with DisallowUnknownFields: %v", decodeErr)
	}

	want := []controlMountBody{
		{Destination: "/workspace", FilesystemID: "fs-alpha", MemoryStoreID: "", ReadOnly: true, CacheDurationS: 45},
		{Destination: "/mnt/user-data", FilesystemID: "", MemoryStoreID: "mem-beta", ReadOnly: false, CacheDurationS: 7},
	}
	if len(gotBody.MountIntents) != len(want) {
		t.Fatalf("every deployment mount must reach the wire: want %d entries, got %d (%+v)",
			len(want), len(gotBody.MountIntents), gotBody.MountIntents)
	}
	for i, w := range want {
		if got := gotBody.MountIntents[i]; got != w {
			t.Errorf("mount_intents[%d] must project verbatim from the deployment policy:\n  want %+v\n  got  %+v", i, w, got)
		}
	}
}
