// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCredentialFile writes a service-credential token file and returns its path.
func writeCredentialFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "service-token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write credential file: %v", err)
	}
	return path
}

func TestFileServiceCredentialPresentsTokenAndPrincipal(t *testing.T) {
	path := writeCredentialFile(t, "tok-abc\n")
	cred, err := NewFileServiceCredential(path, "ocu-mcp-gateway")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	tok, err := cred.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-abc" {
		t.Errorf("token must be the file content with surrounding whitespace trimmed, got %q", tok)
	}
	if got := cred.Principal(); got != "ocu-mcp-gateway" {
		t.Errorf("principal must be the constructed service principal, got %q", got)
	}
}

// TestFileServiceCredentialReReadsFile pins the rotation behavior: the host-side
// service credential is short-lived (§8: TTL ≤60 min), so Control re-renders the
// file and the gateway must present the CURRENT content on the next forward
// without a process restart — the same posture as the boot-set refresh.
func TestFileServiceCredentialReReadsFile(t *testing.T) {
	path := writeCredentialFile(t, "tok-first")
	cred, err := NewFileServiceCredential(path, "gw")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if tok, _ := cred.Token(context.Background()); tok != "tok-first" {
		t.Fatalf("first read: got %q", tok)
	}
	if err := os.WriteFile(path, []byte("tok-rotated\n"), 0o600); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	tok, err := cred.Token(context.Background())
	if err != nil {
		t.Fatalf("Token after rotation: %v", err)
	}
	if tok != "tok-rotated" {
		t.Errorf("the credential must re-read the file per presentation (rotation without restart), got %q", tok)
	}
}

// TestNewFileServiceCredentialFailsClosedAtBoot pins the load-before-bind kinship:
// an unreadable or empty credential file is a CONSTRUCTION error, so a gateway
// that cannot present its F5 service principal refuses to boot rather than
// binding a listener and failing every forward mid-request.
func TestNewFileServiceCredentialFailsClosedAtBoot(t *testing.T) {
	if _, err := NewFileServiceCredential(filepath.Join(t.TempDir(), "absent"), "gw"); err == nil {
		t.Error("a missing credential file must fail at construction (fail-closed)")
	}
	if _, err := NewFileServiceCredential(writeCredentialFile(t, "  \n"), "gw"); err == nil {
		t.Error("a whitespace-only credential file must fail at construction (an empty token is no credential)")
	}
}

func TestNewFileServiceCredentialRequiresPathAndPrincipal(t *testing.T) {
	if _, err := NewFileServiceCredential("", "gw"); err == nil {
		t.Error("an empty path must be a construction error")
	}
	if _, err := NewFileServiceCredential(writeCredentialFile(t, "tok"), ""); err == nil {
		t.Error("an empty principal must be a construction error (the forward asserts a named service principal)")
	}
}

// TestFileServiceCredentialFailsClosedWhenFileVanishes pins the per-presentation
// fail-closed posture: if the credential file becomes unreadable (or is blanked)
// after boot, the next Token refuses — the forward is never sent with a stale or
// empty credential (NFR-SEC-26).
func TestFileServiceCredentialFailsClosedWhenFileVanishes(t *testing.T) {
	path := writeCredentialFile(t, "tok")
	cred, err := NewFileServiceCredential(path, "gw")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := cred.Token(context.Background()); err == nil {
		t.Error("a vanished credential file must fail closed on Token, never present a cached token")
	}

	path2 := writeCredentialFile(t, "tok")
	cred2, err := NewFileServiceCredential(path2, "gw")
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if err := os.WriteFile(path2, []byte("\n"), 0o600); err != nil {
		t.Fatalf("blank: %v", err)
	}
	if _, err := cred2.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("a blanked credential file must fail closed naming the empty-token cause, got %v", err)
	}
}
