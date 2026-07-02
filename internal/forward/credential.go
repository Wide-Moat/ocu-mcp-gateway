// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// FileServiceCredential is the minimal-shelf ServiceCredential: the host-side
// service-to-service token (the "Generic internal token", component-01:39 / §8)
// delivered as a root-owned file on the config plane, exactly like the boot-set.
// The full shelf swaps in a customer-PKI workload identity behind the same seam.
//
// Rotation: §8 bounds host-side service credentials at ≤60 min TTL, so Control
// re-renders the file and Token re-reads it PER PRESENTATION — the next forward
// carries the current token without a process restart (the boot-set refresh
// posture, applied to the F5 credential). Nothing is cached, so a revoked token
// is never presented from memory.
//
// Fail-closed at both ends: construction probe-reads the file (a gateway that
// cannot present its F5 service principal refuses to BOOT, the load-before-bind
// kinship), and Token refuses if the file has since vanished or blanked — a
// forward is never sent with an empty credential (NFR-SEC-26).
type FileServiceCredential struct {
	path      string
	principal string
}

// NewFileServiceCredential builds the file-backed service credential. The path
// and the principal name are both required, and the file must exist and hold a
// non-empty token NOW: a misconfigured credential fails at construction, not on
// the first forward.
func NewFileServiceCredential(path, principal string) (*FileServiceCredential, error) {
	if path == "" {
		return nil, fmt.Errorf("forward: NewFileServiceCredential requires a credential file path (fail-closed, NFR-SEC-26)")
	}
	if principal == "" {
		return nil, fmt.Errorf("forward: NewFileServiceCredential requires a service principal name (the forward asserts a named principal)")
	}
	c := &FileServiceCredential{path: path, principal: principal}
	if _, err := c.read(); err != nil {
		return nil, fmt.Errorf("forward: service credential probe-read failed at construction: %w", err)
	}
	return c, nil
}

// Token re-reads the credential file and returns the current token (rotation
// without restart). An unreadable or empty file is a fail-closed refusal — the
// error reaches Forward, which wraps it in ErrNoServiceCredential.
func (c *FileServiceCredential) Token(context.Context) (string, error) {
	return c.read()
}

// Principal is the gateway service principal name this credential asserts.
func (c *FileServiceCredential) Principal() string { return c.principal }

// read loads and trims the token. The error never contains file CONTENT — only
// the path and the cause class — so a partially-written token cannot leak into a
// log line.
func (c *FileServiceCredential) read() (string, error) {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return "", fmt.Errorf("read service credential %q: %w", c.path, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("service credential file %q holds an empty token (fail-closed)", c.path)
	}
	return tok, nil
}
