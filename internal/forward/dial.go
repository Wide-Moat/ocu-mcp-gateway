// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
)

// The F5 token taxonomy (02-trust-boundaries §8, component-01:39). The gateway
// presents a host-side service-to-service credential (the "Generic internal
// token") on the forward — its OWN service principal, never the caller's
// credential and never an operator scope. The minimal shelf signs with a
// host-local key; the full shelf presents a customer-PKI workload identity. Both
// satisfy the ServiceCredential seam below.

// ServiceCredential is the gateway's own host-side service-to-service credential,
// presented on the F5 forward (NFR-SEC-23, NFR-SEC-26). The concrete shelf
// (host-local signing key on minimal, customer-PKI workload identity on full)
// lives below this seam — like the caller-auth two-shelf split, this abstracts
// both shelves of one presentation so the full-shelf identity drops in without a
// rewrite.
//
// It presents ONLY the gateway service principal; it cannot carry a caller
// credential (there is no caller material reachable from a SessionRequest), and
// it carries no operator scope (the gateway holds a service principal only, so
// the Control plane never treats a forwarded request as more privileged — the
// P1-S2 mitigation).
type ServiceCredential interface {
	// Token returns the host-side service-to-service credential to present on the
	// forward (a bearer the Control plane validates as the gateway's service
	// principal), or an error if the credential is unavailable (fail-closed: a
	// forward without a service credential is refused, never sent anonymously).
	// The context lets a workload-identity implementation refresh a short-lived
	// token (≤60 min per §8); a static host-local key implementation ignores it.
	Token(ctx context.Context) (string, error)
	// Principal is the gateway service principal name this credential asserts. It
	// is the gateway's own identity, distinct from any caller, recorded for audit
	// and asserted on the forward.
	Principal() string
}

// DialConfig is the mTLS-1.3 transport configuration for the F5 leg (NFR-SEC-37:
// inter-component traffic is encrypted in transit). TLS 1.3 is the floor; the CA
// is the auto-generated self-signed CA on the minimal shelf and the customer CA
// on the full shelf. The concrete cert material is loaded from config; this type
// is the transport-policy seam the live dial uses.
type DialConfig struct {
	// Endpoint is the Control/operator API base URL (the F5 target — the Control
	// SESSION ingress, never the operator ingress). Empty => fail closed.
	Endpoint string
	// TLS is the mTLS client config. A nil TLS config with a non-empty Endpoint
	// is a misconfiguration: the F5 leg MUST be mTLS (NFR-SEC-37), so an
	// unencrypted forward is refused at construction.
	TLS *tls.Config
}

// minTLS13 returns a tls.Config that enforces TLS 1.3 as the minimum, used as the
// safe default when a DialConfig supplies a CA/cert but does not pin the minimum
// version. It is the NFR-SEC-37 floor for the inter-component leg.
func minTLS13(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	return cfg
}

// ErrNoServiceCredential is the fail-closed refusal when the gateway has no
// service credential to present on the forward. A forward without the gateway's
// own service principal is refused, never sent anonymously (NFR-SEC-26).
var ErrNoServiceCredential = errors.New("forward: no gateway service credential available (fail-closed)")

// hardenDialConfig enforces the transport invariants before a live dial: a
// non-empty endpoint REQUIRES an mTLS config (NFR-SEC-37), and the TLS minimum is
// raised to 1.3. It returns the hardened TLS config (the live dialer's transport)
// or an error. The returned config is stored on the forwarder at construction and
// used by the dial, so the validation and the transport are one and the same.
func hardenDialConfig(dc DialConfig) (*tls.Config, error) {
	if dc.Endpoint == "" {
		return nil, fmt.Errorf("%w: no Control endpoint configured", ErrForwardFailed)
	}
	if dc.TLS == nil {
		return nil, fmt.Errorf("%w: F5 leg requires an mTLS config (NFR-SEC-37); refusing an unencrypted forward", ErrForwardFailed)
	}
	return minTLS13(dc.TLS), nil
}
