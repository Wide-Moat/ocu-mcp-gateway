// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"errors"
	"testing"
)

func TestNewControlForwarderRequiresIdentity(t *testing.T) {
	if _, err := NewControlForwarder(ServiceIdentity{Name: ""}, "https://control"); err == nil {
		t.Fatal("an empty service identity must fail closed")
	}
}

func TestControlForwarderFailsClosedWithoutEndpoint(t *testing.T) {
	f, err := NewControlForwarder(ServiceIdentity{Name: "gw"}, "")
	if err != nil {
		t.Fatalf("NewControlForwarder: %v", err)
	}
	_, ferr := f.Forward(context.Background(), SessionRequest{})
	if !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("a forward with no endpoint must fail closed, got %v", ferr)
	}
}

func TestControlForwarderFailsClosedWithUnreachableEndpoint(t *testing.T) {
	f, err := NewControlForwarder(ServiceIdentity{Name: "gw"}, "https://control.internal:8443")
	if err != nil {
		t.Fatalf("NewControlForwarder: %v", err)
	}
	// The transport is not yet wired, so even a configured endpoint fails closed
	// rather than pretending success.
	_, ferr := f.Forward(context.Background(), SessionRequest{})
	if !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("an unreachable endpoint must fail closed, got %v", ferr)
	}
}

func TestControlForwarderExposesIdentityNotCaller(t *testing.T) {
	f, _ := NewControlForwarder(ServiceIdentity{Name: "ocu-mcp-gateway"}, "")
	if f.Identity().Name != "ocu-mcp-gateway" {
		t.Fatalf("Identity should return the gateway service principal, got %q", f.Identity().Name)
	}
}
