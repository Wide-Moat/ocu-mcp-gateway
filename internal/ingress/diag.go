// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"fmt"
	"io"
	"os"
)

// forwardDiag is the operator diagnostic sink for forward failures. It defaults to
// stderr so a distroless container surfaces WHY a forward was refused (a mount-scope
// admission fail, a wire drift, a dial/TLS error, a control non-2xx all otherwise
// return an identical leak-free 502 to the caller with no log). It is a package var
// so a test can redirect it; production never rebinds it.
//
// What is logged is the forward ERROR ONLY — which carries the fail-closed error
// class, the endpoint, the path, and any control status, but NEVER a credential or
// a request body (the caller bearer and the service token are not part of the
// error, and are not read here). So the operator log is actionable without being a
// credential leak.
var forwardDiag io.Writer = os.Stderr

// logForwardFailure writes the exact forward error to the diagnostic sink. The
// caller-facing response stays a leak-free 502; this is the operator-only cause.
func logForwardFailure(err error, resource string) {
	if err == nil {
		return
	}
	fmt.Fprintf(forwardDiag, "ocu-mcp-gatewayd: forward refused for %s: %v\n", resource, err)
}

// swapForwardDiag redirects the diagnostic sink to w and returns a function that
// restores the previous sink. It exists for tests; production does not call it.
func swapForwardDiag(w io.Writer) func() {
	prev := forwardDiag
	forwardDiag = w
	return func() { forwardDiag = prev }
}
