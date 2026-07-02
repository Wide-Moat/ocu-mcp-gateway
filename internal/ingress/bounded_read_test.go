// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// A self-audit found the transport bound (§I, invariant #8) fake-green: deleting
// the MaxBytesReader line from readBounded left TestOversizeBody413 GREEN,
// because the profile's per-kind size ceiling refuses an oversized body with the
// SAME 413 — but only AFTER the whole body has been read into memory. The 413 is
// identical; the DoS guard (never buffer an unbounded body) is the property that
// silently vanished. The test below pins BOTH halves the 413 alone cannot:
//
//   - the byte budget: the handler reads at most cap+ε from the wire, proven by
//     counting what the handler actually consumed from the body reader;
//   - the message class: the refusal is the TRANSPORT cap's stable reason
//     ("request body too large"), not the profile ceiling's
//     ("payload_over_size_bound"), so the guard that fired is observable.
//
// Red-probe: delete the MaxBytesReader line from readBounded — the old 413 test
// stays GREEN (the ceiling masks it) while BOTH prongs here go RED (the whole
// body is consumed; the refusal carries the profile class).

// countingReader counts the bytes the handler actually consumes from the wire.
type countingReader struct {
	r    io.Reader
	read int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	return n, err
}

func TestBoundedReadStopsAtTransportCap(t *testing.T) {
	h := acceptingHandler(t, &recordingForwarder{err: forward.ErrForwardFailed}, nil)

	// A well-formed tool-call 16× over the transport cap. Well-formed matters: an
	// unbounded read would hand valid JSON to the validator, whose per-kind
	// ceiling also answers 413 — exactly the masking this test must see through.
	pad := strings.Repeat("a", 16*maxBodyBytes)
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"pad":"` + pad + `"}}}`
	cr := &countingReader{r: strings.NewReader(raw)}

	req := httptest.NewRequest(http.MethodPost, "/", cr)
	req.Header.Set(protocolVersionHeader, pinnedProtocolVersion)
	req.Header.Set("Authorization", "Bearer sk-ocu-good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body must be 413, got %d", rec.Code)
	}
	// Message-class prong: the refusal must be the transport cap's reason class.
	// If the profile ceiling answered instead, the transport bound did not fire.
	if !strings.Contains(rec.Body.String(), "request body too large") {
		t.Errorf("the 413 must carry the transport-cap reason class %q (the DoS guard), not a downstream ceiling's; got body %q",
			"request body too large", rec.Body.String())
	}
	// Byte-budget prong: the handler must stop reading at the cap (+ε for the
	// cap-detection byte and buffering slack), never consume the whole body.
	const epsilon = 64 << 10
	if cr.read > maxBodyBytes+epsilon {
		t.Errorf("the handler consumed %d bytes from the wire; the transport bound must stop reading at %d+ε (an unbounded read IS the DoS, whatever status is returned)",
			cr.read, maxBodyBytes)
	}
}
