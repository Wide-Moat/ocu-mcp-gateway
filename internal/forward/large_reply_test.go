// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// A large exec reply must parse and reach the caller as a bounded result — NEVER a 502
// with the whole output lost. The F5 exec reply carries base64(stdout)+base64(stderr)
// in a JSON envelope; control bounds each stream at its own ceiling (defaultStdioCap,
// 8MiB). The gateway's reply read (maxReplyBytes) MUST be large enough that a LEGAL
// control reply always parses — otherwise io.LimitReader truncates the JSON mid-string,
// json.Unmarshal fails, and the forward returns ErrForwardFailed (a 502) with the
// entire result discarded. This was a real live defect (task #127): ~48KiB+ of stdout
// base64'd past the old 64KiB cap → 502, output lost.

// largeStdoutControl serves the create+exec surface, returning an exec reply whose
// stdout is `size` bytes (before base64), with the given truncation flag. It models a
// control reply near/at the stream ceiling.
func largeStdoutControl(t *testing.T, pki *mTLSTestPKI, size int, truncated bool) string {
	t.Helper()
	payload := strings.Repeat("x", size)
	execHandler := func(w http.ResponseWriter, _ controlExecBody) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(controlExecResponse{
			ExitCode:        0,
			StdoutB64:       base64.StdEncoding.EncodeToString([]byte(payload)),
			StdoutTruncated: truncated,
		})
	}
	ctl := &twoHopControl{}
	srv := ctl.serveWith(t, pki, execHandler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// largeStdoutStderrControl returns an exec reply with BOTH streams filled to the given
// sizes (before base64) — used to model control's legal maximum reply (two streams at
// the source ceiling) and the read-cap boundary.
func largeStdoutStderrControl(t *testing.T, pki *mTLSTestPKI, outSize, errSize int) string {
	t.Helper()
	execHandler := func(w http.ResponseWriter, _ controlExecBody) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(controlExecResponse{
			ExitCode:  0,
			StdoutB64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("o", outSize))),
			StderrB64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", errSize))),
		})
	}
	ctl := &twoHopControl{}
	srv := ctl.serveWith(t, pki, execHandler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestLargeReplyParsesNotDropped is the task #127/#131 keystone: an exec reply at
// control's LEGAL MAXIMUM (each stream at the 64KiB source ceiling #128 → two 64KiB
// streams base64'd + envelope ≈ 176KiB, well past the OLD 64KiB read cap) must parse
// and relay a non-error result, not a 502. Red-probe: setting maxReplyBytes below
// control's legal max (e.g. 64KiB) truncates the reply mid-JSON and the forward returns
// ErrForwardFailed — this reds until the cap covers control's legal reply size. The
// 256KiB cap (#131) sits with headroom over the ~176KiB legal max.
func TestLargeReplyParsesNotDropped(t *testing.T) {
	pki := newMTLSTestPKI(t)
	// Control's legal maximum: TWO streams at the 64KiB source ceiling. The combined
	// base64 + envelope (~176KiB) exceeds the old 64KiB read cap but is under 256KiB.
	const streamSize = controlReplyStreamCeiling // 64KiB per #128
	url := largeStdoutStderrControl(t, pki, streamSize, streamSize)

	f := newExecForwarder(t, pki, url)
	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-large",
		ToolCall:    ToolCall{Name: "bash_tool", Argv: []string{"/bin/sh", "-c", "big"}},
	})
	if err != nil {
		t.Fatalf("a control-legal-max exec reply (~176KiB) must PARSE and relay, not fail closed (502); got %v", err)
	}
	var shape callToolResultShape
	if uerr := json.Unmarshal(resp.Result, &shape); uerr != nil {
		t.Fatalf("the large reply must project a CallToolResult, got %q (%v)", resp.Result, uerr)
	}
	if shape.IsError {
		t.Errorf("a successful large-output command must be isError:false, got %+v", shape.Content)
	}
	if len(shape.Content) == 0 || len(shape.Content[0].Text) == 0 {
		t.Errorf("the large output must reach the caller (bounded), not be dropped, got %+v", shape.Content)
	}
}

// TestControlTruncationFlagIsSurfaced pins that control's stdout_truncated flag is not
// silently swallowed: when control reports it truncated a stream at its ceiling, the
// caller must be TOLD (a "[output truncated ...]" note), not handed a body that looks
// complete. The flag is parsed today but never surfaced. isError stays false (a
// truncated success is still a success). This is the SAME single-synthesis layer as the
// [Exit code: N] marker.
//
// Red-probe: without surfacing, the content is just the (bounded) output with no
// truncation note — the assertion reds until the note is appended.
func TestControlTruncationFlagIsSurfaced(t *testing.T) {
	pki := newMTLSTestPKI(t)
	// A modest stdout, but control says it truncated the stream (the flag is the signal,
	// independent of the size that reached the gateway).
	url := largeStdoutControl(t, pki, 1<<10, true)

	f := newExecForwarder(t, pki, url)
	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-trunc",
		ToolCall:    ToolCall{Name: "bash_tool", Argv: []string{"/bin/sh", "-c", "big"}},
	})
	if err != nil {
		t.Fatalf("a truncated reply must still relay a result, got %v", err)
	}
	var shape callToolResultShape
	if uerr := json.Unmarshal(resp.Result, &shape); uerr != nil {
		t.Fatalf("truncated reply must project a CallToolResult, got %q (%v)", resp.Result, uerr)
	}
	if shape.IsError {
		t.Errorf("a truncated SUCCESS is still a success (isError:false), got %+v", shape)
	}
	if len(shape.Content) == 0 || !strings.Contains(shape.Content[0].Text, "truncated") {
		t.Errorf("control's truncation flag must be surfaced to the caller (\"[output truncated ...]\"), got %+v", shape.Content)
	}
}

// TestGatewayBoundContentTruncationIsSurfaced pins the OTHER truncation path: a stream
// that exceeds the gateway's own content bound (beyond control's ceiling) is trimmed by
// boundContent, and that gateway-side trim is ALSO surfaced (not just control's flag).
// This exercises the maxExecContentBytes bound and the gatewayTruncated branch.
func TestGatewayBoundContentTruncationIsSurfaced(t *testing.T) {
	pki := newMTLSTestPKI(t)
	// A stdout LARGER than the gateway content bound, with control's flag NOT set — so
	// only the gateway-side boundContent trim can surface the note.
	url := largeStdoutControl(t, pki, maxExecContentBytes+(1<<10), false)

	f := newExecForwarder(t, pki, url)
	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-gwtrunc",
		ToolCall:    ToolCall{Name: "bash_tool", Argv: []string{"/bin/sh", "-c", "big"}},
	})
	if err != nil {
		t.Fatalf("an over-bound reply must still parse and relay, got %v", err)
	}
	var shape callToolResultShape
	if uerr := json.Unmarshal(resp.Result, &shape); uerr != nil {
		t.Fatalf("over-bound reply must project a CallToolResult, got %q (%v)", resp.Result, uerr)
	}
	text := shape.Content[0].Text
	if !strings.Contains(text, "truncated") {
		t.Errorf("a gateway-side boundContent trim must be surfaced, got a %d-byte body with no note", len(text))
	}
	// The body must actually be bounded (not the full over-bound stream).
	if len(text) > maxExecContentBytes+64 { // +note length headroom
		t.Errorf("the relayed body must be bounded near maxExecContentBytes, got %d bytes", len(text))
	}
}

// TestReplyOverReadCapIsBounded is the task #131 boundary: a reply whose SERIALIZED
// size exceeds the tight maxReplyBytes read cap is refused fail-closed (the LimitReader
// truncates → the parse fails → ErrForwardFailed), NOT parsed as if complete. With
// control now bounding each stream at 64KiB (#128), such a reply is ILLEGAL (control
// would never emit it); the tight cap is the anti-hostile read bound restored now that
// control guarantees small replies. This pins that the cap is real — a hostile control
// cannot make the gateway buffer an unbounded reply.
func TestReplyOverReadCapIsBounded(t *testing.T) {
	pki := newMTLSTestPKI(t)
	// A single stream large enough that its base64 alone exceeds maxReplyBytes: raw >
	// maxReplyBytes×3/4. This is NOT a legal control reply (streams are capped at 64KiB
	// source-side); it models a hostile/oversized reply the tight cap must refuse.
	oversizeRaw := maxReplyBytes // base64 grows ×4/3, so this alone is > maxReplyBytes
	url := largeStdoutControl(t, pki, oversizeRaw, false)

	f := newExecForwarder(t, pki, url)
	_, err := f.Forward(context.Background(), SessionRequest{
		Principal:   auth.Caller{Tenant: "tenant-a"},
		SessionHint: "chat-oversize",
		ToolCall:    ToolCall{Name: "bash_tool", Argv: []string{"/bin/sh", "-c", "hostile"}},
	})
	if err == nil {
		t.Fatalf("a reply exceeding the read cap must be refused fail-closed, not parsed as complete")
	}
	if !errors.Is(err, ErrForwardFailed) {
		t.Errorf("an over-cap reply must fail closed with ErrForwardFailed, got %v", err)
	}
}
