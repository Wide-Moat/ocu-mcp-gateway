// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The gate's placement is the property under test, not merely its verdict.
// ADR-0041 puts it between the tool-name allowlist and the resolve step, so a
// denied call reaches neither the serializer nor Control and creates no session.
// A gate that decided correctly but ran after provisioning would leave a session
// behind for a call it refused.

// TestToolArgumentsFromReadsThePathArgument pins the extraction the gate feeds.
// A gate that cannot see the argument silently degrades to a tool-name check,
// which is the pre-ADR-0041 behaviour wearing a policy file.
func TestToolArgumentsFromReadsThePathArgument(t *testing.T) {
	raw := []byte(`{"params":{"name":"view","arguments":{"path":"/home/assistant/x","description":"d"}}}`)
	args := toolArgumentsFrom(raw)
	if got, _ := args["path"].(string); got != "/home/assistant/x" {
		t.Errorf("path argument = %v, want /home/assistant/x — the gate would evaluate "+
			"a call whose argument it cannot read", args["path"])
	}
}

// TestToolArgumentsFromIsEmptyOnAnUnreadableBody fails soft in the extractor and
// hard in the evaluator: an unreadable argument set yields an empty map, which
// Decide refuses for any tool carrying a predicate. Returning something
// non-empty here would invent an argument the caller never sent.
func TestToolArgumentsFromIsEmptyOnAnUnreadableBody(t *testing.T) {
	for name, raw := range map[string]string{
		"arguments absent":     `{"params":{"name":"view"}}`,
		"arguments not object": `{"params":{"name":"view","arguments":"nope"}}`,
		"params absent":        `{}`,
		"not JSON":             `{`,
	} {
		if got := toolArgumentsFrom([]byte(raw)); len(got) != 0 {
			t.Errorf("%s yielded %v, want an empty map — inventing an argument the "+
				"caller never sent would decide the call on fabricated input", name, got)
		}
	}
}

// TestToolArgumentsFromDoesNotDecodeNestedStructure keeps the extractor to the
// one shape the policy language uses. The predicate reads a top-level string;
// decoding deeper would build a surface the policy cannot express and a reader
// cannot audit.
func TestToolArgumentsFromDoesNotDecodeNestedStructure(t *testing.T) {
	raw := []byte(`{"params":{"name":"view","arguments":{"path":{"nested":"/etc/passwd"}}}}`)
	args := toolArgumentsFrom(raw)
	if _, isString := args["path"].(string); isString {
		t.Error("a nested object decoded to a string path; the evaluator would compare " +
			"a prefix against a value the caller did not send as a path")
	}
}

// TestGateRunsBeforeAnySideEffect is the ordering invariant. It asserts on the
// SOURCE order of the checks in the request path rather than on a live request,
// because the property is "no session exists for a denied call" — something a
// unit test cannot observe after the fact, but a reader of the handler can.
func TestGateRunsBeforeAnySideEffect(t *testing.T) {
	raw, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("read the request path: %v", err)
	}
	src := string(raw)

	// Anchors are real call sites, not comments: a comment could be moved without
	// moving the code it describes, which would make this test agree with a
	// handler that no longer does what it says.
	gate := strings.Index(src, "h.authz.Decide(")
	allowlist := strings.Index(src, "allowedToolNames[name]")
	serialize := strings.Index(src, "h.serializer.Acquire(")
	for name, idx := range map[string]int{
		"h.authz.Decide": gate, "allowedToolNames": allowlist, "h.serializer.Acquire": serialize,
	} {
		if idx < 0 {
			t.Fatalf("anchor %q not found in the request path; this test can no longer "+
				"see the ordering it claims to check", name)
		}
	}

	if gate < allowlist {
		t.Error("the authz gate runs BEFORE the tool-name allowlist; it would then " +
			"evaluate a policy rule for a name the gateway does not serve")
	}
	if gate > serialize {
		t.Error("the authz gate runs AFTER the serializer; a denied call would have " +
			"acquired a session slot, so the refusal leaves state behind")
	}
}

// TestDeniedCallIs403AndNeverForwards is the behavioural half. The source-order
// test above proves WHERE the gate sits; this proves it has an effect — without
// it, ignoring the evaluator's verdict entirely leaves every test green, because
// the permissive baseline allows the calls the other tests make.
func TestDeniedCallIsRefusedAndNeverForwards(t *testing.T) {
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	// view is granted, but only under the baseline's prefixes. /etc/passwd is a
	// path the policy does not admit, so the call must die at the gate.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"view","arguments":{"path":"/etc/passwd"}}}`
	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", body)

	if rec.Code != http.StatusForbidden {
		t.Errorf("a path outside every granted prefix returned %d, want %d", rec.Code, http.StatusForbidden)
	}
	if fwd.got != nil {
		t.Error("a denied call reached the F5 forward; the refusal must land before " +
			"any session is provisioned, or Control materializes state for a call " +
			"that must never execute")
	}
}
