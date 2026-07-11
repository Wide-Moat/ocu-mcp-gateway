// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
)

// The tool descriptions steer the chat model to a WRITABLE path. Bare one-liners gave
// the model zero path guidance, so its first write landed on the read-only rootfs
// (/home/assistant was RO) and failed with a permission error. These pin that every
// advertised tool's description carries the fleet-true path steering — the writable
// workspace and the persistent, downloadable store — and, critically, that no
// description promises a capability the fleet cannot yet keep (a directory listing of
// /mnt/user-data). A description is a contract with the model; a false one wastes a turn.

// toolDescriptions returns name→description from the live tools/list response, so the
// assertions run against exactly what the SDK sees (not the raw file).
func toolDescriptions(t *testing.T) map[string]string {
	t.Helper()
	fwd := &recordingForwarder{resp: forward.SessionResponse{Correlation: "c1"}}
	h := acceptingHandler(t, fwd, nil)

	rec := post(h, pinnedProtocolVersion, "sk-ocu-good", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/list returned %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var env struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("tools/list response is not a JSON-RPC result: %v (body %q)", err, rec.Body.String())
	}
	out := make(map[string]string, len(env.Result.Tools))
	for _, tool := range env.Result.Tools {
		out[tool.Name] = tool.Description
	}
	return out
}

// TestToolDescriptionsSteerToWritablePaths pins that each advertised tool's description
// names the writable workspace (/home/assistant) so the model does not write to the
// read-only rootfs, and that the file-writing tools also name the persistent,
// downloadable store (/mnt/user-data). view is read-only, so it names the paths to read
// from, not the write targets. Red-probe: reverting a description to a bare one-liner
// drops the path token and reds.
func TestToolDescriptionsSteerToWritablePaths(t *testing.T) {
	desc := toolDescriptions(t)

	// Every served tool names the writable workspace.
	for _, name := range []string{"bash_tool", "create_file", "str_replace", "view"} {
		d, ok := desc[name]
		if !ok {
			t.Errorf("tool %q is not advertised; expected it in tools/list", name)
			continue
		}
		if !strings.Contains(d, "/home/assistant") {
			t.Errorf("%s description must steer to the writable workspace /home/assistant, got %q", name, d)
		}
	}

	// The file-writing tools name the persistent, downloadable store so the model knows
	// where user-facing output goes.
	for _, name := range []string{"bash_tool", "create_file"} {
		if !strings.Contains(desc[name], "/mnt/user-data") {
			t.Errorf("%s description must name the persistent store /mnt/user-data for downloadable output, got %q", name, desc[name])
		}
	}
}

// TestToolDescriptionsUseTwoDirContract pins the negative contract of the two-mount
// guest layout: every /mnt/user-data mention in a description MUST name one of the
// two real mountpoints (/mnt/user-data/uploads, the user's read-only upload area, or
// /mnt/user-data/outputs, the deliverable sink the user's Files panel serves). A BARE
// /mnt/user-data is the retired flat single-mount contract: steering the model there
// writes to a directory that is only a mount parent, so the file never reaches the
// user - a false contract that wastes turns.
func TestToolDescriptionsUseTwoDirContract(t *testing.T) {
	desc := toolDescriptions(t)
	for name, d := range desc {
		rest := d
		for {
			i := strings.Index(rest, "/mnt/user-data")
			if i < 0 {
				break
			}
			tail := rest[i+len("/mnt/user-data"):]
			if !strings.HasPrefix(tail, "/uploads") && !strings.HasPrefix(tail, "/outputs") {
				t.Errorf("%s description names a BARE /mnt/user-data (the retired flat layout); every mention must be /mnt/user-data/uploads or /mnt/user-data/outputs; description=%q", name, d)
			}
			rest = tail
		}
	}
}

// TestToolDescriptionsAreBounded pins that no description exceeds the discovery-surface
// ceiling (maxToolDescriptionBytes = 8192, NFR-SEC-51). The enrichment stays well under.
func TestToolDescriptionsAreBounded(t *testing.T) {
	const maxToolDescriptionBytes = 8192
	for name, d := range toolDescriptions(t) {
		if len(d) > maxToolDescriptionBytes {
			t.Errorf("%s description is %d bytes, over the %d cap (NFR-SEC-51)", name, len(d), maxToolDescriptionBytes)
		}
	}
}
