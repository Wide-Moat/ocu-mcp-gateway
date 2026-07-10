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

// TestToolDescriptionsDoNotPromiseDirListing pins the negative contract: no description
// tells the model it can LIST the contents of /mnt/user-data — a directory listing there
// is broken until a later change lands, so promising it would make the model issue a
// call the fleet cannot serve. The check is conservative: the string "/mnt/user-data"
// must not appear next to a listing verb (ls, list, browse) in any description.
func TestToolDescriptionsDoNotPromiseDirListing(t *testing.T) {
	desc := toolDescriptions(t)
	for name, d := range desc {
		lower := strings.ToLower(d)
		if !strings.Contains(lower, "/mnt/user-data") {
			continue
		}
		for _, verb := range []string{"ls /mnt/user-data", "list /mnt/user-data", "list the contents of /mnt/user-data", "browse /mnt/user-data", "ls the"} {
			if strings.Contains(lower, verb) {
				t.Errorf("%s description promises a /mnt/user-data directory listing (%q), which the fleet cannot yet serve; description=%q", name, verb, d)
			}
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
