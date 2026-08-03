// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"encoding/json"
	"testing"
)

// A command that exits without writing to stdout yields an empty Text. The key
// must still be emitted: MCP TextContent requires "text", and a caller that
// validates the envelope rejects the whole CallToolResult when it is absent,
// reporting the tool call as failed although the guest ran it and wrote its
// file. Encoding "no output" as an absent field turns a success into a failure
// two hops away, where the cause is unreadable.
func TestEmptyTextBlockStillCarriesTheTextKey(t *testing.T) {
	b, err := json.Marshal(contentBlock{Type: "text"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Look for the KEY. Searching the raw bytes for "text" matches the VALUE in
	// "type":"text" and passes with the key absent — the check has to decode.
	if _, ok := back["text"]; !ok {
		t.Errorf("an empty text block serialised as %s; the text key must be "+
			"present or the caller fails CallToolResult validation", b)
	}
}
