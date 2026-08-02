// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A tool the forwarder implements but the list does not advertise cannot be
// called by anyone.
//
// resolve_scope was in exactly that state: fully written, documented, fail-closed
// on a control fault -- and absent from tools_list.json, so tools/list returned
// four names and no client could ever reach the fifth. The pane spent the evening
// unable to name its own chat's storage while the capability sat one JSON entry
// away. This guard fails for that specific shape: an implemented synthetic tool
// missing from the advertised list.
func TestListAdvertisesEverySyntheticToolTheForwarderHandles(t *testing.T) {
	advertised := map[string]bool{}
	raw, err := os.ReadFile("tools_list.json")
	if err != nil {
		t.Fatalf("read tools_list.json: %v", err)
	}
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("parse tools_list.json: %v", err)
	}
	for _, tool := range list.Tools {
		advertised[tool.Name] = true
	}
	if len(advertised) == 0 {
		t.Fatal("no tools advertised at all; the guard would pass vacuously")
	}

	// The forwarder dispatches a synthetic tool by comparing the call name to a
	// literal. Read those literals rather than restating them here: a list
	// written by hand would drift from the code exactly the way the JSON did.
	src, err := os.ReadFile(filepath.Join("..", "forward", "http.go"))
	if err != nil {
		t.Fatalf("read forward/http.go: %v", err)
	}
	re := regexp.MustCompile(`req\.ToolCall\.Name == "([a-z_]+)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no synthetic tool dispatch in forward/http.go; the guard " +
			"would pass while checking nothing — the pattern has drifted")
	}

	var missing []string
	for _, m := range matches {
		if name := m[1]; !advertised[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("the forwarder implements %s but tools/list does not advertise "+
			"%s, so no client can call it", strings.Join(missing, ", "),
			map[bool]string{true: "it", false: "them"}[len(missing) == 1])
	}
}

// A synthetic tool must not require an argument its handler never reads.
//
// resolve_scope was first advertised with the schema shape copied from a file
// tool: a required "description" string. Nothing reads it -- the dispatch keys
// off the session hint carried on X-Chat-Id and consumes no ToolCall arguments
// at all. The gateway does not validate arguments against the schema, so the
// call still worked; the cost falls on the caller, which is told to invent a
// value, and on a strict client, which would refuse to call without one.
//
// This case turns on the REQUIRED list, so restoring that property reds it
// while every other advertised tool keeps its own required arguments.
func TestSyntheticToolRequiresNothingItNeverReads(t *testing.T) {
	raw, err := os.ReadFile("tools_list.json")
	if err != nil {
		t.Fatalf("read tools_list.json: %v", err)
	}
	var list struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Required []string `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("parse tools_list.json: %v", err)
	}

	var seen bool
	for _, tool := range list.Tools {
		if tool.Name != "resolve_scope" {
			continue
		}
		seen = true
		if len(tool.InputSchema.Required) > 0 {
			t.Errorf("resolve_scope requires %v, but its handler reads no "+
				"arguments; a caller cannot supply what nothing consumes",
				tool.InputSchema.Required)
		}
	}
	if !seen {
		t.Fatal("resolve_scope is not advertised at all; this guard checked nothing")
	}

	// Known-positive control: a tool that DOES take arguments must still declare
	// them. Without this, deleting every required list everywhere would pass.
	for _, tool := range list.Tools {
		if tool.Name == "bash_tool" && len(tool.InputSchema.Required) == 0 {
			t.Error("bash_tool declares no required arguments; the guard above " +
				"would then be passing for the wrong reason")
		}
	}
}
