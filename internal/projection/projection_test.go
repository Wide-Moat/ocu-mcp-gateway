// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package projection

import "testing"

// These pin the single-source-of-truth projection both the ingress boundary and the
// forward-level e2e import, so the argv and guest scripts cannot drift between what
// production sends and what a test proves.

func TestProjectBashToolIsPosixShellNoStdin(t *testing.T) {
	argv, stdin := Project("bash_tool", []byte(`{"command":"echo hi"}`))
	if len(argv) != 3 || argv[0] != "/bin/sh" || argv[1] != "-c" || argv[2] != "echo hi" {
		t.Errorf("bash_tool must project to [/bin/sh -c \"echo hi\"], got %v", argv)
	}
	if len(stdin) != 0 {
		t.Errorf("bash_tool carries its command in argv, not stdin; got stdin %q", stdin)
	}
}

func TestProjectFileToolsRunInterpreterWithOpaqueStdin(t *testing.T) {
	for _, name := range []string{"create_file", "str_replace", "view"} {
		args := `{"path":"/tmp/a","file_text":"x","old_str":"a","new_str":"b"}`
		argv, stdin := Project(name, []byte(args))
		if len(argv) != 3 || argv[0] != InterpreterPath || argv[1] != "-c" {
			t.Errorf("%s must project to [%s -c <script>], got %v", name, InterpreterPath, argv)
		}
		if argv[2] != FileToolScripts[name] {
			t.Errorf("%s must run its committed script (single source of truth), argv[2] diverged", name)
		}
		// The stdin is the caller's exact bytes — opaque, never re-parsed/re-serialized.
		if string(stdin) != args {
			t.Errorf("%s stdin must be the arguments verbatim.\n got: %s\nwant: %s", name, stdin, args)
		}
	}
}

func TestProjectStdinIsACopyNotAliased(t *testing.T) {
	// The returned stdin must not alias the caller's slice (a later mutation of the
	// input must not change what was projected).
	in := []byte(`{"path":"/tmp/a","file_text":"x"}`)
	_, stdin := Project("create_file", in)
	orig := string(stdin)
	in[0] = 'X' // mutate the caller's buffer
	if string(stdin) != orig {
		t.Errorf("projected stdin must be a copy, not aliased to the caller's buffer")
	}
}

func TestProjectUnknownToolHasNoProjection(t *testing.T) {
	for _, name := range []string{"sub_agent", "not_a_real_tool", ""} {
		argv, stdin := Project(name, []byte(`{"x":"y"}`))
		if argv != nil || stdin != nil {
			t.Errorf("%q must have no projection (create-only path), got argv=%v stdin=%q", name, argv, stdin)
		}
	}
}

func TestProjectEmptyOrMissingArgsHasNoProjection(t *testing.T) {
	// bash_tool with no command, and a file tool with no arguments, both have nothing
	// to run — the create-only path.
	if argv, _ := Project("bash_tool", []byte(`{}`)); argv != nil {
		t.Errorf("bash_tool with no command must have no projection, got %v", argv)
	}
	if argv, _ := Project("create_file", nil); argv != nil {
		t.Errorf("create_file with no arguments must have no projection, got %v", argv)
	}
}
