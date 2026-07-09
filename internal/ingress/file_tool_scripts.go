// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

// The file tools (create_file, view, str_replace) are exec projections, exactly like
// bash_tool — the gateway runs a small program in the guest over the exec hop rather
// than calling a guest RPC. Each projects to the guest interpreter running a FIXED
// script; the tool's arguments ride as an OPAQUE JSON object on the child's stdin, so
// arbitrary caller bytes (a path, a file body — newlines, quotes, NUL) are read as
// DATA and can never break out of an argument into the command line. This is the
// injection-safe mechanism: no caller value is ever interpolated into the argv or a
// shell string. The gateway does not parse the arguments (invariant #3); the script
// reads and validates them inside the guest.
//
// The interpreter is /usr/bin/python3 (an ABSOLUTE path). It is present in the
// PoC-parity guest image that supports these tools; a minimal guest without python3
// cannot serve the file tools (see the guest-image note in the projection). The
// scripts implement the canonical file-edit semantics — create with parent dirs, a
// single unambiguous string replace with the standard error messages, and a numbered
// view — reading a JSON payload from stdin so the caller's strings never reach argv.

// fileInterpreterPath is the absolute path to the guest interpreter the file-tool
// scripts run under. Absolute so it does not depend on PATH resolution in a
// near-empty guest.
const fileInterpreterPath = "/usr/bin/python3"

// createFileScript reads {path, file_text} from stdin JSON, creates any missing
// parent directories, writes the file, and prints a success line. On any failure it
// prints "Error: <cause>" and exits non-zero (a Tier-2 tool error the caller sees).
const createFileScript = `
import sys, json, os
try:
    data = json.loads(sys.stdin.read())
    path = data['path']
    file_text = data['file_text']
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'w') as f:
        f.write(file_text)
    print("Successfully created " + path)
except Exception as e:
    print("Error: " + str(e))
    sys.exit(1)
`

// strReplaceScript reads {path, old_str, new_str} from stdin JSON and performs a
// single, unambiguous string replacement. The three error semantics are the canonical
// file-edit ones and are kept EXACT: identical old/new is refused; old_str not found
// is refused; more than one occurrence is refused with a request for more context
// (so an edit is never applied ambiguously). On success it writes the file and prints
// a success line.
const strReplaceScript = `
import sys, json
try:
    data = json.loads(sys.stdin.read())
    path = data['path']
    old_str = data['old_str']
    new_str = data.get('new_str', '')
    if old_str == new_str:
        print("Error: old_str and new_str are identical. No changes would be made.")
        sys.exit(1)
    with open(path, 'r') as f:
        content = f.read()
    if old_str not in content:
        print("Error: old_str not found in " + path)
        sys.exit(1)
    count = content.count(old_str)
    if count > 1:
        print("Error: Found " + str(count) + " occurrences of old_str in " + path + ". Add more surrounding context to make it unique.")
        sys.exit(1)
    new_content = content.replace(old_str, new_str, 1)
    with open(path, 'w') as f:
        f.write(new_content)
    print("Successfully replaced text in " + path)
except Exception as e:
    print("Error: " + str(e))
    sys.exit(1)
`

// viewScript reads {path} from stdin JSON and prints the target with line numbers for
// a text file, a listing for a directory, and a "not found" error otherwise. The
// image-resize path of the original tool is OUT OF SCOPE here (a text/dir view is what
// the demo needs); a binary/image file is shown as its raw numbered bytes like any
// other file rather than resized. A read failure is an "Error: <cause>" with a
// non-zero exit (a Tier-2 tool error).
const viewScript = `
import sys, json, os
try:
    data = json.loads(sys.stdin.read())
    path = data['path']
    if os.path.isdir(path):
        entries = sorted(os.listdir(path))
        for name in entries:
            print(name)
    elif os.path.isfile(path):
        with open(path, 'r', errors='replace') as f:
            for i, line in enumerate(f, start=1):
                sys.stdout.write(str(i).rjust(6) + "\t" + line)
    else:
        print("Error: path not found: " + path)
        sys.exit(1)
except Exception as e:
    print("Error: " + str(e))
    sys.exit(1)
`

// fileToolScripts maps a file-tool name to the guest script it projects to. A tool
// NOT in this map has no file-tool projection (bash_tool projects separately; any
// other name has no projection at all — the create-only/-32602 path).
var fileToolScripts = map[string]string{
	"create_file": createFileScript,
	"str_replace": strReplaceScript,
	"view":        viewScript,
}
