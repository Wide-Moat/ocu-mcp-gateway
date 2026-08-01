// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

// Package projection is the single source of truth for mapping an OCU MCP tool-call
// onto the guest exec it runs: the command argv and any stdin payload. It is a LEAF
// package (no dependency on ingress or forward) so BOTH the ingress boundary (which
// builds the real projection for the live forward) and the forward-level e2e test
// (which drives the create+exec hops with the SAME projection) import it. Sharing one
// projection means the argv and the guest scripts CANNOT drift between what production
// sends and what a test proves — an earlier e2e inlined a hand-copied script and
// claimed an anti-drift guard that did not exist; there is now exactly one copy.
//
// The projection keeps the arguments OPAQUE (invariant #3): for the file tools it
// forwards the whole tool-arguments JSON verbatim as the guest child's stdin, never
// parsing or interpolating a caller string into the argv. Caller strings ride as stdin
// DATA the fixed script parses inside the guest, so newlines/quotes/NUL cannot break
// out of an argument (the injection-safe mechanism).
//
// Result-shaping boundary (a note the guest scripts here must honor): the GATEWAY is
// the single layer that synthesizes an "[Exit code: N]" marker for a silent non-zero
// exit (see projectCallToolResult in the forward package). The guest scripts must NOT
// emit that marker themselves — a second synthesis would double the marker. The scripts
// print their own diagnostics ("Error: ...") on failure and exit non-zero; the gateway
// synthesizes the marker ONLY when a non-zero exit produced no output on either stream.
package projection

import "encoding/json"

// InterpreterPath is the absolute path to the guest interpreter the file-tool scripts
// run under. Absolute so it does not depend on PATH resolution in a near-empty guest.
// A deployment advertising the file tools MUST run a guest that ships it (a guest-image
// contract, like the /bin/sh requirement for bash_tool).
const InterpreterPath = "/usr/bin/python3"

// CreateFileScript reads {path, file_text} from stdin JSON, creates any missing parent
// directories, writes the file, and prints a success line. On any failure it prints
// "Error: <cause>" and exits non-zero (a Tier-2 tool error the caller sees) — writing
// NOTHING (no partial/empty file left behind).
const CreateFileScript = `
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

// StrReplaceScript reads {path, old_str, new_str} from stdin JSON and performs a
// single, unambiguous string replacement. The three error semantics are the canonical
// file-edit ones and are kept EXACT: identical old/new is refused; old_str not found is
// refused; more than one occurrence is refused with a request for more context (so an
// edit is never applied ambiguously). On success it writes the file and prints a
// success line. On any error it leaves the file unchanged.
const StrReplaceScript = `
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

// ViewScript reads {path} from stdin JSON and prints the target. It mirrors the PoC view
// tool (mcp_tools.py:677-778):
//
//   - Binary files (.xlsx/.xls/.docx/.pptx/.pdf/.zip/.tar/.gz): refuse with a targeted
//     hint (read the SKILL.md first, or the unpack command for archives) and exit 1, so
//     the caller sees a Tier-2 tool error whose content is the hint rather than a garbled
//     text dump.
//   - Images (.jpg/.jpeg/.png/.gif/.webp): open with PIL, adaptively fit to a byte budget
//     (RAW_JPEG_BUDGET below), and emit a sentinel-framed base64 JPEG the GATEWAY turns
//     into an image_url content block. On success (exit 0) stdout is exactly two lines:
//     "OCU_VIEW_IMAGE_JPEG_B64 <path>" then the base64 (one line, no wrapping). When PIL
//     is unavailable the script prints a clear text line and exits 0 - never garbled
//     binary.
//   - Directories: entries listed. Text files: numbered lines (errors='replace' so a
//     non-UTF8 body does not raise). A missing path is an "Error: <cause>", exit 1.
//
// RAW_JPEG_BUDGET is the pre-base64 JPEG byte target. Control bounds each exec-reply
// stream at 64 KiB (ocu-control guestexec defaultStdioCap), and base64 inflates the
// bytes 4/3, so a 45000-byte JPEG becomes ~60000 base64 bytes and, with the sentinel
// line + JSON framing, survives the 64 KiB reply-stream ceiling on an UNMODIFIED stand.
// A deployment that raises the control ceiling for image quality can raise this in step.
// The starting encode is 1280px / quality 80 (PoC parity); the loop then steps quality
// 80->60->40, then max dimension 1280->960->640->480, until the encoded JPEG fits.
const ViewScript = `
import sys, json, os, base64
from io import BytesIO

RAW_JPEG_BUDGET = 45000

BINARY_HINTS = {
    '.xlsx': 'Excel spreadsheet. Read SKILL first:\n  view /mnt/skills/public/xlsx/SKILL.md',
    '.xls': 'Excel spreadsheet (old). Read SKILL first:\n  view /mnt/skills/public/xlsx/SKILL.md',
    '.docx': 'Word document. Read SKILL first:\n  view /mnt/skills/public/docx/SKILL.md',
    '.pptx': 'PowerPoint. Read SKILL first:\n  view /mnt/skills/public/pptx/SKILL.md',
    '.pdf': 'PDF document. Read SKILL first:\n  view /mnt/skills/public/pdf/SKILL.md',
    '.zip': 'ZIP archive. Use: unzip -l ',
    '.tar': 'TAR archive. Use: tar -tvf ',
    '.gz': 'Gzip file. Use: gunzip -c ',
}
IMAGE_EXTS = ('.jpg', '.jpeg', '.png', '.gif', '.webp')


def render_image(path):
    try:
        from PIL import Image
    except ImportError:
        print("Image file: " + path + " (rendering unavailable: PIL missing in guest)")
        return
    img = Image.open(path)
    if img.mode in ('RGBA', 'P'):
        img = img.convert('RGB')
    for max_dim in (1280, 960, 640, 480):
        work = img.copy()
        if max(work.size) > max_dim:
            work.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
        for quality in (80, 60, 40):
            buf = BytesIO()
            work.save(buf, format='JPEG', quality=quality)
            data = buf.getvalue()
            if len(data) <= RAW_JPEG_BUDGET:
                print("OCU_VIEW_IMAGE_JPEG_B64 " + path)
                sys.stdout.write(base64.b64encode(data).decode('ascii'))
                return
    print("OCU_VIEW_IMAGE_JPEG_B64 " + path)
    sys.stdout.write(base64.b64encode(data).decode('ascii'))


try:
    data = json.loads(sys.stdin.read())
    path = data['path']
    lower = path.lower()
    ext = None
    for e in list(BINARY_HINTS.keys()) + list(IMAGE_EXTS):
        if lower.endswith(e):
            ext = e
            break
    if ext in IMAGE_EXTS and os.path.isfile(path):
        render_image(path)
    elif ext in BINARY_HINTS and os.path.isfile(path):
        hint = BINARY_HINTS[ext]
        if ext in ('.zip', '.tar', '.gz'):
            hint = hint + path
        print("Error: Cannot view binary file with 'cat'. This is a " + ext + " file.")
        print("")
        print(hint)
        sys.exit(1)
    elif os.path.isdir(path):
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

// FileToolScripts maps a file-tool name to the guest script it projects to. A tool NOT
// in this map has no file-tool projection (bash_tool projects separately in Project;
// any other name has no projection at all — the create-only path).
var FileToolScripts = map[string]string{
	"create_file": CreateFileScript,
	"str_replace": StrReplaceScript,
	"view":        ViewScript,
}

// Project derives the guest exec projection (the command argv and any stdin payload)
// for a validated tool-call's name and arguments. It returns (nil, nil) for a tool with
// no projection (the create-only path). It injects no credential.
//
// bash_tool {"command":"..."} runs the command through the POSIX shell
// (["/bin/sh","-c",command]), the command in the argv, no stdin: /bin/sh not bash (a
// POSIX /bin/sh is the guest-image contract; a `bash` binary is promised by no guest);
// an ABSOLUTE path (no PATH dependence); -c not -lc (`-l`/login is undefined for a
// busybox `sh` and unwanted for a stateless tool-call).
//
// The file tools (create_file, view, str_replace) project to the guest interpreter
// running a FIXED script (["/usr/bin/python3","-c",<script>]) with the WHOLE
// tool-arguments JSON carried VERBATIM on stdin. The gateway does not parse the
// arguments (invariant #3); it forwards the arguments bytes UNCHANGED as the stdin
// payload. A tool-call with no arguments object has nothing to act on, so it has no
// projection.
func Project(name string, arguments []byte) (argv []string, stdin []byte) {
	if name == "bash_tool" {
		var args struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(arguments, &args); err != nil || args.Command == "" {
			return nil, nil
		}
		return []string{"/bin/sh", "-c", args.Command}, nil
	}
	if script, ok := FileToolScripts[name]; ok {
		if len(arguments) == 0 {
			return nil, nil
		}
		return []string{InterpreterPath, "-c", script}, append([]byte(nil), arguments...)
	}
	// Any other tool name has no gateway exec projection (sub_agent is delisted; an
	// off-surface name a caller sends directly falls here) — the create-only path.
	return nil, nil
}
