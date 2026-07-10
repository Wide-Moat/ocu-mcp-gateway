// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package ingress

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/projection"
)

// D4 (deploy/PARITY-LEDGER-147.md): the PoC view tool renders images (resize -> JPEG ->
// base64 -> image_url content block) and refuses binaries with a targeted SKILL.md hint
// (mcp_tools.py:719-778). These pin the guest-side ViewScript arms: the binary-hint
// refusal (f) and the image-render sentinel (g). The gateway-side sentinel projection is
// pinned in the forward package (h).

// tinyPNG is a valid 2x2 red PNG (hardcoded bytes) used to drive the image-render path
// without depending on any external fixture.
var tinyPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
	0x08, 0x02, 0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a, 0x73, 0x00, 0x00, 0x00,
	0x10, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xfc, 0xcf, 0x00, 0x02,
	0x4c, 0x60, 0x92, 0x01, 0x00, 0x0d, 0x1d, 0x01, 0x03, 0x82, 0xc9, 0x71,
	0xff, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60,
	0x82,
}

// (f) a binary file (fake.xlsx) through ViewScript refuses with the SKILL.md hint and a
// non-zero exit (surfaces as a Tier-2 tool error whose content is the hint).
func TestViewScriptBinaryHintXlsx(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fake.xlsx")
	if err := os.WriteFile(target, []byte("PK\x03\x04not-a-real-xlsx"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, projection.ViewScript, `{"path":`+jsonStr(target)+`}`)
	if code == 0 {
		t.Fatalf("a binary .xlsx view must fail non-zero (Tier-2 tool error), got 0 (out=%q)", out)
	}
	if !strings.Contains(out, "SKILL") {
		t.Errorf("the .xlsx hint must point at the SKILL protocol, got %q", out)
	}
	if !strings.Contains(out, "/mnt/skills/public/xlsx/SKILL.md") {
		t.Errorf("the .xlsx hint must name the xlsx SKILL.md path, got %q", out)
	}
}

// (g) a tiny valid PNG through ViewScript renders: first stdout line is the sentinel
// "OCU_VIEW_IMAGE_JPEG_B64 <path>", second line the base64 decoding to a JPEG (magic
// 0xFF 0xD8). SKIPs with a clear message when local python3 lacks PIL (the gateway-side
// sentinel projection (h) covers the wire contract unconditionally).
func TestViewScriptImageRendersSentinel(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on the test host; the guest runs the script")
	}
	if err := exec.Command("python3", "-c", "import PIL").Run(); err != nil {
		t.Skip("PIL (Pillow) not on the local python3; the fat guest bakes it (requirements.txt pillow) - the gateway-side sentinel projection (h) covers the wire contract")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "pic.png")
	if err := os.WriteFile(target, tinyPNG, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runScript(t, projection.ViewScript, `{"path":`+jsonStr(target)+`}`)
	if code != 0 {
		t.Fatalf("an image view must succeed (exit 0) with a rendered sentinel, got exit %d out=%q", code, out)
	}
	lines := strings.SplitN(strings.TrimRight(out, "\n"), "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("image view must emit a sentinel line then a base64 line, got %q", out)
	}
	if lines[0] != "OCU_VIEW_IMAGE_JPEG_B64 "+target {
		t.Errorf("first line must be the exact sentinel %q, got %q", "OCU_VIEW_IMAGE_JPEG_B64 "+target, lines[0])
	}
	raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if derr != nil {
		t.Fatalf("the second line must be valid base64, got %q (%v)", lines[1], derr)
	}
	if len(raw) < 2 || raw[0] != 0xFF || raw[1] != 0xD8 {
		t.Errorf("the decoded bytes must be a JPEG (magic 0xFF 0xD8), got % x", raw[:min(2, len(raw))])
	}
}
