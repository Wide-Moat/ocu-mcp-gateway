// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// D4 (deploy/PARITY-LEDGER-147.md), gateway side: when the guest ViewScript renders an
// image it emits a sentinel-framed zero-exit reply ("OCU_VIEW_IMAGE_JPEG_B64 <path>\n"
// + base64 JPEG). projectCallToolResult must parse that sentinel BEFORE any truncation
// and emit a two-block CallToolResult: a text block "Image: <path>" and an image_url
// block carrying the data: URL. A malformed sentinel (bad base64, or bytes that are not
// a JPEG) falls through to the plain-text relay - never a broken image block.

// imageResultShape decodes the two-block image CallToolResult: text blocks carry Text,
// image blocks carry the nested image_url.url.
type imageResultShape struct {
	Content []struct {
		Type     string `json:"type"`
		Text     string `json:"text"`
		ImageURL struct {
			URL string `json:"url"`
		} `json:"image_url"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

// jpegBytes returns a minimal valid JPEG (SOI + EOI) - enough for the magic-byte check.
func jpegBytes() []byte {
	return []byte{0xFF, 0xD8, 0xFF, 0xD9}
}

func sentinelReply(t *testing.T, path string, jpeg []byte) execResponseWire {
	t.Helper()
	stdout := "OCU_VIEW_IMAGE_JPEG_B64 " + path + "\n" + base64.StdEncoding.EncodeToString(jpeg)
	return execResponseWire{
		ExitCode:  0,
		StdoutB64: base64.StdEncoding.EncodeToString([]byte(stdout)),
	}
}

// (h1) a valid sentinel-framed image reply projects text + image_url blocks.
func TestViewImageSentinelProjectsImageBlock(t *testing.T) {
	const path = "/mnt/user-data/outputs/chart.png"
	blob, err := projectCallToolResult(sentinelReply(t, path, jpegBytes()),
		[]string{"/usr/bin/python3", "-c", "<viewscript>"})
	if err != nil {
		t.Fatalf("projectCallToolResult: %v", err)
	}
	var shape imageResultShape
	if uerr := json.Unmarshal(blob, &shape); uerr != nil {
		t.Fatalf("result must be a CallToolResult, got %q (%v)", blob, uerr)
	}
	if shape.IsError {
		t.Errorf("a rendered image is a success (isError:false), got isError:true %+v", shape.Content)
	}
	if len(shape.Content) != 2 {
		t.Fatalf("a rendered image must carry TWO content blocks (text + image_url), got %d: %+v", len(shape.Content), shape.Content)
	}
	if shape.Content[0].Type != "text" || shape.Content[0].Text != "Image: "+path {
		t.Errorf("first block must be text \"Image: %s\", got %+v", path, shape.Content[0])
	}
	if shape.Content[1].Type != "image_url" {
		t.Errorf("second block must be type image_url, got %q", shape.Content[1].Type)
	}
	wantPrefix := "data:image/jpeg;base64,"
	if !strings.HasPrefix(shape.Content[1].ImageURL.URL, wantPrefix) {
		t.Errorf("image_url must be a data: URL, got %q", shape.Content[1].ImageURL.URL)
	}
	// The data URL payload must decode to the JPEG bytes.
	payload := strings.TrimPrefix(shape.Content[1].ImageURL.URL, wantPrefix)
	raw, derr := base64.StdEncoding.DecodeString(payload)
	if derr != nil || len(raw) < 2 || raw[0] != 0xFF || raw[1] != 0xD8 {
		t.Errorf("the data URL must carry the JPEG bytes (magic 0xFF 0xD8), got %v / % x", derr, raw)
	}
}

// (h2) a sentinel whose payload is NOT valid base64 falls through to the plain-text
// relay (a single text block, no image block) - never a broken image.
func TestViewImageMalformedBase64FallsThroughToText(t *testing.T) {
	const path = "/mnt/user-data/outputs/broken.png"
	stdout := "OCU_VIEW_IMAGE_JPEG_B64 " + path + "\n" + "!!!not-base64!!!"
	blob, err := projectCallToolResult(execResponseWire{
		ExitCode:  0,
		StdoutB64: base64.StdEncoding.EncodeToString([]byte(stdout)),
	}, []string{"/usr/bin/python3", "-c", "<viewscript>"})
	if err != nil {
		t.Fatalf("projectCallToolResult: %v", err)
	}
	var shape imageResultShape
	if uerr := json.Unmarshal(blob, &shape); uerr != nil {
		t.Fatalf("result must be a CallToolResult, got %q (%v)", blob, uerr)
	}
	if len(shape.Content) != 1 || shape.Content[0].Type != "text" {
		t.Fatalf("a malformed sentinel must fall through to a single plain-text block, got %+v", shape.Content)
	}
	if shape.Content[0].ImageURL.URL != "" {
		t.Errorf("a malformed sentinel must NOT emit an image block, got url %q", shape.Content[0].ImageURL.URL)
	}
	// The raw sentinel text is relayed verbatim as the fallback.
	if !strings.Contains(shape.Content[0].Text, "OCU_VIEW_IMAGE_JPEG_B64") {
		t.Errorf("the fallback text must be the raw stdout, got %q", shape.Content[0].Text)
	}
}

// (h3) a sentinel whose base64 decodes but is NOT a JPEG (wrong magic) also falls through
// to plain text - the magic-byte guard, not just the base64 guard.
func TestViewImageNonJPEGFallsThroughToText(t *testing.T) {
	const path = "/mnt/user-data/outputs/notjpeg.png"
	notJPEG := []byte{0x00, 0x01, 0x02, 0x03}
	blob, err := projectCallToolResult(sentinelReply(t, path, notJPEG),
		[]string{"/usr/bin/python3", "-c", "<viewscript>"})
	if err != nil {
		t.Fatalf("projectCallToolResult: %v", err)
	}
	var shape imageResultShape
	if uerr := json.Unmarshal(blob, &shape); uerr != nil {
		t.Fatalf("result must be a CallToolResult, got %q (%v)", blob, uerr)
	}
	if len(shape.Content) != 1 || shape.Content[0].Type != "text" {
		t.Errorf("a non-JPEG sentinel payload must fall through to a single plain-text block, got %+v", shape.Content)
	}
}
