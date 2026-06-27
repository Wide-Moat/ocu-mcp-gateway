// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package profile

import (
	"errors"
	"testing"

	"pgregory.net/rapid"
)

// TestValidatorNeverPanicsAndDenyIsLeakFree is the property test the component
// spec mandates on the schema validator (NFR-SEC-51, NFR-SEC-46). For ANY input
// bytes and ANY message kind, the validator must:
//   - never panic;
//   - return either nil (accept) or an error that wraps ErrDenied (a structured
//     deny), never a bare/unclassified error;
//   - on a deny, expose ONLY a stable reason class via Deny.Reason.String() —
//     the reason string must be one of the closed set and must not contain the
//     input bytes (no caller payload echoed, invariant #5).
func TestValidatorNeverPanicsAndDenyIsLeakFree(t *testing.T) {
	v, err := NewValidator(stubBase{}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	kinds := []Kind{
		KindCallToolRequest, KindCallToolResult, KindTool, KindError,
		KindInitializeResult, KindInvalid,
	}
	// The closed set of leak-free reason strings.
	allowedReasons := map[string]bool{
		"base_schema_violation":        true,
		"profile_constraint_violation": true,
		"payload_over_size_bound":      true,
		"batching_not_permitted":       true,
		"internal":                     true,
	}

	rapid.Check(t, func(t *rapid.T) {
		raw := []byte(rapid.String().Draw(t, "raw"))
		kind := kinds[rapid.IntRange(0, len(kinds)-1).Draw(t, "kind")]

		// Must not panic.
		err := v.Validate(kind, raw)
		if err == nil {
			return // accept is a valid outcome
		}
		// A non-nil error MUST be a structured deny.
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("validator returned a non-deny error %v for kind=%v", err, kind)
		}
		var d *Deny
		if !errors.As(err, &d) {
			t.Fatalf("deny error did not unwrap to *Deny: %v", err)
		}
		// The reason must be from the closed leak-free set.
		reason := d.Reason.String()
		if !allowedReasons[reason] {
			t.Fatalf("deny reason %q is not in the closed leak-free set", reason)
		}
		// The reason must not echo the input bytes (invariant #5). The reason is
		// drawn from a fixed closed set of class strings; a genuine payload echo
		// would surface a non-trivial run of the input inside it. A short input
		// (e.g. "a") can coincidentally be a substring of a class name
		// ("b-a-se_schema_violation") without any echo, so only a non-trivial
		// input that is BOTH contained in the reason AND not itself a substring of
		// any fixed class name counts as a leak. The robust invariant is simpler:
		// the reason must equal one of the closed class strings exactly — which is
		// already asserted above — so a payload echo is impossible by construction.
		// We additionally assert the reason length is bounded (no payload could
		// inflate it).
		if len(reason) > 64 {
			t.Fatalf("deny reason is unexpectedly long (%d bytes); a class string is short and fixed: %q", len(reason), reason)
		}
	})
}

// TestEnvelopeNeverPanics is the companion property over the single-message
// envelope check: any input must yield accept or a leak-free batching/base deny,
// never a panic.
func TestEnvelopeNeverPanics(t *testing.T) {
	v, err := NewValidator(stubBase{}, DefaultLimits())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	rapid.Check(t, func(t *rapid.T) {
		raw := []byte(rapid.String().Draw(t, "raw"))
		err := v.ValidateSingleMessageEnvelope(raw)
		if err == nil {
			return
		}
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("envelope returned a non-deny error: %v", err)
		}
	})
}
