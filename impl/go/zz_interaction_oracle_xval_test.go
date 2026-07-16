package npamp

import (
	"encoding/hex"
	"testing"
)

// TestInteractionOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/interaction_oracle.py) and this Go implementation AGREE, and that the agreement
// is NON-CIRCULAR: the body hexes below are the oracle's ACTUAL output, built by its own from-scratch
// RFC-8949 canonical-CBOR encoder from spec/companion/89_interaction_channel.md — NOT dumped from this
// impl. For each oracle vector the impl is exercised as the spec requires:
//
//   - a "valid"/"acceptable" body MUST decode through ValidateInteractionPayload / DecodeInteractionBody
//     to the frame_kind + corr the oracle declares, AND re-encode (EncodeInteractionBody) to the exact
//     oracle bytes — proving the impl produces the same canonical form an independent encoder does;
//   - a "MUST-reject" body MUST be rejected (a non-nil error).
//
// A drift in either the oracle or the impl fails here in `go test`, before the full conformance runner.
func TestInteractionOracleCrossValidate(t *testing.T) {
	const corr2a = "2a" // every vector's corr is the 1-byte token 0x2a

	accept := []struct {
		name    string
		ft      FrameType
		hexBody string
	}{
		{"valid_event", FrameInteractEvent, "a30019010001412a0203"},
		{"valid_prompt_req", FrameInteractPromptReq, "a40019010201412a0201036a596f7572206e616d653f"},
		{"valid_approval_req", FrameInteractApprovalReq, "a40019010401412a026f64656c657465207265636f726420580302"},
		{"valid_approval_result", FrameInteractApprovalResult, "a30019010501412a0200"},
		{"valid_error_approval_held", FrameInteractError, "a50019010701412a0206037820617070726f76616c2068656c6420666f722068756d616e206465636973696f6e05686131623263336434"},
		{"valid_event_ack", FrameInteractEventAck, "a20019010101412a"},
		{"fwd_compat_event", FrameInteractEvent, "a40019010001412a020318636c6675747572652d6669656c64"},
	}
	for _, tc := range accept {
		t.Run(tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, corr, err := DecodeInteractionEnvelope(tc.ft, body)
			if err != nil {
				t.Fatalf("oracle body rejected by impl: %v", err)
			}
			if fk != uint64(tc.ft) {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
			}
			if got := hex.EncodeToString(corr); got != corr2a {
				t.Fatalf("corr = %s, want %s", got, corr2a)
			}
			// Round-trip: decode to fields, re-encode canonically, expect the exact oracle bytes.
			fields, err := DecodeInteractionBody(tc.ft, body)
			if err != nil {
				t.Fatalf("DecodeInteractionBody rejected an accepted body: %v", err)
			}
			reenc := hex.EncodeToString(EncodeInteractionBody(fields))
			if reenc != tc.hexBody {
				t.Fatalf("re-encoded body = %s, want oracle bytes %s (canonical-form disagreement)", reenc, tc.hexBody)
			}
		})
	}

	reject := []struct {
		name    string
		ft      FrameType
		hexBody string
	}{
		{"nonshortest_key", FrameInteractEvent, "a1180000"},
		{"unknown_negative_key", FrameInteractEvent, "a40019010001412a02032009"},
		{"missing_required_event_class", FrameInteractEvent, "a20019010001412a"},
		{"wrong_major_type_event_class", FrameInteractEvent, "a30019010001412a026178"},
		{"frame_kind_mismatch", FrameInteractEvent, "a30019010201412a0203"},
		{"corr_not_bytes", FrameInteractEvent, "a30019010001182a0203"},
		{"missing_corr", FrameInteractEvent, "a2001901000203"},
		{"not_a_map", FrameInteractEvent, "05"},
	}
	for _, tc := range reject {
		t.Run(tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			if _, _, verr := DecodeInteractionEnvelope(tc.ft, body); verr == nil {
				t.Fatalf("oracle=MUST-reject but impl ACCEPTED body %s", tc.hexBody)
			}
		})
	}
}
