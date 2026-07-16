package npamp

import (
	"encoding/hex"
	"testing"
)

// TestWorkflowOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/workflow_oracle.py) and this Go implementation AGREE: the oracle's from-scratch
// canonical-CBOR bodies decode through ValidateWorkflowPayload/DecodeWorkflowEnvelope to the envelope
// the oracle declares, the oracle's MUST-reject bodies are rejected, and every valid body re-encodes
// (DecodeWorkflowBody -> EncodeWorkflowBody) byte-identically to the oracle's independent bytes. The
// body hexes below are the oracle's ACTUAL output — non-circular, built by the oracle's independent
// RFC-8949 encoder, NOT by this impl — so a drift in either the oracle or the impl fails here in
// `go test`, before the full conformance runner. Two independent implementations agreeing is what
// makes the corpus vectors non-circular.
func TestWorkflowOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name     string
		ft       FrameType
		hexBody  string
		accept   bool   // oracle result is valid/acceptable
		wantCorr string // expected corr hex; "" means the frame carries no corr
	}{
		// valid + acceptable vectors (tcId 1–6)
		{"submit_req", FrameWorkflowSubmitReq, "a400190100014163026973756d6d6172697a650b01", true, "63"},
		{"submit_result", FrameWorkflowSubmitResult, "a40019010101416302667461736b2d370300", true, "63"},
		{"step_event_no_corr", FrameWorkflowStepEvent, "a40019010602667461736b2d3703000401", true, ""},
		{"complete_no_corr", FrameWorkflowComplete, "a40019010702667461736b2d3703030402", true, ""},
		{"error_approval_required", FrameWorkflowError, "a5001901080141630204037768656c6420666f722068756d616e20617070726f76616c0566617070722d31", true, "63"},
		{"fwd_compat_nonneg", FrameWorkflowSubmitReq, "a500190100014163026973756d6d6172697a650b0118636c6675747572652d6669656c64", true, "63"},

		// MUST-reject vectors (tcId 7–16)
		{"nonshortest_key", FrameWorkflowSubmitReq, "a1180000", false, ""},
		{"unknown_negative_key", FrameWorkflowSubmitReq, "a5001901000141630261780b012009", false, ""},
		{"missing_task_type", FrameWorkflowSubmitReq, "a3001901000141630b01", false, ""},
		{"missing_effect", FrameWorkflowSubmitReq, "a300190100014163026178", false, ""},
		{"wrong_type_effect", FrameWorkflowSubmitReq, "a4001901000141630261780b646e6f7065", false, ""},
		{"frame_kind_mismatch", FrameWorkflowSubmitReq, "a4001901020141630261780b01", false, ""},
		{"corr_not_bytes", FrameWorkflowSubmitReq, "a4001901000118630261780b01", false, ""},
		{"missing_corr", FrameWorkflowSubmitReq, "a3001901000261780b01", false, ""},
		{"missing_error_message", FrameWorkflowError, "a3001901080141630204", false, ""},
		{"not_a_map", FrameWorkflowSubmitReq, "05", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, corr, decErr := DecodeWorkflowEnvelope(tc.ft, body)

			if !tc.accept {
				if decErr == nil {
					t.Fatalf("oracle=MUST-reject but impl ACCEPTED")
				}
				return
			}

			// valid / acceptable: the impl MUST accept and agree on the envelope.
			if decErr != nil {
				t.Fatalf("oracle body rejected by impl: %v", decErr)
			}
			if fk != uint64(tc.ft) {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
			}
			if got := hex.EncodeToString(corr); got != tc.wantCorr {
				t.Fatalf("corr = %q, want %q", got, tc.wantCorr)
			}

			// Re-encode canonical and assert byte-identity with the oracle's bytes: proves the Go
			// impl produces exactly the independent oracle's canonical encoding (agreement, not
			// self-consistency).
			fields, derr := DecodeWorkflowBody(tc.ft, body)
			if derr != nil {
				t.Fatalf("DecodeWorkflowBody: %v", derr)
			}
			reenc := hex.EncodeToString(EncodeWorkflowBody(fields))
			if reenc != tc.hexBody {
				t.Fatalf("re-encoded body = %s, want oracle bytes %s", reenc, tc.hexBody)
			}
		})
	}
}
