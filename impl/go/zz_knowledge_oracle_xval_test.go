package npamp

import (
	"encoding/hex"
	"testing"
)

// TestKnowledgeOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/knowledge_oracle.py) and this Go implementation AGREE, which is
// what makes the knowledge.body.decode corpus vectors NON-CIRCULAR: the body hexes
// below are the oracle's ACTUAL output, built by its from-scratch RFC-8949 encoder
// from spec/companion/8b_knowledge_channel.md §4/§6/§9 — NOT dumped from this impl —
// so a drift in either the oracle or the impl fails here in `go test`, before the
// full conformance runner.
//
// For each ACCEPTED vector: ValidateKnowledgePayload/DecodeKnowledgeEnvelope decodes
// it to the envelope the oracle declares, AND re-encoding the decoded body
// (DecodeKnowledgeBody -> EncodeKnowledgeBody) reproduces the oracle's canonical bytes
// exactly (the two independent encoders converge on the one RFC-8949 canonical form).
// For each MUST-reject vector: the impl returns an error, matching the oracle's
// result:"invalid".
func TestKnowledgeOracleCrossValidate(t *testing.T) {
	const corrHex = "71" // the oracle's 1-byte correlation token for every vector

	accept := []struct {
		name    string
		ft      FrameType
		hexBody string
	}{
		{"query_req_min", FrameKnowledgeQueryReq, "a200190100014171"},
		{"query_req_full", FrameKnowledgeQueryReq, "a5001901000141710270766563746f72206461746162617365730368636f727075732d61060a"},
		{"query_result", FrameKnowledgeQueryResult, "a4001901010141710281a30065646f632d3101757468652072657472696576656420636f6e74656e740468636f727075732d6103f4"},
		{"subscribe_req", FrameKnowledgeSubscribeReq, "a400190104014171026e7374616e64696e672071756572790904"},
		{"subscribe_ack", FrameKnowledgeSubscribeAck, "a400190105014171024201020304"},
		{"update_removed_only", FrameKnowledgeUpdate, "a500190106014171024201020307058165646f632d39"},
		{"update_results_present", FrameKnowledgeUpdate, "a5001901060141710242010203080481a30065646f632d3101757468652072657472696576656420636f6e74656e740468636f727075732d61"},
		{"error", FrameKnowledgeError, "a400190109014171020103716d616c666f726d65642072657175657374"},
		{"fwd_compat_nonneg", FrameKnowledgeQueryReq, "a30019010001417118636c6675747572652d6669656c64"},
	}
	for _, tc := range accept {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, corr, err := DecodeKnowledgeEnvelope(tc.ft, body)
			if err != nil {
				t.Fatalf("oracle body rejected by impl: %v", err)
			}
			if fk != uint64(tc.ft) {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
			}
			if got := hex.EncodeToString(corr); got != corrHex {
				t.Fatalf("corr = %s, want %s", got, corrHex)
			}
			// Round-trip: decode to portable fields, re-encode canonically, and assert
			// byte-identity with the oracle's independent bytes.
			fields, err := DecodeKnowledgeBody(tc.ft, body)
			if err != nil {
				t.Fatalf("DecodeKnowledgeBody rejected an accepted vector: %v", err)
			}
			reenc := EncodeKnowledgeBody(fields)
			if got := hex.EncodeToString(reenc); got != tc.hexBody {
				t.Fatalf("re-encode = %s, want (oracle) %s", got, tc.hexBody)
			}
		})
	}

	reject := []struct {
		name    string
		ft      FrameType
		hexBody string
	}{
		{"nonshortest_key", FrameKnowledgeQueryReq, "a1180000"},
		{"unknown_negative_key", FrameKnowledgeQueryReq, "a4001901000141710261782009"},
		{"missing_required_credit", FrameKnowledgeSubscribeReq, "a300190104014171026171"},
		{"wrong_major_type_credit", FrameKnowledgeSubscribeReq, "a300190104014171096178"},
		{"frame_kind_mismatch", FrameKnowledgeQueryReq, "a200190101014171"},
		{"corr_not_bytes", FrameKnowledgeQueryReq, "a2001901000105"},
		{"corr_empty", FrameKnowledgeQueryReq, "a2001901000140"},
		{"update_neither", FrameKnowledgeUpdate, "a400190106014171024201020301"},
		{"missing_corr", FrameKnowledgeQueryReq, "a100190100"},
		{"not_a_map", FrameKnowledgeQueryReq, "05"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			if _, _, verr := DecodeKnowledgeEnvelope(tc.ft, body); verr == nil {
				t.Fatalf("oracle=MUST-reject but impl ACCEPTED body %s", tc.hexBody)
			}
		})
	}
}
