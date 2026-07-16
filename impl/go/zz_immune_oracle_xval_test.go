package npamp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestImmuneOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/immune_oracle.py) and this Go implementation AGREE, and that the
// agreement is NON-CIRCULAR: every body hex below is the oracle's ACTUAL output,
// produced by the oracle's from-scratch RFC-8949 canonical-CBOR encoder from the
// companion's own key tables (spec/companion/85_immune_channel.md §4-§8) — NOT dumped
// from this impl. A drift in either the oracle or the impl fails here in `go test`,
// before the full conformance runner.
//
//   - valid vectors: the impl MUST accept them, the decoded envelope MUST match the
//     oracle's declared frame_kind/corr, and re-encoding the decoded body MUST
//     reproduce the oracle's exact canonical bytes (impl agrees with the oracle's
//     independent encoder).
//   - MUST-reject vectors: the impl MUST return an error (the §4/§6/§8 reject clauses).
func TestImmuneOracleCrossValidate(t *testing.T) {
	valid := []struct {
		name    string
		ft      FrameType
		hexBody string
		wantFK  uint64
	}{
		{"report_req", FrameImmuneReportReq, "a500190100014163026a616e6f6d616c792d343203010403", 0x0100},
		{"report_result", FrameImmuneReportResult, "a4001901010141630201036574726b2d37", 0x0101},
		{"immune_error", FrameImmuneError, "a400190102014163020103716d616c666f726d65642072657175657374", 0x0102},
		{"gossip_advertise", FrameImmuneGossipAdvertise, "a30018c00141630281a300429a1c01070303", 0x00C0},
		{"gossip_retract", FrameImmuneGossipRetract, "a50018c401416302429a1c03080400", 0x00C4},
		{"fwd_compat_report_req", FrameImmuneReportReq, "a600190100014163026a616e6f6d616c792d34320301040318636c6675747572652d6669656c64", 0x0100},
	}
	const wantCorrHex = "63" // every oracle valid vector uses the 1-byte corr 0x63
	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, corr, err := DecodeImmuneEnvelope(tc.ft, body)
			if err != nil {
				t.Fatalf("oracle valid body rejected by impl: %v", err)
			}
			if fk != tc.wantFK {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.wantFK))
			}
			if got := hex.EncodeToString(corr); got != wantCorrHex {
				t.Fatalf("corr = %s, want %s", got, wantCorrHex)
			}
			// Re-encode the decoded body and assert byte-identity with the oracle's
			// canonical bytes: the impl's encoder agrees with the oracle's independent
			// RFC-8949 encoder (round-trip canonical stability).
			fields, err := DecodeImmuneBody(tc.ft, body)
			if err != nil {
				t.Fatalf("DecodeImmuneBody rejected a valid oracle body: %v", err)
			}
			reenc := EncodeImmuneBody(fields)
			if !bytes.Equal(reenc, body) {
				t.Fatalf("re-encode = %s, want oracle bytes %s", hex.EncodeToString(reenc), tc.hexBody)
			}
		})
	}

	reject := []struct {
		name    string
		ft      FrameType
		hexBody string
	}{
		{"nonshortest_key", FrameImmuneReportReq, "a1180000"},
		{"unknown_negative_key", FrameImmuneReportReq, "a600190100014163026178030104032009"},
		{"missing_report_id", FrameImmuneReportReq, "a40019010001416303010403"},
		{"wrong_major_type_anomaly_class", FrameImmuneReportReq, "a50019010001416302617803636261640403"},
		{"frame_kind_mismatch", FrameImmuneReportReq, "a50019010101416302617803010403"},
		{"corr_not_bytes", FrameImmuneReportReq, "a50019010001186302617803010403"},
		{"corr_empty", FrameImmuneReportReq, "a500190100014002617803010403"},
		{"missing_corr", FrameImmuneReportReq, "a40019010002617803010403"},
		{"nested_descriptor_missing_item_id", FrameImmuneGossipAdvertise, "a30018c00141630281a10107"},
		{"retract_missing_version", FrameImmuneGossipRetract, "a40018c401416302429a1c0400"},
		{"map_keys_out_of_order", FrameImmuneReportReq, "a201416300190100"},
		{"not_a_map", FrameImmuneReportReq, "05"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			if _, _, verr := DecodeImmuneEnvelope(tc.ft, body); verr == nil {
				t.Fatalf("oracle MUST-reject vector was ACCEPTED by impl")
			}
		})
	}
}
