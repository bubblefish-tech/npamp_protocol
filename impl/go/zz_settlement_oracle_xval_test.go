package npamp

import (
	"encoding/hex"
	"testing"
)

// TestSettlementOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/settlement_oracle.py) and this Go implementation AGREE, and does so
// NON-CIRCULARLY: every hexBody below is the oracle's ACTUAL output — canonical CBOR built by the
// oracle's from-scratch RFC-8949 encoder from the companion's §4/§6/§8 key tables, NOT dumped from
// this impl. For each accepted vector the impl's ValidateSettlementPayload/DecodeSettlementEnvelope
// must decode it (frame_kind + corr as the oracle declares) AND a canonical re-encode
// (DecodeSettlementBody -> EncodeSettlementBody) must reproduce the oracle's exact bytes, proving the
// Go codec produces the same canonical form the independent oracle does. For each MUST-reject vector
// the impl must return an error. A drift in either the oracle or the impl fails here in `go test`,
// before the full conformance runner.
func TestSettlementOracleCrossValidate(t *testing.T) {
	const wantCorr = "01020304" // CORR = 0x01020304 (settlement_oracle.py); byte string, like MEMORY.
	cases := []struct {
		name    string
		ft      FrameType
		hexBody string
		accept  bool
	}{
		// Accepted (result "valid"/"acceptable") — the oracle's canonical operation bodies.
		{"intent_req", FrameSettleIntentReq, "a40019010001440102030402756f626c69676174696f6e3a696e766f6963652d34320802", true},
		{"intent_result", FrameSettleIntentResult, "a4001901010144010203040270736574746c656d656e743a732d3030310367736574746c6564", true},
		{"receipt_req", FrameReceiptReq, "a4001901020144010203040270736574746c656d656e743a732d3030310400", true},
		{"receipt_result", FrameReceiptResult, "a30019010301440102030402a3006d726563656970743a722d3030310170736574746c656d656e743a732d3030310567736574746c6564", true},
		{"settle_error_approval_required", FrameSettleError, "a50019010401440102030402040371617070726f76616c207265717569726564056e617070726f76616c3a612d303031", true},
		{"batch_commit_req", FrameSettleBatchCommitReq, "a50018a0014401020304026f62617463683a622d323032362d30370344deadbeef0702", true},
		{"batch_commit_result", FrameSettleBatchCommitResult, "a40018a1014401020304026f62617463683a622d323032362d30370369636f6d6d6974746564", true},
		{"fwd_compat_intent_req", FrameSettleIntentReq, "a50019010001440102030402756f626c69676174696f6e3a696e766f6963652d3432080218636c6675747572652d6669656c64", true},
		// MUST-reject (result "invalid") — the companion's §4/§5.3/§6 reject clauses as invalid CBOR.
		{"nonshortest_key", FrameSettleIntentReq, "a1180000", false},
		{"unknown_negative_key", FrameSettleIntentReq, "a50019010001440102030402617808022009", false},
		{"missing_obligation_ref", FrameSettleIntentReq, "a3001901000144010203040802", false},
		{"wrong_major_type_obligation_ref", FrameSettleIntentReq, "a40019010001440102030402090802", false},
		{"missing_effect", FrameSettleIntentReq, "a300190100014401020304026178", false},
		{"frame_kind_mismatch", FrameSettleIntentReq, "a4001901020144010203040261780802", false},
		{"corr_not_bytes", FrameSettleIntentReq, "a40019010001040261780802", false},
		{"corr_empty", FrameSettleIntentReq, "a40019010001400261780802", false},
		{"batch_missing_commitment", FrameSettleBatchCommitReq, "a40018a0014401020304026962617463683a622d310702", false},
		{"not_a_map", FrameSettleIntentReq, "05", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, corr, derr := DecodeSettlementEnvelope(tc.ft, body)
			if !tc.accept {
				if derr == nil {
					t.Fatalf("oracle=MUST-reject but impl ACCEPTED body %s", tc.hexBody)
				}
				return
			}
			if derr != nil {
				t.Fatalf("oracle body rejected by impl: %v", derr)
			}
			if fk != uint64(tc.ft) {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
			}
			if got := hex.EncodeToString(corr); got != wantCorr {
				t.Fatalf("corr = %s, want %s", got, wantCorr)
			}
			// Canonical re-encode MUST reproduce the oracle's exact bytes: the Go codec agrees with
			// the independent oracle on the one canonical form (RFC 8949 §4.2.1).
			fields, berr := DecodeSettlementBody(tc.ft, body)
			if berr != nil {
				t.Fatalf("DecodeSettlementBody rejected an accepted body: %v", berr)
			}
			reenc := hex.EncodeToString(EncodeSettlementBody(fields))
			if reenc != tc.hexBody {
				t.Fatalf("canonical re-encode = %s, want oracle bytes %s", reenc, tc.hexBody)
			}
		})
	}
}
