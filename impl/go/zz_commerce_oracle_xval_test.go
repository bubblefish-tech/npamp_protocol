package npamp

import (
	"encoding/hex"
	"testing"
)

// TestCommerceOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/commerce_oracle.py) and this Go implementation AGREE: the oracle's from-scratch
// canonical-CBOR bodies decode through ValidateCommercePayload/DecodeCommerceEnvelope exactly as the
// oracle declares — accepted when the oracle marks them valid/acceptable, rejected when the oracle
// marks them MUST-reject. The body hexes below are the oracle's ACTUAL output (test-vectors/gen/out/
// commerce.json) — non-circular, built by the oracle's independent RFC-8949 encoder, NOT by this impl
// — so a drift in either the oracle or the impl fails here in `go test`, before the full conformance
// runner. Two independent implementations agreeing is what makes the corpus vectors non-circular.
//
// For every ACCEPTED body it additionally re-encodes the decoded map with EncodeCommerceBody and
// asserts the bytes are byte-identical to the oracle's — proving the Go impl produces the SAME one
// canonical form the independent oracle produced (RFC 8949 §4.2.1; spec/companion/88 §4.1).
func TestCommerceOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name     string
		ft       FrameType
		hexBody  string
		accept   bool
		wantCorr string // hex of the expected corr, on accepted cases
	}{
		// ---- valid / acceptable (accepted by the impl) ----
		{"valid_mandate_create", FrameCommerceMandateCreateReq,
			"a600190100014163026b70617965723a616c696365036970617965653a626f6204a300193039010202635553440d03", true, "63"},
		{"valid_mandate_read", FrameCommerceMandateReadReq,
			"a400190102014163026b6d616e646174653a78797a0300", true, "63"},
		{"valid_intent_propose", FrameCommerceIntentProposeReq,
			"a50019010801416302826770617274793a616770617274793a620381a3006770617274793a61016770617274793a6202a300193039010202635553440702", true, "63"},
		{"valid_commerce_error_approval_required", FrameCommerceError,
			"a50019010e01416302040371617070726f76616c2072657175697265640568617070723a313233", true, "63"},
		{"fwd_compat_nonneg", FrameCommerceMandateCreateReq,
			"a700190100014163026b70617965723a616c696365036970617965653a626f6204a300193039010202635553440d0318636c6675747572652d6669656c64", true, "63"},
		// ---- MUST-reject (rejected by the impl) ----
		{"nonshortest_key", FrameCommerceMandateCreateReq, "a1180000", false, ""},
		{"unknown_negative_key", FrameCommerceMandateCreateReq,
			"a70019010001416302617003617104a300193039010202635553440d032009", false, ""},
		{"missing_required_amount", FrameCommerceMandateCreateReq,
			"a500190100014163026b70617965723a616c696365036970617965653a626f620d03", false, ""},
		{"wrong_major_type_payer", FrameCommerceMandateCreateReq,
			"a6001901000141630209036970617965653a626f6204a300193039010202635553440d03", false, ""},
		{"frame_kind_mismatch", FrameCommerceMandateCreateReq,
			"a600190102014163026b70617965723a616c696365036970617965653a626f6204a300193039010202635553440d03", false, ""},
		{"corr_not_bytes", FrameCommerceMandateCreateReq,
			"a600190100011863026b70617965723a616c696365036970617965653a626f6204a300193039010202635553440d03", false, ""},
		{"not_a_map", FrameCommerceMandateCreateReq, "05", false, ""},
		{"malformed_amount_missing_currency", FrameCommerceMandateCreateReq,
			"a600190100014163026b70617965723a616c696365036970617965653a626f6204a20019303901020d03", false, ""},
		{"malformed_amount_wrong_type_scale", FrameCommerceMandateCreateReq,
			"a600190100014163026b70617965723a616c696365036970617965653a626f6204a300193039016374776f02635553440d03", false, ""},
		{"leg_party_not_in_parties", FrameCommerceIntentProposeReq,
			"a50019010801416302826770617274793a616770617274793a620381a3006770617274793a61016770617274793a6302a300193039010202635553440702", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, corr, derr := DecodeCommerceEnvelope(tc.ft, body)
			if tc.accept {
				if derr != nil {
					t.Fatalf("oracle=accept but impl REJECTED: %v", derr)
				}
				if fk != uint64(tc.ft) {
					t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
				}
				if got := hex.EncodeToString(corr); got != tc.wantCorr {
					t.Fatalf("corr = %s, want %s", got, tc.wantCorr)
				}
				// Re-encode the decoded map and prove it reproduces the oracle's canonical bytes.
				fields, berr := DecodeCommerceBody(tc.ft, body)
				if berr != nil {
					t.Fatalf("DecodeCommerceBody rejected an accepted body: %v", berr)
				}
				reenc := hex.EncodeToString(EncodeCommerceBody(fields))
				if reenc != tc.hexBody {
					t.Fatalf("re-encoded body\n got  %s\n want %s (oracle canonical bytes)", reenc, tc.hexBody)
				}
				return
			}
			if derr == nil {
				t.Fatalf("oracle=MUST-reject but impl ACCEPTED")
			}
		})
	}
}
