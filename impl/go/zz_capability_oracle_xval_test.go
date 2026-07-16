package npamp

import (
	"encoding/hex"
	"testing"
)

// TestCapabilityOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/capability_oracle.py) and this Go implementation AGREE on the
// NPAMP-CAP payload-decode contract. The body hexes below are the oracle's ACTUAL
// output — built by the oracle's from-scratch RFC-8949 canonical-CBOR encoder from the
// spec/companion/84 key tables, NOT dumped from this impl — so a drift in either the
// oracle or the impl fails here in `go test`, before the full conformance runner.
//
// For every VALID vector the impl must (a) decode the envelope to the frame_kind and
// corr the oracle declares, and (b) re-encode the decoded body canonically to the
// exact oracle bytes (round-trip: the impl produces the same canonical form the
// independent oracle did). For every MUST-REJECT vector the impl must return an error
// from both DecodeCapabilityEnvelope and DecodeCapabilityBody.
func TestCapabilityOracleCrossValidate(t *testing.T) {
	const corrHex = "7a"
	cases := []struct {
		name    string
		ft      FrameType
		hexBody string
		valid   bool
	}{
		// VALID (result "valid" / "acceptable" in the oracle) — decode + round-trip.
		{"issue_req", FrameCapIssueReq, "a50019010001417a02676167656e742d62036b726561643a6c65646765720902", true},
		{"delegate_req", FrameCapDelegateReq, "a50019010201417a02656361702d3103676167656e742d630702", true},
		{"revoke_req", FrameCapRevokeReq, "a40019010401417a02656361702d310503", true},
		{"lookup_req", FrameCapLookupReq, "a30019010601417a0800", true},
		{"error", FrameCapError, "a40019010801417a02040371617070726f76616c207265717569726564", true},
		{"fwd_compat_issue", FrameCapIssueReq, "a60019010001417a02676167656e742d62036b726561643a6c6564676572090218636c6675747572652d6669656c64", true},
		// MUST-REJECT (result "invalid") — both envelope and body decode error.
		{"nonshortest_key", FrameCapIssueReq, "a1180000", false},
		{"unknown_neg_key", FrameCapIssueReq, "a60019010001417a02676167656e742d62036b726561643a6c656467657209022009", false},
		{"missing_subject", FrameCapIssueReq, "a40019010001417a036b726561643a6c65646765720902", false},
		{"wrong_type_subject", FrameCapIssueReq, "a50019010001417a0209036b726561643a6c65646765720902", false},
		{"frame_kind_mismatch", FrameCapIssueReq, "a50019010101417a02676167656e742d62036b726561643a6c65646765720902", false},
		{"corr_wrong_type", FrameCapIssueReq, "a50019010001187a02676167656e742d62036b726561643a6c65646765720902", false},
		{"corr_empty", FrameCapIssueReq, "a500190100014002676167656e742d62036b726561643a6c65646765720902", false},
		{"not_a_map", FrameCapIssueReq, "05", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			if !tc.valid {
				if _, _, err := DecodeCapabilityEnvelope(tc.ft, body); err == nil {
					t.Fatalf("MUST-reject vector decoded envelope without error")
				}
				if _, err := DecodeCapabilityBody(tc.ft, body); err == nil {
					t.Fatalf("MUST-reject vector decoded body without error")
				}
				return
			}
			// Valid: envelope decodes to the oracle's declared frame_kind + corr.
			fk, corr, err := DecodeCapabilityEnvelope(tc.ft, body)
			if err != nil {
				t.Fatalf("oracle body rejected by impl: %v", err)
			}
			if fk != uint64(tc.ft) {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
			}
			if got := hex.EncodeToString(corr); got != corrHex {
				t.Fatalf("corr = %s, want %s", got, corrHex)
			}
			// Round-trip: decode to fields, re-encode canonically, expect the exact
			// oracle bytes back (the impl agrees with the independent canonical form).
			fields, err := DecodeCapabilityBody(tc.ft, body)
			if err != nil {
				t.Fatalf("valid body failed full decode: %v", err)
			}
			reEnc := EncodeCapabilityBody(fields)
			if got := hex.EncodeToString(reEnc); got != tc.hexBody {
				t.Fatalf("re-encoded body = %s, want oracle bytes %s", got, tc.hexBody)
			}
		})
	}
}
