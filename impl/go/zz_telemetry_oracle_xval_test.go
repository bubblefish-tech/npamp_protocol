package npamp

import (
	"encoding/hex"
	"testing"
)

// TestTelemetryOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/telemetry_oracle.py) and this Go implementation AGREE. The body hexes below are
// the oracle's ACTUAL output — canonical CBOR built by the oracle's from-scratch RFC-8949 encoder from
// the spec/companion/87 key tables, NOT dumped from this impl — so they are non-circular. For each
// VALID vector the test (1) decodes the envelope through DecodeTelemetryEnvelope and checks the
// frame_kind and corr the oracle declares, and (2) decodes the full body and RE-ENCODES it through
// EncodeTelemetryBody, asserting the bytes are byte-identical to the oracle's — proving the Go codec
// produces the same one canonical form. For each MUST-REJECT vector the test asserts
// ValidateTelemetryPayload returns an error. A drift in either the oracle or the impl fails here in
// `go test`, before the full conformance runner.
func TestTelemetryOracleCrossValidate(t *testing.T) {
	valid := []struct {
		name     string
		ft       FrameType
		hexBody  string
		wantCorr string // hex; "" means the standalone report omits corr (§4.1/§5)
	}{
		{"report_standalone_metrics", FrameTelemetryReport, "a30019010003000481a400686370752e6c6f6164011b0000018bcfe56800020003182a", ""},
		{"report_subscribed_events", FrameTelemetryReport, "a50019010001416302412a03070581a3006867632e7061757365011b0000018bcfe568010202", "63"},
		{"report_health", FrameTelemetryReport, "a30019010003010681a3006773746f72616765011b0000018bcfe568020201", ""},
		{"report_mixed", FrameTelemetryReport, "a50019010003020481a4006b71756575652e6465707468011b0000018bcfe56803020203220581a2006572656b6579011b0000018bcfe568040681a300636e6574011b0000018bcfe568050200", ""},
		{"subscribe", FrameTelemetrySubscribe, "a3001901010141630708", "63"},
		{"subscribe_selector", FrameTelemetrySubscribe, "a600190101014163028200010381686370752e6c6f616405020704", "63"},
		{"sub_ack", FrameTelemetrySubAck, "a40019010201416302412a0304", "63"},
		{"unsubscribe", FrameTelemetryUnsubscribe, "a30019010301416302412a", "63"},
		{"credit", FrameTelemetryCredit, "a40019010401416302412a0310", "63"},
		{"error", FrameTelemetryError, "a3001901050141630201", "63"},
		{"fwd_compat_subscribe", FrameTelemetrySubscribe, "a400190101014163070818636c6675747572652d6669656c64", "63"},
	}
	for _, tc := range valid {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, corr, err := DecodeTelemetryEnvelope(tc.ft, body)
			if err != nil {
				t.Fatalf("oracle body rejected by impl: %v", err)
			}
			if fk != uint64(tc.ft) {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
			}
			if got := hex.EncodeToString(corr); got != tc.wantCorr {
				t.Fatalf("corr = %q, want %q", got, tc.wantCorr)
			}
			// Round-trip: decode -> re-encode canonical -> MUST equal the independent oracle bytes.
			fields, err := DecodeTelemetryBody(tc.ft, body)
			if err != nil {
				t.Fatalf("DecodeTelemetryBody rejected oracle body: %v", err)
			}
			reenc := hex.EncodeToString(EncodeTelemetryBody(fields))
			if reenc != tc.hexBody {
				t.Fatalf("re-encoded body = %s, want (oracle) %s", reenc, tc.hexBody)
			}
		})
	}

	reject := []struct {
		name    string
		ft      FrameType
		hexBody string
	}{
		{"non_shortest_key", FrameTelemetrySubscribe, "a1180000"},
		{"non_canonical_key_order", FrameTelemetrySubscribe, "a201416300190101"},
		{"unknown_negative_key", FrameTelemetrySubscribe, "a40019010101416307082009"},
		{"subscribe_missing_credit", FrameTelemetrySubscribe, "a200190101014163"},
		{"corr_wrong_type", FrameTelemetrySubscribe, "a30019010101090708"},
		{"corr_empty", FrameTelemetrySubscribe, "a30019010101400708"},
		{"frame_kind_mismatch", FrameTelemetryReport, "a30019010103000481a4006178010102000301"},
		{"report_empty_content", FrameTelemetryReport, "a2001901000300"},
		{"report_missing_batch_seq", FrameTelemetryReport, "a2001901000481a4006178010102000301"},
		{"report_corr_without_sub_id", FrameTelemetryReport, "a40019010001416303000481a4006178010102000301"},
		{"metric_missing_value", FrameTelemetryReport, "a30019010003000481a300617801010200"},
		{"metric_wrong_type_name", FrameTelemetryReport, "a30019010003000481a40009010102000301"},
		{"health_missing_status", FrameTelemetryReport, "a30019010003000681a2006773746f726167650101"},
		{"payload_not_a_map", FrameTelemetrySubscribe, "05"},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			if _, _, err := DecodeTelemetryEnvelope(tc.ft, body); err == nil {
				t.Fatalf("MUST-reject body was ACCEPTED by impl (want error): %s", tc.hexBody)
			}
		})
	}
}
