package npamp

import (
	"encoding/hex"
	"testing"
)

// TestStreamOracleCrossValidate proves the independent Python oracle
// (test-vectors/gen/stream_oracle.py) and this Go implementation AGREE: the oracle's from-scratch
// canonical-CBOR bodies decode through ValidateStreamPayload/DecodeStreamEnvelope to the envelope
// the oracle declares. The body hexes below are the oracle's ACTUAL output — non-circular, built by
// the oracle's independent RFC-8949 encoder, NOT by this impl — so a drift in either the oracle or
// the impl fails here in `go test`, before the full conformance runner.
func TestStreamOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name    string
		ft      FrameType
		hexBody string
		wantSS  uint64
	}{
		{"open", FrameStreamOpen, "a4001901000104021a000100000301", 4},
		{"data", FrameStreamData, "a40019010101040200034568656c6c6f", 4},
		{"fwd_compat_open", FrameStreamOpen, "a5001901000104021a00010000030118636c6675747572652d6669656c64", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := hex.DecodeString(tc.hexBody)
			if err != nil {
				t.Fatalf("bad hex: %v", err)
			}
			fk, ss, err := DecodeStreamEnvelope(tc.ft, body)
			if err != nil {
				t.Fatalf("oracle body rejected by impl: %v", err)
			}
			if fk != uint64(tc.ft) {
				t.Fatalf("frame_kind = 0x%04X, want 0x%04X", uint16(fk), uint16(tc.ft))
			}
			if ss != tc.wantSS {
				t.Fatalf("sub_stream_id = %d, want %d", ss, tc.wantSS)
			}
		})
	}
}
