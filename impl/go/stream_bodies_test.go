package npamp

import (
	"errors"
	"testing"
)

// NPAMP-STREAM structural validation (spec/companion/80_stream_channel.md §4-§5). The envelope
// diverges from NPAMP-MEMORY: key 1 is sub_stream_id, an Unsigned int, NOT a byte-string corr.

func TestValidateStreamPayload_GoodOpen(t *testing.T) {
	body := cborEncode(map[uint64]any{
		0: uint64(FrameStreamOpen),
		1: uint64(4),     // sub_stream_id (even = handshake initiator, §6.1)
		2: uint64(65536), // init_window
		3: uint64(0x01),  // content_type = token-text
	})
	if _, err := ValidateStreamPayload(FrameStreamOpen, body); err != nil {
		t.Fatalf("valid STREAM_OPEN rejected: %v", err)
	}
}

func TestValidateStreamPayload_Rejects(t *testing.T) {
	cases := []struct {
		name string
		ft   FrameType
		body []byte
	}{
		{"frame_kind_mismatch", FrameStreamOpen, cborEncode(map[uint64]any{0: uint64(FrameStreamData), 1: uint64(4), 2: uint64(1), 3: uint64(1)})},
		{"missing_sub_stream_id", FrameStreamOpen, cborEncode(map[uint64]any{0: uint64(FrameStreamOpen), 2: uint64(1), 3: uint64(1)})},
		{"sub_stream_id_wrong_type", FrameStreamOpen, cborEncode(map[uint64]any{0: uint64(FrameStreamOpen), 1: []byte("x"), 2: uint64(1), 3: uint64(1)})},
		{"missing_required_init_window", FrameStreamOpen, cborEncode(map[uint64]any{0: uint64(FrameStreamOpen), 1: uint64(4), 3: uint64(1)})},
		{"wrong_type_content_type", FrameStreamOpen, cborEncode(map[uint64]any{0: uint64(FrameStreamOpen), 1: uint64(4), 2: uint64(1), 3: "text"})},
		{"data_wrong_type", FrameStreamData, cborEncode(map[uint64]any{0: uint64(FrameStreamData), 1: uint64(4), 2: uint64(0), 3: "notbytes"})},
		{"not_a_map", FrameStreamData, cborEncode(uint64(5))},
		// §4.3: an unknown NEGATIVE integer key MUST be rejected. Build the canonical 4-entry OPEN
		// then splice a 5th pair (-1 -> 9): -1 encodes as 0x20 (major 1, arg 0), which sorts after
		// the uint keys 0x00-0x03, so the map stays canonically ordered; bump the count 0xa4 -> 0xa5.
		{"unknown_negative_key", FrameStreamOpen, func() []byte {
			b := cborEncode(map[uint64]any{0: uint64(FrameStreamOpen), 1: uint64(4), 2: uint64(1), 3: uint64(1)})
			return append([]byte{0xa5}, append(append([]byte{}, b[1:]...), 0x20, 0x09)...)
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ValidateStreamPayload(tc.ft, tc.body); !errors.Is(err, ErrStreamMalformed) {
				t.Fatalf("%s: want ErrStreamMalformed, got err=%v", tc.name, err)
			}
		})
	}
}

func TestValidateStreamPayload_AcceptsUnknownNonNegKey(t *testing.T) {
	// §4.3 forward-compat: an unknown NON-negative integer key MUST be accepted (ignored).
	body := cborEncode(map[uint64]any{0: uint64(FrameStreamOpen), 1: uint64(4), 2: uint64(1), 3: uint64(1), 99: "future"})
	if _, err := ValidateStreamPayload(FrameStreamOpen, body); err != nil {
		t.Fatalf("unknown non-negative key rejected (violates forward-compat §4.3): %v", err)
	}
}

func TestDecodeStreamEnvelope(t *testing.T) {
	body := cborEncode(map[uint64]any{0: uint64(FrameStreamOpen), 1: uint64(6), 2: uint64(1), 3: uint64(1)})
	fk, ssid, err := DecodeStreamEnvelope(FrameStreamOpen, body)
	if err != nil {
		t.Fatalf("DecodeStreamEnvelope: %v", err)
	}
	if fk != uint64(FrameStreamOpen) {
		t.Fatalf("frame_kind = 0x%04X, want 0x0100", uint16(fk))
	}
	if ssid != 6 {
		t.Fatalf("sub_stream_id = %d, want 6", ssid)
	}
}
