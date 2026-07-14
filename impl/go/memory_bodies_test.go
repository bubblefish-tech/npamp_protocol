package npamp

import (
	"errors"
	"testing"
)

// rawMap encodes a CBOR map from key/value pairs given ALREADY in canonical key
// order — used to construct payloads (including ones with negative keys) that the
// key-only cborEncode(map[uint64]any) helper cannot express.
func rawMap(pairs ...[2]any) []byte {
	out := encodeHead(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, cborEncode(p[0])...)
		out = append(out, cborEncode(p[1])...)
	}
	return out
}

func kv(k uint64, v any) [2]any { return [2]any{k, v} }

func TestValidateMemoryPayload_GoodCreate(t *testing.T) {
	// A valid MEMORY_CREATE_REQ: envelope + required content(2) + effect(11).
	body := cborEncode(map[uint64]any{
		0:  uint64(FrameMemoryCreateReq),
		1:  []byte("corr-1"),
		2:  "remember this",
		11: uint64(EffectNonIdempotentWrite),
	})
	if _, err := ValidateMemoryPayload(FrameMemoryCreateReq, body); err != nil {
		t.Fatalf("valid create rejected: %v", err)
	}
}

func TestValidateMemoryPayload_Rejects(t *testing.T) {
	good := func(extra map[uint64]any) []byte {
		m := map[uint64]any{0: uint64(FrameMemoryCreateReq), 1: []byte("c"), 2: "x", 11: uint64(2)}
		for k, v := range extra {
			m[k] = v
		}
		return cborEncode(m)
	}
	cases := []struct {
		name    string
		ft      FrameType
		payload []byte
	}{
		{"not_a_map", FrameMemoryCreateReq, cborEncode(uint64(5))},
		{"frame_kind_mismatch", FrameMemoryCreateReq, cborEncode(map[uint64]any{0: uint64(FrameMemoryReadReq), 1: []byte("c"), 2: "x", 11: uint64(2)})},
		{"missing_frame_kind", FrameMemoryCreateReq, cborEncode(map[uint64]any{1: []byte("c"), 2: "x", 11: uint64(2)})},
		{"missing_corr", FrameMemoryCreateReq, cborEncode(map[uint64]any{0: uint64(FrameMemoryCreateReq), 2: "x", 11: uint64(2)})},
		{"empty_corr", FrameMemoryCreateReq, cborEncode(map[uint64]any{0: uint64(FrameMemoryCreateReq), 1: []byte{}, 2: "x", 11: uint64(2)})},
		{"missing_required_content", FrameMemoryCreateReq, cborEncode(map[uint64]any{0: uint64(FrameMemoryCreateReq), 1: []byte("c"), 11: uint64(2)})},
		{"missing_required_effect", FrameMemoryCreateReq, cborEncode(map[uint64]any{0: uint64(FrameMemoryCreateReq), 1: []byte("c"), 2: "x"})},
		{"wrong_type_content", FrameMemoryCreateReq, cborEncode(map[uint64]any{0: uint64(FrameMemoryCreateReq), 1: []byte("c"), 2: uint64(9), 11: uint64(2)})},
		{"not_a_memory_frame", FramePing, good(nil)},
		{"non_deterministic_cbor", FrameMemoryCreateReq, []byte{0xa1, 0x18, 0x00, 0x00}}, // non-shortest key
		// unknown NEGATIVE key on an otherwise-valid READ_REQ (§4.3 reject).
		{"unknown_negative_key", FrameMemoryReadReq, rawMap(
			kv(0, uint64(FrameMemoryReadReq)), kv(1, []byte("c")), kv(2, "rid"), kv(3, uint64(0)),
			[2]any{int64(-1), uint64(9)},
		)},
	}
	for _, c := range cases {
		_, err := ValidateMemoryPayload(c.ft, c.payload)
		if !errors.Is(err, ErrMemoryMalformed) {
			t.Errorf("%s: err = %v, want ErrMemoryMalformed", c.name, err)
		}
	}
}

func TestValidateMemoryPayload_ForwardCompatAcceptsUnknownNonNegKey(t *testing.T) {
	// An unknown NON-negative key (99) on a valid create MUST be accepted (§4.3).
	body := rawMap(
		kv(0, uint64(FrameMemoryCreateReq)), kv(1, []byte("c")), kv(2, "x"),
		kv(11, uint64(2)), kv(99, "future-field"),
	)
	if _, err := ValidateMemoryPayload(FrameMemoryCreateReq, body); err != nil {
		t.Errorf("unknown non-negative key rejected, want accepted: %v", err)
	}
}

func TestValidateMemoryRecord(t *testing.T) {
	rec := cborEncode(map[uint64]any{0: "rid", 1: "content", 2: "src", 6: "2026-07-13T00:00:00Z"})
	dv, err := cborDecodeTop(rec)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := ValidateMemoryRecord(dv.(*cborMap)); err != nil {
		t.Errorf("valid memory_record rejected: %v", err)
	}
	// Missing required content (1).
	bad := cborEncode(map[uint64]any{0: "rid", 2: "src"})
	dv2, _ := cborDecodeTop(bad)
	if err := ValidateMemoryRecord(dv2.(*cborMap)); !errors.Is(err, ErrMemoryMalformed) {
		t.Errorf("record missing content accepted, want rejected")
	}
}
