package npamp

import (
	"bytes"
	"errors"
	"testing"
)

// DecodeMemoryBody is the inverse of EncodeMemoryBody: it validates a Memory body for a frame
// type and returns its fields as a map[uint64]any so a consumer (e.g. a daemon routing native
// memory frames) can read content/effect/etc. without reaching into unexported internals.

func TestDecodeMemoryBody_RoundTripsCreate(t *testing.T) {
	// A valid MEMORY_CREATE_REQ body: envelope frame_kind(0)+corr(1) + REQUIRED content(2,text)
	// + effect(11,uint), plus an optional metadata map(10) to exercise nested-map flattening.
	body := cborEncode(map[uint64]any{
		0:  uint64(FrameMemoryCreateReq),
		1:  []byte("corr-1"),
		2:  "remember this",
		10: map[uint64]any{0: "k", 1: "v"},
		11: uint64(EffectNonIdempotentWrite),
	})

	fields, err := DecodeMemoryBody(FrameMemoryCreateReq, body)
	if err != nil {
		t.Fatalf("DecodeMemoryBody: unexpected error: %v", err)
	}
	if got, ok := fields[2].(string); !ok || got != "remember this" {
		t.Fatalf("content (2): got %#v, want %q", fields[2], "remember this")
	}
	if got, ok := fields[11].(uint64); !ok || got != uint64(EffectNonIdempotentWrite) {
		t.Fatalf("effect (11): got %#v, want %d", fields[11], EffectNonIdempotentWrite)
	}
	if got, ok := fields[1].([]byte); !ok || !bytes.Equal(got, []byte("corr-1")) {
		t.Fatalf("corr (1): got %#v, want corr-1", fields[1])
	}
	// Nested metadata map(10) MUST flatten to a map[uint64]any, not leak an unexported *cborMap.
	meta, ok := fields[10].(map[uint64]any)
	if !ok {
		t.Fatalf("metadata (10): got %T, want map[uint64]any", fields[10])
	}
	if meta[0] != "k" || meta[1] != "v" {
		t.Fatalf("metadata (10): got %#v, want {0:k,1:v}", meta)
	}
}

func TestDecodeMemoryBody_RejectsMalformed(t *testing.T) {
	// Missing REQUIRED content(2): ValidateMemoryPayload rejects, so DecodeMemoryBody MUST error
	// (never return a partial map that a caller could mistake for a valid request).
	bad := cborEncode(map[uint64]any{
		0:  uint64(FrameMemoryCreateReq),
		1:  []byte("c"),
		11: uint64(2),
	})
	fields, err := DecodeMemoryBody(FrameMemoryCreateReq, bad)
	if !errors.Is(err, ErrMemoryMalformed) {
		t.Fatalf("DecodeMemoryBody(malformed): want ErrMemoryMalformed, got err=%v", err)
	}
	if fields != nil {
		t.Fatalf("DecodeMemoryBody(malformed): want nil map on error, got %#v", fields)
	}
}
