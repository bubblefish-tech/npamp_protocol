package npamp

import (
	"errors"
	"fmt"
)

// NPAMP-STREAM operation-body validation — spec/companion/80_stream_channel.md §4-§5. A Stream
// frame payload is a deterministic-CBOR map (memory_cbor.go, shared codec). This file adds the
// per-frame field schemas and the structural validation the spec requires: the common envelope
// (§4.2 frame_kind + sub_stream_id), the required/typed body fields (§5), and the
// forward-compatibility rule (§4.3: ignore unknown non-negative keys, reject unknown negative keys).
// It reuses the generic cborKind / memField / checkFields helpers defined in memory_bodies.go.

// ErrStreamMalformed is returned for any structural fault a receiver answers with STREAM_RESET
// (StreamStateError, §5/§8): invalid deterministic CBOR, a payload that is not a map, a missing
// required field, a wrong CBOR major type, a frame_kind that contradicts the frame type, a
// sub_stream_id that is not an unsigned int, or an unknown negative / non-integer key.
var ErrStreamMalformed = errors.New("npamp/stream: malformed")

// streamSchemas holds the body-field schema at keys 2+ per Stream frame type (the common-envelope
// keys 0/1 are validated separately). Transcribed from spec/companion/80 §5.1-§5.5.
var streamSchemas = map[FrameType][]memField{
	FrameStreamOpen: { // §5.1
		{2, kUint, true}, {3, kUint, true}, {4, kText, false}, {5, kUint, false},
	},
	FrameStreamData: { // §5.2
		{2, kUint, true}, {3, kBytes, true}, {4, kUint, false},
	},
	FrameStreamClose:        {{2, kUint, true}},                 // §5.3
	FrameStreamReset:        {{2, kUint, true}, {3, kUint, true}}, // §5.4
	FrameStreamWindowUpdate: {{2, kUint, true}},                 // §5.5
}

// ValidateStreamPayload decodes and structurally validates a Stream frame payload for frame type ft.
// It returns the decoded map on success. On any structural fault it returns an error wrapping
// ErrStreamMalformed (§4-§5): the payload is not valid deterministic CBOR, is not a map, has a
// frame_kind (0) that contradicts ft, omits or mistypes sub_stream_id (1), omits a required field,
// carries a field of the wrong CBOR major type, or carries an unknown negative / non-integer key.
// Unknown non-negative keys are accepted and left in the returned map (forward compatibility, §4.3).
func ValidateStreamPayload(ft FrameType, payload []byte) (*cborMap, error) {
	schema, known := streamSchemas[ft]
	if !known {
		return nil, fmt.Errorf("%w: 0x%04X is not a Stream frame type", ErrStreamMalformed, uint16(ft))
	}
	v, err := cborDecodeTop(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStreamMalformed, err)
	}
	m, ok := v.(*cborMap)
	if !ok {
		return nil, fmt.Errorf("%w: payload is not a CBOR map", ErrStreamMalformed)
	}

	// Common envelope (§4.2): frame_kind (0) MUST equal ft; sub_stream_id (1) MUST be an unsigned
	// int (the correlation key — an Unsigned int, unlike NPAMP-MEMORY's byte-string corr).
	fk, ok := m.get(0)
	if !ok {
		return nil, fmt.Errorf("%w: missing frame_kind (0)", ErrStreamMalformed)
	}
	fkv, ok := fk.(uint64)
	if !ok {
		return nil, fmt.Errorf("%w: frame_kind (0) is not an unsigned int", ErrStreamMalformed)
	}
	if fkv != uint64(ft) {
		return nil, fmt.Errorf("%w: frame_kind 0x%04X contradicts frame type 0x%04X", ErrStreamMalformed, uint16(fkv), uint16(ft))
	}
	ssid, ok := m.get(1)
	if !ok {
		return nil, fmt.Errorf("%w: missing sub_stream_id (1)", ErrStreamMalformed)
	}
	if _, ok := ssid.(uint64); !ok {
		return nil, fmt.Errorf("%w: sub_stream_id (1) is not an unsigned int", ErrStreamMalformed)
	}

	if err := checkFields(m, schema, map[uint64]bool{0: true, 1: true}); err != nil {
		// checkFields reports via ErrMemoryMalformed (shared helper); re-wrap under ErrStreamMalformed
		// so callers get a consistent Stream error surface (the inner text is preserved for logs).
		return nil, fmt.Errorf("%w: %v", ErrStreamMalformed, err)
	}
	return m, nil
}
