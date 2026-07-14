package npamp

// Exported NPAMP-STREAM body codec surface for the conformance adapter (harness/adapters) and
// downstream consumers, mirroring the NPAMP-MEMORY surface (memory_api.go).

// DecodeStreamEnvelope validates a Stream body for frame type ft (spec/companion/80 §4: deterministic
// -CBOR map, envelope + per-frame required keys, forward-compat key rules) and returns the envelope's
// frame_kind (key 0) and sub_stream_id (key 1). A non-nil error (wrapping ErrStreamMalformed) means
// the body MUST be rejected (§4/§5): not a deterministic-CBOR map, a frame_kind that contradicts ft,
// a sub_stream_id that is not an unsigned int, a missing/mistyped required field, or an unknown
// negative key.
func DecodeStreamEnvelope(ft FrameType, body []byte) (frameKind, subStreamID uint64, err error) {
	m, e := ValidateStreamPayload(ft, body)
	if e != nil {
		return 0, 0, e
	}
	if fk, ok := m.get(0); ok {
		if u, ok2 := fk.(uint64); ok2 {
			frameKind = u
		}
	}
	if s, ok := m.get(1); ok {
		if u, ok2 := s.(uint64); ok2 {
			subStreamID = u
		}
	}
	return frameKind, subStreamID, nil
}

// EncodeStreamBody canonically encodes a Stream frame body as deterministic CBOR (RFC 8949 §4.2.1;
// spec/companion/80 §4.1). Keys are unsigned integers; values may be uint64, int64, []byte, string,
// []any, bool, nil, or map[uint64]any (nested). It is the inverse of the codec DecodeStreamEnvelope
// validates, used by producers and independent vector generators.
func EncodeStreamBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}
