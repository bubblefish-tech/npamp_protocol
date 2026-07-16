package npamp

// Exported NPAMP-INTERACT body codec surface for the conformance adapter (harness/adapters/go) and
// downstream consumers, mirroring the NPAMP-MEMORY surface (memory_api.go). These wrap the internal
// deterministic-CBOR codec (memory_cbor.go, shared) and the body validator (interaction_bodies.go) so
// a separate package can encode/validate NPAMP-INTERACT bodies without reaching into unexported
// internals.

// EncodeInteractionBody canonically encodes an Interaction operation body as deterministic CBOR
// (RFC 8949 §4.2.1; spec/companion/89_interaction_channel.md §4.1). Keys are unsigned integers;
// values may be uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested). The
// output is the one canonical form (shortest-form integers, canonically ordered keys, definite
// lengths). It is the inverse of the codec DecodeInteractionBody validates.
func EncodeInteractionBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}

// DecodeInteractionEnvelope validates an Interaction body for frame type ft (spec/companion/89 §4:
// deterministic-CBOR map, envelope + per-frame required keys, forward-compat key rules) and returns
// the envelope's frame_kind (key 0) and corr (key 1). A non-nil error (wrapping
// ErrInteractionMalformed) means the body MUST be rejected (§4.1/§4.2/§4.3): not a deterministic-CBOR
// map, missing a REQUIRED key, a key of the wrong CBOR major type, a frame_kind that contradicts ft,
// a corr that is not a 1–64-byte byte string, or an unknown negative key.
func DecodeInteractionEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateInteractionPayload(ft, body)
	if e != nil {
		return 0, nil, e
	}
	if fk, ok := m.get(0); ok {
		if u, ok2 := fk.(uint64); ok2 {
			frameKind = u
		}
	}
	if c, ok := m.get(1); ok {
		if b, ok2 := c.([]byte); ok2 {
			corr = b
		}
	}
	return frameKind, corr, nil
}

// DecodeInteractionBody validates an Interaction body for frame type ft (spec §4 — deterministic-CBOR
// map, envelope + per-frame required keys, forward-compat key rules) and returns its fields as a
// map[uint64]any: the inverse of EncodeInteractionBody. Values are the Go-native CBOR types the codec
// produces — uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested maps are
// flattened recursively via cborToGo, never leaked as an unexported type). A non-nil error wraps
// ErrInteractionMalformed and means the body MUST be rejected (§4.1/§4.2/§4.3; §8 malformed_request);
// on error the returned map is nil.
func DecodeInteractionBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateInteractionPayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateInteractionPayload only returns on a top-level CBOR map.
		return nil, ErrInteractionMalformed
	}
	return out, nil
}
