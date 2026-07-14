package npamp

// Exported Memory body codec surface for the conformance adapter (harness/adapters/go) and
// downstream consumers. These wrap the internal deterministic-CBOR codec (memory_cbor.go) and the
// body validator (memory_bodies.go) so a separate package can encode/validate NPAMP-MEMORY bodies
// without reaching into unexported internals.

// EncodeMemoryBody canonically encodes a Memory operation body as deterministic CBOR (RFC 8949
// §4.2.1; spec/companion/81_memory_channel.md §4.1). Keys are unsigned integers; values may be
// uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested). The output is the one
// canonical form (shortest-form integers, canonically ordered keys, definite lengths).
func EncodeMemoryBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}

// DecodeMemoryEnvelope validates a Memory body for frame type ft (spec §4: deterministic-CBOR map,
// envelope + per-frame required keys, forward-compat key rules) and returns the envelope's
// frame_kind (key 0) and corr (key 1). A non-nil error means the body MUST be rejected (§4.1/§4.2/
// §4.3): not a deterministic-CBOR map, missing a REQUIRED key, a key of the wrong CBOR major type,
// a frame_kind that contradicts ft, or an unknown negative key.
func DecodeMemoryEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateMemoryPayload(ft, body)
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

// DecodeMemoryBody validates a Memory body for frame type ft (spec §4 — deterministic-CBOR map,
// envelope + per-frame required keys, forward-compat key rules) and returns its fields as a
// map[uint64]any: the inverse of EncodeMemoryBody. Values are the Go-native CBOR types the codec
// produces — uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested maps are
// flattened recursively, never leaked as an unexported type). A non-nil error wraps
// ErrMemoryMalformed and means the body MUST be rejected (§4.1/§4.2/§4.3; §8 malformed_request);
// on error the returned map is nil.
func DecodeMemoryBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateMemoryPayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateMemoryPayload only returns on a top-level CBOR map.
		return nil, ErrMemoryMalformed
	}
	return out, nil
}

// cborToGo converts a decoded CBOR value into portable Go types, recursively rewriting the
// unexported *cborMap into map[uint64]any (every NPAMP-MEMORY map key is an unsigned integer after
// validation) and descending into arrays. Scalars (uint64, int64, []byte, string, bool, nil) pass
// through unchanged.
func cborToGo(v any) any {
	switch t := v.(type) {
	case *cborMap:
		out := make(map[uint64]any, len(t.entries))
		for _, e := range t.entries {
			if uk, ok := e.key.(uint64); ok {
				out[uk] = cborToGo(e.val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, el := range t {
			out[i] = cborToGo(el)
		}
		return out
	default:
		return v
	}
}
