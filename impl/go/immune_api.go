package npamp

// Exported NPAMP-IMMUNE body codec surface for the conformance adapter
// (harness/adapters/go) and downstream consumers, mirroring the NPAMP-MEMORY
// (memory_api.go) and NPAMP-STREAM (stream_api.go) surfaces.

// DecodeImmuneEnvelope validates an Immune body for frame type ft
// (spec/companion/85 §4: deterministic-CBOR map, envelope + per-frame required keys,
// nested gossip-descriptor/item required keys, forward-compat key rules) and returns
// the envelope's frame_kind (key 0) and corr (key 1). A non-nil error (wrapping
// ErrImmuneMalformed) means the body MUST be rejected (§4/§6/§8): not a
// deterministic-CBOR map, a frame_kind that contradicts ft, a corr that is not a
// non-empty 1–64-byte byte string, a missing/mistyped required field, a malformed
// nested descriptor/item, or an unknown negative key.
func DecodeImmuneEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateImmunePayload(ft, body)
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

// DecodeImmuneBody validates an Immune body for frame type ft (spec §4/§6/§8 —
// deterministic-CBOR map, envelope + per-frame required keys, nested
// descriptor/item required keys, forward-compat key rules) and returns its fields as
// a map[uint64]any: the inverse of EncodeImmuneBody. Values are the Go-native CBOR
// types the codec produces — uint64, int64, []byte, string, []any, bool, nil, or
// map[uint64]any (nested maps are flattened recursively, never leaked as an
// unexported type). A non-nil error wraps ErrImmuneMalformed and means the body MUST
// be rejected (§4/§6/§8 malformed_request); on error the returned map is nil.
func DecodeImmuneBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateImmunePayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateImmunePayload only returns on a top-level CBOR map.
		return nil, ErrImmuneMalformed
	}
	return out, nil
}

// EncodeImmuneBody canonically encodes an Immune operation body as deterministic CBOR
// (RFC 8949 §4.2.1; spec/companion/85 §4.1). Keys are unsigned integers; values may
// be uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested, for
// gossip descriptors/items). The output is the one canonical form (shortest-form
// integers, canonically ordered keys, definite lengths) — the inverse of the codec
// DecodeImmuneEnvelope validates, used by producers and independent vector generators.
func EncodeImmuneBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}
