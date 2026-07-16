package npamp

// Exported NPAMP-CAP body codec surface for the conformance adapter (harness/adapters)
// and downstream consumers, mirroring the NPAMP-MEMORY surface (memory_api.go).

// DecodeCapabilityEnvelope validates a Capability body for frame type ft
// (spec/companion/84 §4: deterministic-CBOR map, envelope + per-frame required keys,
// forward-compat key rules) and returns the envelope's frame_kind (key 0) and corr
// (key 1). A non-nil error (wrapping ErrCapMalformed) means the body MUST be rejected
// (§4.1/§4.2/§4.3): not a deterministic-CBOR map, a frame_kind that contradicts ft, a
// corr that is not a non-empty 1–64 B byte string, a missing/mistyped required field,
// or an unknown negative key.
func DecodeCapabilityEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateCapabilityPayload(ft, body)
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

// DecodeCapabilityBody validates a Capability body for frame type ft (spec §4 —
// deterministic-CBOR map, envelope + per-frame required keys, forward-compat key
// rules) and returns its fields as a map[uint64]any: the inverse of EncodeCapabilityBody.
// Values are the Go-native CBOR types the codec produces — uint64, int64, []byte,
// string, []any, bool, nil, or map[uint64]any (nested maps are flattened recursively,
// never leaked as an unexported type). A non-nil error wraps ErrCapMalformed and means
// the body MUST be rejected (§4.1/§4.2/§4.3; §8 malformed_request); on error the
// returned map is nil.
func DecodeCapabilityBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateCapabilityPayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateCapabilityPayload only returns on a top-level CBOR map.
		return nil, ErrCapMalformed
	}
	return out, nil
}

// EncodeCapabilityBody canonically encodes a Capability operation body as deterministic
// CBOR (RFC 8949 §4.2.1; spec/companion/84 §4.1). Keys are unsigned integers; values
// may be uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested).
// The output is the one canonical form (shortest-form integers, canonically ordered
// keys, definite lengths). It is the inverse of the codec DecodeCapabilityEnvelope
// validates, used by producers and independent vector generators.
func EncodeCapabilityBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}
