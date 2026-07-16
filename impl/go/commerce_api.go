package npamp

// Exported NPAMP-COMMERCE body codec surface for the conformance adapter (harness/adapters/go) and
// downstream consumers, mirroring the NPAMP-MEMORY surface (memory_api.go). These wrap the shared
// deterministic-CBOR codec (memory_cbor.go) and the Commerce body validator (commerce_bodies.go) so a
// separate package can encode/validate NPAMP-COMMERCE bodies without reaching into unexported internals.

// EncodeCommerceBody canonically encodes a Commerce operation body as deterministic CBOR (RFC 8949
// §4.2.1; spec/companion/88_commerce_channel.md §4.1). Keys are unsigned integers; values may be
// uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested — e.g. a §4.3 amount or
// a §6.6 leg). The output is the one canonical form (shortest-form integers, canonically ordered
// keys, definite lengths). It is the inverse of the codec DecodeCommerceBody validates.
func EncodeCommerceBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}

// DecodeCommerceEnvelope validates a Commerce body for frame type ft (spec §4: deterministic-CBOR map,
// envelope + per-frame required keys, §4.3 amount + §6.6 leg-party rules, forward-compat key rules)
// and returns the envelope's frame_kind (key 0) and corr (key 1). A non-nil error (wrapping
// ErrCommerceMalformed) means the body MUST be rejected (§4.1/§4.2/§4.3/§4.4/§6.6): not a
// deterministic-CBOR map, a frame_kind that contradicts ft, a corr that is not a 1–64-byte byte
// string, a missing/mistyped REQUIRED key, a malformed amount, a leg party not in `parties`, or an
// unknown negative key.
func DecodeCommerceEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateCommercePayload(ft, body)
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

// DecodeCommerceBody validates a Commerce body for frame type ft (spec §4 — deterministic-CBOR map,
// envelope + per-frame required keys, §4.3 amount + §6.6 leg-party rules, forward-compat key rules)
// and returns its fields as a map[uint64]any: the inverse of EncodeCommerceBody. Values are the
// Go-native CBOR types the codec produces — uint64, int64, []byte, string, []any, bool, nil, or
// map[uint64]any (nested maps such as a §4.3 amount or a §6.6 leg are flattened recursively, never
// leaked as an unexported type). A non-nil error wraps ErrCommerceMalformed and means the body MUST
// be rejected (§8 malformed_request); on error the returned map is nil.
func DecodeCommerceBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateCommercePayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateCommercePayload only returns on a top-level CBOR map.
		return nil, ErrCommerceMalformed
	}
	return out, nil
}
