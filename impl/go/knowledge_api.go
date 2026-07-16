package npamp

// Exported NPAMP-KNOWLEDGE body codec surface for the conformance adapter
// (harness/adapters) and downstream consumers, mirroring the NPAMP-MEMORY
// (memory_api.go) and NPAMP-STREAM (stream_api.go) surfaces.

// DecodeKnowledgeEnvelope validates a Knowledge body for frame type ft
// (spec/companion/8b §4: deterministic-CBOR map, envelope + per-frame required keys,
// forward-compat key rules, §6.5 update-results-or-removed) and returns the
// envelope's frame_kind (key 0) and corr (key 1). A non-nil error (wrapping
// ErrKnowledgeMalformed) means the body MUST be rejected (§4/§6/§9): not a
// deterministic-CBOR map, a frame_kind that contradicts ft, a corr that is not a
// 1–64-byte byte string, a missing/mistyped required field, an unknown negative key,
// or a KNOWLEDGE_UPDATE with neither results nor removed.
func DecodeKnowledgeEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateKnowledgePayload(ft, body)
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

// DecodeKnowledgeBody validates a Knowledge body for frame type ft (spec §4/§6/§9 —
// deterministic-CBOR map, envelope + per-frame required keys, forward-compat key
// rules, §6.5 update-results-or-removed) and returns its fields as a map[uint64]any:
// the inverse of EncodeKnowledgeBody. Values are the Go-native CBOR types the codec
// produces — uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any
// (nested maps such as a knowledge_result are flattened recursively, never leaked as
// an unexported type). A non-nil error wraps ErrKnowledgeMalformed and means the body
// MUST be rejected; on error the returned map is nil.
func DecodeKnowledgeBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateKnowledgePayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateKnowledgePayload only returns on a top-level CBOR map.
		return nil, ErrKnowledgeMalformed
	}
	return out, nil
}

// EncodeKnowledgeBody canonically encodes a Knowledge frame body as deterministic
// CBOR (RFC 8949 §4.2.1; spec/companion/8b §4.1). Keys are unsigned integers; values
// may be uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested,
// e.g. a knowledge_result). It is the inverse of the codec DecodeKnowledgeBody
// validates, used by producers and by the independent vector cross-validation test.
func EncodeKnowledgeBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}
