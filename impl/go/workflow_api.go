package npamp

// Exported NPAMP-WORKFLOW body codec surface for the conformance adapter (harness/adapters) and
// downstream consumers, mirroring the NPAMP-MEMORY (memory_api.go) and NPAMP-STREAM (stream_api.go)
// surfaces.

// DecodeWorkflowEnvelope validates a Workflow body for frame type ft (spec/companion/8a §4:
// deterministic-CBOR map, envelope + per-frame required keys, forward-compat key rules) and returns
// the envelope's frame_kind (key 0) and corr (key 1). A non-nil error (wrapping ErrWorkflowMalformed)
// means the body MUST be rejected (§4/§6/§8): not a deterministic-CBOR map, a frame_kind that
// contradicts ft, a corr that is absent or not a byte string on a corr-bearing frame, a missing/
// mistyped required field, or an unknown negative key. For WORKFLOW_STEP_EVENT (0x0106) and
// WORKFLOW_COMPLETE (0x0107) — which carry NO corr (§4.2, §5.2) — corr is returned nil.
func DecodeWorkflowEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateWorkflowPayload(ft, body)
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

// DecodeWorkflowBody validates a Workflow body for frame type ft (spec §4 — deterministic-CBOR map,
// envelope + per-frame required keys, forward-compat key rules) and returns its fields as a
// map[uint64]any: the inverse of EncodeWorkflowBody. Values are the Go-native CBOR types the codec
// produces — uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested maps are
// flattened recursively, never leaked as an unexported type). A non-nil error wraps
// ErrWorkflowMalformed and means the body MUST be rejected (§4/§6/§8 malformed_request); on error the
// returned map is nil.
func DecodeWorkflowBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateWorkflowPayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateWorkflowPayload only returns on a top-level CBOR map.
		return nil, ErrWorkflowMalformed
	}
	return out, nil
}

// EncodeWorkflowBody canonically encodes a Workflow frame body as deterministic CBOR (RFC 8949
// §4.2.1; spec/companion/8a §4.1). Keys are unsigned integers; values may be uint64, int64, []byte,
// string, []any, bool, nil, or map[uint64]any (nested). It is the inverse of the codec
// DecodeWorkflowBody validates, used by producers and independent vector generators; the output is
// the one canonical form (shortest-form integers, canonically ordered keys, definite lengths).
func EncodeWorkflowBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}
