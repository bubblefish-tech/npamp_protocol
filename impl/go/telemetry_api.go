package npamp

// Exported NPAMP-TELEMETRY body codec surface for the conformance adapter (harness/adapters) and
// downstream consumers, mirroring the NPAMP-MEMORY (memory_api.go) and NPAMP-STREAM (stream_api.go)
// surfaces. These wrap the shared deterministic-CBOR codec (memory_cbor.go) and the Telemetry body
// validator (telemetry_bodies.go).

// DecodeTelemetryEnvelope validates a Telemetry body for frame type ft (spec/companion/87 §4:
// deterministic-CBOR map, envelope + per-frame required keys, forward-compat key rules) and returns
// the envelope's frame_kind (key 0) and corr (key 1). corr is returned nil for a standalone
// (unsolicited) TELEMETRY_REPORT, which omits it (§4.1, §5). A non-nil error (wrapping
// ErrTelemetryMalformed) means the body MUST be rejected (§4-§8): not a deterministic-CBOR map, a
// frame_kind that contradicts ft, a corr present/absent in violation of §4.1/§5, a missing/mistyped
// required field, a TELEMETRY_REPORT with no content, or an unknown negative key.
func DecodeTelemetryEnvelope(ft FrameType, body []byte) (frameKind uint64, corr []byte, err error) {
	m, e := ValidateTelemetryPayload(ft, body)
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

// DecodeTelemetryBody validates a Telemetry body for frame type ft (spec §4-§8) and returns its fields
// as a map[uint64]any: the inverse of EncodeTelemetryBody. Values are the Go-native CBOR types the
// shared codec produces — uint64, int64, []byte, string, []any, bool, nil, or map[uint64]any (nested
// maps whose keys are unsigned integers are rewritten recursively; a nested map key that is not an
// unsigned integer is dropped by the conversion, so this form is used for round-trip cross-validation
// of bodies whose nested maps are unsigned-int-keyed). A non-nil error wraps ErrTelemetryMalformed and
// means the body MUST be rejected; on error the returned map is nil.
func DecodeTelemetryBody(ft FrameType, body []byte) (map[uint64]any, error) {
	m, err := ValidateTelemetryPayload(ft, body)
	if err != nil {
		return nil, err
	}
	out, ok := cborToGo(m).(map[uint64]any)
	if !ok {
		// Unreachable: ValidateTelemetryPayload only returns on a top-level CBOR map.
		return nil, ErrTelemetryMalformed
	}
	return out, nil
}

// EncodeTelemetryBody canonically encodes a Telemetry operation body as deterministic CBOR (RFC 8949
// §4.2.1; spec/companion/87 §4). Keys are unsigned integers; values may be uint64, int64, []byte,
// string, []any, bool, nil, or map[uint64]any (nested). The output is the one canonical form
// (shortest-form integers, canonically ordered keys, definite lengths) — the inverse of the codec
// DecodeTelemetryBody validates, used by producers and by the independent-oracle cross-validation test.
func EncodeTelemetryBody(fields map[uint64]any) []byte {
	return cborEncode(fields)
}
