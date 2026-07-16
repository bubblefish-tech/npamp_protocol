package npamp

import "fmt"

// Exported NPAMP-BRIDGE codec surface for the conformance adapter (harness/adapters/
// go) and downstream consumers — spec/companion/10_bridge_framework.md §3–§8. These
// wrap the payload codec and validator (bridge_bodies.go) so a separate package can
// build and parse Bridge payloads without reaching into unexported internals, mirror-
// ing the EncodeMemoryBody / DecodeMemoryEnvelope surface of the native channels.

// EncodeBridgePayload builds a canonical Bridge frame payload (§3): a BridgeEnvelope
// TLV, an OPTIONAL SafetyLabel TLV (encoded iff safety is non-nil), then the foreign
// message carried verbatim (§1). The layout is fully determined, so DecodeBridgeFrame
// followed by EncodeBridgePayload reproduces the exact input octets. Pass a nil
// safety to omit the SafetyLabel TLV; pass an empty (non-nil) foreign for a payload
// with no foreign body.
func EncodeBridgePayload(env BridgeEnvelope, safety *SafetyLabel, foreign []byte) []byte {
	return EncodeBridgeFrame(BridgeFrame{Envelope: env, Safety: safety, Foreign: foreign})
}

// DecodeBridgeFrame validates a Bridge payload for frame type ft (§4/§5/§7) and
// returns the decoded BridgeFrame: the envelope, the optional SafetyLabel (nil when
// absent), and the foreign message verbatim. A non-nil error wraps ErrBridgeMalformed
// and means the frame MUST be rejected with BRIDGE_ERROR code EnvelopeMalformed (§6).
func DecodeBridgeFrame(ft FrameType, payload []byte) (BridgeFrame, error) {
	return ValidateBridgePayload(ft, payload)
}

// DecodeBridgeEnvelope validates a Bridge payload for frame type ft and returns just
// the decoded envelope (§4) — the protocol, message_kind, content_type, flags,
// correlation_id, and method — discarding the SafetyLabel and foreign message. A
// non-nil error means the frame MUST be rejected (§6 EnvelopeMalformed).
func DecodeBridgeEnvelope(ft FrameType, payload []byte) (BridgeEnvelope, error) {
	f, err := ValidateBridgePayload(ft, payload)
	if err != nil {
		return BridgeEnvelope{}, err
	}
	return f.Envelope, nil
}

// BridgeTransportError is a §6 below-foreign-protocol failure: the request did not
// reach the foreign endpoint, so a BRIDGE_ERROR carries this N-PAMP transport error
// in place of a foreign message. The Code is drawn from the §6 registry (1–5); the
// Message is an OPTIONAL human-readable string. A failure WITHIN the foreign protocol
// is NOT one of these — it is reported by carrying the foreign protocol's own error
// object verbatim (§6 first paragraph), which the codec preserves as BridgeFrame.
// Foreign and never reduces to text.
type BridgeTransportError struct {
	Code    BridgeErrorCode
	Message string
}

// EncodeBridgeTransportError encodes a §6 transport-error object for the foreign-
// message slot of a BRIDGE_ERROR frame as: code (u8), msg_len (u8), msg (UTF-8).
//
// The §6 table defines the transport-error CODE REGISTRY (1–5) normatively; it does
// not fix the octet layout of the transport-error object itself. This function uses
// the minimal deterministic layout above so the below-protocol error is machine-
// readable; a protocol mapping that builds on this document MAY specify a richer
// object. It panics if Message exceeds 255 octets (the u8 msg_len cannot represent it).
func EncodeBridgeTransportError(te BridgeTransportError) []byte {
	msg := []byte(te.Message)
	if len(msg) > 255 {
		panic(fmt.Errorf("npamp/bridge: transport-error message %d octets exceeds u8 msg_len", len(msg)))
	}
	out := make([]byte, 0, 2+len(msg))
	out = append(out, byte(te.Code), byte(len(msg)))
	return append(out, msg...)
}

// DecodeBridgeTransportError decodes the transport-error object produced by
// EncodeBridgeTransportError. It returns an error wrapping ErrBridgeMalformed if the
// object is truncated or trailing-garbled. Use it only on the foreign slot of a
// BRIDGE_ERROR whose failure is below the foreign protocol; a foreign-protocol error
// object is opaque and MUST be surfaced verbatim, not decoded here.
func DecodeBridgeTransportError(b []byte) (BridgeTransportError, error) {
	if len(b) < 2 {
		return BridgeTransportError{}, fmt.Errorf("%w: transport-error truncated before msg_len (%d < 2 octets)", ErrBridgeMalformed, len(b))
	}
	msgLen := int(b[1])
	end := 2 + msgLen
	if len(b) != end {
		return BridgeTransportError{}, fmt.Errorf("%w: transport-error length mismatch (declared %d, have %d)", ErrBridgeMalformed, end, len(b))
	}
	return BridgeTransportError{Code: BridgeErrorCode(b[0]), Message: string(b[2:end])}, nil
}
