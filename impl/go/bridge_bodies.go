package npamp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// NPAMP-BRIDGE payload codec + structural validation —
// spec/companion/10_bridge_framework.md §3–§8.
//
// A Bridge frame payload (the octets after the 36-octet N-PAMP header and before the
// AEAD tag) is a fixed-layout sequence (§3):
//
//	BridgeEnvelope TLV (Type 0x0010, REQUIRED, first)
//	SafetyLabel   TLV (Type 0x0013, OPTIONAL)
//	<foreign message>  (carried verbatim, §1)
//
// TLVs use the core extension-TLV encoding (Type u16, Length u16, Value; tlv.go). The
// foreign message is the octets following the final TLV. This file encodes and
// decodes that structure and enforces the §4/§5 MUST-reject rules. It does NOT parse
// or re-serialize the foreign message: the message is preserved octet-for-octet (§1
// Transparency), which the round-trip encode/decode here guarantees.

// ErrBridgeMalformed is returned for any structural fault a receiver reports as
// BRIDGE_ERROR code EnvelopeMalformed (§4, §6 code 1): the envelope is absent,
// truncated, or trailing-garbled; the message_kind contradicts the frame type (§4);
// a BRIDGE_REQUEST carries an empty correlation_id or a BRIDGE_NOTIFY a non-empty one
// (§5); or a present SafetyLabel TLV is malformed (§7).
var ErrBridgeMalformed = errors.New("npamp/bridge: envelope_malformed")

// BridgeEnvelope is the decoded §4 BridgeEnvelope value. Multi-octet integers are
// big-endian on the wire; every scalar here is a single octet. CorrelationID and
// Method are the raw variable-length fields (each length-prefixed by a u8 on the
// wire, so each is at most 255 octets).
type BridgeEnvelope struct {
	Protocol      BridgeProtocol    // protocol_id (§4)
	Kind          BridgeMessageKind // message_kind (§4; MUST agree with the frame type)
	ContentType   BridgeContentType // content_type (§4; foreign-message encoding)
	Flags         uint8             // flags (§4; bit 0 = final, bits 1–7 reserved/ignored)
	CorrelationID []byte            // correlation_id (§5); non-empty on request/reply, empty on notify
	Method        []byte            // method (§4; UTF-8 op name, e.g. "tools/call"); empty when not applicable
}

// Final reports whether the envelope's `final` flag (bit 0) is set (§4). Reserved
// bits 1–7 are ignored per §4, so only bit 0 is consulted.
func (e BridgeEnvelope) Final() bool { return e.Flags&BridgeFlagFinal != 0 }

// SafetyLabel is the decoded §7 SafetyLabel value.
type SafetyLabel struct {
	Effect BridgeEffect // effect (§7 side-effect class)
	Scope  []byte       // scope (§7; UTF-8 resource/scope hint, advisory); at most 255 octets
}

// BridgeFrame is a fully decoded Bridge payload: the required envelope, the optional
// SafetyLabel (nil when absent), and the foreign message carried verbatim (§1, §3).
type BridgeFrame struct {
	Envelope BridgeEnvelope
	Safety   *SafetyLabel // nil when no SafetyLabel TLV was present
	Foreign  []byte       // the foreign message, octet-for-octet (may be empty)
}

// EffectiveEffect applies the §7 fail-safe: when a SafetyLabel is present its effect
// governs; when it is ABSENT the effect MUST be treated as destructive (a receiver
// MUST NOT treat absence on a state-mutating operation as read_only). A caller uses
// this rather than reading Safety directly so the fail-safe cannot be forgotten.
func (f BridgeFrame) EffectiveEffect() BridgeEffect {
	if f.Safety == nil {
		return BridgeEffectDestructive
	}
	return f.Safety.Effect
}

// encodeEnvelopeValue encodes the §4 BridgeEnvelope value (the TLV Value, without the
// 4-octet TLV header). Layout: protocol_id, message_kind, content_type, flags,
// corr_len, correlation_id, method_len, method. It panics if CorrelationID or Method
// exceeds 255 octets, which the u8 length fields cannot represent.
func encodeEnvelopeValue(e BridgeEnvelope) []byte {
	if len(e.CorrelationID) > 255 {
		panic(fmt.Errorf("npamp/bridge: correlation_id %d octets exceeds u8 corr_len", len(e.CorrelationID)))
	}
	if len(e.Method) > 255 {
		panic(fmt.Errorf("npamp/bridge: method %d octets exceeds u8 method_len", len(e.Method)))
	}
	out := make([]byte, 0, 5+len(e.CorrelationID)+1+len(e.Method))
	out = append(out, byte(e.Protocol), byte(e.Kind), byte(e.ContentType), e.Flags, byte(len(e.CorrelationID)))
	out = append(out, e.CorrelationID...)
	out = append(out, byte(len(e.Method)))
	out = append(out, e.Method...)
	return out
}

// encodeSafetyValue encodes the §7 SafetyLabel value (effect, scope_len, scope). It
// panics if Scope exceeds 255 octets.
func encodeSafetyValue(s SafetyLabel) []byte {
	if len(s.Scope) > 255 {
		panic(fmt.Errorf("npamp/bridge: scope %d octets exceeds u8 scope_len", len(s.Scope)))
	}
	out := make([]byte, 0, 2+len(s.Scope))
	out = append(out, byte(s.Effect), byte(len(s.Scope)))
	out = append(out, s.Scope...)
	return out
}

// EncodeBridgeFrame encodes a BridgeFrame to its canonical wire payload (§3): the
// envelope TLV, the optional SafetyLabel TLV, then the foreign message verbatim. The
// layout is fully determined (fixed field order, definite lengths), so a decode
// followed by an EncodeBridgeFrame reproduces the exact input octets — the property
// the cross-validation test asserts against the independent oracle's bytes.
func EncodeBridgeFrame(f BridgeFrame) []byte {
	out := TLV{Type: TLVBridgeEnvelope, Value: encodeEnvelopeValue(f.Envelope)}.Encode(nil)
	if f.Safety != nil {
		out = TLV{Type: TLVSafetyLabel, Value: encodeSafetyValue(*f.Safety)}.Encode(out)
	}
	return append(out, f.Foreign...)
}

// decodeEnvelopeValue decodes a §4 BridgeEnvelope value and requires that it consumes
// the whole slice v (the declared TLV Value): trailing octets inside the envelope TLV
// are a malformation. It enforces the exact length arithmetic of the two u8-prefixed
// variable fields.
func decodeEnvelopeValue(v []byte) (BridgeEnvelope, error) {
	// Fixed head: protocol_id, message_kind, content_type, flags, corr_len (5 octets).
	if len(v) < 5 {
		return BridgeEnvelope{}, fmt.Errorf("%w: envelope value truncated before corr_len (%d < 5 octets)", ErrBridgeMalformed, len(v))
	}
	corrLen := int(v[4])
	// correlation_id (corr_len octets) then method_len (1 octet).
	if len(v) < 5+corrLen+1 {
		return BridgeEnvelope{}, fmt.Errorf("%w: envelope value truncated in correlation_id/method_len", ErrBridgeMalformed)
	}
	corr := v[5 : 5+corrLen]
	methodLen := int(v[5+corrLen])
	end := 5 + corrLen + 1 + methodLen
	if len(v) < end {
		return BridgeEnvelope{}, fmt.Errorf("%w: envelope value truncated in method", ErrBridgeMalformed)
	}
	if len(v) != end {
		return BridgeEnvelope{}, fmt.Errorf("%w: envelope value has %d trailing octet(s)", ErrBridgeMalformed, len(v)-end)
	}
	e := BridgeEnvelope{
		Protocol:    BridgeProtocol(v[0]),
		Kind:        BridgeMessageKind(v[1]),
		ContentType: BridgeContentType(v[2]),
		Flags:       v[3],
	}
	// Copy the variable fields out of the caller's buffer so the decoded frame does
	// not alias the input (the caller may reuse or mutate the payload slice).
	e.CorrelationID = append([]byte(nil), corr...)
	e.Method = append([]byte(nil), v[5+corrLen+1:end]...)
	return e, nil
}

// decodeSafetyValue decodes a §7 SafetyLabel value (effect, scope_len, scope) and
// requires exact consumption of the declared TLV Value.
func decodeSafetyValue(v []byte) (SafetyLabel, error) {
	if len(v) < 2 {
		return SafetyLabel{}, fmt.Errorf("%w: SafetyLabel value truncated before scope_len (%d < 2 octets)", ErrBridgeMalformed, len(v))
	}
	scopeLen := int(v[1])
	end := 2 + scopeLen
	if len(v) < end {
		return SafetyLabel{}, fmt.Errorf("%w: SafetyLabel value truncated in scope", ErrBridgeMalformed)
	}
	if len(v) != end {
		return SafetyLabel{}, fmt.Errorf("%w: SafetyLabel value has %d trailing octet(s)", ErrBridgeMalformed, len(v)-end)
	}
	return SafetyLabel{Effect: BridgeEffect(v[0]), Scope: append([]byte(nil), v[2:end]...)}, nil
}

// ValidateBridgePayload decodes and structurally validates a Bridge frame payload for
// frame type ft, returning the decoded BridgeFrame on success. On any structural
// fault it returns an error wrapping ErrBridgeMalformed (§4 / §6 EnvelopeMalformed):
//
//   - ft is not a Bridge frame type (§2);
//   - the payload does not begin with a BridgeEnvelope TLV (Type 0x0010), or that TLV
//     is truncated or trailing-garbled (§4 "envelope absent or truncated");
//   - message_kind does not agree with ft (§4);
//   - a BRIDGE_REQUEST or a reply frame carries an empty correlation_id, or a
//     BRIDGE_NOTIFY carries a non-empty one (§5, §8);
//   - a present SafetyLabel TLV is malformed (§7).
//
// The foreign message (the octets after the final TLV) is returned verbatim in
// BridgeFrame.Foreign and is never inspected. A missing SafetyLabel is NOT a
// structural fault here — its §7 fail-safe is applied by BridgeFrame.EffectiveEffect,
// because whether an operation is state-mutating is method-specific and known only to
// the responder, not to this wire decoder.
func ValidateBridgePayload(ft FrameType, payload []byte) (BridgeFrame, error) {
	wantKind, isBridge := BridgeKindForFrame(ft)
	if !isBridge {
		return BridgeFrame{}, fmt.Errorf("%w: 0x%04X is not a Bridge frame type", ErrBridgeMalformed, uint16(ft))
	}

	// §4: the envelope MUST be present as the first TLV. Need at least a 4-octet TLV
	// header to read its Type and Length.
	if len(payload) < 4 {
		return BridgeFrame{}, fmt.Errorf("%w: payload too short for a BridgeEnvelope TLV (%d < 4 octets)", ErrBridgeMalformed, len(payload))
	}
	envType := TLVType(binary.BigEndian.Uint16(payload[0:2]))
	envLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if envType != TLVBridgeEnvelope {
		return BridgeFrame{}, fmt.Errorf("%w: first TLV type 0x%04X is not BridgeEnvelope (0x0010)", ErrBridgeMalformed, uint16(envType))
	}
	if len(payload) < 4+envLen {
		return BridgeFrame{}, fmt.Errorf("%w: BridgeEnvelope TLV length %d exceeds remaining payload", ErrBridgeMalformed, envLen)
	}
	env, err := decodeEnvelopeValue(payload[4 : 4+envLen])
	if err != nil {
		return BridgeFrame{}, err
	}

	// §4: message_kind MUST agree with the frame type.
	if env.Kind != wantKind {
		return BridgeFrame{}, fmt.Errorf("%w: message_kind 0x%02X contradicts frame type 0x%04X (expected kind 0x%02X)",
			ErrBridgeMalformed, byte(env.Kind), uint16(ft), byte(wantKind))
	}

	// §5/§8: correlation_id presence rules keyed on the frame's role.
	switch {
	case ft == FrameBridgeNotify:
		if len(env.CorrelationID) != 0 {
			return BridgeFrame{}, fmt.Errorf("%w: BRIDGE_NOTIFY MUST set corr_len=0 (got %d, §5/§8)", ErrBridgeMalformed, len(env.CorrelationID))
		}
	case ft == FrameBridgeRequest:
		if len(env.CorrelationID) == 0 {
			return BridgeFrame{}, fmt.Errorf("%w: BRIDGE_REQUEST MUST carry a non-empty correlation_id (§5)", ErrBridgeMalformed)
		}
	default: // reply frames (RESPONSE, ERROR, STREAM_DATA, STREAM_END)
		// §5: a reply MUST echo the originating request's correlation_id verbatim;
		// since a request's id is non-empty, an empty id on a reply cannot echo one.
		if len(env.CorrelationID) == 0 {
			return BridgeFrame{}, fmt.Errorf("%w: a reply frame MUST echo the request's non-empty correlation_id (§5)", ErrBridgeMalformed)
		}
	}

	// §3/§7: an OPTIONAL SafetyLabel TLV may immediately follow the envelope; the
	// octets after it (or after the envelope, if none) are the foreign message.
	rest := payload[4+envLen:]
	var safety *SafetyLabel
	if len(rest) >= 4 && TLVType(binary.BigEndian.Uint16(rest[0:2])) == TLVSafetyLabel {
		sLen := int(binary.BigEndian.Uint16(rest[2:4]))
		if len(rest) < 4+sLen {
			return BridgeFrame{}, fmt.Errorf("%w: SafetyLabel TLV length %d exceeds remaining payload", ErrBridgeMalformed, sLen)
		}
		s, serr := decodeSafetyValue(rest[4 : 4+sLen])
		if serr != nil {
			return BridgeFrame{}, serr
		}
		safety = &s
		rest = rest[4+sLen:]
	}

	return BridgeFrame{
		Envelope: env,
		Safety:   safety,
		Foreign:  append([]byte(nil), rest...),
	}, nil
}

// CorrelateBridgeReply reports whether a decoded reply envelope correlates to a
// decoded request envelope (§5): the reply's correlation_id MUST equal the request's
// verbatim, and correlation is by identifier, NOT by frame sequence number. It
// returns false when either identifier is empty (an empty id never correlates).
func CorrelateBridgeReply(request, reply BridgeEnvelope) bool {
	if len(request.CorrelationID) == 0 || len(reply.CorrelationID) == 0 {
		return false
	}
	return bytes.Equal(request.CorrelationID, reply.CorrelationID)
}
