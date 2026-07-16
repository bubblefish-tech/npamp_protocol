package npamp

// NPAMP-BRIDGE frame types, code points, and predicates —
// spec/companion/10_bridge_framework.md §2, §4, §6, §7.
//
// The Bridge channel (0x000D, ChanBridge) carries a FOREIGN agentic protocol (for
// example MCP or A2A) octet-for-octet (§1 Transparency), gaining N-PAMP's transport,
// multiplexing, and key schedule. Unlike the native operation channels (Memory,
// Settlement, Stream, …) whose frame bodies are deterministic-CBOR maps, a Bridge
// frame payload is a fixed-layout TLV envelope carried AROUND the foreign message:
//
//	BridgeEnvelope TLV (Type 0x0010, REQUIRED)  — §4, routing/correlation/method
//	SafetyLabel   TLV (Type 0x0013, OPTIONAL)   — §7, side-effect class + scope hint
//	<foreign message>                           — §1, carried verbatim, never modified
//
// The envelope byte layout and MUST-reject rules live in bridge_bodies.go; the
// exported codec surface and the structured transport error live in bridge_api.go.
//
// These frame-type values live in the per-channel application band (0x0100+); they
// carry their NPAMP-BRIDGE meaning ONLY on the Bridge channel (draft-02 §4.6,
// per-channel frame-type namespace), so a value here may coincide numerically with a
// frame type of another channel. The reserved all-channel frame types (PING 0x0001,
// CLOSE 0x0003, ERROR 0x0005, KEY_UPDATE 0x0006, …) retain their core meaning on the
// Bridge channel and MUST NOT be reused for application traffic (§2).

const (
	// FrameBridgeRequest is a foreign request that expects a reply (RESPONSE or
	// ERROR). It MUST carry a non-empty correlation_id (§5).
	FrameBridgeRequest FrameType = 0x0100
	// FrameBridgeResponse is a successful reply; correlation echoes the request (§5).
	FrameBridgeResponse FrameType = 0x0101
	// FrameBridgeError is a failed reply; it carries the foreign protocol's own error
	// object verbatim, or an N-PAMP transport error below the foreign protocol (§6).
	FrameBridgeError FrameType = 0x0102
	// FrameBridgeNotify is a one-way message; no reply is expected or permitted, and
	// corr_len MUST be 0 (§5, §8).
	FrameBridgeNotify FrameType = 0x0103
	// FrameBridgeStreamData is one chunk of a streamed reply; correlation echoes the
	// request (§2, §5).
	FrameBridgeStreamData FrameType = 0x0104
	// FrameBridgeStreamEnd terminates a stream; the envelope `final` flag is set (§2).
	FrameBridgeStreamEnd FrameType = 0x0105
)

// TLV extension types defined by NPAMP-BRIDGE within the Bridge-channel payload
// (§3), encoded with the core extension-TLV encoding (Type u16, Length u16, Value;
// tlv.go). These are payload-layer TLVs, distinct in role from the handshake/
// connection TLVs in tlv.go although they share the u16 TLVType space.
const (
	// TLVBridgeEnvelope carries the BridgeEnvelope value (§4). REQUIRED and first.
	TLVBridgeEnvelope TLVType = 0x0010
	// TLVSafetyLabel carries the SafetyLabel value (§7). OPTIONAL; when present it
	// immediately follows the envelope and precedes the foreign message.
	TLVSafetyLabel TLVType = 0x0013
)

// BridgeProtocol is the §4 `protocol_id` — the foreign agentic protocol a Bridge
// frame carries. 0x10–0x7F are experimental and 0x80–0xFF are private use; a structural
// decoder accepts any value (whether a given protocol is CARRIED is a per-peer
// capability reported as ProtocolUnsupported, §6, not a wire malformation).
type BridgeProtocol uint8

const (
	BridgeProtoMCP       BridgeProtocol = 0x01
	BridgeProtoA2A       BridgeProtocol = 0x02
	BridgeProtoHTTP2     BridgeProtocol = 0x03
	BridgeProtoWebSocket BridgeProtocol = 0x04
)

var bridgeProtocolNames = map[BridgeProtocol]string{
	BridgeProtoMCP: "MCP", BridgeProtoA2A: "A2A",
	BridgeProtoHTTP2: "HTTP/2", BridgeProtoWebSocket: "WebSocket",
}

// Name returns the registered foreign-protocol name, or "" if p is experimental,
// private-use, or otherwise unregistered.
func (p BridgeProtocol) Name() string { return bridgeProtocolNames[p] }

// BridgeMessageKind is the §4 `message_kind`. It MUST agree with the frame type; the
// agreement table is BridgeKindForFrame / bridgeFrameForKind below.
type BridgeMessageKind uint8

const (
	BridgeKindRequest      BridgeMessageKind = 0x01
	BridgeKindResponse     BridgeMessageKind = 0x02
	BridgeKindNotification BridgeMessageKind = 0x03
	BridgeKindError        BridgeMessageKind = 0x04
	BridgeKindStreamData   BridgeMessageKind = 0x05
	BridgeKindStreamEnd    BridgeMessageKind = 0x06
)

// BridgeContentType is the §4 `content_type` — the foreign message's own encoding.
// A structural decoder records it but does not reject an unregistered value (it
// describes the opaque foreign octets, not the envelope).
type BridgeContentType uint8

const (
	BridgeContentJSON      BridgeContentType = 0x01 // application/json
	BridgeContentCBOR      BridgeContentType = 0x02 // application/cbor
	BridgeContentGRPCProto BridgeContentType = 0x03 // application/grpc+proto
)

// BridgeEffect is the §7 SafetyLabel `effect` — the side-effect class of a request.
// A receiver MUST NOT treat the ABSENCE of a SafetyLabel on a state-mutating
// operation as read_only; absence MUST be treated as destructive (fail-safe, §7).
// See BridgeFrame.EffectiveEffect (bridge_bodies.go), which applies that fail-safe.
type BridgeEffect uint8

const (
	BridgeEffectReadOnly           BridgeEffect = 0x00
	BridgeEffectIdempotentWrite    BridgeEffect = 0x01
	BridgeEffectNonIdempotentWrite BridgeEffect = 0x02
	BridgeEffectDestructive        BridgeEffect = 0x03
)

// BridgeFlagFinal is envelope `flags` bit 0 (§4): set on the terminating frame of a
// stream. Bits 1–7 are reserved; senders MUST set them 0 and receivers MUST ignore
// them (so a decoder never rejects on a nonzero reserved bit).
const BridgeFlagFinal uint8 = 0x01

// BridgeErrorCode is a §6 below-foreign-protocol transport-error code: a failure
// where the request did not reach the foreign endpoint. A failure WITHIN the foreign
// protocol is reported instead by carrying that protocol's own error object verbatim
// (§6 first paragraph), never reduced to one of these codes.
type BridgeErrorCode uint8

const (
	BridgeErrEnvelopeMalformed   BridgeErrorCode = 1 // §4: envelope missing/invalid
	BridgeErrProtocolUnsupported BridgeErrorCode = 2 // protocol_id not carried by this peer
	BridgeErrMethodUnsupported   BridgeErrorCode = 3 // operation recognized but not carried
	BridgeErrNotDelivered        BridgeErrorCode = 4 // foreign endpoint did not accept it
	BridgeErrSafetyPolicy        BridgeErrorCode = 5 // refused by a local safety policy (§7)
)

var bridgeErrorNames = map[BridgeErrorCode]string{
	BridgeErrEnvelopeMalformed:   "EnvelopeMalformed",
	BridgeErrProtocolUnsupported: "ProtocolUnsupported",
	BridgeErrMethodUnsupported:   "MethodUnsupported",
	BridgeErrNotDelivered:        "NotDelivered",
	BridgeErrSafetyPolicy:        "SafetyPolicy",
}

// Name returns the §6 transport-error name, or "" for an unregistered code.
func (c BridgeErrorCode) Name() string { return bridgeErrorNames[c] }

// bridgeFrameKind maps each Bridge frame type to the message_kind the envelope MUST
// carry (§4 "MUST agree with the frame type"). Note the mapping is NOT the identity
// of the low byte: BRIDGE_ERROR (0x0102) pairs with kind 0x04 and BRIDGE_NOTIFY
// (0x0103) with kind 0x03, so a table — not arithmetic — defines the agreement.
var bridgeFrameKind = map[FrameType]BridgeMessageKind{
	FrameBridgeRequest:    BridgeKindRequest,
	FrameBridgeResponse:   BridgeKindResponse,
	FrameBridgeError:      BridgeKindError,
	FrameBridgeNotify:     BridgeKindNotification,
	FrameBridgeStreamData: BridgeKindStreamData,
	FrameBridgeStreamEnd:  BridgeKindStreamEnd,
}

// BridgeKindForFrame returns the message_kind that a frame of type ft MUST carry,
// and whether ft is a Bridge frame type at all (§4).
func BridgeKindForFrame(ft FrameType) (BridgeMessageKind, bool) {
	k, ok := bridgeFrameKind[ft]
	return k, ok
}

// IsBridgeFrame reports whether ft is an NPAMP-BRIDGE frame type (0x0100–0x0105). It
// does not consider the channel; a caller has already established that the frame
// arrived on the Bridge channel (0x000D), on which these values carry their
// NPAMP-BRIDGE meaning (§2, per-channel frame-type namespace).
func IsBridgeFrame(ft FrameType) bool {
	return ft >= FrameBridgeRequest && ft <= FrameBridgeStreamEnd
}

// IsBridgeRequest reports whether ft is the reply-eliciting Bridge frame — the only
// frame a requester originates that a responder answers (with a RESPONSE, an ERROR,
// or a STREAM_DATA/STREAM_END sequence; §2, §5). It MUST carry a non-empty
// correlation_id (§5).
func IsBridgeRequest(ft FrameType) bool { return ft == FrameBridgeRequest }

// IsBridgeReply reports whether ft is a frame that echoes an originating request's
// correlation_id (§5): RESPONSE, ERROR, STREAM_DATA, or STREAM_END.
func IsBridgeReply(ft FrameType) bool {
	switch ft {
	case FrameBridgeResponse, FrameBridgeError, FrameBridgeStreamData, FrameBridgeStreamEnd:
		return true
	default:
		return false
	}
}
