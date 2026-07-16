package npamp

// NPAMP-COMMERCE companion frame types — spec/companion/88_commerce_channel.md §3.
//
// The Commerce channel (0x000E, min-profile Standard, Bidirectional) carries N-PAMP-native
// agentic-commerce operations: payment-mandate lifecycle (issue/read/revoke/status) and multi-party
// settlement intents (propose/respond/status), plus one structured error frame. It is NOT a Bridge
// carriage class — the operation body is N-PAMP's own deterministic-CBOR encoding, so the correlation
// token, operation semantics, and error object all live INSIDE the body (§2.2). Frame bodies are
// deterministic-CBOR maps (§4.1) whose common-envelope key 1 is corr — a per-exchange byte-string
// correlation token (§4.2, §5), like NPAMP-MEMORY's corr and unlike NPAMP-STREAM's uint sub_stream_id.
//
// The core specification reserves NO sub-0x0100 companion-extension range for the Commerce channel
// (§2.2, §3.3), so ALL fifteen Commerce-native frame types live in the per-channel application band
// at 0x0100+. These values carry their NPAMP-COMMERCE meaning ONLY on the Commerce channel
// (draft-01 §4.6, per-channel frame-type namespace), so a value here may coincide numerically with a
// frame type of another channel.
const (
	FrameCommerceMandateCreateReq    FrameType = 0x0100
	FrameCommerceMandateCreateResult FrameType = 0x0101
	FrameCommerceMandateReadReq      FrameType = 0x0102
	FrameCommerceMandateReadResult   FrameType = 0x0103
	FrameCommerceMandateRevokeReq    FrameType = 0x0104
	FrameCommerceMandateRevokeResult FrameType = 0x0105
	FrameCommerceMandateStatusReq    FrameType = 0x0106
	FrameCommerceMandateStatusResult FrameType = 0x0107
	FrameCommerceIntentProposeReq    FrameType = 0x0108
	FrameCommerceIntentProposeResult FrameType = 0x0109
	FrameCommerceIntentRespondReq    FrameType = 0x010A
	FrameCommerceIntentRespondResult FrameType = 0x010B
	FrameCommerceIntentStatusReq     FrameType = 0x010C
	FrameCommerceIntentStatusResult  FrameType = 0x010D
	FrameCommerceError               FrameType = 0x010E
)

// IsCommerceFrame reports whether ft is an NPAMP-COMMERCE frame type — one of the application-band
// operation frames (0x0100–0x010E). It does not consider the channel; a caller has already
// established that the frame arrived on the Commerce channel (0x000E), on which these values carry
// their NPAMP-COMMERCE meaning.
func IsCommerceFrame(ft FrameType) bool {
	return ft >= FrameCommerceMandateCreateReq && ft <= FrameCommerceError
}

// IsCommerceRequest reports whether ft is an NPAMP-COMMERCE request frame — one a requester
// originates and that a responder answers with the matching *_RESULT or with FrameCommerceError
// (§3.1). The *_RESULT and error frames return false.
func IsCommerceRequest(ft FrameType) bool {
	switch ft {
	case FrameCommerceMandateCreateReq, FrameCommerceMandateReadReq, FrameCommerceMandateRevokeReq,
		FrameCommerceMandateStatusReq, FrameCommerceIntentProposeReq, FrameCommerceIntentRespondReq,
		FrameCommerceIntentStatusReq:
		return true
	default:
		return false
	}
}
