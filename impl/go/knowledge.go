package npamp

// NPAMP-KNOWLEDGE companion frame types — spec/companion/8b_knowledge_channel.md §3.
//
// These are channel-specific frame types interpreted only on the Knowledge channel
// (0x0012); a given value has no NPAMP-KNOWLEDGE meaning on any other channel
// (draft-01 §4.6, per-channel frame-type namespace). The core specification reserves
// NO companion-extension range for the Knowledge channel (§3.3), so — like the
// Telemetry-family native channels — every one of the ten frame types lives in the
// channel-specific application band at 0x0100+ (§3.1); this document defines no frame
// in the companion-extension band 0x0030–0x00FF and consumes no extension-TLV code
// point.
const (
	// Application-band operation frames (0x0100+): the two operation classes
	// (retrieval query, standing subscription) plus a single structured error frame.
	FrameKnowledgeQueryReq        FrameType = 0x0100
	FrameKnowledgeQueryResult     FrameType = 0x0101
	FrameKnowledgeQueryStreamData FrameType = 0x0102
	FrameKnowledgeQueryStreamEnd  FrameType = 0x0103
	FrameKnowledgeSubscribeReq    FrameType = 0x0104
	FrameKnowledgeSubscribeAck    FrameType = 0x0105
	FrameKnowledgeUpdate          FrameType = 0x0106
	FrameKnowledgeCredit          FrameType = 0x0107
	FrameKnowledgeUnsubscribe     FrameType = 0x0108
	FrameKnowledgeError           FrameType = 0x0109
)

// IsKnowledgeFrame reports whether ft is an NPAMP-KNOWLEDGE companion frame type —
// one of the ten application-band operation frames (0x0100–0x0109). It does not
// consider the channel; a caller has already established that the frame arrived on
// the Knowledge channel (0x0012), on which these values carry their NPAMP-KNOWLEDGE
// meaning.
func IsKnowledgeFrame(ft FrameType) bool {
	return ft >= FrameKnowledgeQueryReq && ft <= FrameKnowledgeError
}

// IsKnowledgeRequest reports whether ft is an NPAMP-KNOWLEDGE request frame — one
// that a requester originates and that a responder answers with a result/stream/ACK
// or with FrameKnowledgeError (spec §3.1, §5). Only KNOWLEDGE_QUERY_REQ and
// KNOWLEDGE_SUBSCRIBE_REQ originate an operation; the result, stream, ACK, update,
// credit, unsubscribe, and error frames return false.
func IsKnowledgeRequest(ft FrameType) bool {
	switch ft {
	case FrameKnowledgeQueryReq, FrameKnowledgeSubscribeReq:
		return true
	default:
		return false
	}
}
