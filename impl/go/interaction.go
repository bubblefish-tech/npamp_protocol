package npamp

// NPAMP-INTERACT companion frame types — spec/companion/89_interaction_channel.md §3.
//
// These are channel-specific frame types interpreted only on the Interaction channel
// (0x000F); a given value has no NPAMP-INTERACT meaning on any other channel (draft-02
// §4.6, per-channel frame-type namespace). The Interaction channel has NO reserved
// companion-extension range of its own (§3.3), so all eight frame types live in the
// channel-specific application band at 0x0100+.
//
// Unlike NPAMP-MEMORY and NPAMP-STREAM, the Interaction channel carries no foreign
// protocol: the operation body IS N-PAMP's own deterministic-CBOR encoding, and the
// correlation token lives inside the body as a byte-string `corr` (§4.2, §5) — like
// NPAMP-MEMORY's corr, and unlike NPAMP-STREAM's unsigned-int sub_stream_id.
const (
	// Application-band operation frames (0x0100+): request/result pairs for the
	// three operation classes (event, prompt, approval), plus a cancel and a single
	// structured error frame.
	FrameInteractEvent          FrameType = 0x0100
	FrameInteractEventAck       FrameType = 0x0101
	FrameInteractPromptReq      FrameType = 0x0102
	FrameInteractPromptResult   FrameType = 0x0103
	FrameInteractApprovalReq    FrameType = 0x0104
	FrameInteractApprovalResult FrameType = 0x0105
	FrameInteractCancel         FrameType = 0x0106
	FrameInteractError          FrameType = 0x0107
)

// IsInteractionFrame reports whether ft is an NPAMP-INTERACT companion frame type — one
// of the eight application-band operation frames (0x0100–0x0107). It does not consider
// the channel; a caller has already established that the frame arrived on the
// Interaction channel (0x000F), on which these values carry their NPAMP-INTERACT
// meaning.
func IsInteractionFrame(ft FrameType) bool {
	return ft >= FrameInteractEvent && ft <= FrameInteractError
}

// IsInteractionRequest reports whether ft is a frame a peer originates that opens an
// exchange requiring a reply from the responder: an INTERACT_EVENT (which elicits an
// INTERACT_EVENT_ACK only when its `ack` flag is set, §6.1), an INTERACT_PROMPT_REQ
// (answered by INTERACT_PROMPT_RESULT or INTERACT_ERROR), or an INTERACT_APPROVAL_REQ
// (answered by INTERACT_APPROVAL_RESULT or INTERACT_ERROR). The reply frames
// (INTERACT_EVENT_ACK, the two *_RESULT frames, INTERACT_ERROR) and the fire-and-forget
// INTERACT_CANCEL return false: a cancel withdraws an exchange and is not itself
// answered (§6.4).
func IsInteractionRequest(ft FrameType) bool {
	switch ft {
	case FrameInteractEvent, FrameInteractPromptReq, FrameInteractApprovalReq:
		return true
	default:
		return false
	}
}
