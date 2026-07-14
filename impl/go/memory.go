package npamp

// NPAMP-MEMORY companion frame types — spec/companion/81_memory_channel.md §3.
//
// These are channel-specific frame types interpreted only on the Memory channel
// (0x0001); a given value has no NPAMP-MEMORY meaning on any other channel
// (draft-02 §4.6, per-channel frame-type namespace). The set is the per-operation
// request/result application-band frames (0x0100–0x010E) plus the two eviction and
// revive frames in the companion-extension band (0x0035–0x0036, the range the core
// reserves for the Memory channel).
const (
	// Application-band operation frames (0x0100+): per-operation request/result
	// pairs plus a single structured error frame.
	FrameMemoryCreateReq          FrameType = 0x0100
	FrameMemoryCreateResult       FrameType = 0x0101
	FrameMemoryReadReq            FrameType = 0x0102
	FrameMemoryReadResult         FrameType = 0x0103
	FrameMemoryUpdateReq          FrameType = 0x0104
	FrameMemoryUpdateResult       FrameType = 0x0105
	FrameMemoryDeleteReq          FrameType = 0x0106
	FrameMemoryDeleteResult       FrameType = 0x0107
	FrameMemoryRetrieveReq        FrameType = 0x0108
	FrameMemoryRetrieveResult     FrameType = 0x0109
	FrameMemoryRetrieveStreamData FrameType = 0x010A
	FrameMemoryRetrieveStreamEnd  FrameType = 0x010B
	FrameMemoryStatusReq          FrameType = 0x010C
	FrameMemoryStatusResult       FrameType = 0x010D
	FrameMemoryError              FrameType = 0x010E

	// Companion-extension band eviction/revive frames (0x0035–0x0036), the Memory
	// channel's reserved range in the core's Reserved Frame-Type Ranges table.
	FrameMemoryEvict  FrameType = 0x0035
	FrameMemoryRevive FrameType = 0x0036
)

// IsMemoryFrame reports whether ft is an NPAMP-MEMORY companion frame type — one
// of the application-band operation frames (0x0100–0x010E) or an eviction/revive
// frame (0x0035–0x0036). It does not consider the channel; a caller has already
// established that the frame arrived on the Memory channel (0x0001), on which
// these values carry their NPAMP-MEMORY meaning.
func IsMemoryFrame(ft FrameType) bool {
	switch {
	case ft == FrameMemoryEvict || ft == FrameMemoryRevive:
		return true
	case ft >= FrameMemoryCreateReq && ft <= FrameMemoryError:
		return true
	default:
		return false
	}
}

// IsMemoryRequest reports whether ft is an NPAMP-MEMORY request frame — one that a
// requester originates and that a responder answers with a matching *_RESULT (or a
// retrieval stream) or with FrameMemoryError (spec §3, §5). The reply, stream, and
// error frames return false.
func IsMemoryRequest(ft FrameType) bool {
	switch ft {
	case FrameMemoryCreateReq, FrameMemoryReadReq, FrameMemoryUpdateReq,
		FrameMemoryDeleteReq, FrameMemoryRetrieveReq, FrameMemoryStatusReq,
		FrameMemoryEvict, FrameMemoryRevive:
		return true
	default:
		return false
	}
}
