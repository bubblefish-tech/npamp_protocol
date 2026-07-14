package npamp

// NPAMP-STREAM companion frame types — spec/companion/80_stream_channel.md §3/§5.
//
// The Stream channel (0x000C, min-profile Standard) carries native multiplexed sub-streams with
// QUIC-style absolute-offset flow control. Frame bodies are deterministic-CBOR maps (§4.1). Unlike
// NPAMP-MEMORY, the common-envelope key 1 is sub_stream_id — an Unsigned int that is the persistent
// correlation key of a long-lived multi-frame sub-stream — NOT a per-exchange byte-string corr, and
// there is no *_RESULT frame family (STREAM_OPEN is the only reply-eliciting frame; the sole
// structured error is STREAM_RESET).
//
// These frame-type values live in the per-channel application band (0x0100+); they carry their
// NPAMP-STREAM meaning ONLY on the Stream channel (draft-02 §4.6, per-channel frame-type namespace),
// so a value here may coincide numerically with a frame type of another channel.
const (
	FrameStreamOpen         FrameType = 0x0100
	FrameStreamData         FrameType = 0x0101
	FrameStreamClose        FrameType = 0x0102
	FrameStreamReset        FrameType = 0x0103
	FrameStreamWindowUpdate FrameType = 0x0104
)

// IsStreamFrame reports whether ft is an NPAMP-STREAM frame type (0x0100–0x0104). It does not
// consider the channel; a caller has already established that the frame arrived on the Stream
// channel (0x000C), on which these values carry their NPAMP-STREAM meaning.
func IsStreamFrame(ft FrameType) bool {
	return ft >= FrameStreamOpen && ft <= FrameStreamWindowUpdate
}
