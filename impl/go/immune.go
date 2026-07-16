package npamp

// NPAMP-IMMUNE companion frame types — spec/companion/85_immune_channel.md §3.
//
// These are channel-specific frame types interpreted only on the Immune channel
// (0x0005); a given value has no NPAMP-IMMUNE meaning on any other channel
// (draft-01 §4.6, per-channel frame-type namespace). The set is the anomaly-report
// request/result pair plus a single structured error frame in the application band
// (0x0100–0x0102), and the five defensive-gossip propagation frames in the reserved
// companion-extension band (0x00C0–0x00C4, the range the core reserves for the
// Immune channel's propagation extension and this companion defines).
//
// Unlike NPAMP-STREAM (whose envelope key 1 is a uint sub_stream_id) the Immune
// common-envelope key 1 is corr — a per-exchange byte-string correlation token
// (§4.2, §5), the same envelope shape as NPAMP-MEMORY.
const (
	// Application-band operation frames (0x0100+): the anomaly-report request/result
	// pair plus a single channel-wide structured error frame (§3.1).
	FrameImmuneReportReq    FrameType = 0x0100
	FrameImmuneReportResult FrameType = 0x0101
	FrameImmuneError        FrameType = 0x0102

	// Reserved companion-extension propagation band (0x00C0–0x00C4): the
	// defensive-gossip advertise/ack, pull, and retract exchange this companion
	// defines in the range the core specification reserves for Immune propagation
	// (§3.3).
	FrameImmuneGossipAdvertise  FrameType = 0x00C0
	FrameImmuneGossipAck        FrameType = 0x00C1
	FrameImmuneGossipPullReq    FrameType = 0x00C2
	FrameImmuneGossipPullResult FrameType = 0x00C3
	FrameImmuneGossipRetract    FrameType = 0x00C4
)

// IsImmuneFrame reports whether ft is an NPAMP-IMMUNE companion frame type — one of
// the application-band anomaly-report/error frames (0x0100–0x0102) or a
// propagation-band gossip frame (0x00C0–0x00C4). It does not consider the channel;
// a caller has already established that the frame arrived on the Immune channel
// (0x0005), on which these values carry their NPAMP-IMMUNE meaning.
func IsImmuneFrame(ft FrameType) bool {
	switch {
	case ft >= FrameImmuneGossipAdvertise && ft <= FrameImmuneGossipRetract:
		return true
	case ft >= FrameImmuneReportReq && ft <= FrameImmuneError:
		return true
	default:
		return false
	}
}

// IsImmuneRequest reports whether ft is an NPAMP-IMMUNE request frame — one that a
// requester originates and that a responder answers with a matching *_RESULT/_ACK
// or with FrameImmuneError (§3, §5). The reply and error frames return false.
func IsImmuneRequest(ft FrameType) bool {
	switch ft {
	case FrameImmuneReportReq, FrameImmuneGossipAdvertise,
		FrameImmuneGossipPullReq, FrameImmuneGossipRetract:
		return true
	default:
		return false
	}
}

// IsImmunePropagationFrame reports whether ft is one of the reserved propagation-band
// defensive-gossip frames (0x00C0–0x00C4, §3.3). The defensive-gossip operation is
// OPTIONAL: a responder that does not implement it MUST reply IMMUNE_ERROR
// unknown_operation to any such frame (§3.3, §10).
func IsImmunePropagationFrame(ft FrameType) bool {
	return ft >= FrameImmuneGossipAdvertise && ft <= FrameImmuneGossipRetract
}
