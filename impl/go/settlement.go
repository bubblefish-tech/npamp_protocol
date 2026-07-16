package npamp

// NPAMP-SETTLEMENT companion frame types — spec/companion/86_settlement_channel.md §3.
//
// These are channel-specific frame types interpreted only on the Settlement channel
// (0x0007); a given value has no NPAMP-SETTLEMENT meaning on any other channel
// (core specification §4.6, per-channel frame-type namespace). The set is the
// per-operation request/result application-band frames (0x0100–0x0104) plus the two
// batch-commitment frames in the companion-extension band (0x00A0–0x00A1) — the
// public Settlement half of the shared 0x00A0–0x00A3 Settlement/Audit
// batch-commitment range (§3.3). The Audit half (0x00A2–0x00A3) is out of scope for
// this document and carries no NPAMP-SETTLEMENT meaning.
const (
	// Application-band operation frames (0x0100+): per-operation request/result
	// pairs plus a single structured error frame (§3.1).
	FrameSettleIntentReq    FrameType = 0x0100
	FrameSettleIntentResult FrameType = 0x0101
	FrameReceiptReq         FrameType = 0x0102
	FrameReceiptResult      FrameType = 0x0103
	FrameSettleError        FrameType = 0x0104

	// Companion-extension band batch-commitment frames (0x00A0–0x00A1), the public
	// Settlement half of the reserved 0x00A0–0x00A3 range (§3.3). Batch commitment is
	// OPTIONAL to implement; a responder that does not implement it MUST reply
	// SETTLE_ERROR with code unknown_operation (§3.3, §8).
	FrameSettleBatchCommitReq    FrameType = 0x00A0
	FrameSettleBatchCommitResult FrameType = 0x00A1
)

// IsSettlementFrame reports whether ft is an NPAMP-SETTLEMENT companion frame type —
// one of the application-band operation frames (0x0100–0x0104) or a batch-commitment
// frame (0x00A0–0x00A1). It does not consider the channel; a caller has already
// established that the frame arrived on the Settlement channel (0x0007), on which
// these values carry their NPAMP-SETTLEMENT meaning. The Audit half of the shared
// range (0x00A2–0x00A3) is deliberately excluded (§3.3).
func IsSettlementFrame(ft FrameType) bool {
	switch {
	case ft == FrameSettleBatchCommitReq || ft == FrameSettleBatchCommitResult:
		return true
	case ft >= FrameSettleIntentReq && ft <= FrameSettleError:
		return true
	default:
		return false
	}
}

// IsSettlementRequest reports whether ft is an NPAMP-SETTLEMENT request frame — one
// that a peer originates and that is answered with a matching *_RESULT or with
// SETTLE_ERROR (§3.1, §7). The result and error frames return false. Because the
// Settlement channel is Bidirectional and assigns no fixed initiator/responder role
// (§2), either peer MAY originate any of these requests.
func IsSettlementRequest(ft FrameType) bool {
	switch ft {
	case FrameSettleIntentReq, FrameReceiptReq, FrameSettleBatchCommitReq:
		return true
	default:
		return false
	}
}
