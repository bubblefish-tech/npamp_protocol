package npamp

// NPAMP-TELEMETRY companion frame types — spec/companion/87_telemetry_channel.md §3.
//
// The Telemetry channel (0x000A, min-profile Standard, direction Bidirectional) carries a peer's own
// operational metrics, discrete events, and health statements in bulk, plus a subscribe/credit
// lifecycle that bounds a bulk producer. Frame bodies are deterministic-CBOR maps (§4). The Telemetry
// channel has NO core-reserved companion-extension range (§3), so every operational frame lives in the
// channel-application band at 0x0100 and above.
//
// Unlike NPAMP-STREAM (whose envelope key 1 is a uint sub_stream_id), the Telemetry envelope key 1 is
// a byte-string corr like NPAMP-MEMORY — but with a divergence of its own: corr is CONDITIONAL, present
// on every frame EXCEPT a standalone (unsolicited) TELEMETRY_REPORT, which omits it (§4.1, §5).
//
// These frame-type values live in the per-channel application band (0x0100+); they carry their
// NPAMP-TELEMETRY meaning ONLY on the Telemetry channel (draft-01 §4.6, per-channel frame-type
// namespace), so a value here may coincide numerically with a frame type of another channel.
const (
	FrameTelemetryReport      FrameType = 0x0100
	FrameTelemetrySubscribe   FrameType = 0x0101
	FrameTelemetrySubAck      FrameType = 0x0102
	FrameTelemetryUnsubscribe FrameType = 0x0103
	FrameTelemetryCredit      FrameType = 0x0104
	FrameTelemetryError       FrameType = 0x0105
)

// TelemetryErrorCode is a §8 Telemetry error code carried in a TELEMETRY_ERROR (0x0105).
type TelemetryErrorCode uint64

const (
	TelErrMalformedPayload    TelemetryErrorCode = 1
	TelErrKindMismatch        TelemetryErrorCode = 2
	TelErrFilterUnsupported   TelemetryErrorCode = 3
	TelErrUnknownSubscription TelemetryErrorCode = 4
	TelErrSubscriptionRefused TelemetryErrorCode = 5
	TelErrNotAdvertised       TelemetryErrorCode = 6
)

// IsTelemetryFrame reports whether ft is an NPAMP-TELEMETRY companion frame type — one of the
// channel-application operation frames (0x0100–0x0105). It does not consider the channel; a caller has
// already established that the frame arrived on the Telemetry channel (0x000A), on which these values
// carry their NPAMP-TELEMETRY meaning.
func IsTelemetryFrame(ft FrameType) bool {
	return ft >= FrameTelemetryReport && ft <= FrameTelemetryError
}
