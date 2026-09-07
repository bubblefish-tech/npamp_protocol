// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import "errors"

// SessionErrorCode is a core session/handshake error code carried in an ERROR frame
// (FrameError, 0x0005) on the Control channel (0x0000). These are the registered codes
// of the core Error/Alert Code Registry (registries/error_codes.csv, draft
// {#error-registry}); they are distinct from the per-channel application error codes
// (e.g. BridgeErrorCode), which live in their own channel frames.
type SessionErrorCode uint8

const (
	// ErrCodeUnexpectedMessage is the state-machine total default: a frame not legal
	// for the current state (out-of-order, wrong-flight, repeated, an application frame
	// before ESTABLISHED, or an unknown/unexpected type).
	ErrCodeUnexpectedMessage SessionErrorCode = 1
	// ErrCodeDecryptFailed is a fatal authentication failure: an AEAD open failed, or a
	// handshake CertVerify signature or Finished MAC did not verify.
	ErrCodeDecryptFailed SessionErrorCode = 2
	// ErrCodeReplayDetected is a discard: a sequence number below or already inside the
	// replay window. The frame is dropped and counted; the connection survives.
	ErrCodeReplayDetected SessionErrorCode = 3
	// ErrCodeUnknownChannel is a discard: a frame on a channel the peer did not advertise.
	ErrCodeUnknownChannel SessionErrorCode = 4
	// ErrCodeUnknownCriticalTLV is fatal: an unknown extension TLV with the high bit (0x8000) set.
	ErrCodeUnknownCriticalTLV SessionErrorCode = 5
	// ErrCodeHandshakeTimeout is fatal (timer): the handshake did not complete in time.
	ErrCodeHandshakeTimeout SessionErrorCode = 6
	// ErrCodeDowngradeDetected is fatal: a profile/algorithm selection not covered by the
	// transcript the handshake MAC and CertVerify authenticate.
	ErrCodeDowngradeDetected SessionErrorCode = 7
	// ErrCodeCloseIncomplete is fatal (timer): a CLOSE was not acknowledged in time.
	ErrCodeCloseIncomplete SessionErrorCode = 8
	// ErrCodeKeyUpdateOutOfOrder is fatal: a KeyUpdateMarker announced an epoch other than
	// current+1, or was malformed.
	ErrCodeKeyUpdateOutOfOrder SessionErrorCode = 9
	// ErrCodeFlowControl is fatal: cumulative sent-payload exceeded the advertised FLOW_UPDATE limit.
	ErrCodeFlowControl SessionErrorCode = 10
)

// ErrorReaction is a code's registered reaction: fatal aborts the connection (and, once
// a traffic key exists, carries the code in an ERROR frame before teardown); discard
// drops and counts the offending frame while the connection survives, sending no ERROR.
type ErrorReaction uint8

const (
	ReactionFatal ErrorReaction = iota
	ReactionDiscard
)

// Reaction returns the registered reaction for a code (registries/error_codes.csv).
// Only replay_detected and unknown_channel are discard; every other defined code is fatal.
func (c SessionErrorCode) Reaction() ErrorReaction {
	switch c {
	case ErrCodeReplayDetected, ErrCodeUnknownChannel:
		return ReactionDiscard
	default:
		return ReactionFatal
	}
}

// errCodeName maps each defined code to its registry name, for diagnostics and tests.
var errCodeName = map[SessionErrorCode]string{
	ErrCodeUnexpectedMessage:   "unexpected_message",
	ErrCodeDecryptFailed:       "decrypt_failed",
	ErrCodeReplayDetected:      "replay_detected",
	ErrCodeUnknownChannel:      "unknown_channel",
	ErrCodeUnknownCriticalTLV:  "unknown_critical_tlv",
	ErrCodeHandshakeTimeout:    "handshake_timeout",
	ErrCodeDowngradeDetected:   "downgrade_detected",
	ErrCodeCloseIncomplete:     "close_incomplete",
	ErrCodeKeyUpdateOutOfOrder: "key_update_out_of_order",
	ErrCodeFlowControl:         "flow_control_error",
}

// String returns the registered name of a code, or a hex fallback for an unassigned value.
func (c SessionErrorCode) String() string {
	if n, ok := errCodeName[c]; ok {
		return n
	}
	return "error_code(" + itoaHex(uint64(c)) + ")"
}

// ErrMalformedErrorBody reports that an ERROR payload did not decode as the two-key
// deterministic-CBOR map { 1 => code, 2 => context } the ERROR frame requires.
var ErrMalformedErrorBody = errors.New("npamp: malformed ERROR body")

// SessionError is the surfaced form of an ERROR frame RECEIVED from the peer: it carries
// the wire code the peer reported and its diagnostic context. Per the draft
// ({#error-handling}), an authenticated ERROR frame is advisory — the receiver surfaces
// the sender's reason and closes, and MUST NOT reply with an ERROR of its own (no error
// loop). The SDK Recv path returns a *SessionError when it decodes a peer ERROR so a
// caller can distinguish "the peer aborted, and this is why" from a transport fault.
type SessionError struct {
	Code    SessionErrorCode
	Context []byte
}

// Error implements error. The context is diagnostic and MAY be empty; it is not
// interpreted here (a caller that wants it reads e.Context).
func (e *SessionError) Error() string {
	return "npamp: peer aborted the association with " + e.Code.String()
}

// EncodeErrorBody returns the ERROR-frame payload (draft {#error-handling}): the
// deterministic-CBOR (RFC 8949 §4.2.1) map { 1 => code: 0..255, 2 => context: bstr }.
// context is diagnostic detail, always present, and MAY be zero-length; a nil context is
// encoded as a zero-length byte string.
func EncodeErrorBody(code SessionErrorCode, context []byte) []byte {
	if context == nil {
		context = []byte{}
	}
	return cborEncode(map[uint64]any{1: uint64(code), 2: context})
}

// DecodeErrorBody parses a payload produced by EncodeErrorBody, returning the code and
// its diagnostic context. It requires the canonical two-entry map with integer keys 1
// (a uint in 0..255) and 2 (a byte string), keys in ascending order, and no trailing
// bytes — anything else is ErrMalformedErrorBody.
func DecodeErrorBody(b []byte) (SessionErrorCode, []byte, error) {
	// map header: major type 5, argument 2 (0xa2) — exactly two entries.
	if len(b) < 1 || b[0] != 0xa2 {
		return 0, nil, ErrMalformedErrorBody
	}
	p := 1
	// entry 1: key 1 (0x01) => code (a small uint 0..255).
	if p >= len(b) || b[p] != 0x01 {
		return 0, nil, ErrMalformedErrorBody
	}
	p++
	code, n, err := cborReadUint(b[p:])
	if err != nil || code > 255 {
		return 0, nil, ErrMalformedErrorBody
	}
	p += n
	// entry 2: key 2 (0x02) => context (a byte string).
	if p >= len(b) || b[p] != 0x02 {
		return 0, nil, ErrMalformedErrorBody
	}
	p++
	ctx, n, err := cborReadBstr(b[p:])
	if err != nil {
		return 0, nil, ErrMalformedErrorBody
	}
	p += n
	if p != len(b) {
		return 0, nil, ErrMalformedErrorBody // trailing bytes
	}
	return SessionErrorCode(code), ctx, nil
}

// cborReadUint reads a shortest-form CBOR unsigned integer (major type 0) at the start
// of b, returning its value and the number of bytes consumed.
func cborReadUint(b []byte) (uint64, int, error) {
	if len(b) < 1 || b[0]>>5 != 0 {
		return 0, 0, ErrMalformedErrorBody
	}
	ai := b[0] & 0x1f
	switch {
	case ai < 24:
		return uint64(ai), 1, nil
	case ai == 24:
		if len(b) < 2 || b[1] < 24 { // shortest-form: 1-byte arg must be >= 24
			return 0, 0, ErrMalformedErrorBody
		}
		return uint64(b[1]), 2, nil
	case ai == 25:
		if len(b) < 3 {
			return 0, 0, ErrMalformedErrorBody
		}
		v := uint64(b[1])<<8 | uint64(b[2])
		if v < 256 { // shortest-form: a 2-byte argument MUST encode a value >= 256, else the
			return 0, 0, ErrMalformedErrorBody // 1-byte (ai==24) or in-header (ai<24) form was required
		}
		return v, 3, nil
	default:
		return 0, 0, ErrMalformedErrorBody // wider ints not used by this body
	}
}

// cborReadBstr reads a definite-length CBOR byte string (major type 2) at the start of
// b, returning its bytes and the number of bytes consumed (header + content). The length
// uses the same argument encoding as a uint, so it is decoded by viewing the header with
// the major type masked to 0 and reusing cborReadUint (which also enforces shortest form).
func cborReadBstr(b []byte) ([]byte, int, error) {
	if len(b) < 1 || b[0]>>5 != 2 {
		return nil, 0, ErrMalformedErrorBody
	}
	hdr := make([]byte, len(b))
	copy(hdr, b)
	hdr[0] &= 0x1f // reinterpret the argument bits as a major-type-0 uint
	ln, hn, err := cborReadUint(hdr)
	if err != nil {
		return nil, 0, ErrMalformedErrorBody
	}
	end := hn + int(ln)
	if end < hn || end > len(b) {
		return nil, 0, ErrMalformedErrorBody
	}
	return b[hn:end], end, nil
}

// itoaHex renders v as a lowercase hex string with a 0x prefix (small helper for String()).
func itoaHex(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var buf [18]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	return "0x" + string(buf[i:])
}
