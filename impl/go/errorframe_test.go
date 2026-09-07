// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"testing"
)

// TestEncodeErrorBodyDeterministic pins the exact canonical-CBOR bytes of the two-key
// ERROR body { 1 => code, 2 => context }, independently of the encoder: a map of two
// entries (0xa2), key 1 -> uint code, key 2 -> byte string context.
func TestEncodeErrorBodyDeterministic(t *testing.T) {
	// code=1 (unexpected_message), empty context: a2 01 01 02 40
	got := EncodeErrorBody(ErrCodeUnexpectedMessage, nil)
	want := []byte{0xa2, 0x01, 0x01, 0x02, 0x40}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeErrorBody(1, nil) = % x, want % x", got, want)
	}
	// code=10 (flow_control_error), context "hi": a2 01 0a 02 42 68 69
	got = EncodeErrorBody(ErrCodeFlowControl, []byte("hi"))
	want = []byte{0xa2, 0x01, 0x0a, 0x02, 0x42, 'h', 'i'}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeErrorBody(10, \"hi\") = % x, want % x", got, want)
	}
}

// TestErrorBodyRoundTrip checks Encode then Decode recovers the code and context for
// every defined code and several context lengths (including a >23-byte context to
// exercise the 1-byte length header).
func TestErrorBodyRoundTrip(t *testing.T) {
	codes := []SessionErrorCode{
		ErrCodeUnexpectedMessage, ErrCodeDecryptFailed, ErrCodeReplayDetected,
		ErrCodeUnknownChannel, ErrCodeUnknownCriticalTLV, ErrCodeHandshakeTimeout,
		ErrCodeDowngradeDetected, ErrCodeCloseIncomplete, ErrCodeKeyUpdateOutOfOrder,
		ErrCodeFlowControl,
	}
	ctxs := [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte("A"), 40)}
	for _, c := range codes {
		for _, ctx := range ctxs {
			enc := EncodeErrorBody(c, ctx)
			gc, gctx, err := DecodeErrorBody(enc)
			if err != nil {
				t.Fatalf("DecodeErrorBody(code=%d ctxlen=%d): %v", c, len(ctx), err)
			}
			if gc != c {
				t.Fatalf("round-trip code = %d, want %d", gc, c)
			}
			wantCtx := ctx
			if wantCtx == nil {
				wantCtx = []byte{}
			}
			if !bytes.Equal(gctx, wantCtx) {
				t.Fatalf("round-trip ctx = % x, want % x", gctx, wantCtx)
			}
		}
	}
}

// TestDecodeErrorBodyRejectsMalformed confirms non-conforming bodies fail closed.
func TestDecodeErrorBodyRejectsMalformed(t *testing.T) {
	bad := [][]byte{
		nil,                                // empty
		{0xa1, 0x01, 0x01},                 // one-entry map
		{0xa3, 0x01, 0x01, 0x02, 0x40, 0x03, 0x00}, // three-entry map
		{0xa2, 0x02, 0x01, 0x01, 0x40},     // keys out of order / wrong key
		{0xa2, 0x01, 0x20, 0x02, 0x40},     // code is a negative int (major 1), not a uint
		{0xa2, 0x01, 0x01, 0x02, 0x41},     // context claims 1 byte but none present
		{0xa2, 0x01, 0x01, 0x02, 0x40, 0x00}, // trailing byte
		{0xa2, 0x01, 0x19, 0x01, 0x00, 0x02, 0x40}, // code 256 (>255)
	}
	for i, b := range bad {
		if _, _, err := DecodeErrorBody(b); err == nil {
			t.Fatalf("case %d: DecodeErrorBody(% x) accepted a malformed body", i, b)
		}
	}
}

// TestSessionErrorCodeReaction pins the fatal/discard classification.
func TestSessionErrorCodeReaction(t *testing.T) {
	for _, c := range []SessionErrorCode{ErrCodeReplayDetected, ErrCodeUnknownChannel} {
		if c.Reaction() != ReactionDiscard {
			t.Fatalf("code %s should be discard", c)
		}
	}
	for _, c := range []SessionErrorCode{ErrCodeUnexpectedMessage, ErrCodeDecryptFailed, ErrCodeCloseIncomplete, ErrCodeFlowControl} {
		if c.Reaction() != ReactionFatal {
			t.Fatalf("code %s should be fatal", c)
		}
	}
}
