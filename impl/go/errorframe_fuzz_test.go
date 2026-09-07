// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"testing"
)

// FuzzDecodeErrorBody drives DecodeErrorBody, the ERROR-frame CBOR-map decoder, with
// arbitrary octets. The body carries a length-prefixed byte string (context) inside a
// two-entry map with no independent outer length bounding it, so this is another
// dual-length-field-disagreement shape: cborReadBstr's own declared length must
// exactly consume the remaining bytes (DecodeErrorBody rejects any trailing octets).
// On a successful decode it asserts: no panic; and decode-then-encode stability --
// EncodeErrorBody(code, ctx) must reproduce the exact input, which additionally proves
// the decoder never over-accepts a non-canonical (non-shortest-form) integer or
// byte-string-length encoding as equivalent to the canonical one it would itself emit.
func FuzzDecodeErrorBody(f *testing.F) {
	f.Add(EncodeErrorBody(ErrCodeUnexpectedMessage, nil))
	f.Add(EncodeErrorBody(ErrCodeFlowControl, []byte("hi")))
	f.Add(EncodeErrorBody(ErrCodeDowngradeDetected, bytes.Repeat([]byte{0x7A}, 40)))
	f.Add([]byte{})
	f.Add([]byte{0xa2}) // map header claiming 2 entries, nothing following
	f.Add([]byte{0xa1, 0x01, 0x01})                   // wrong entry count (1, not 2)
	f.Add([]byte{0xa2, 0x01, 0x18, 0x05, 0x02, 0x40}) // non-shortest-form uint (0x18 0x05 for a value <24)
	// A byte-string header whose length claims more octets than actually follow --
	// the length-field-vs-buffer-size smuggling shape this decoder must reject.
	f.Add([]byte{0xa2, 0x01, 0x01, 0x02, 0x58, 0xFF, 0x00})
	// Valid two-entry body plus trailing garbage after the declared content ends.
	f.Add(append(EncodeErrorBody(ErrCodeReplayDetected, []byte("x")), 0xFF, 0xFF))

	f.Fuzz(func(t *testing.T, data []byte) {
		code, ctx, err := DecodeErrorBody(data)
		if err != nil {
			return
		}
		got := EncodeErrorBody(code, ctx)
		if !bytes.Equal(got, data) {
			t.Fatalf("decode-then-encode is not stable for code %d, ctx % x -- input % x, re-encoded % x", code, ctx, data, got)
		}
	})
}
