// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"testing"
)

// FuzzDecodeTLVs drives DecodeTLVs with arbitrary octets. Each parsed TLV carries its
// own explicit u16 Length field with no outer envelope length independently bounding
// it, so this is exactly the shape where a decoder could over-accept a length field
// that overruns (or under-consumes) the buffer -- the class this target guards. On a
// successful decode it asserts: no panic; re-encoding the parsed TLVs byte-for-byte
// reproduces the input (proving every declared Length was honored exactly, with no
// slack the encoder and decoder disagree about); and the parsed count never exceeds
// MaxTLVsPerFrame.
func FuzzDecodeTLVs(f *testing.F) {
	encodeAll := func(tlvs ...TLV) []byte {
		var buf []byte
		for _, t := range tlvs {
			buf = t.Encode(buf)
		}
		return buf
	}
	f.Add([]byte{}) // no TLVs at all
	f.Add(encodeAll(TLV{Type: TLVProfileOffer, Value: []byte{0x01, 0x02, 0x03}}))
	f.Add(encodeAll(
		TLV{Type: TLVKEMOffer, Value: []byte{0x11, 0xec}},
		TLV{Type: TLVSigOffer, Value: []byte{0x08, 0x07}},
	))
	f.Add(encodeAll(TLV{Type: TLVKEMShare, Value: nil})) // zero-length value
	f.Add([]byte{0x00, 0x01, 0x00})                       // 3 octets: below the 4-octet TLV-header minimum
	// A declared Length that overruns the remaining buffer -- the core smuggling shape:
	// the TLV claims more value octets than actually follow it.
	f.Add([]byte{0x00, 0x01, 0xFF, 0xFF, 0x01, 0x02})
	// A well-formed TLV immediately followed by a truncated second TLV header.
	f.Add(append(encodeAll(TLV{Type: TLVProfileSelect, Value: []byte{0x01}}), 0x00, 0x02))
	// MaxTLVsPerFrame+1 zero-length TLVs, to exercise the ErrTooManyTLVs path.
	{
		var many []byte
		for range MaxTLVsPerFrame + 1 {
			many = TLV{Type: TLVProfileOffer, Value: nil}.Encode(many)
		}
		f.Add(many)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		tlvs, err := DecodeTLVs(data)
		if err != nil {
			if tlvs != nil {
				t.Fatalf("DecodeTLVs returned a non-nil slice alongside error %v: %v", err, tlvs)
			}
			return
		}
		if len(tlvs) > MaxTLVsPerFrame {
			t.Fatalf("DecodeTLVs returned %d TLVs on success, exceeding MaxTLVsPerFrame=%d without erroring", len(tlvs), MaxTLVsPerFrame)
		}

		var re []byte
		for _, tv := range tlvs {
			re = tv.Encode(re)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("decode-then-encode is not stable for %d TLVs:\n  input        = % x\n  re-encoded   = % x", len(tlvs), data, re)
		}
	})
}
