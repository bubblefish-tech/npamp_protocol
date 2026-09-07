// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzFrameUnmarshalBinary drives Frame.UnmarshalBinary with arbitrary octets. It
// asserts three things on every input: (1) no panic (native fuzzing catches that on
// its own); (2) when decode succeeds, the declared Payload Length field (octets
// 17..20) exactly matches the number of payload octets actually consumed -- there is
// exactly ONE length field authoritative for the frame boundary, so a decoder that
// accepted a buffer whose trailing length disagreed with the header's declared length
// would be the dual-length-parser smuggling class this target exists to catch; and
// (3) decode-then-encode stability: re-marshaling the decoded frame reproduces the
// exact input octets, since every wire field (version, flags, type, channel, seq,
// payload) is fully determined by the struct and the CRC is recomputed deterministically.
func FuzzFrameUnmarshalBinary(f *testing.F) {
	seedFrame := func(fr *Frame) []byte {
		buf, err := fr.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return buf
	}
	f.Add(seedFrame(ping()))
	f.Add(seedFrame(&Frame{Flags: FlagENC, Type: 0x0100, Channel: uint16(ChanMemory), Seq: 1, Payload: []byte("hello")}))
	f.Add(seedFrame(&Frame{Flags: FlagCOMP | FlagENC, Type: uint16(FrameError), Channel: uint16(ChanControl), Seq: 0xFFFFFFFFFFFFFFFF, Payload: bytes.Repeat([]byte{0xAB}, 512)}))
	f.Add([]byte{}) // empty buffer
	f.Add(bytes.Repeat([]byte{0x00}, HeaderSize-1)) // one short of a full header
	f.Add(bytes.Repeat([]byte{0xFF}, HeaderSize))   // full-size garbage header
	// A header whose declared Payload Length wildly exceeds MaxFrameSize -- must be
	// rejected without allocating or hanging (guards a hostile length field, though
	// ReadFrame is the primary enforcement point for that; UnmarshalBinary itself only
	// ever sees the exact buffer it was handed).
	{
		hostile := &Frame{Type: 1, Channel: 1, Seq: 1}
		buf, _ := hostile.MarshalBinary()
		binary.BigEndian.PutUint32(buf[17:21], 0xFFFFFFFF)
		f.Add(buf) // length field now disagrees with the (zero-length) actual payload
	}
	{
		// A truncated-but-otherwise-valid frame: the header (and its CRC, which covers
		// only octets 0..20) is completely untouched, but the trailing payload bytes
		// are shorter than the header's own declared Payload Length -- the length
		// field and the buffer disagree without any header field being corrupted,
		// which is the shape a genuine truncated read (or a hostile short buffer
		// following a legitimately-produced header) would take.
		withPayload := &Frame{Type: 2, Channel: 1, Seq: 9, Payload: bytes.Repeat([]byte{0xCC}, 10)}
		buf := seedFrame(withPayload)
		f.Add(buf[:len(buf)-3]) // declares 10 payload octets; only 7 are actually present
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var fr Frame
		err := fr.UnmarshalBinary(data)
		if err != nil {
			return // any rejection is acceptable; the invariants below apply on success only
		}

		// A successful decode is only valid when the header's declared Payload Length
		// exactly matches the payload UnmarshalBinary actually captured -- the single
		// length field that governs the frame boundary, per the doc comment above.
		declared := binary.BigEndian.Uint32(data[17:21])
		if int(declared) != len(fr.Payload) {
			t.Fatalf("UnmarshalBinary accepted a length-field/payload mismatch: declared Payload Length %d, decoded %d payload octets (input %d octets)",
				declared, len(fr.Payload), len(data))
		}
		if HeaderSize+len(fr.Payload) != len(data) {
			t.Fatalf("UnmarshalBinary accepted %d input octets while HeaderSize+payload = %d -- trailing or missing octets not accounted for",
				len(data), HeaderSize+len(fr.Payload))
		}

		// Decode-then-encode stability: re-marshaling must reproduce the exact input.
		buf2, err := fr.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary of a successfully decoded frame failed: %v", err)
		}
		if !bytes.Equal(buf2, data) {
			t.Fatalf("decode-then-encode is not stable:\n  input   = % x\n  re-marshaled = % x", data, buf2)
		}

		// Re-decoding the re-marshaled bytes must succeed and agree field-for-field
		// (idempotence: a second pass through the decoder must not diverge).
		var fr2 Frame
		if err := fr2.UnmarshalBinary(buf2); err != nil {
			t.Fatalf("re-decoding a freshly re-marshaled frame failed: %v", err)
		}
		if fr2.Version != fr.Version || fr2.Flags != fr.Flags || fr2.Type != fr.Type ||
			fr2.Channel != fr.Channel || fr2.Seq != fr.Seq || !bytes.Equal(fr2.Payload, fr.Payload) {
			t.Fatalf("decode is not idempotent: first = %+v, second = %+v", fr, fr2)
		}
	})
}

// FuzzReadFrame drives ReadFrame, the streaming entry point that locates one frame at
// the front of a buffer that MAY be followed by more frames. Its consumed-octet count
// n is the second length signal in this codebase (alongside the header's own Payload
// Length field), so this target specifically guards against the two disagreeing: n
// MUST always equal exactly HeaderSize+len(payload) as UnmarshalBinary itself would
// derive from the same prefix, and decoding buf[:n] alone (simulating a caller that
// advances past exactly n octets) must reproduce an identical result. If ReadFrame
// ever used bytes beyond n to decide anything, or disagreed with UnmarshalBinary about
// how many octets the frame occupies, that is exactly the length-field smuggling class
// this codebase's single-length-field design is meant to preclude.
func FuzzReadFrame(f *testing.F) {
	one, _ := ping().MarshalBinary()
	two := append(append([]byte{}, one...), one...) // two concatenated frames
	f.Add(one)
	f.Add(two)
	f.Add([]byte{})
	f.Add(one[:HeaderSize-1])                    // short header
	f.Add(append(append([]byte{}, one...), 0x00)) // one valid frame plus one stray trailing byte
	{
		withPayload := &Frame{Type: 2, Channel: 1, Seq: 7, Payload: []byte("relay")}
		buf, _ := withPayload.MarshalBinary()
		f.Add(buf[:len(buf)-1]) // declared length longer than what's actually buffered (ErrIncompleteFrame)
	}
	{
		hostile := &Frame{Type: 1, Channel: 1, Seq: 1}
		buf, _ := hostile.MarshalBinary()
		binary.BigEndian.PutUint32(buf[17:21], MaxFrameSize) // declared length alone exceeds the cap
		f.Add(buf)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fr, n, err := ReadFrame(data)
		if err != nil {
			if fr != nil || n != 0 {
				t.Fatalf("ReadFrame returned a non-nil frame or nonzero n alongside error %v: frame=%v n=%d", err, fr, n)
			}
			return
		}
		if n <= 0 || n > len(data) {
			t.Fatalf("ReadFrame reported an out-of-range consumed length n=%d for a %d-octet buffer", n, len(data))
		}
		if n != HeaderSize+len(fr.Payload) {
			t.Fatalf("ReadFrame's consumed length disagrees with the decoded frame: n=%d, HeaderSize+len(payload)=%d", n, HeaderSize+len(fr.Payload))
		}

		// Decoding exactly the first n octets in isolation must succeed and agree,
		// proving n is the sole authority for the frame boundary -- ReadFrame did not
		// consult (or get influenced by) any byte beyond data[:n].
		var fr2 Frame
		if err := fr2.UnmarshalBinary(data[:n]); err != nil {
			t.Fatalf("ReadFrame accepted a frame that UnmarshalBinary(data[:n]) rejects: %v (n=%d)", err, n)
		}
		if fr2.Type != fr.Type || fr2.Channel != fr.Channel || fr2.Seq != fr.Seq || !bytes.Equal(fr2.Payload, fr.Payload) {
			t.Fatalf("ReadFrame's result disagrees with UnmarshalBinary(data[:n]): ReadFrame=%+v Unmarshal=%+v", fr, fr2)
		}
	})
}
