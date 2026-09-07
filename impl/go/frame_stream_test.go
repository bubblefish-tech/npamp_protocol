// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"errors"
	"testing"
)

// TestReadFrameSelfDelimiting is the R4.3 self-delimiting round-trip vector: several
// frames with different payload lengths are marshalled and concatenated into one
// byte stream (as a TCP/TLS transport delivers them, with no message boundaries),
// then split back into frames using only the fixed 36-octet header and the Payload
// Length field. Recovery MUST be byte-exact and boundary-exact.
//
// It is mutation-surviving: a reader that ignored Payload Length and consumed the
// whole buffer would recover only one frame, and one that mis-sized the boundary
// would corrupt the second frame's header CRC.
func TestReadFrameSelfDelimiting(t *testing.T) {
	originals := []*Frame{
		{Type: 0x0100, Channel: 0x0001, Seq: 0, Payload: nil},                             // zero-length payload
		{Type: 0x0011, Channel: 0x0002, Seq: 1, Payload: []byte{0xAA}},                    // 1 octet
		{Type: 0x0035, Channel: 0x000C, Seq: 2, Payload: bytes.Repeat([]byte{0xBE}, 300)}, // long
	}

	var stream []byte
	var wire [][]byte
	for _, f := range originals {
		b, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, b)
		stream = append(stream, b...)
	}

	// Split the concatenated stream back into frames using ReadFrame.
	var got []*Frame
	rest := stream
	for len(rest) > 0 {
		f, n, err := ReadFrame(rest)
		if err != nil {
			t.Fatalf("ReadFrame at offset %d: %v", len(stream)-len(rest), err)
		}
		if n <= 0 {
			t.Fatalf("ReadFrame consumed %d octets", n)
		}
		got = append(got, f)
		rest = rest[n:]
	}
	if len(got) != len(originals) {
		t.Fatalf("recovered %d frames, want %d", len(got), len(originals))
	}
	for i := range got {
		reb, err := got[i].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reb, wire[i]) {
			t.Fatalf("frame %d not recovered byte-exact from the stream", i)
		}
	}

	// A prefix shorter than the fixed header needs more bytes.
	if _, _, err := ReadFrame(stream[:HeaderSize-1]); !errors.Is(err, ErrShortHeader) {
		t.Fatalf("short header: got %v, want ErrShortHeader", err)
	}
	// A complete header whose declared payload has not fully arrived. wire[1] is a
	// 37-octet frame (36 header + 1 payload); trimming to the header alone leaves the
	// declared payload octet missing.
	if _, _, err := ReadFrame(wire[1][:HeaderSize]); !errors.Is(err, ErrIncompleteFrame) {
		t.Fatalf("incomplete frame: got %v, want ErrIncompleteFrame", err)
	}
}
