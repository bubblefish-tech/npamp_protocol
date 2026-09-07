// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"testing"
)

// TestGRPCLengthPrefixedMessage_RoundTrip proves encode/decode are inverse
// operations for both the compressed and uncompressed flag.
func TestGRPCLengthPrefixedMessage_RoundTrip(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		msg := []byte("a protobuf-shaped message body")
		wire := encodeGRPCLengthPrefixedMessage(compressed, msg)
		gotCompressed, gotMsg, err := decodeGRPCLengthPrefixedMessage(wire)
		if err != nil {
			t.Fatalf("compressed=%v decode: %v", compressed, err)
		}
		if gotCompressed != compressed {
			t.Errorf("compressed = %v, want %v", gotCompressed, compressed)
		}
		if !bytes.Equal(gotMsg, msg) {
			t.Errorf("msg = %q, want %q", gotMsg, msg)
		}
	}
}

// TestGRPCLengthPrefixedMessage_EmptyMessage proves a zero-length message
// (a valid gRPC unary call with an empty request, e.g. google.protobuf.Empty)
// round-trips correctly.
func TestGRPCLengthPrefixedMessage_EmptyMessage(t *testing.T) {
	wire := encodeGRPCLengthPrefixedMessage(false, nil)
	_, msg, err := decodeGRPCLengthPrefixedMessage(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(msg) != 0 {
		t.Errorf("msg = %q, want empty", msg)
	}
}

// TestGRPCLengthPrefixedMessage_TooShort_Rejected is a MUTATION ANCHOR
// (RED-EVIDENCE): fewer than 5 octets cannot hold the LPM header and MUST be
// rejected, not silently treated as a length-0 or partially-read frame.
func TestGRPCLengthPrefixedMessage_TooShort_Rejected(t *testing.T) {
	if _, _, err := decodeGRPCLengthPrefixedMessage([]byte{0x00, 0x00}); err == nil {
		t.Fatal("decodeGRPCLengthPrefixedMessage accepted a 2-octet frame (too short for the 5-octet header)")
	}
}

// TestGRPCLengthPrefixedMessage_LengthMismatch_Rejected is a MUTATION ANCHOR:
// a declared length that disagrees with the actual remaining octets MUST be
// rejected -- accepting it would silently truncate or over-read the message.
func TestGRPCLengthPrefixedMessage_LengthMismatch_Rejected(t *testing.T) {
	wire := encodeGRPCLengthPrefixedMessage(false, []byte("hello"))
	wire[4] = 99 // declared length now disagrees with the 5 actual message octets
	if _, _, err := decodeGRPCLengthPrefixedMessage(wire); err == nil {
		t.Fatal("decodeGRPCLengthPrefixedMessage accepted a frame whose declared length disagrees with its actual octets")
	}
}

// TestGRPCLengthPrefixedMessage_BadCompressedFlag_Rejected asserts the
// compressed-flag octet is a boolean 0/1 value, not an arbitrary byte.
func TestGRPCLengthPrefixedMessage_BadCompressedFlag_Rejected(t *testing.T) {
	wire := encodeGRPCLengthPrefixedMessage(false, []byte("x"))
	wire[0] = 2
	if _, _, err := decodeGRPCLengthPrefixedMessage(wire); err == nil {
		t.Fatal("decodeGRPCLengthPrefixedMessage accepted compressed-flag octet 2")
	}
}
