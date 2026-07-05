package npamp_test

import (
	"bytes"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// Example_secureRecordLayer composes the draft-00 OPEN-protocol primitives this module provides —
// the HKDF key schedule, the AES-256-GCM record layer, and the 36-octet frame codec — into one
// send -> receive round-trip over an in-memory "wire".
//
// What this module deliberately does NOT provide: the 1.5-RTT handshake (X25519MLKEM768 + Ed25519)
// that establishes the master secret, and the TCP/TLS transport that carries the frames. Those live
// in a consuming product. Here the master secret is a fixed
// demo value and the "wire" is a byte slice, so the example is self-contained and deterministic.
// Standard profile only (SHA-256, X25519MLKEM768, Ed25519, AES-256-GCM).
func Example_secureRecordLayer() {
	// 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV from the master
	//    secret. In a live session the master secret is the handshake output; here it is fixed.
	master := bytes.Repeat([]byte{0x2b}, 32)
	ts, err := npamp.DeriveTrafficSecret(master, npamp.DirClientToServer, 0, npamp.AEADAES256GCM, npamp.ChanMemory, npamp.ProfileStandard)
	if err != nil {
		panic(err)
	}
	key, iv, err := npamp.DeriveKeyIV(ts, npamp.ProfileStandard)
	if err != nil {
		panic(err)
	}

	// 2. Sender: seal an application payload into an AEAD-protected frame on the Memory channel.
	//    The AEAD associated data is the 21-octet header prefix, so the ciphertext is bound to the
	//    frame's type/channel/seq/length — a tampered header makes the open fail.
	const appType uint16 = 0x0120 // application frame type (app-defined; this module is wire-only)
	plaintext := []byte("hello over n-pamp")
	seq := uint64(0)
	out := npamp.Frame{Flags: npamp.FlagENC, Type: appType, Channel: uint16(npamp.ChanMemory), Seq: seq}
	var aad [21]byte
	out.HeaderPrefix(aad[:], uint32(len(plaintext)+16)) // +16 = AES-256-GCM authentication tag
	sealed, err := npamp.SealAES256GCM(key, iv, seq, aad[:], plaintext)
	if err != nil {
		panic(err)
	}
	out.Payload = sealed
	wire, err := out.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

	// 4. Receiver: parse the frame (validates magic/version/CRC32C) and open the payload under the
	//    same key/seq and the reconstructed header-prefix AAD.
	var in npamp.Frame
	if err := in.UnmarshalBinary(wire); err != nil {
		panic(err)
	}
	var raad [21]byte
	in.HeaderPrefix(raad[:], uint32(len(in.Payload)))
	opened, err := npamp.OpenAES256GCM(key, iv, in.Seq, raad[:], in.Payload)
	if err != nil {
		panic(err)
	}

	fmt.Printf("channel=%d seq=%d encrypted=%t\n", in.Channel, in.Seq, in.Flags&npamp.FlagENC != 0)
	fmt.Printf("recovered: %s\n", opened)
	// Output:
	// channel=1 seq=0 encrypted=true
	// recovered: hello over n-pamp
}
