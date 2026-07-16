package npamp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestFrameSealOracleCrossValidate proves NON-CIRCULARITY for the whole-frame AEAD ops (TRACK C4):
// the sealed bytes below are the ACTUAL output of the independent Python oracle
// (test-vectors/gen/frame_seal_oracle.py), which builds the 21-octet header-prefix AAD from scratch
// (spec/02 §4.2), the per-frame nonce from scratch (iv XOR (0^4||seq), spec/06), and the
// ciphertext||tag with pyca/cryptography's AES-256-GCM (OpenSSL) — an AEAD independent of Go's
// crypto/aes+crypto/cipher. This test asserts SealAES256GCM under the header-prefix AAD reproduces
// those bytes, that OpenAES256GCM round-trips, and that a tampered header (AAD), a wrong sequence
// number (nonce), and a flipped tag each MUST fail — so a drift in either the oracle or the impl
// fails here in `go test`, before the language-agnostic conformance runner.
func TestFrameSealOracleCrossValidate(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	var iv [12]byte
	for i := range iv {
		iv[i] = byte(0xa0 + i)
	}

	// prefixFor mirrors the adapter: build the frame header and take its 21-octet CRC-covered prefix,
	// which the record layer uses as the AEAD associated data.
	prefixFor := func(flags uint8, ftype FrameType, ch ChannelID, seq uint64, ptLen int) []byte {
		f := &Frame{Version: 2, Flags: flags, Type: uint16(ftype), Channel: uint16(ch), Seq: seq}
		p := make([]byte, 21)
		f.HeaderPrefix(p, uint32(ptLen))
		return p
	}

	cases := []struct {
		name   string
		ftype  FrameType
		ch     ChannelID
		seq    uint64
		pt     string
		sealed string
	}{
		{"memory_seq7", 0x0100, ChanMemory, 7, "npamp-frame-payload",
			"b5bc2a775bd97a4ad5a078a930a674e0de9673d05ba32b57d89d89c3473089ab87210d"},
		{"stream_highseq", 0x0101, ChanStream, 0x00000000ff00000a, "stream-data-body",
			"9e2469f41e20b2b2916f04adfb5736a9f0381886ab328e86ee8ab8700c4eae77"},
		{"control_seq0", 0x0001, ChanControl, 0, "PING",
			"b651326a46ec3ccaf8d17b24f4b4bd53511bd251"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt := []byte(c.pt)
			aad := prefixFor(FlagENC, c.ftype, c.ch, c.seq, len(pt))
			sealed, err := SealAES256GCM(key, iv, c.seq, aad, pt)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if got := hex.EncodeToString(sealed); got != c.sealed {
				t.Fatalf("sealed mismatch\n got %s\nwant %s", got, c.sealed)
			}
			back, err := OpenAES256GCM(key, iv, c.seq, aad, sealed)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if !bytes.Equal(back, pt) {
				t.Fatalf("open plaintext = %q, want %q", back, pt)
			}
		})
	}

	// MUST-reject cases operate on the memory_seq7 frame (V1).
	v1sealed, _ := hex.DecodeString(cases[0].sealed)
	v1pt := len([]byte(cases[0].pt))

	t.Run("tampered_aad_channel", func(t *testing.T) {
		// Reconstruct the AAD with the wrong channel (0x0002 instead of Memory 0x0001): AAD mismatch.
		badAAD := prefixFor(FlagENC, 0x0100, 0x0002, 7, v1pt)
		if _, err := OpenAES256GCM(key, iv, 7, badAAD, v1sealed); err == nil {
			t.Fatal("tampered-AAD open MUST fail, but it succeeded")
		}
	})
	t.Run("wrong_seq_nonce", func(t *testing.T) {
		// Open with seq 8 (sealed under 7): both the derived nonce and the AAD diverge.
		badAAD := prefixFor(FlagENC, 0x0100, ChanMemory, 8, v1pt)
		if _, err := OpenAES256GCM(key, iv, 8, badAAD, v1sealed); err == nil {
			t.Fatal("wrong-seq open MUST fail, but it succeeded")
		}
	})
	t.Run("tampered_tag", func(t *testing.T) {
		aad := prefixFor(FlagENC, 0x0100, ChanMemory, 7, v1pt)
		bad := append([]byte(nil), v1sealed...)
		bad[len(bad)-1] ^= 0x01
		if _, err := OpenAES256GCM(key, iv, 7, aad, bad); err == nil {
			t.Fatal("tampered-tag open MUST fail, but it succeeded")
		}
	})
}
