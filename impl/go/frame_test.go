package npamp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"testing"
)

func ping() *Frame {
	return &Frame{Flags: 0, Type: uint16(FramePing), Channel: uint16(ChanControl), Seq: 0}
}

func TestFrameRoundTrip(t *testing.T) {
	in := &Frame{Flags: FlagENC, Type: 0x0100, Channel: uint16(ChanMemory), Seq: 42, Payload: []byte("payload")}
	buf, err := in.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != HeaderSize+len(in.Payload) {
		t.Fatalf("len = %d", len(buf))
	}
	var out Frame
	if err := out.UnmarshalBinary(buf); err != nil {
		t.Fatal(err)
	}
	if out.Version != ProtocolVersion || out.Flags != FlagENC || out.Type != 0x0100 ||
		out.Channel != uint16(ChanMemory) || out.Seq != 42 || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestCRCValidatedBeforeOtherFields(t *testing.T) {
	buf, _ := ping().MarshalBinary()
	buf[5] ^= 0xFF // corrupt a CRC-covered field without fixing the CRC
	var f Frame
	if err := f.UnmarshalBinary(buf); err != ErrBadCRC {
		t.Fatalf("want ErrBadCRC, got %v", err)
	}
}

func TestBadMagicAfterValidCRC(t *testing.T) {
	buf, _ := ping().MarshalBinary()
	buf[0] = 0x00
	binary.BigEndian.PutUint32(buf[21:25], crc32.Checksum(buf[0:21], castagnoli)) // re-validate CRC
	var f Frame
	if err := f.UnmarshalBinary(buf); err != ErrBadMagic {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

func TestBadVersionAfterValidCRC(t *testing.T) {
	buf, _ := ping().MarshalBinary()
	buf[4] = (buf[4] & 0x0F) | (0x3 << 4)                                         // set version nibble to 3, preserve flags
	binary.BigEndian.PutUint32(buf[21:25], crc32.Checksum(buf[0:21], castagnoli)) // re-validate CRC over mutated prefix
	var f Frame
	if err := f.UnmarshalBinary(buf); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestWireVectorRejectsBadMagic(t *testing.T) {
	// Exact conformance-corpus header.decode tc4 frame: valid CRC over its own
	// prefix, wrong magic (5850414d). Pins the corpus bytes to the reference
	// decoder — dropping the magic check makes this fail.
	buf, err := hex.DecodeString("5850414d2000010000000000000000000000000000f312de9b0000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	var f Frame
	if err := f.UnmarshalBinary(buf); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

func TestWireVectorRejectsBadVersion(t *testing.T) {
	// Exact conformance-corpus header.decode tc5 frame: valid magic and CRC over
	// its own prefix, wrong version nibble (0x3). Pins the corpus bytes to the
	// reference decoder — dropping the version check makes this fail.
	buf, err := hex.DecodeString("4e50414d3000010000000000000000000000000000e19864e00000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	var f Frame
	if err := f.UnmarshalBinary(buf); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestReservedMustBeZero(t *testing.T) {
	buf, _ := ping().MarshalBinary()
	buf[30] = 1 // reserved octet (25..35), not covered by CRC
	var f Frame
	if err := f.UnmarshalBinary(buf); err != ErrReservedNonzero {
		t.Fatalf("want ErrReservedNonzero, got %v", err)
	}
}

func TestShortHeader(t *testing.T) {
	var f Frame
	if err := f.UnmarshalBinary(make([]byte, 10)); err != ErrShortHeader {
		t.Fatalf("want ErrShortHeader, got %v", err)
	}
}

func TestNonceConstruction(t *testing.T) {
	var iv [12]byte
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	n := DeriveNonce(iv, 0x0102030405060708)
	// expected = iv XOR (00 00 00 00 || seq_be8)
	var want [12]byte
	binary.BigEndian.PutUint64(want[4:12], 0x0102030405060708)
	for i := range want {
		want[i] ^= iv[i]
	}
	if n != want {
		t.Fatalf("nonce mismatch: %x != %x", n, want)
	}
	// seq=0 must yield exactly the IV (channel plays no role: there is no channel input)
	if DeriveNonce(iv, 0) != iv {
		t.Fatal("nonce(iv,0) must equal iv (no channel in nonce)")
	}
}

func TestAEADRoundTripAndTamper(t *testing.T) {
	var key [32]byte
	var iv [12]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(0x10 + i)
	}
	aad := make([]byte, 21)
	(&Frame{Type: uint16(FramePing), Channel: uint16(ChanControl)}).HeaderPrefix(aad, 5)
	pt := []byte("hello")
	sealed, err := SealAES256GCM(key, iv, 7, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAES256GCM(key, iv, 7, aad, sealed)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %v %q", err, got)
	}
	aad[5] ^= 1 // tamper associated data
	if _, err := OpenAES256GCM(key, iv, 7, aad, sealed); err == nil {
		t.Fatal("tampered AAD must fail authentication")
	}
}

func TestHkdfPrefixIsProtocolSpecific(t *testing.T) {
	if LabelPrefix != "n-pamp " {
		t.Fatalf("LabelPrefix = %q", LabelPrefix)
	}
	if LabelPrefix == "tls13 " {
		t.Fatal("prefix must NOT be the TLS 1.3 prefix (domain separation)")
	}
	out, err := HkdfExpandLabel(bytes.Repeat([]byte{1}, 32), "key", nil, 32, hashForProfile(ProfileHigh))
	if err != nil || len(out) != 32 {
		t.Fatalf("expand: %v len=%d", err, len(out))
	}
}

func TestProfileInvariants(t *testing.T) {
	if !ProfileStandard.Valid() || !ProfileSovereign.Valid() || Profile(0x04).Valid() {
		t.Fatal("profile validity")
	}
	if ProfileStandard.KDFHash() != "SHA-256" || ProfileHigh.KDFHash() != "SHA-384" {
		t.Fatal("kdf hash")
	}
	if ProfileStandard.MinKEM() != KEMX25519MLKEM768 || ProfileSovereign.MinKEM() != KEMX25519MLKEM1024 {
		t.Fatal("min kem")
	}
}

func TestRegistries(t *testing.T) {
	if ChanSpatial != 0x0013 || ChanControl.Name() != "Control" || !ChannelID(0x0014).Reserved() {
		t.Fatal("channel registry")
	}
	if ALPN != "n-pamp/2" || TLVAnomalyCharge != 0x12 || SigMLDSA87 != 0x0905 {
		t.Fatal("constants")
	}
	if !TLVType(0x8001).ForwardIncompatible() || TLVType(0x12).ForwardIncompatible() {
		t.Fatal("forward-incompat bit")
	}
}
