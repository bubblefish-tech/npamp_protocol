package npamp

import (
	"encoding/hex"
	"testing"
)

// TestNonceDeriveOracleCrossValidate proves NON-CIRCULARITY for the per-frame nonce (TRACK C5): the
// nonce bytes below are the ACTUAL output of the independent Python oracle
// (test-vectors/gen/nonce_tlv_oracle.py), computed from scratch as iv XOR (0^4 || seq_BE64) per
// spec/06 §"Key Schedule and Nonces" (the Channel ID is NOT mixed in) — NOT dumped from
// impl/go/aead.go DeriveNonce. This asserts DeriveNonce reproduces those bytes for seq 0
// (nonce == iv), a low-octet seq, a high seq folded into octets 4..11, and a full-width XOR.
func TestNonceDeriveOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name  string
		iv    string
		seq   uint64
		nonce string
	}{
		{"seq_zero_identity", "a0a1a2a3a4a5a6a7a8a9aaab", 0, "a0a1a2a3a4a5a6a7a8a9aaab"},
		{"low_octet", "a0a1a2a3a4a5a6a7a8a9aaab", 1, "a0a1a2a3a4a5a6a7a8a9aaaa"},
		{"high_seq", "000000000000000000000000", 0x00000000ff00000a, "0000000000000000ff00000a"},
		{"full_width_xor", "ffffffffffffffffffffffff", 0x0102030405060708, "fffffffffefdfcfbfaf9f8f7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ivb, err := hex.DecodeString(c.iv)
			if err != nil || len(ivb) != 12 {
				t.Fatalf("bad iv hex: %v", err)
			}
			var iv [12]byte
			copy(iv[:], ivb)
			got := DeriveNonce(iv, c.seq)
			if h := hex.EncodeToString(got[:]); h != c.nonce {
				t.Fatalf("nonce = %s, want %s", h, c.nonce)
			}
		})
	}
}

// TestTLVEncodeOracleCrossValidate proves NON-CIRCULARITY for the extension-TLV wire encoding
// (TRACK C5): the TLV bytes below are the ACTUAL output of the independent Python oracle
// (test-vectors/gen/nonce_tlv_oracle.py), assembled from scratch as Type(BE16)||Length(BE16)||Value
// per spec/02 §"Extension TLV encoding" — NOT dumped from impl/go/tlv.go TLV.Encode. It asserts
// TLV.Encode reproduces those bytes, including a zero-length value and a forward-incompatible
// (high-bit) type, whose ENCODING is legal even though DECODING an unknown one MUST reject.
func TestTLVEncodeOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name  string
		typ   TLVType
		value string
		tlv   string
	}{
		{"path_challenge", 0x0015, "1111111111111111111111111111111111111111111111111111111111111111",
			"001500201111111111111111111111111111111111111111111111111111111111111111"},
		{"zero_length", 0x0002, "", "00020000"},
		{"keyupdate_marker", 0x0017, "0001020304050607", "001700080001020304050607"},
		{"ratchet_generation", 0x0019, "0000000000000005", "001900080000000000000005"},
		{"high_bit_type_legal", 0x8001, "abcd", "80010002abcd"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			val, err := hex.DecodeString(c.value)
			if err != nil {
				t.Fatalf("bad value hex: %v", err)
			}
			got := TLV{Type: c.typ, Value: val}.Encode(nil)
			if h := hex.EncodeToString(got); h != c.tlv {
				t.Fatalf("tlv encode = %s, want %s", h, c.tlv)
			}
		})
	}
}
