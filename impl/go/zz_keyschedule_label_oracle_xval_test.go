package npamp

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

const (
	xvSecret32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	xvSecret48 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	xvTHKem    = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

func xvHash(name string) func() hash.Hash {
	if name == "sha384" {
		return sha512.New384
	}
	return sha256.New
}

// TestHkdfExpandLabelOracleCrossValidate proves NON-CIRCULARITY for HKDF-Expand-Label (TRACK C6):
// the OKM bytes below are the ACTUAL output of the independent Python oracle
// (test-vectors/gen/keyschedule_label_oracle.py). That oracle implements HKDF over stdlib
// hmac/hashlib (RFC 5869) and the RFC 8446 §7.1 HkdfLabel with the "n-pamp " prefix, and PROVES its
// own mechanism against RFC 5869 Appendix-A.1 TC1 and RFC 8448 §3 (the "tls13 " prefix) before
// emitting — so these expected values trace to the RFCs, never to impl/go. This asserts
// HkdfExpandLabel reproduces them (the bytes are reproducible ONLY with the "n-pamp " prefix, so a
// "tls13 " impl fails), and that a length beyond 255*HashLen MUST error (RFC 5869 §2.3).
func TestHkdfExpandLabelOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name    string
		hash    string
		secret  string
		label   string
		context string
		length  int
		out     string
	}{
		{"key32_prefix_discriminator", "sha256", xvSecret32, "key", "", 32,
			"3ed9435c451cfedb0cbccdb8e5a8fd957f4e942a834fd1de6ac4aa00de088150"},
		{"iv12", "sha256", xvSecret32, "iv", "", 12, "0d9a0b276cd21e696c09c452"},
		{"finished", "sha256", xvSecret32, "finished", "", 32,
			"e09de935b094501795c653b885cc9f863a9f79a8054daa522658b0d3f6ff4dba"},
		{"c_hs_with_context", "sha256", xvSecret32, "c hs", xvTHKem, 32,
			"01b4c0ef106e5204e5b485fffdea7f8ab7bf08b1960017cd7ecfc3a6d65de82d"},
		{"master_sha384", "sha384", xvSecret48, "master", "", 48,
			"336e8b95fe0a85fdb0cdbdb75af6f646b88d5a7461ac3f005ce6045351b558bfd10166c83c869c5b384b6238b086f436"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secret, _ := hex.DecodeString(c.secret)
			ctx, _ := hex.DecodeString(c.context)
			out, err := HkdfExpandLabel(secret, c.label, ctx, c.length, xvHash(c.hash))
			if err != nil {
				t.Fatalf("expand-label: %v", err)
			}
			if h := hex.EncodeToString(out); h != c.out {
				t.Fatalf("okm mismatch\n got %s\nwant %s", h, c.out)
			}
		})
	}

	t.Run("length_exceeded_MUST_reject", func(t *testing.T) {
		secret, _ := hex.DecodeString(xvSecret32)
		if _, err := HkdfExpandLabel(secret, "key", nil, 255*32+1, sha256.New); err == nil {
			t.Fatal("length > 255*HashLen MUST error, but it succeeded")
		}
	})
}

// TestTrafficKeyIVOracleCrossValidate proves NON-CIRCULARITY for the §5 traffic-key derivation
// (TRACK C6): the (key,iv) bytes below are the ACTUAL output of the same independent, RFC-anchored
// oracle, which builds the traffic context dir(1)||epoch(8 BE)||suite(2 BE)||channel(2 BE) and the
// key/iv Expand-Labels from scratch — NOT dumped from impl/go/keyschedule.go. The direction- and
// channel-discriminator cases produce different keys under the SAME master, proving the tuple is
// actually bound into the schedule.
func TestTrafficKeyIVOracleCrossValidate(t *testing.T) {
	cases := []struct {
		name    string
		profile Profile
		master  string
		dir     Direction
		epoch   uint64
		suite   AEADID
		channel ChannelID
		key     string
		iv      string
	}{
		{"std_c2s_control", ProfileStandard, xvSecret32, DirClientToServer, 0, AEADAES256GCM, ChanControl,
			"4e56739d78066f3f2bd0edf62fb652b3e90398d5c5b95f38287eb1d767e6dacc", "0d45a2552d9ea33375b2d11c"},
		{"std_s2c_dir_discriminator", ProfileStandard, xvSecret32, DirServerToClient, 0, AEADAES256GCM, ChanControl,
			"8d53363df4f41c3b53b1d03d80761ac72bbdf5f6c922226adbfda269e16874c6", "29be009f5364a86090089312"},
		{"std_memory_channel_discriminator", ProfileStandard, xvSecret32, DirClientToServer, 0, AEADAES256GCM, ChanMemory,
			"f9fd0ac17b096ba2e22ff8f8479d88396f878b0a80da26ddded820a590cc86e0", "89e38010d128513dad30099e"},
		{"std_epoch5_chacha_stream", ProfileStandard, xvSecret32, DirClientToServer, 5, AEADChaCha20Poly1305, ChanStream,
			"20024f3e2ae4fdc690cf325c913b703e39a02730bc6c31e15b800eea2068e005", "246cb32f9835b64386faf2b6"},
		{"high_sha384_c2s_control", ProfileHigh, xvSecret48, DirClientToServer, 0, AEADAES256GCM, ChanControl,
			"3563a4d0c367f614c66b012790072de040794c1309e98ec1d82d4c6de3e18c98", "796ce4749ebd77d152784b22"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			master, _ := hex.DecodeString(c.master)
			ts, err := DeriveTrafficSecret(master, c.dir, c.epoch, c.suite, c.channel, c.profile)
			if err != nil {
				t.Fatalf("traffic secret: %v", err)
			}
			key, iv, err := DeriveKeyIV(ts, c.profile)
			if err != nil {
				t.Fatalf("key/iv: %v", err)
			}
			if h := hex.EncodeToString(key[:]); h != c.key {
				t.Fatalf("key = %s, want %s", h, c.key)
			}
			if h := hex.EncodeToString(iv[:]); h != c.iv {
				t.Fatalf("iv = %s, want %s", h, c.iv)
			}
		})
	}
}
