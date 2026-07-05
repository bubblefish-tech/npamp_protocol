package npamp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"testing"
)

// kemWireKAT mirrors test-vectors/v1/kem-wire-kat.json (ADR-0007):
// standards-derived vectors (NIST ACVP FIPS 203; RFC 7748 section 6.1) that
// pin the X25519MLKEM768 ML-KEM-first wire order (spec/10 section 4,
// ADR-0005).
type kemWireKAT struct {
	KEMCodepoint string `json:"kem_codepoint"`
	Keygen       struct {
		D  string `json:"d"`
		Z  string `json:"z"`
		EK string `json:"ek"`
	} `json:"mlkem768_keygen"`
	X25519 struct {
		AlicePrivate string `json:"alice_private"`
		AlicePublic  string `json:"alice_public"`
		BobPrivate   string `json:"bob_private"`
		BobPublic    string `json:"bob_public"`
		SharedSecret string `json:"shared_secret"`
	} `json:"x25519_rfc7748_6_1"`
	DecapsRef struct {
		SharedSecretK string `json:"shared_secret_K"`
	} `json:"mlkem768_decaps_reference"`
	WireLayout struct {
		KEMShareLen       int `json:"kem_share_len"`
		KEMCiphertextLen  int `json:"kem_ciphertext_len"`
		CombinedSecretLen int `json:"combined_secret_len"`
	} `json:"wire_layout"`
}

// TestKEMWireKAT runs the Go-public-executable legs of the KEM-wire KAT (the
// KAT's coverage.go_public_executable list). The NIST decapsulation anchor
// (expanded-dk import) is NOT executable via Go's seed-only public
// crypto/mlkem API — that limitation is documented in the KAT file itself and
// its shared_secret_K is exercised here only as fixed IKM for the
// combined-secret ordering leg.
func TestKEMWireKAT(t *testing.T) {
	var kat kemWireKAT
	loadKAT(t, "kem-wire-kat.json", &kat)

	if got := mustHexU16(t, "kem_codepoint", kat.KEMCodepoint); KEMID(got) != KEMX25519MLKEM768 {
		t.Fatalf("kem_codepoint = 0x%04x, want 0x%04x", got, uint16(KEMX25519MLKEM768))
	}

	seed := concat(mustHex(t, "d", kat.Keygen.D), mustHex(t, "z", kat.Keygen.Z))
	ekWant := mustHex(t, "ek", kat.Keygen.EK)

	// Leg 1 (NIST FIPS 203 anchor): deterministic ML-KEM-768 keygen from d||z.
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatalf("NewDecapsulationKey768: %v", err)
	}
	if got := dk.EncapsulationKey().Bytes(); !bytes.Equal(got, ekWant) {
		t.Fatalf("ML-KEM-768 ek does not reproduce the NIST ACVP vector")
	}

	// Leg 2 (RFC 7748 section 6.1 anchor): X25519 keypairs and DH.
	alicePriv := mustHex(t, "alice_private", kat.X25519.AlicePrivate)
	alicePub := mustHex(t, "alice_public", kat.X25519.AlicePublic)
	bobPriv := mustHex(t, "bob_private", kat.X25519.BobPrivate)
	bobPub := mustHex(t, "bob_public", kat.X25519.BobPublic)
	xssWant := mustHex(t, "shared_secret", kat.X25519.SharedSecret)

	alice, err := ecdh.X25519().NewPrivateKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := ecdh.X25519().NewPrivateKey(bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(alice.PublicKey().Bytes(), alicePub) || !bytes.Equal(bob.PublicKey().Bytes(), bobPub) {
		t.Fatal("X25519 public keys do not reproduce RFC 7748 section 6.1")
	}
	bobPubKey, err := ecdh.X25519().NewPublicKey(bobPub)
	if err != nil {
		t.Fatal(err)
	}
	aliceSS, err := alice.ECDH(bobPubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceSS, xssWant) {
		t.Fatal("X25519 shared secret does not reproduce RFC 7748 section 6.1")
	}

	// Leg 3 (wire order, KEMShare): the impl's KEMShare MUST be
	// ek (1184) || alice_public (32) — ML-KEM-first (ADR-0005).
	client, err := NewKEMClient(seed, alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	share := client.KEMShare()
	if len(share) != kat.WireLayout.KEMShareLen || len(share) != KEMShareSize768 {
		t.Fatalf("KEMShare is %d octets, want %d", len(share), kat.WireLayout.KEMShareLen)
	}
	if !bytes.Equal(share, concat(ekWant, alicePub)) {
		t.Fatal("KEMShare is not ek || x25519_pub (ML-KEM-first wire order violated)")
	}

	// Leg 4 (wire order, KEMCiphertext + anchored X25519 half): the server
	// encapsulates to the client share using bob's RFC 7748 key; the client
	// parses ct (1088) || bob_public (32) and MUST recover the RFC 7748
	// X25519 shared secret. The ML-KEM shared-secret VALUE on this leg is
	// round-trip (encapsulated here), per the KAT's documented Go-public
	// coverage; its NIST anchor is carried as data for expanded-dk impls.
	ct, serverSS, err := EncapsulateWith(share, bob)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != kat.WireLayout.KEMCiphertextLen || len(ct) != KEMCiphertextSize768 {
		t.Fatalf("KEMCiphertext is %d octets, want %d", len(ct), kat.WireLayout.KEMCiphertextLen)
	}
	if !bytes.Equal(ct[mlkem.CiphertextSize768:], bobPub) {
		t.Fatal("KEMCiphertext is not ct || server_x25519_pub (ML-KEM-first wire order violated)")
	}
	if !bytes.Equal(serverSS.X25519, xssWant) {
		t.Fatal("server X25519 shared secret does not reproduce RFC 7748 section 6.1")
	}
	clientSS, err := client.SharedSecrets(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientSS.X25519, xssWant) {
		t.Fatal("client-decapsulated X25519 shared secret does not reproduce RFC 7748 section 6.1")
	}
	if !bytes.Equal(clientSS.MLKEM, serverSS.MLKEM) {
		t.Fatal("ML-KEM-768 encapsulate/decapsulate round-trip mismatch")
	}
	if got := clientSS.Combined(); len(got) != kat.WireLayout.CombinedSecretLen || !bytes.Equal(got, serverSS.Combined()) {
		t.Fatalf("combined secret: len=%d want %d, or client/server mismatch", len(got), kat.WireLayout.CombinedSecretLen)
	}

	// Leg 5 (IKM order): with the vector's fixed secrets (NIST decaps K, RFC
	// 7748 shared secret), the HKDF-Extract IKM MUST be ML-KEM_SS || X25519_SS
	// and MUST NOT be the reverse.
	kNIST := mustHex(t, "shared_secret_K", kat.DecapsRef.SharedSecretK)
	ssVec := SharedSecrets{MLKEM: kNIST, X25519: xssWant}
	if !bytes.Equal(ssVec.Combined(), concat(kNIST, xssWant)) {
		t.Fatal("Combined() is not ML-KEM_SS || X25519_SS")
	}
	hs, err := HandshakeSecret(ssVec, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	mlkemFirst, err := hkdf.Extract(sha256.New, concat(kNIST, xssWant), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hs, mlkemFirst) {
		t.Fatal("HandshakeSecret != HKDF-Extract(zero salt, ML-KEM_SS || X25519_SS)")
	}
	x25519First, err := hkdf.Extract(sha256.New, concat(xssWant, kNIST), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hs, x25519First) {
		t.Fatal("HandshakeSecret matches the X25519-first IKM order (ADR-0005 violation)")
	}
}
