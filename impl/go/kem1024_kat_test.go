// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha512"
	"errors"
	"testing"
)

// RFC 5903 section 8.2 (384-Bit Random ECP Group / Group 20) is the published,
// standards-anchored secp384r1 ECDH known-answer vector. It anchors the ECDHE
// (P-384) leg of the SecP384r1MLKEM1024 KEM-wire KAT non-circularly (F3): the
// expected public keys and the shared-secret x-coordinate come from the RFC,
// never from this implementation — the same role RFC 7748 section 6.1 plays for
// the X25519MLKEM768 KAT.
//
// The ML-KEM-1024 leg is exercised here by round-trip through the real code path.
// Its NIST-ACVP (d,z,ek) value anchor (T18.3, formerly tracked-not-silently-absent)
// is kem1024_acvp_test.go / test-vectors/v1/mlkem1024-acvp-kat.json (E3.3): a
// BoringSSL-vendored NIST/ACVP ML-KEM-1024 keygen vector proves
// crypto/mlkem.NewDecapsulationKey1024(d||z) reproduces the independent ek
// byte-exactly, separately from this file's RFC 5903 ECDHE anchor.
const (
	rfc5903P384InitiatorPriv = "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194"
	rfc5903P384InitiatorX    = "667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA"
	rfc5903P384InitiatorY    = "9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C"
	rfc5903P384ResponderPriv = "41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC"
	rfc5903P384ResponderX    = "E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571"
	rfc5903P384ResponderY    = "DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C"
	rfc5903P384SharedX       = "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746"
)

// TestKEMWireKAT1024 proves the SecP384r1MLKEM1024 (KEM 0x11ed) wire and shared-
// secret ordering is ECDHE-first (P-384 first), matching draft-ietf-tls-ecdhe-
// mlkem — the reverse of the X25519MLKEM768 order. The P-384 legs are anchored
// to RFC 5903 section 8.2; the ordering legs are mutation-surviving (reverting
// to ML-KEM-first fails them).
func TestKEMWireKAT1024(t *testing.T) {
	iPriv := mustHex(t, "i", rfc5903P384InitiatorPriv)
	rPriv := mustHex(t, "r", rfc5903P384ResponderPriv)
	iPubWant := concat(concat([]byte{0x04}, mustHex(t, "gix", rfc5903P384InitiatorX)), mustHex(t, "giy", rfc5903P384InitiatorY))
	rPubWant := concat(concat([]byte{0x04}, mustHex(t, "grx", rfc5903P384ResponderX)), mustHex(t, "gry", rfc5903P384ResponderY))
	girxWant := mustHex(t, "girx", rfc5903P384SharedX)

	// Leg 1 (RFC 5903 anchor): crypto/ecdh P-384 reproduces the RFC public keys
	// (uncompressed 0x04||X||Y) and the shared-secret x-coordinate from the raw
	// private scalars — the wrong curve or a broken ECDH cannot reproduce these.
	iKey, err := ecdh.P384().NewPrivateKey(iPriv)
	if err != nil {
		t.Fatal(err)
	}
	rKey, err := ecdh.P384().NewPrivateKey(rPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(iKey.PublicKey().Bytes(), iPubWant) {
		t.Fatal("initiator public key does not reproduce RFC 5903 section 8.2 (0x04||gix||giy)")
	}
	if !bytes.Equal(rKey.PublicKey().Bytes(), rPubWant) {
		t.Fatal("responder public key does not reproduce RFC 5903 section 8.2 (0x04||grx||gry)")
	}
	rPub, err := ecdh.P384().NewPublicKey(rPubWant)
	if err != nil {
		t.Fatal(err)
	}
	ecdhSS, err := iKey.ECDH(rPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(ecdhSS) != P384SharedSecretSize || !bytes.Equal(ecdhSS, girxWant) {
		t.Fatal("secp384r1 ECDH shared secret does not reproduce RFC 5903 section 8.2 girx (x-coordinate)")
	}

	// Build the real client with the RFC 5903 initiator P-384 key + a fixed
	// ML-KEM-1024 seed, so the KAT drives the production code path.
	seed := make([]byte, 64)
	for j := range seed {
		seed[j] = byte(j)
	}
	client, err := NewKEMClient1024(seed, iPriv)
	if err != nil {
		t.Fatal(err)
	}
	share := client.KEMShare()
	if len(share) != KEMShareSize1024 {
		t.Fatalf("KEMShare is %d octets, want %d", len(share), KEMShareSize1024)
	}

	// Leg 2 (wire order, KEMShare): ECDHE-first — secp384r1 pub (97) precedes
	// the ML-KEM-1024 ek (1568). Reverting to ek-first fails here.
	if !bytes.Equal(share[:P384PublicKeySize], iPubWant) {
		t.Fatal("KEMShare does not begin with the secp384r1 public key (ECDHE-first wire order violated)")
	}

	// Leg 3 (server side, RFC 5903 responder key): the server encapsulates using
	// the RFC 5903 responder P-384 key; its ECDHE half MUST be the RFC girx.
	ct, serverSS, err := EncapsulateWith1024(share, rKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != KEMCiphertextSize1024 {
		t.Fatalf("KEMCiphertext is %d octets, want %d", len(ct), KEMCiphertextSize1024)
	}
	if !bytes.Equal(ct[:P384PublicKeySize], rPubWant) {
		t.Fatal("KEMCiphertext does not begin with the server secp384r1 public key (ECDHE-first wire order violated)")
	}
	if !bytes.Equal(serverSS.ECDHE, girxWant) {
		t.Fatal("server ECDHE shared secret does not reproduce RFC 5903 section 8.2 girx")
	}

	// Leg 4 (client decapsulate): recover the same ECDHE secret + ML-KEM round-trip.
	clientSS, err := client.SharedSecrets(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientSS.ECDHE, girxWant) {
		t.Fatal("client-decapsulated ECDHE shared secret does not reproduce RFC 5903 section 8.2 girx")
	}
	if !bytes.Equal(clientSS.MLKEM, serverSS.MLKEM) {
		t.Fatal("ML-KEM-1024 encapsulate/decapsulate round-trip mismatch")
	}

	// Leg 5 (IKM order — the mutation-surviving core): the combined HKDF-Extract
	// IKM MUST be ECDHE_ss || ML-KEM_ss (P-384 first) and MUST NOT be the reverse
	// (the X25519MLKEM768-style ML-KEM-first order). Reverting kem1024's
	// Combined() to ML-KEM-first fails both assertions.
	combined := clientSS.Combined()
	if len(combined) != CombinedSecretSize1024 {
		t.Fatalf("combined secret is %d octets, want %d", len(combined), CombinedSecretSize1024)
	}
	if !bytes.Equal(combined, concat(girxWant, clientSS.MLKEM)) {
		t.Fatal("Combined() is not ECDHE_ss || ML-KEM_ss (SecP384r1MLKEM1024 must be P-384-first)")
	}
	if bytes.Equal(combined, concat(clientSS.MLKEM, girxWant)) {
		t.Fatal("Combined() matches the ML-KEM-first IKM order (that is the 768 order, not SecP384r1MLKEM1024)")
	}
	if !bytes.Equal(clientSS.Combined(), serverSS.Combined()) {
		t.Fatal("client/server combined secret mismatch")
	}
}

// TestHandshakeSecret1024KAT proves HandshakeSecret1024 (keyschedule.go)
// against an independent HKDF-Extract oracle (this test's own crypto/hkdf
// call, never HandshakeSecret1024 itself — F3 non-circularity) over the RFC
// 5903 section 8.2-anchored ECDHE secret combined ECDHE-first with a fixed
// synthetic ML-KEM shared secret, per spec/10 section 5 / section 4a. The
// ML-KEM leg's real encapsulate/decapsulate round trip is already anchored by
// TestKEMWireKAT1024 above; this test isolates the HandshakeSecret1024
// combiner (HKDF-Extract, SHA-384, ECDHE-first ordering) the way
// TestKeyScheduleKAT isolates HandshakeSecret with fixed-hex IKM legs.
func TestHandshakeSecret1024KAT(t *testing.T) {
	ecdheSS := mustHex(t, "girx", rfc5903P384SharedX) // RFC 5903 section 8.2 anchor (48 octets)
	mlkemSS := make([]byte, 32)
	for i := range mlkemSS {
		mlkemSS[i] = byte(0xA0 + i) // fixed synthetic ML-KEM shared secret (opaque IKM here; the real ML-KEM leg is anchored above)
	}
	ss := SharedSecrets1024{ECDHE: ecdheSS, MLKEM: mlkemSS}

	for _, p := range []Profile{ProfileHigh, ProfileSovereign} {
		got, err := HandshakeSecret1024(ss, p)
		if err != nil {
			t.Fatalf("HandshakeSecret1024(%s): %v", p, err)
		}
		if len(got) != sha512.Size384 {
			t.Fatalf("HandshakeSecret1024(%s) is %d octets, want %d (SHA-384 HashLen)", p, len(got), sha512.Size384)
		}
		// Independent oracle: HKDF-Extract(salt = 48 zero octets, IKM = ECDHE_SS || ML-KEM_SS).
		want, err := hkdf.Extract(sha512.New384, ss.Combined(), make([]byte, sha512.Size384))
		if err != nil {
			t.Fatalf("oracle HKDF-Extract: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("HandshakeSecret1024(%s) != HKDF-Extract(48 zero octets, ECDHE_SS || ML-KEM_SS)", p)
		}

		// Mutation guard: the reversed (ML-KEM-first, X25519MLKEM768-style) IKM order
		// MUST NOT match. Reverting SharedSecrets1024.Combined() to ML-KEM-first fails this.
		reversedIKM := concat(mlkemSS, ecdheSS)
		reversed, err := hkdf.Extract(sha512.New384, reversedIKM, make([]byte, sha512.Size384))
		if err != nil {
			t.Fatalf("oracle reversed HKDF-Extract: %v", err)
		}
		if bytes.Equal(got, reversed) {
			t.Fatalf("HandshakeSecret1024(%s) matches the ML-KEM-first IKM order (SecP384r1MLKEM1024 must be ECDHE-first)", p)
		}
	}

	// Fail-closed guard: ProfileStandard must never reach this combiner (it uses
	// HandshakeSecret + SharedSecrets, not HandshakeSecret1024).
	if _, err := HandshakeSecret1024(ss, ProfileStandard); !errors.Is(err, ErrHandshakeSecret1024StandardProfile) {
		t.Fatalf("HandshakeSecret1024(ProfileStandard) = %v, want ErrHandshakeSecret1024StandardProfile", err)
	}
}
