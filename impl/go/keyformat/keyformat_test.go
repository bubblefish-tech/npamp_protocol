// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package keyformat

// keyformat_test.go exercises the round-trip and typed-accessor behavior of
// the versioned key-storage format against REAL key material produced by the
// same stdlib crypto types the rest of this module uses (crypto/mlkem,
// crypto/ecdh, crypto/ed25519) — not fixtures invented for this test. Each
// round trip additionally reconstructs a live, USABLE key from the decoded
// bytes (a fresh mlkem.DecapsulationKey / ecdh.PrivateKey / ed25519 sign-
// verify) to prove the format carries genuinely reusable key material, not
// merely bytes that happen to compare equal.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestRoundTripEd25519SigPrivateAndPublic encodes and decodes a real Ed25519
// identity key pair (the same crypto/ed25519 type impl/go/handshake.go and
// impl/go/sdk use for CertVerify), then proves the decoded keys are still
// live and correct by signing with the decoded private key and verifying
// with the decoded public key.
func TestRoundTripEd25519SigPrivateAndPublic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	privData, err := EncodeSigPrivate(npamp.SigEd25519, priv)
	if err != nil {
		t.Fatalf("EncodeSigPrivate: %v", err)
	}
	pubData, err := EncodeSigPublic(npamp.SigEd25519, pub)
	if err != nil {
		t.Fatalf("EncodeSigPublic: %v", err)
	}

	gotAlg, gotPriv, err := DecodeSigPrivate(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPrivate: %v", err)
	}
	if gotAlg != npamp.SigEd25519 {
		t.Fatalf("decoded algorithm = 0x%04x, want SigEd25519 (0x%04x)", uint16(gotAlg), uint16(npamp.SigEd25519))
	}
	if !bytes.Equal(gotPriv, priv) {
		t.Fatal("decoded Ed25519 private key material is not byte-identical to the original")
	}

	// Explicit metadata check via the low-level Decode, not just the typed
	// accessor's algorithm return: FormatVersion and Generation must round
	// trip correctly too, not merely "decode without error".
	privRec, err := Decode(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("Decode(privData): %v", err)
	}
	if privRec.FormatVersion != CurrentFormatVersion {
		t.Fatalf("decoded FormatVersion = %d, want %d", privRec.FormatVersion, CurrentFormatVersion)
	}
	if privRec.Generation != npamp.ALPN {
		t.Fatalf("decoded Generation = %q, want %q", privRec.Generation, npamp.ALPN)
	}
	if privRec.Role != RoleSigPrivate {
		t.Fatalf("decoded Role = %v, want %v", privRec.Role, RoleSigPrivate)
	}

	gotAlg2, gotPub, err := DecodeSigPublic(pubData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPublic: %v", err)
	}
	if gotAlg2 != npamp.SigEd25519 {
		t.Fatalf("decoded algorithm = 0x%04x, want SigEd25519 (0x%04x)", uint16(gotAlg2), uint16(npamp.SigEd25519))
	}
	if !bytes.Equal(gotPub, pub) {
		t.Fatal("decoded Ed25519 public key material is not byte-identical to the original")
	}

	// Functional proof, not just byte comparison: the decoded private key
	// must still produce signatures the decoded public key verifies.
	msg := []byte("keyformat round-trip probe")
	sig := ed25519.Sign(ed25519.PrivateKey(gotPriv), msg)
	if !ed25519.Verify(ed25519.PublicKey(gotPub), msg, sig) {
		t.Fatal("signature made with the decoded private key does not verify under the decoded public key")
	}
}

// TestRoundTripX25519MLKEM768KEMPrivateAndPublic encodes and decodes a real
// X25519MLKEM768 hybrid-KEM key pair built directly from crypto/mlkem and
// crypto/ecdh (the same providers impl/go/kem.go wraps), then proves the
// decoded private key reconstructs the identical live decapsulation key
// (its re-derived encapsulation key matches the original byte-for-byte).
func TestRoundTripX25519MLKEM768KEMPrivateAndPublic(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("mlkem.GenerateKey768: %v", err)
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh X25519 GenerateKey: %v", err)
	}

	privData, err := EncodeKEMPrivate(npamp.KEMX25519MLKEM768, dk.Bytes(), xk.Bytes())
	if err != nil {
		t.Fatalf("EncodeKEMPrivate: %v", err)
	}
	pubData, err := EncodeKEMPublic(npamp.KEMX25519MLKEM768, dk.EncapsulationKey().Bytes(), xk.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("EncodeKEMPublic: %v", err)
	}

	group, seed2, xpriv2, err := DecodeKEMPrivate(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeKEMPrivate: %v", err)
	}
	if group != npamp.KEMX25519MLKEM768 {
		t.Fatalf("decoded group = 0x%04x, want 0x%04x", uint16(group), uint16(npamp.KEMX25519MLKEM768))
	}
	if !bytes.Equal(seed2, dk.Bytes()) {
		t.Fatal("decoded ML-KEM-768 seed is not byte-identical to the original")
	}
	if !bytes.Equal(xpriv2, xk.Bytes()) {
		t.Fatal("decoded X25519 private key is not byte-identical to the original")
	}

	// Functional proof: reconstruct live keys from the decoded bytes and
	// confirm they reproduce the identical public materials.
	dk2, err := mlkem.NewDecapsulationKey768(seed2)
	if err != nil {
		t.Fatalf("mlkem.NewDecapsulationKey768(decoded seed): %v", err)
	}
	if !bytes.Equal(dk2.EncapsulationKey().Bytes(), dk.EncapsulationKey().Bytes()) {
		t.Fatal("decapsulation key reconstructed from the decoded seed has a different encapsulation key")
	}
	xk2, err := ecdh.X25519().NewPrivateKey(xpriv2)
	if err != nil {
		t.Fatalf("ecdh X25519 NewPrivateKey(decoded bytes): %v", err)
	}
	if !bytes.Equal(xk2.PublicKey().Bytes(), xk.PublicKey().Bytes()) {
		t.Fatal("X25519 private key reconstructed from the decoded bytes has a different public key")
	}

	group2, mlkemEK2, xpub2, err := DecodeKEMPublic(pubData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeKEMPublic: %v", err)
	}
	if group2 != npamp.KEMX25519MLKEM768 {
		t.Fatalf("decoded public-record group = 0x%04x, want 0x%04x", uint16(group2), uint16(npamp.KEMX25519MLKEM768))
	}
	if !bytes.Equal(mlkemEK2, dk.EncapsulationKey().Bytes()) {
		t.Fatal("decoded ML-KEM-768 encapsulation key is not byte-identical to the original")
	}
	if !bytes.Equal(xpub2, xk.PublicKey().Bytes()) {
		t.Fatal("decoded X25519 public key is not byte-identical to the original")
	}
}

// TestRoundTripSecP384r1MLKEM1024KEMPrivateAndPublic is
// TestRoundTripX25519MLKEM768KEMPrivateAndPublic for the Sovereign/High
// group (ML-KEM-1024 + P-384), confirming the format's KEM handling is not
// accidentally specific to the 768/X25519 group's component sizes.
func TestRoundTripSecP384r1MLKEM1024KEMPrivateAndPublic(t *testing.T) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatalf("mlkem.GenerateKey1024: %v", err)
	}
	pk, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh P384 GenerateKey: %v", err)
	}

	privData, err := EncodeKEMPrivate(npamp.KEMSecP384r1MLKEM1024, dk.Bytes(), pk.Bytes())
	if err != nil {
		t.Fatalf("EncodeKEMPrivate: %v", err)
	}
	pubData, err := EncodeKEMPublic(npamp.KEMSecP384r1MLKEM1024, dk.EncapsulationKey().Bytes(), pk.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("EncodeKEMPublic: %v", err)
	}

	group, seed2, ppriv2, err := DecodeKEMPrivate(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeKEMPrivate: %v", err)
	}
	if group != npamp.KEMSecP384r1MLKEM1024 {
		t.Fatalf("decoded group = 0x%04x, want 0x%04x", uint16(group), uint16(npamp.KEMSecP384r1MLKEM1024))
	}
	if !bytes.Equal(seed2, dk.Bytes()) {
		t.Fatal("decoded ML-KEM-1024 seed is not byte-identical to the original")
	}
	if !bytes.Equal(ppriv2, pk.Bytes()) {
		t.Fatal("decoded P-384 private key is not byte-identical to the original")
	}

	dk2, err := mlkem.NewDecapsulationKey1024(seed2)
	if err != nil {
		t.Fatalf("mlkem.NewDecapsulationKey1024(decoded seed): %v", err)
	}
	if !bytes.Equal(dk2.EncapsulationKey().Bytes(), dk.EncapsulationKey().Bytes()) {
		t.Fatal("decapsulation key reconstructed from the decoded seed has a different encapsulation key")
	}
	pk2, err := ecdh.P384().NewPrivateKey(ppriv2)
	if err != nil {
		t.Fatalf("ecdh P384 NewPrivateKey(decoded bytes): %v", err)
	}
	if !bytes.Equal(pk2.PublicKey().Bytes(), pk.PublicKey().Bytes()) {
		t.Fatal("P-384 private key reconstructed from the decoded bytes has a different public key")
	}

	group2, mlkemEK2, ppub2, err := DecodeKEMPublic(pubData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeKEMPublic: %v", err)
	}
	if group2 != npamp.KEMSecP384r1MLKEM1024 {
		t.Fatalf("decoded public-record group = 0x%04x, want 0x%04x", uint16(group2), uint16(npamp.KEMSecP384r1MLKEM1024))
	}
	if !bytes.Equal(mlkemEK2, dk.EncapsulationKey().Bytes()) {
		t.Fatal("decoded ML-KEM-1024 encapsulation key is not byte-identical to the original")
	}
	if !bytes.Equal(ppub2, pk.PublicKey().Bytes()) {
		t.Fatal("decoded P-384 public key is not byte-identical to the original")
	}
}

// TestRoundTripMLDSA87OpaqueMaterial confirms the format can carry ML-DSA-87
// key material at its registered FIPS 204 sizes even though this Go
// toolchain has no stdlib ML-DSA type to construct a live key from — this is
// the documented "opaque bytes" case (see keyformat.go's registry doc
// comment and doc.go). The bytes here are NOT a real ML-DSA key pair (there
// is nothing in this Go tree that can generate one); this test proves only
// that the size-gated storage round trip is honest for this algorithm
// family, not that this package can sign or verify with it.
func TestRoundTripMLDSA87OpaqueMaterial(t *testing.T) {
	pub := make([]byte, 2592) // FIPS 204 Table 2 ML-DSA-87 public-key size
	if _, err := rand.Read(pub); err != nil {
		t.Fatalf("rand.Read(pub): %v", err)
	}
	priv := make([]byte, 4896) // FIPS 204 Table 2 ML-DSA-87 private-key size
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand.Read(priv): %v", err)
	}

	pubData, err := EncodeSigPublic(npamp.SigMLDSA87, pub)
	if err != nil {
		t.Fatalf("EncodeSigPublic(SigMLDSA87): %v", err)
	}
	privData, err := EncodeSigPrivate(npamp.SigMLDSA87, priv)
	if err != nil {
		t.Fatalf("EncodeSigPrivate(SigMLDSA87): %v", err)
	}

	gotPubAlg, gotPub, err := DecodeSigPublic(pubData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPublic(SigMLDSA87): %v", err)
	}
	if gotPubAlg != npamp.SigMLDSA87 || !bytes.Equal(gotPub, pub) {
		t.Fatal("ML-DSA-87 public-key round trip did not reproduce the original algorithm/bytes")
	}

	gotPrivAlg, gotPriv, err := DecodeSigPrivate(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPrivate(SigMLDSA87): %v", err)
	}
	if gotPrivAlg != npamp.SigMLDSA87 || !bytes.Equal(gotPriv, priv) {
		t.Fatal("ML-DSA-87 private-key round trip did not reproduce the original algorithm/bytes")
	}

	// Wrong size for the algorithm MUST be rejected, not silently accepted.
	if _, err := EncodeSigPublic(npamp.SigMLDSA87, pub[:len(pub)-1]); err != ErrComponentSize {
		t.Fatalf("EncodeSigPublic(SigMLDSA87, short key): err = %v, want %v", err, ErrComponentSize)
	}
}

// TestEncodeIsDeterministic confirms re-encoding a decoded record reproduces
// the exact original wire bytes — the property a "deterministic CBOR" claim
// actually promises, checked directly rather than assumed.
func TestEncodeIsDeterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	data, err := EncodeSigPublic(npamp.SigEd25519, pub)
	if err != nil {
		t.Fatalf("EncodeSigPublic: %v", err)
	}
	rec, err := Decode(data, npamp.ALPN)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	reEncoded, err := Encode(rec)
	if err != nil {
		t.Fatalf("Encode(decoded record): %v", err)
	}
	if !bytes.Equal(data, reEncoded) {
		t.Fatal("re-encoding a decoded record did not reproduce the original bytes")
	}
}
