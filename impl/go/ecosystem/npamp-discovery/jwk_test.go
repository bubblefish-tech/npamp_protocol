// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// testPub/testPriv are a fixed, deterministic Ed25519 keypair for tests (determinism, not
// secrecy, is what these tests need).
var testSeed = []byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(testSeed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("priv.Public() did not return ed25519.PublicKey")
	}
	return pub, priv
}

func TestBuildOKPJWKRoundTrips(t *testing.T) {
	pub, _ := testKeypair(t)
	jwk, err := BuildOKPJWK(pub)
	if err != nil {
		t.Fatalf("BuildOKPJWK: %v", err)
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		t.Fatalf("BuildOKPJWK produced kty=%q crv=%q, want OKP/Ed25519", jwk.Kty, jwk.Crv)
	}
	got, err := ParseOKPJWK(jwk)
	if err != nil {
		t.Fatalf("ParseOKPJWK: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("round-tripped key does not equal original: got %x want %x", got, pub)
	}
}

func TestBuildOKPJWKRejectsWrongKeySize(t *testing.T) {
	if _, err := BuildOKPJWK(make([]byte, 16)); err != ErrKeySize {
		t.Fatalf("BuildOKPJWK(16 bytes) error = %v, want ErrKeySize", err)
	}
}

// TestBuildOKPJWKChangesWithKey is the A4 mutation-surviving test: the encoded x field
// must actually depend on the input key.
func TestBuildOKPJWKChangesWithKey(t *testing.T) {
	pubA, _ := testKeypair(t)
	pubB := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pubB, pubA)
	pubB[0] ^= 0xFF
	jwkA, err := BuildOKPJWK(pubA)
	if err != nil {
		t.Fatalf("BuildOKPJWK(A): %v", err)
	}
	jwkB, err := BuildOKPJWK(pubB)
	if err != nil {
		t.Fatalf("BuildOKPJWK(B): %v", err)
	}
	if jwkA.X == jwkB.X {
		t.Fatal("BuildOKPJWK produced the same x field for two different keys")
	}
}

func TestParseOKPJWKRejectsPrivateKeyMaterial(t *testing.T) {
	pub, _ := testKeypair(t)
	jwk, err := BuildOKPJWK(pub)
	if err != nil {
		t.Fatalf("BuildOKPJWK: %v", err)
	}
	jwk.D = base64.RawURLEncoding.EncodeToString([]byte("private-material"))
	if _, err := ParseOKPJWK(jwk); err != ErrPrivateKeyJWK {
		t.Fatalf("ParseOKPJWK(with d) error = %v, want ErrPrivateKeyJWK", err)
	}
}

func TestParseOKPJWKRejectsWrongKty(t *testing.T) {
	pub, _ := testKeypair(t)
	jwk, _ := BuildOKPJWK(pub)
	jwk.Kty = "RSA"
	if _, err := ParseOKPJWK(jwk); err != ErrUnsupportedKty {
		t.Fatalf("ParseOKPJWK(kty=RSA) error = %v, want ErrUnsupportedKty", err)
	}
}

func TestParseOKPJWKRejectsWrongCurve(t *testing.T) {
	pub, _ := testKeypair(t)
	jwk, _ := BuildOKPJWK(pub)
	jwk.Crv = "X25519"
	if _, err := ParseOKPJWK(jwk); err != ErrUnsupportedCurve {
		t.Fatalf("ParseOKPJWK(crv=X25519) error = %v, want ErrUnsupportedCurve", err)
	}
}

func TestParseOKPJWKRejectsMalformedX(t *testing.T) {
	jwk := OKPJWK{Kty: "OKP", Crv: "Ed25519", X: "not-valid-base64url!!!"}
	if _, err := ParseOKPJWK(jwk); err != ErrMalformedJWK {
		t.Fatalf("ParseOKPJWK(bad x) error = %v, want ErrMalformedJWK", err)
	}
}

func TestParseOKPJWKRejectsWrongDecodedLength(t *testing.T) {
	jwk := OKPJWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString([]byte("short"))}
	if _, err := ParseOKPJWK(jwk); err != ErrKeySize {
		t.Fatalf("ParseOKPJWK(short x) error = %v, want ErrKeySize", err)
	}
}

func TestParseOKPJWKBytesRoundTrips(t *testing.T) {
	pub, _ := testKeypair(t)
	jwk, _ := BuildOKPJWK(pub)
	raw := []byte(`{"kty":"` + jwk.Kty + `","crv":"` + jwk.Crv + `","x":"` + jwk.X + `"}`)
	got, err := ParseOKPJWKBytes(raw)
	if err != nil {
		t.Fatalf("ParseOKPJWKBytes: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("ParseOKPJWKBytes round-trip mismatch")
	}
}

func TestParseOKPJWKBytesRejectsEmpty(t *testing.T) {
	if _, err := ParseOKPJWKBytes(nil); err != ErrMalformedJWK {
		t.Fatalf("ParseOKPJWKBytes(nil) error = %v, want ErrMalformedJWK", err)
	}
}
