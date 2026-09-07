// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Provider-path demonstration for N-PAMP's provider-foundation work (requirement
// R2.1; docs/provider-matrix.md). Where hybridkem_kat_test.go grades the combiner
// against fixed RFC 10024 (formerly draft-ietf-tls-ecdhe-mlkem) vectors, this file proves the OTHER
// half of E0.2: that the reference SDK's stdlib provider path (crypto/mlkem +
// crypto/ecdh, as wired in ../kem.go and ../kem1024.go) produces raw component
// shared secrets that flow, in isolation, into the standalone provider-agnostic
// combiner adapter (hybridkem.Combine) and reproduce the reference key schedule's
// HKDF-Extract IKM byte-for-byte, in the correct per-group order. This is the
// concrete provider(E0.2) -> combiner(E0.1) link, exercised on LIVE keys.
//
// It is an external test package (hybridkem_test) so it can import both the
// combiner package under test and the root npamp package (which owns the stdlib
// KEM provider path) without an import cycle: npamp does not import hybridkem.
package hybridkem_test

import (
	"bytes"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/hybridkem"
)

// TestProviderPathX25519MLKEM768 runs a live X25519MLKEM768 exchange through the
// stdlib provider path (crypto/mlkem-768 + crypto/ecdh X25519) and feeds its raw
// component secrets into the standalone combiner adapter, asserting the adapter's
// output equals the reference combiner's and is 64 octets in ML-KEM-first order.
func TestProviderPathX25519MLKEM768(t *testing.T) {
	client, err := npamp.GenerateKEMClient() // stdlib crypto/mlkem-768 + crypto/ecdh X25519
	if err != nil {
		t.Fatalf("GenerateKEMClient: %v", err)
	}
	ct, serverSS, err := npamp.Encapsulate(client.KEMShare()) // server side, stdlib providers
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	clientSS, err := client.SharedSecrets(ct) // client decapsulate, stdlib providers
	if err != nil {
		t.Fatalf("client SharedSecrets: %v", err)
	}

	// The exchange itself must agree on both component secrets.
	if !bytes.Equal(clientSS.MLKEM, serverSS.MLKEM) {
		t.Fatalf("ML-KEM-768 shared secrets disagree between client and server")
	}
	if !bytes.Equal(clientSS.X25519, serverSS.X25519) {
		t.Fatalf("X25519 shared secrets disagree between client and server")
	}
	if len(clientSS.MLKEM) != hybridkem.MLKEMSharedSecretSize {
		t.Fatalf("ML-KEM secret size = %d, want %d", len(clientSS.MLKEM), hybridkem.MLKEMSharedSecretSize)
	}
	if len(clientSS.X25519) != hybridkem.X25519SharedSecretSize {
		t.Fatalf("X25519 secret size = %d, want %d", len(clientSS.X25519), hybridkem.X25519SharedSecretSize)
	}

	// The provider-agnostic adapter must reproduce the reference combiner's IKM
	// byte-for-byte on these LIVE secrets, and be ML-KEM-first (mlkemSS || x25519SS).
	ikm, err := hybridkem.Combine(hybridkem.X25519MLKEM768, clientSS.MLKEM, clientSS.X25519)
	if err != nil {
		t.Fatalf("hybridkem.Combine(X25519MLKEM768): %v", err)
	}
	if want := clientSS.Combined(); !bytes.Equal(ikm, want) {
		t.Fatalf("adapter IKM != reference combiner IKM:\n adapter=%x\n   root=%x", ikm, want)
	}
	if len(ikm) != hybridkem.CombinedSecretSizeX25519MLKEM768 {
		t.Fatalf("combined size = %d, want %d", len(ikm), hybridkem.CombinedSecretSizeX25519MLKEM768)
	}
	if !bytes.Equal(ikm[:hybridkem.MLKEMSharedSecretSize], clientSS.MLKEM) {
		t.Fatalf("combined prefix is not the ML-KEM secret (order wrong: expected ML-KEM-first)")
	}
	if !bytes.Equal(ikm[hybridkem.MLKEMSharedSecretSize:], clientSS.X25519) {
		t.Fatalf("combined suffix is not the X25519 secret (order wrong: expected ML-KEM-first)")
	}
}

// TestProviderPathSecP384r1MLKEM1024 runs a live SecP384r1MLKEM1024 exchange
// through the stdlib provider path (crypto/mlkem-1024 + crypto/ecdh P-384) and
// feeds its raw component secrets into the standalone combiner adapter, asserting
// the adapter's output equals the reference combiner's and is 80 octets in
// P-384-first order (the REVERSE of X25519MLKEM768).
func TestProviderPathSecP384r1MLKEM1024(t *testing.T) {
	client, err := npamp.GenerateKEMClient1024() // stdlib crypto/mlkem-1024 + crypto/ecdh P-384
	if err != nil {
		t.Fatalf("GenerateKEMClient1024: %v", err)
	}
	ct, serverSS, err := npamp.Encapsulate1024(client.KEMShare())
	if err != nil {
		t.Fatalf("Encapsulate1024: %v", err)
	}
	clientSS, err := client.SharedSecrets(ct)
	if err != nil {
		t.Fatalf("client SharedSecrets (1024): %v", err)
	}

	if !bytes.Equal(clientSS.MLKEM, serverSS.MLKEM) {
		t.Fatalf("ML-KEM-1024 shared secrets disagree between client and server")
	}
	if !bytes.Equal(clientSS.ECDHE, serverSS.ECDHE) {
		t.Fatalf("secp384r1 shared secrets disagree between client and server")
	}
	if len(clientSS.ECDHE) != hybridkem.P384SharedSecretSize {
		t.Fatalf("P-384 secret size = %d, want %d", len(clientSS.ECDHE), hybridkem.P384SharedSecretSize)
	}

	// Combine takes (mlkemSS, classicalSS); for this group it emits classicalSS || mlkemSS.
	ikm, err := hybridkem.Combine(hybridkem.SecP384r1MLKEM1024, clientSS.MLKEM, clientSS.ECDHE)
	if err != nil {
		t.Fatalf("hybridkem.Combine(SecP384r1MLKEM1024): %v", err)
	}
	if want := clientSS.Combined(); !bytes.Equal(ikm, want) {
		t.Fatalf("adapter IKM != reference combiner IKM:\n adapter=%x\n   root=%x", ikm, want)
	}
	if len(ikm) != hybridkem.CombinedSecretSizeSecP384r1MLKEM1024 {
		t.Fatalf("combined size = %d, want %d", len(ikm), hybridkem.CombinedSecretSizeSecP384r1MLKEM1024)
	}
	if !bytes.Equal(ikm[:hybridkem.P384SharedSecretSize], clientSS.ECDHE) {
		t.Fatalf("combined prefix is not the P-384 secret (order wrong: expected P-384-first)")
	}
	if !bytes.Equal(ikm[hybridkem.P384SharedSecretSize:], clientSS.MLKEM) {
		t.Fatalf("combined suffix is not the ML-KEM secret (order wrong: expected P-384-first)")
	}
}
