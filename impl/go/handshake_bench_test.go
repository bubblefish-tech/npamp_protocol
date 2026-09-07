// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// Benchmarks in this file measure the per-flight cost of the N-PAMP handshake's real
// primitives: the X25519MLKEM768 hybrid KEM exchange, the HKDF key-schedule chain, the
// TLV flight codecs, and the CertVerify/Finished authentication steps. Measure with a
// NON-race build: `cd impl/go && GOWORK=off go test -bench=. -benchmem -run=^$`. Do not
// pin a headline ns/op captured under `go test -race` -- race instrumentation distorts
// timings by different factors on different code paths.

// benchStandardKEMExchange returns a ready KEMClient plus the server's KEMCiphertext,
// so BenchmarkKEMClientSharedSecrets can measure decapsulation in isolation without
// including key generation or encapsulation in its own loop.
func benchStandardKEMExchange(b *testing.B) (*KEMClient, []byte) {
	b.Helper()
	client, err := GenerateKEMClient()
	if err != nil {
		b.Fatal(err)
	}
	ct, _, err := Encapsulate(client.KEMShare())
	if err != nil {
		b.Fatal(err)
	}
	return client, ct
}

// BenchmarkKEMClientGenerate measures generating a fresh client KEM state (an
// ML-KEM-768 key pair plus an X25519 key pair) -- the client's CLIENT_HELLO-side cost.
func BenchmarkKEMClientGenerate(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := GenerateKEMClient(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKEMEncapsulate measures the server's SERVER_HELLO-side cost: parsing the
// client's KEMShare, encapsulating to it, and performing X25519 with a fresh server key.
func BenchmarkKEMEncapsulate(b *testing.B) {
	client, err := GenerateKEMClient()
	if err != nil {
		b.Fatal(err)
	}
	share := client.KEMShare()
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := Encapsulate(share); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKEMClientSharedSecrets measures the client's post-SERVER_HELLO cost:
// decapsulating the server's KEMCiphertext into the two component shared secrets.
func BenchmarkKEMClientSharedSecrets(b *testing.B) {
	client, ct := benchStandardKEMExchange(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := client.SharedSecrets(ct); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFullKEMExchange measures the complete client-generate + server-encapsulate +
// client-decapsulate round trip -- the full per-connection KEM cost of one handshake.
func BenchmarkFullKEMExchange(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		client, err := GenerateKEMClient()
		if err != nil {
			b.Fatal(err)
		}
		ct, _, err := Encapsulate(client.KEMShare())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := client.SharedSecrets(ct); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClientHelloEncode / Decode measure the CLIENT_HELLO TLV flight codec at
// Standard profile (X25519MLKEM768's 1216-octet KEMShare).
func BenchmarkClientHelloEncode(b *testing.B) {
	ch := &ClientHello{
		ProfileOffer: []Profile{ProfileStandard, ProfileHigh, ProfileSovereign},
		KEMOffer:     []KEMID{KEMX25519MLKEM768, KEMSecP384r1MLKEM1024},
		SigOffer:     []SigID{SigEd25519},
		AEADOffer:    []AEADID{AEADAES256GCM, AEADChaCha20Poly1305},
		KEMShare:     bytes.Repeat([]byte{0xAB}, KEMShareSize768),
	}
	b.ReportAllocs()
	for b.Loop() {
		ch.Encode()
	}
}

func BenchmarkClientHelloDecode(b *testing.B) {
	ch := &ClientHello{
		ProfileOffer: []Profile{ProfileStandard, ProfileHigh, ProfileSovereign},
		KEMOffer:     []KEMID{KEMX25519MLKEM768, KEMSecP384r1MLKEM1024},
		SigOffer:     []SigID{SigEd25519},
		AEADOffer:    []AEADID{AEADAES256GCM, AEADChaCha20Poly1305},
		KEMShare:     bytes.Repeat([]byte{0xAB}, KEMShareSize768),
	}
	payload := ch.Encode()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeClientHello(payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthMessageEncode / Decode measure the SERVER_AUTH/CLIENT_AUTH TLV codec
// (IdentityKey, CertVerify, Finished), which every handshake exchanges twice.
func BenchmarkAuthMessageEncode(b *testing.B) {
	am := &AuthMessage{
		IdentityKey: bytes.Repeat([]byte{0x01}, ed25519.PublicKeySize),
		CertVerify:  bytes.Repeat([]byte{0x02}, 2+ed25519.SignatureSize),
		Finished:    bytes.Repeat([]byte{0x03}, 32),
	}
	b.ReportAllocs()
	for b.Loop() {
		am.Encode()
	}
}

func BenchmarkAuthMessageDecode(b *testing.B) {
	am := &AuthMessage{
		IdentityKey: bytes.Repeat([]byte{0x01}, ed25519.PublicKeySize),
		CertVerify:  bytes.Repeat([]byte{0x02}, 2+ed25519.SignatureSize),
		Finished:    bytes.Repeat([]byte{0x03}, 32),
	}
	payload := am.Encode()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeAuthMessage(payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignCertVerify / VerifyCertVerify measure the CertVerify authentication
// step (Ed25519 sign / verify over the RFC-9846-style signing input) at Standard profile.
func BenchmarkSignCertVerify(b *testing.B) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	th := bytes.Repeat([]byte{0x11}, 32) // a SHA-256-sized transcript hash (Standard profile)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := SignCertVerify(priv, RoleClient, th); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyCertVerify(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	th := bytes.Repeat([]byte{0x11}, 32)
	cv, err := SignCertVerify(priv, RoleClient, th)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := VerifyCertVerify(pub, RoleClient, th, cv); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkComputeFinished / VerifyFinished measure the Finished MAC step at
// Standard profile (HMAC-SHA-256).
func BenchmarkComputeFinished(b *testing.B) {
	key := bytes.Repeat([]byte{0x22}, 32)
	th := bytes.Repeat([]byte{0x33}, 32)
	b.ReportAllocs()
	for b.Loop() {
		ComputeFinished(key, th, ProfileStandard)
	}
}

func BenchmarkVerifyFinished(b *testing.B) {
	key := bytes.Repeat([]byte{0x22}, 32)
	th := bytes.Repeat([]byte{0x33}, 32)
	vd := ComputeFinished(key, th, ProfileStandard)
	b.ReportAllocs()
	for b.Loop() {
		if err := VerifyFinished(key, th, vd, ProfileStandard); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHandshakeKeySchedule measures the full HKDF key-schedule chain from a
// completed KEM exchange to the per-direction handshake and master secrets: the
// per-connection cost that is otherwise invisible inside the KEM/Auth benchmarks above.
func BenchmarkHandshakeKeySchedule(b *testing.B) {
	client, ct := benchStandardKEMExchange(b)
	ss, err := client.SharedSecrets(ct)
	if err != nil {
		b.Fatal(err)
	}
	thKEM := bytes.Repeat([]byte{0x44}, 32)
	thCCV := bytes.Repeat([]byte{0x55}, 32)
	b.ReportAllocs()
	for b.Loop() {
		hs, err := HandshakeSecret(ss, ProfileStandard)
		if err != nil {
			b.Fatal(err)
		}
		cHS, sHS, err := DeriveHandshakeTrafficSecrets(hs, thKEM, ProfileStandard)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DeriveMasterSecret(hs, thCCV, ProfileStandard); err != nil {
			b.Fatal(err)
		}
		if _, err := DeriveFinishedKey(cHS, ProfileStandard); err != nil {
			b.Fatal(err)
		}
		if _, err := DeriveFinishedKey(sHS, ProfileStandard); err != nil {
			b.Fatal(err)
		}
	}
}
