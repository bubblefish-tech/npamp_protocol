// SPDX-License-Identifier: Apache-2.0

package sdk

// Multi-profile SDK negotiation + CertVerify-dispatch tests (internal
// white-box, package sdk). See multiprofile_test.go (package sdk_test) for
// the end-to-end High-profile session over a real TCP+TLS loopback.

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"encoding/binary"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestDefaultClientHelloOffersStandardOnly is the backward-compatibility
// evidence: a zero-value Config (no Profiles set) MUST produce a CLIENT_HELLO
// whose ProfileOffer / SigOffer TLVs are byte-for-byte the single-element
// [Standard] / [Ed25519] a pre-multi-profile caller produced. It inspects the
// RAW TLV bytes off the wire (not just the decoded Go struct), so a change in
// how the default offer is encoded — not only what it decodes to — is caught.
func TestDefaultClientHelloOffersStandardOnly(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	id, err := resolveIdentity(Config{}) // zero-value: no Profiles, no Identity, no MLDSAIdentity
	if err != nil {
		t.Fatalf("resolveIdentity(zero Config): %v", err)
	}
	if len(id.profiles) != 1 || id.profiles[0] != npamp.ProfileStandard {
		t.Fatalf("resolveIdentity defaulted profiles to %v, want [Standard]", id.profiles)
	}

	// runClientHandshake blocks past CLIENT_HELLO waiting for SERVER_HELLO — this
	// test never sends one, so run the client on its own goroutine (net.Pipe is
	// UNBUFFERED: a synchronous Send-then-Recv here would deadlock the single
	// goroutine on the client's blocking Write) and let b.Close() at test end
	// unblock its subsequent read with an error, at which point it exits.
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, _, e := runClientHandshake(ctx, a, id, nil)
		done <- e
	}()

	payload, err := recvCleartext(b, npamp.FrameClientHello)
	if err != nil {
		t.Fatalf("recv CLIENT_HELLO: %v", err)
	}
	tlvs, err := npamp.DecodeTLVs(payload)
	if err != nil {
		t.Fatalf("decode CLIENT_HELLO TLVs: %v", err)
	}
	if len(tlvs) < 3 {
		t.Fatalf("CLIENT_HELLO carries %d TLVs, want at least 3 (ProfileOffer, KEMOffer, SigOffer)", len(tlvs))
	}
	profileOfferTLV, sigOfferTLV := tlvs[0], tlvs[2]
	if profileOfferTLV.Type != npamp.TLVProfileOffer {
		t.Fatalf("tlvs[0].Type = 0x%04x, want TLVProfileOffer (0x01)", uint16(profileOfferTLV.Type))
	}
	if sigOfferTLV.Type != npamp.TLVSigOffer {
		t.Fatalf("tlvs[2].Type = 0x%04x, want TLVSigOffer (0x05)", uint16(sigOfferTLV.Type))
	}

	wantProfileOffer := []byte{byte(npamp.ProfileStandard)} // exactly 1 octet: Standard (0x01)
	if !bytes.Equal(profileOfferTLV.Value, wantProfileOffer) {
		t.Fatalf("ProfileOffer TLV value = %x, want %x (Standard-only, pre-multi-profile default)", profileOfferTLV.Value, wantProfileOffer)
	}
	wantSigOffer := binary.BigEndian.AppendUint16(nil, uint16(npamp.SigEd25519)) // exactly 2 octets: 0x0807
	if !bytes.Equal(sigOfferTLV.Value, wantSigOffer) {
		t.Fatalf("SigOffer TLV value = %x, want %x (Ed25519-only)", sigOfferTLV.Value, wantSigOffer)
	}

	_ = b.Close() // unblock the goroutine's pending SERVER_HELLO read
	<-done
}

// TestVerifyCertVerifyMLDSA87RejectsTamperedSignature is the mutation anchor
// for the High/Sovereign CertVerify verify path. It is deliberately a small,
// fast, direct call into verifyCertVerify — not a full handshake — so the
// property it proves (a tampered ML-DSA-87 CertVerify is REJECTED, never
// silently accepted) is isolated from everything else the handshake does.
//
// MUTATION ANCHOR (RED-EVIDENCE): replacing the non-Standard branch of
// verifyCertVerify with an always-accept (`return nil`) — or with a call to
// npamp.VerifyCertVerify (the Ed25519 checker) in place of
// npamp.VerifyCertVerifyMLDSA87 — flips this test from PASS to FAIL, because
// the tampered signature below would then be silently accepted (or a
// key-size mismatch would surface as a DIFFERENT, non-representative error
// path). See RED-EVIDENCE.md for the recorded mutation/restore cycle.
func TestVerifyCertVerifyMLDSA87RejectsTamperedSignature(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	pub := priv.PublicKey().Bytes()
	th := bytes.Repeat([]byte{0x42}, 48) // a synthetic SHA-384-sized transcript point; content is opaque here

	valid, err := npamp.SignCertVerifyMLDSA87(priv, npamp.RoleServer, th)
	if err != nil {
		t.Fatalf("SignCertVerifyMLDSA87: %v", err)
	}
	// Sanity: the untampered signature verifies through the SAME dispatch path
	// this test exercises, for BOTH High and Sovereign (both use ML-DSA-87 here).
	for _, p := range []npamp.Profile{npamp.ProfileHigh, npamp.ProfileSovereign} {
		if err := verifyCertVerify(pub, p, npamp.RoleServer, th, valid); err != nil {
			t.Fatalf("verifyCertVerify(%s) rejected a genuinely valid ML-DSA-87 CertVerify: %v", p, err)
		}
	}

	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 0xFF // flip the signature's last octet
	for _, p := range []npamp.Profile{npamp.ProfileHigh, npamp.ProfileSovereign} {
		if err := verifyCertVerify(pub, p, npamp.RoleServer, th, tampered); err == nil {
			t.Fatalf("verifyCertVerify(%s) accepted a TAMPERED ML-DSA-87 CertVerify — the High/Sovereign verify path is not real (always-accept, or a swapped verifier)", p)
		}
	}

	// Role binding: the SAME valid signature, verified against the WRONG role
	// (it was signed for RoleServer), must also be rejected — CertVerifySigningInput
	// mixes the role into the context string, so this is a distinct assertion from
	// the byte-tamper above (it would survive a byte-tamper-only mutant that left
	// role-binding untouched).
	if err := verifyCertVerify(pub, npamp.ProfileHigh, npamp.RoleClient, th, valid); err == nil {
		t.Fatal("verifyCertVerify(High) accepted a server CertVerify presented as a client one")
	}
}
