// SPDX-License-Identifier: Apache-2.0

package sdk

// KEM-group wiring tests for High/Sovereign (spec/05_profiles.md "Minimum
// KEM"; spec/10 section 4a): these prove the SDK actually negotiates
// SecP384r1MLKEM1024 for High/Sovereign — not merely that a High-profile
// session completes (multiprofile_test.go's TestHighProfileSessionEndToEnd
// covers that, but a session using X25519MLKEM768 throughout would ALSO pass
// it) — and that a High/Sovereign-offering client refuses a peer that selects
// the weaker X25519MLKEM768 group (downgrade refusal).

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestHighOnlyClientOffersSecP384r1MLKEM1024 inspects the RAW CLIENT_HELLO
// TLV bytes (not just the decoded Go struct) of a client offering only
// ProfileHigh: KEMOffer MUST be exactly [SecP384r1MLKEM1024] (0x11ed), and
// KEMShare MUST be KEMShareSize1024 (1665) octets — the SecP384r1MLKEM1024
// wire size, never KEMShareSize768 (1216).
//
// MUTATION ANCHOR (RED-EVIDENCE): reverting kemGroupForProfiles to always
// return npamp.KEMX25519MLKEM768 (the pre-fix behavior) flips both assertions
// below from PASS to FAIL — the KEMOffer value decodes to 0x11ec and the
// KEMShare is 1216 octets instead of 1665.
func TestHighOnlyClientOffersSecP384r1MLKEM1024(t *testing.T) {
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	id, err := resolveIdentity(Config{
		MLDSAIdentity: mldsaKey,
		Profiles:      []npamp.Profile{npamp.ProfileHigh},
	})
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}

	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

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
	if len(tlvs) < 5 {
		t.Fatalf("CLIENT_HELLO carries %d TLVs, want 5 (ProfileOffer, KEMOffer, SigOffer, AEADOffer, KEMShare)", len(tlvs))
	}
	kemOfferTLV, kemShareTLV := tlvs[1], tlvs[4]
	if kemOfferTLV.Type != npamp.TLVKEMOffer {
		t.Fatalf("tlvs[1].Type = 0x%04x, want TLVKEMOffer (0x03)", uint16(kemOfferTLV.Type))
	}
	if kemShareTLV.Type != npamp.TLVKEMShare {
		t.Fatalf("tlvs[4].Type = 0x%04x, want TLVKEMShare (0x07)", uint16(kemShareTLV.Type))
	}

	wantKEMOffer := binary.BigEndian.AppendUint16(nil, uint16(npamp.KEMSecP384r1MLKEM1024)) // exactly 0x11ed
	if !bytes.Equal(kemOfferTLV.Value, wantKEMOffer) {
		t.Fatalf("KEMOffer TLV value = %x, want %x (SecP384r1MLKEM1024 only)", kemOfferTLV.Value, wantKEMOffer)
	}
	if len(kemShareTLV.Value) != npamp.KEMShareSize1024 {
		t.Fatalf("KEMShare TLV is %d octets, want %d (SecP384r1MLKEM1024)", len(kemShareTLV.Value), npamp.KEMShareSize1024)
	}

	_ = b.Close() // unblock the goroutine's pending SERVER_HELLO read
	<-done
}

// TestHighClientRefusesKEMDowngrade drives a real ProfileHigh-only client
// (which therefore generated key material ONLY for SecP384r1MLKEM1024) up to
// a hand-crafted, deviant SERVER_HELLO that selects ProfileHigh (which the
// client DID offer) but with KEMSelect = X25519MLKEM768 — the KEM group a
// Standard-only peer would use — and asserts the client refuses with
// ErrKEMDowngrade rather than attempting to decapsulate (which would either
// panic on the nil 768 KEM client or silently proceed with mismatched
// primitives). This is the wire-level test of spec/05_profiles.md's "High …
// downgrade refusal to Standard" and spec/10 section 4a's "Sovereign MUST NOT
// accept X25519MLKEM768" carried down to High.
//
// MUTATION ANCHOR (RED-EVIDENCE): deleting the `sh.KEMSelect != wantKEM` case
// from requireSelections flips this test from PASS to FAIL — the client would
// then attempt `kem1024.SharedSecrets(sh.KEMCiphertext)` against a 1120-octet
// (768-sized) ciphertext, which errors with a generic size mismatch rather
// than the named ErrKEMDowngrade the test checks for via errors.Is, so the
// test's errors.Is assertion fails.
func TestHighClientRefusesKEMDowngrade(t *testing.T) {
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("mldsa.GenerateKey: %v", err)
	}
	id, err := resolveIdentity(Config{
		MLDSAIdentity: mldsaKey,
		Profiles:      []npamp.Profile{npamp.ProfileHigh},
	})
	if err != nil {
		t.Fatalf("resolveIdentity: %v", err)
	}

	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, _, e := runClientHandshake(ctx, a, id, nil)
		done <- e
	}()

	chPayload, err := recvCleartext(b, npamp.FrameClientHello)
	if err != nil {
		t.Fatalf("recv CLIENT_HELLO: %v", err)
	}
	ch, err := npamp.DecodeClientHello(chPayload)
	if err != nil {
		t.Fatalf("decode CLIENT_HELLO: %v", err)
	}
	if len(ch.KEMOffer) != 1 || ch.KEMOffer[0] != npamp.KEMSecP384r1MLKEM1024 {
		t.Fatalf("precondition failed: client's KEMOffer = %v, want [SecP384r1MLKEM1024]", ch.KEMOffer)
	}

	// A deviant SERVER_HELLO: ProfileSelect = High (the client's own offer — so the
	// profile-offered check passes), but KEMSelect = X25519MLKEM768 and a
	// correspondingly 768-sized (bogus, content is irrelevant — the client MUST
	// refuse before ever touching KEMCiphertext bytes) ciphertext.
	bad := &npamp.ServerHello{
		ProfileSelect: npamp.ProfileHigh,
		KEMSelect:     npamp.KEMX25519MLKEM768,
		SigSelect:     npamp.SigMLDSA87,
		AEADSelect:    npamp.AEADAES256GCM,
		KEMCiphertext: make([]byte, npamp.KEMCiphertextSize768),
	}
	if err := sendCleartext(b, npamp.FrameServerHello, bad.Encode()); err != nil {
		t.Fatalf("send deviant SERVER_HELLO: %v", err)
	}

	clientErr := <-done
	if clientErr == nil {
		t.Fatal("client accepted a SERVER_HELLO selecting X25519MLKEM768 for a High session — KEM downgrade refusal did not fire")
	}
	if !errors.Is(clientErr, ErrKEMDowngrade) {
		t.Fatalf("client rejected the deviant SERVER_HELLO but not with ErrKEMDowngrade: %v", clientErr)
	}
}
