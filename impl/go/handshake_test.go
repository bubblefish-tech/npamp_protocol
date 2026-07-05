package npamp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
)

func TestClientHelloRoundTrip(t *testing.T) {
	in := &ClientHello{
		ProfileOffer: []Profile{ProfileStandard, ProfileHigh, ProfileSovereign},
		KEMOffer:     []KEMID{KEMX25519MLKEM768, KEMX25519MLKEM1024},
		SigOffer:     []SigID{SigEd25519},
		AEADOffer:    []AEADID{AEADAES256GCM, AEADChaCha20Poly1305},
		KEMShare:     bytes.Repeat([]byte{0xAB}, KEMShareSize768),
	}
	out, err := DecodeClientHello(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in: %+v\nout: %+v", in, out)
	}
}

func TestServerHelloRoundTrip(t *testing.T) {
	in := &ServerHello{
		ProfileSelect: ProfileStandard,
		KEMSelect:     KEMX25519MLKEM768,
		SigSelect:     SigEd25519,
		AEADSelect:    AEADAES256GCM,
		KEMCiphertext: bytes.Repeat([]byte{0xCD}, KEMCiphertextSize768),
	}
	out, err := DecodeServerHello(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in: %+v\nout: %+v", in, out)
	}
}

func TestAuthMessageRoundTrip(t *testing.T) {
	in := &AuthMessage{
		IdentityKey: bytes.Repeat([]byte{0x01}, ed25519.PublicKeySize),
		CertVerify:  bytes.Repeat([]byte{0x02}, 2+ed25519.SignatureSize),
		Finished:    bytes.Repeat([]byte{0x03}, 32),
	}
	out, err := DecodeAuthMessage(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in: %+v\nout: %+v", in, out)
	}
}

// TestHandshakeTLVLayoutEnforced checks the decoders reject a missing TLV, an
// extra TLV, and an out-of-order layout (spec/10 sections 1 and 6.4 fix both
// the set and the order).
func TestHandshakeTLVLayoutEnforced(t *testing.T) {
	auth := &AuthMessage{
		IdentityKey: bytes.Repeat([]byte{0x01}, 32),
		CertVerify:  bytes.Repeat([]byte{0x02}, 66),
		Finished:    bytes.Repeat([]byte{0x03}, 32),
	}
	good := auth.TLVs()

	encode := func(tlvs []TLV) []byte {
		var out []byte
		for _, v := range tlvs {
			out = v.Encode(out)
		}
		return out
	}

	// Missing TLV.
	if _, err := DecodeAuthMessage(encode(good[:2])); !errors.Is(err, ErrHandshakeTLVOrder) {
		t.Fatalf("missing Finished TLV not rejected (err=%v)", err)
	}
	// Extra TLV.
	extra := append(append([]TLV{}, good...), TLV{Type: TLVPathChallenge, Value: make([]byte, 32)})
	if _, err := DecodeAuthMessage(encode(extra)); !errors.Is(err, ErrHandshakeTLVOrder) {
		t.Fatalf("extra TLV not rejected (err=%v)", err)
	}
	// Out of order.
	swapped := []TLV{good[1], good[0], good[2]}
	if _, err := DecodeAuthMessage(encode(swapped)); !errors.Is(err, ErrHandshakeTLVOrder) {
		t.Fatalf("out-of-order TLVs not rejected (err=%v)", err)
	}
	// Truncated TLV stream.
	if _, err := DecodeAuthMessage(encode(good)[:5]); !errors.Is(err, ErrTruncatedTLV) {
		t.Fatalf("truncated payload not rejected (err=%v)", err)
	}
	// Bad select sizes.
	sh := &ServerHello{ProfileSelect: ProfileStandard, KEMSelect: KEMX25519MLKEM768, SigSelect: SigEd25519, AEADSelect: AEADAES256GCM, KEMCiphertext: []byte{1}}
	tlvs := sh.TLVs()
	tlvs[1].Value = []byte{0x11} // KEMSelect must be 2 octets
	if _, err := DecodeServerHello(encode(tlvs)); !errors.Is(err, ErrHandshakeTLVValue) {
		t.Fatalf("1-octet KEMSelect not rejected (err=%v)", err)
	}
}

// TestHandshakeFlowStandard runs the full 1.5-RTT handshake (spec/10 section
// 1) in memory at the Standard profile with real dependencies — real
// X25519MLKEM768 (crypto/mlkem + crypto/ecdh), real Ed25519 identities, the
// real transcript, key schedule, and record layer — and checks that both
// peers authenticate each other and arrive at the same master secret, and
// that the AUTH frames really seal/open as AEAD-protected wire frames
// (section 6.4).
func TestHandshakeFlowStandard(t *testing.T) {
	p := ProfileStandard

	// Long-term identities.
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// --- Flight 1: CLIENT_HELLO (cleartext) ---
	kem, err := GenerateKEMClient()
	if err != nil {
		t.Fatal(err)
	}
	ch := &ClientHello{
		ProfileOffer: []Profile{ProfileStandard},
		KEMOffer:     []KEMID{KEMX25519MLKEM768},
		SigOffer:     []SigID{SigEd25519},
		AEADOffer:    []AEADID{AEADAES256GCM},
		KEMShare:     kem.KEMShare(),
	}
	chWire := ch.Encode()

	clientT := NewTranscript(p)
	clientT.AddFrame(FrameClientHello, ch.TLVs())

	// --- Server: decode CH, encapsulate, send SERVER_HELLO (cleartext) ---
	chRecv, err := DecodeClientHello(chWire)
	if err != nil {
		t.Fatal(err)
	}
	serverT := NewTranscript(p)
	serverT.AddFrame(FrameClientHello, chRecv.TLVs())

	kemCT, serverSS, err := Encapsulate(chRecv.KEMShare)
	if err != nil {
		t.Fatal(err)
	}
	sh := &ServerHello{
		ProfileSelect: ProfileStandard,
		KEMSelect:     KEMX25519MLKEM768,
		SigSelect:     SigEd25519,
		AEADSelect:    AEADAES256GCM,
		KEMCiphertext: kemCT,
	}
	shWire := sh.Encode()
	serverT.AddFrame(FrameServerHello, sh.TLVs())

	// --- Client: decode SH, decapsulate ---
	shRecv, err := DecodeServerHello(shWire)
	if err != nil {
		t.Fatal(err)
	}
	clientT.AddFrame(FrameServerHello, shRecv.TLVs())
	clientSS, err := kem.SharedSecrets(shRecv.KEMCiphertext)
	if err != nil {
		t.Fatal(err)
	}

	// --- Both: handshake secrets from TH_kem ---
	thKemC, thKemS := clientT.Sum(), serverT.Sum()
	if !bytes.Equal(thKemC, thKemS) {
		t.Fatal("TH_kem differs between peers")
	}
	hsC, err := HandshakeSecret(clientSS, p)
	if err != nil {
		t.Fatal(err)
	}
	hsS, err := HandshakeSecret(serverSS, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hsC, hsS) {
		t.Fatal("handshake_secret differs between peers")
	}
	cHS, sHS, err := DeriveHandshakeTrafficSecrets(hsS, thKemS, p)
	if err != nil {
		t.Fatal(err)
	}

	// sealAuth seals an AUTH plaintext as a real N-PAMP frame under the
	// sender's handshake traffic key (spec/10 section 6.4: FlagENC, Control
	// channel, seq 0, AAD = 21-octet header prefix).
	sealAuth := func(ft FrameType, baseSecret []byte, dir Direction, plaintext []byte) []byte {
		t.Helper()
		ts, err := DeriveTrafficSecret(baseSecret, dir, 0, AEADAES256GCM, ChanControl, p)
		if err != nil {
			t.Fatal(err)
		}
		key, iv, err := DeriveKeyIV(ts, p)
		if err != nil {
			t.Fatal(err)
		}
		f := Frame{Flags: FlagENC, Type: uint16(ft), Channel: uint16(ChanControl), Seq: 0}
		var aad [21]byte
		f.HeaderPrefix(aad[:], uint32(len(plaintext)+16))
		sealed, err := SealAES256GCM(key, iv, 0, aad[:], plaintext)
		if err != nil {
			t.Fatal(err)
		}
		f.Payload = sealed
		wire, err := f.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	openAuth := func(wire []byte, baseSecret []byte, dir Direction, wantType FrameType) *AuthMessage {
		t.Helper()
		var f Frame
		if err := f.UnmarshalBinary(wire); err != nil {
			t.Fatal(err)
		}
		if f.Type != uint16(wantType) || f.Flags&FlagENC == 0 {
			t.Fatalf("frame type=0x%04x flags=%02x", f.Type, f.Flags)
		}
		ts, err := DeriveTrafficSecret(baseSecret, dir, 0, AEADAES256GCM, ChanControl, p)
		if err != nil {
			t.Fatal(err)
		}
		key, iv, err := DeriveKeyIV(ts, p)
		if err != nil {
			t.Fatal(err)
		}
		var aad [21]byte
		f.HeaderPrefix(aad[:], uint32(len(f.Payload)))
		pt, err := OpenAES256GCM(key, iv, f.Seq, aad[:], f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := DecodeAuthMessage(pt)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}

	// --- Flight 3: SERVER_AUTH (encrypted, s-hs key) ---
	serverT.AddFrameType(FrameServerAuth)
	serverT.AddTLV(TLV{Type: TLVIdentityKey, Value: serverPub})
	sCV, err := SignCertVerify(serverPriv, RoleServer, serverT.Sum()) // signs TH_sId
	if err != nil {
		t.Fatal(err)
	}
	serverT.AddTLV(TLV{Type: TLVCertVerify, Value: sCV})
	sFinKey, err := DeriveFinishedKey(sHS, p)
	if err != nil {
		t.Fatal(err)
	}
	sFin := ComputeFinished(sFinKey, serverT.Sum(), p) // MACs TH_sCV
	serverAuth := &AuthMessage{IdentityKey: serverPub, CertVerify: sCV, Finished: sFin}
	serverT.AddTLV(TLV{Type: TLVFinished, Value: sFin})
	serverAuthWire := sealAuth(FrameServerAuth, sHS, DirServerToClient, serverAuth.Encode())

	// --- Client: open + verify SERVER_AUTH ---
	sAuthRecv := openAuth(serverAuthWire, sHS, DirServerToClient, FrameServerAuth)
	clientT.AddFrameType(FrameServerAuth)
	clientT.AddTLV(TLV{Type: TLVIdentityKey, Value: sAuthRecv.IdentityKey})
	if err := VerifyCertVerify(sAuthRecv.IdentityKey, RoleServer, clientT.Sum(), sAuthRecv.CertVerify); err != nil {
		t.Fatalf("server CertVerify rejected: %v", err)
	}
	clientT.AddTLV(TLV{Type: TLVCertVerify, Value: sAuthRecv.CertVerify})
	cSideSFinKey, err := DeriveFinishedKey(sHS, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFinished(cSideSFinKey, clientT.Sum(), sAuthRecv.Finished, p); err != nil {
		t.Fatalf("server Finished rejected: %v", err)
	}
	clientT.AddTLV(TLV{Type: TLVFinished, Value: sAuthRecv.Finished})

	// --- Flight 4: CLIENT_AUTH (encrypted, c-hs key) ---
	clientT.AddFrameType(FrameClientAuth)
	clientT.AddTLV(TLV{Type: TLVIdentityKey, Value: clientPub})
	cCV, err := SignCertVerify(clientPriv, RoleClient, clientT.Sum()) // signs TH_cId
	if err != nil {
		t.Fatal(err)
	}
	clientT.AddTLV(TLV{Type: TLVCertVerify, Value: cCV})
	thCCVClient := clientT.Sum() // TH_cCV: master is derived from this
	cFinKey, err := DeriveFinishedKey(cHS, p)
	if err != nil {
		t.Fatal(err)
	}
	cFin := ComputeFinished(cFinKey, thCCVClient, p)
	clientAuth := &AuthMessage{IdentityKey: clientPub, CertVerify: cCV, Finished: cFin}
	clientAuthWire := sealAuth(FrameClientAuth, cHS, DirClientToServer, clientAuth.Encode())

	// --- Server: open + verify CLIENT_AUTH, reach Established ---
	cAuthRecv := openAuth(clientAuthWire, cHS, DirClientToServer, FrameClientAuth)
	serverT.AddFrameType(FrameClientAuth)
	serverT.AddTLV(TLV{Type: TLVIdentityKey, Value: cAuthRecv.IdentityKey})
	if err := VerifyCertVerify(cAuthRecv.IdentityKey, RoleClient, serverT.Sum(), cAuthRecv.CertVerify); err != nil {
		t.Fatalf("client CertVerify rejected: %v", err)
	}
	serverT.AddTLV(TLV{Type: TLVCertVerify, Value: cAuthRecv.CertVerify})
	thCCVServer := serverT.Sum()
	sSideCFinKey, err := DeriveFinishedKey(cHS, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFinished(sSideCFinKey, thCCVServer, cAuthRecv.Finished, p); err != nil {
		t.Fatalf("client Finished rejected: %v", err)
	}

	// --- Both: master secret at the client-auth boundary ---
	masterC, err := DeriveMasterSecret(hsC, thCCVClient, p)
	if err != nil {
		t.Fatal(err)
	}
	masterS, err := DeriveMasterSecret(hsS, thCCVServer, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(masterC, masterS) {
		t.Fatal("master secret differs between peers")
	}

	// Downgrade protection (section 6.3): a peer whose transcript saw a
	// different (e.g. stripped) offer computes a different TH and the
	// Finished MAC fails.
	tampered := NewTranscript(p)
	chTampered := *ch
	chTampered.ProfileOffer = []Profile{ProfileStandard} // same
	chTampered.AEADOffer = []AEADID{AEADChaCha20Poly1305} // forced different suite
	tampered.AddFrame(FrameClientHello, chTampered.TLVs())
	tampered.AddFrame(FrameServerHello, sh.TLVs())
	tampered.AddFrameType(FrameServerAuth)
	tampered.AddTLV(TLV{Type: TLVIdentityKey, Value: serverPub})
	tampered.AddTLV(TLV{Type: TLVCertVerify, Value: sCV})
	if err := VerifyFinished(sFinKey, tampered.Sum(), sFin, p); !errors.Is(err, ErrFinishedMismatch) {
		t.Fatalf("Finished verified over a tampered negotiation transcript (err=%v)", err)
	}
}
