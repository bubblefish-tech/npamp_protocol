package npamp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"testing"
)

// handshakeFlowKAT mirrors test-vectors/v1/handshake-flow-kat.json (issue #60,
// class golden-interop). Unlike the standards-anchored primitive KATs, this
// vector pins the Go reference's SERIALIZED handshake frames so every language
// impl reproduces them byte-for-byte. The CLIENT_HELLO assertion below is the
// one that would have caught the draft-00-vs-draft-01 ProfileOffer wire bug.
type handshakeFlowKAT struct {
	Inputs struct {
		ClientX25519Private       string `json:"client_x25519_private"`
		ServerX25519Private       string `json:"server_x25519_private"`
		MLKEM768SeedDZ            string `json:"mlkem768_seed_dz"`
		MLKEMCiphertext           string `json:"mlkem_ciphertext"`
		ClientIdentityEd25519Seed string `json:"client_identity_ed25519_seed"`
		ServerIdentityEd25519Seed string `json:"server_identity_ed25519_seed"`
		MLKEMSharedSecret         string `json:"mlkem_shared_secret"`
		X25519SharedSecret        string `json:"x25519_shared_secret"`
		CombinedSecret            string `json:"combined_secret"`
	} `json:"inputs"`
	Expected struct {
		Frames struct {
			ClientHello string `json:"client_hello"`
			ServerHello string `json:"server_hello"`
			ServerAuth  string `json:"server_auth"`
			ClientAuth  string `json:"client_auth"`
		} `json:"frames"`
		AuthPlaintext struct {
			ServerAuth string `json:"server_auth"`
			ClientAuth string `json:"client_auth"`
		} `json:"auth_plaintext"`
		Transcript struct {
			THKem string `json:"th_kem"`
			THSID string `json:"th_sid"`
			THSCV string `json:"th_scv"`
			THCID string `json:"th_cid"`
			THCCV string `json:"th_ccv"`
		} `json:"transcript"`
		Secrets struct {
			HandshakeSecret     string `json:"handshake_secret"`
			CHSSecret           string `json:"c_hs_secret"`
			SHSSecret           string `json:"s_hs_secret"`
			MasterSecret        string `json:"master_secret"`
			CHSTrafficSecret    string `json:"c_hs_traffic_secret"`
			CHSKey              string `json:"c_hs_key"`
			CHSIV               string `json:"c_hs_iv"`
			SHSTrafficSecret    string `json:"s_hs_traffic_secret"`
			SHSKey              string `json:"s_hs_key"`
			SHSIV               string `json:"s_hs_iv"`
			AppC2STrafficSecret string `json:"app_c2s_traffic_secret"`
			AppC2SKey           string `json:"app_c2s_key"`
			AppC2SIV            string `json:"app_c2s_iv"`
			AppS2CTrafficSecret string `json:"app_s2c_traffic_secret"`
			AppS2CKey           string `json:"app_s2c_key"`
			AppS2CIV            string `json:"app_s2c_iv"`
		} `json:"secrets"`
		FinishedKeys struct {
			Server string `json:"server"`
			Client string `json:"client"`
		} `json:"finished_keys"`
		Finished struct {
			Server string `json:"server"`
			Client string `json:"client"`
		} `json:"finished"`
		CertVerify struct {
			Server string `json:"server"`
			Client string `json:"client"`
		} `json:"cert_verify"`
		KEM struct {
			KEMShare      string `json:"kem_share"`
			KEMCiphertext string `json:"kem_ciphertext"`
		} `json:"kem"`
	} `json:"expected"`
}

// TestHandshakeFlowKAT rebuilds every handshake artifact through the real impl
// code path from the frozen pinned inputs and asserts byte-equality with the
// expected wire bytes. It is NOT env-gated: an ordinary `go test` runs it
// against the frozen corpus.
func TestHandshakeFlowKAT(t *testing.T) {
	var kat handshakeFlowKAT
	loadKAT(t, "handshake-flow-kat.json", &kat)
	p := ProfileStandard

	clientX25519Priv := mustHex(t, "client_x25519_private", kat.Inputs.ClientX25519Private)
	serverX25519Priv := mustHex(t, "server_x25519_private", kat.Inputs.ServerX25519Private)
	mlkemSeed := mustHex(t, "mlkem768_seed_dz", kat.Inputs.MLKEM768SeedDZ)
	mlkemCiphertext := mustHex(t, "mlkem_ciphertext", kat.Inputs.MLKEMCiphertext)
	clientEdSeed := mustHex(t, "client_identity_ed25519_seed", kat.Inputs.ClientIdentityEd25519Seed)
	serverEdSeed := mustHex(t, "server_identity_ed25519_seed", kat.Inputs.ServerIdentityEd25519Seed)
	wantMLKEMSS := mustHex(t, "mlkem_shared_secret", kat.Inputs.MLKEMSharedSecret)
	wantX25519SS := mustHex(t, "x25519_shared_secret", kat.Inputs.X25519SharedSecret)

	clientPriv := ed25519.NewKeyFromSeed(clientEdSeed)
	serverPriv := ed25519.NewKeyFromSeed(serverEdSeed)
	clientPub := clientPriv.Public().(ed25519.PublicKey)
	serverPub := serverPriv.Public().(ed25519.PublicKey)

	// --- Self-validating input: decapsulate the pinned ML-KEM ciphertext under
	// the pinned seed and X25519 leg, and recover mlkem_shared_secret. This is
	// deterministic and does not require seed-injectable encapsulation. ---
	kem, err := NewKEMClient(mlkemSeed, clientX25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	kemShare := kem.KEMShare()
	if got := mustHex(t, "kem_share", kat.Expected.KEM.KEMShare); !bytes.Equal(kemShare, got) {
		t.Fatalf("KEMShare != expected")
	}
	// The pinned KEMCiphertext = ml-kem ciphertext || server X25519 public.
	wantKEMCT := mustHex(t, "kem_ciphertext", kat.Expected.KEM.KEMCiphertext)
	if !bytes.Equal(wantKEMCT[:len(wantKEMCT)-32], mlkemCiphertext) {
		t.Fatalf("pinned kem_ciphertext front != pinned mlkem_ciphertext input")
	}
	ss, err := kem.SharedSecrets(wantKEMCT)
	if err != nil {
		t.Fatalf("decapsulate pinned ciphertext: %v", err)
	}
	if !bytes.Equal(ss.MLKEM, wantMLKEMSS) {
		t.Fatalf("decapsulated ML-KEM shared secret != pinned mlkem_shared_secret (self-validating input failed)")
	}
	if !bytes.Equal(ss.X25519, wantX25519SS) {
		t.Fatalf("X25519 shared secret != pinned x25519_shared_secret")
	}

	// --- Rebuild CLIENT_HELLO through the real impl and assert byte-equality. ---
	ch := &ClientHello{
		ProfileOffer: []Profile{ProfileStandard},
		KEMOffer:     []KEMID{KEMX25519MLKEM768},
		SigOffer:     []SigID{SigEd25519},
		AEADOffer:    []AEADID{AEADAES256GCM},
		KEMShare:     kemShare,
	}
	chPayload := ch.Encode()
	chFrame := marshalFrameKAT(t, FrameClientHello, chPayload)
	if !bytes.Equal(chFrame, mustHex(t, "client_hello", kat.Expected.Frames.ClientHello)) {
		t.Fatalf("CLIENT_HELLO frame != expected (the ProfileOffer wire-drift guard)")
	}

	// --- Rebuild SERVER_HELLO. The KEMCiphertext is the pinned value (encaps is
	// non-deterministic, so we cannot regenerate it — we reuse the pinned CT and
	// verify the serialized frame). ---
	sh := &ServerHello{
		ProfileSelect: ProfileStandard,
		KEMSelect:     KEMX25519MLKEM768,
		SigSelect:     SigEd25519,
		AEADSelect:    AEADAES256GCM,
		KEMCiphertext: wantKEMCT,
	}
	shPayload := sh.Encode()
	shFrame := marshalFrameKAT(t, FrameServerHello, shPayload)
	if !bytes.Equal(shFrame, mustHex(t, "server_hello", kat.Expected.Frames.ServerHello)) {
		t.Fatalf("SERVER_HELLO frame != expected")
	}

	// --- Transcript + key ladder through the real impl. ---
	tr := NewTranscript(p)
	tr.AddFrame(FrameClientHello, ch.TLVs())
	tr.AddFrame(FrameServerHello, sh.TLVs())
	thKem := tr.Sum()
	assertHex(t, "th_kem", thKem, kat.Expected.Transcript.THKem)

	hs, err := HandshakeSecret(ss, p)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "handshake_secret", hs, kat.Expected.Secrets.HandshakeSecret)
	cHS, sHS, err := DeriveHandshakeTrafficSecrets(hs, thKem, p)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "c_hs_secret", cHS, kat.Expected.Secrets.CHSSecret)
	assertHex(t, "s_hs_secret", sHS, kat.Expected.Secrets.SHSSecret)

	// SERVER_AUTH.
	tr.AddFrameType(FrameServerAuth)
	tr.AddTLV(TLV{Type: TLVIdentityKey, Value: serverPub})
	thSID := tr.Sum()
	assertHex(t, "th_sid", thSID, kat.Expected.Transcript.THSID)
	sCV, err := SignCertVerify(serverPriv, RoleServer, thSID)
	if err != nil {
		t.Fatal(err)
	}
	// Ed25519 is deterministic (RFC 8032), so the pinned signature must match.
	assertHex(t, "cert_verify.server", sCV, kat.Expected.CertVerify.Server)
	if err := VerifyCertVerify(serverPub, RoleServer, thSID, sCV); err != nil {
		t.Fatalf("server CertVerify rejected: %v", err)
	}
	tr.AddTLV(TLV{Type: TLVCertVerify, Value: sCV})
	thSCV := tr.Sum()
	assertHex(t, "th_scv", thSCV, kat.Expected.Transcript.THSCV)
	sFinKey, err := DeriveFinishedKey(sHS, p)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "finished_keys.server", sFinKey, kat.Expected.FinishedKeys.Server)
	sFin := ComputeFinished(sFinKey, thSCV, p)
	assertHex(t, "finished.server", sFin, kat.Expected.Finished.Server)
	tr.AddTLV(TLV{Type: TLVFinished, Value: sFin})
	serverAuth := &AuthMessage{IdentityKey: serverPub, CertVerify: sCV, Finished: sFin}
	serverAuthPlain := serverAuth.Encode()
	assertHex(t, "auth_plaintext.server", serverAuthPlain, kat.Expected.AuthPlaintext.ServerAuth)
	serverAuthFrame := sealAuthKAT(t, FrameServerAuth, sHS, DirServerToClient, serverAuthPlain, p)
	if !bytes.Equal(serverAuthFrame, mustHex(t, "server_auth", kat.Expected.Frames.ServerAuth)) {
		t.Fatalf("SERVER_AUTH frame != expected")
	}

	// CLIENT_AUTH.
	tr.AddFrameType(FrameClientAuth)
	tr.AddTLV(TLV{Type: TLVIdentityKey, Value: clientPub})
	thCID := tr.Sum()
	assertHex(t, "th_cid", thCID, kat.Expected.Transcript.THCID)
	cCV, err := SignCertVerify(clientPriv, RoleClient, thCID)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "cert_verify.client", cCV, kat.Expected.CertVerify.Client)
	if err := VerifyCertVerify(clientPub, RoleClient, thCID, cCV); err != nil {
		t.Fatalf("client CertVerify rejected: %v", err)
	}
	tr.AddTLV(TLV{Type: TLVCertVerify, Value: cCV})
	thCCV := tr.Sum()
	assertHex(t, "th_ccv", thCCV, kat.Expected.Transcript.THCCV)
	cFinKey, err := DeriveFinishedKey(cHS, p)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "finished_keys.client", cFinKey, kat.Expected.FinishedKeys.Client)
	cFin := ComputeFinished(cFinKey, thCCV, p)
	assertHex(t, "finished.client", cFin, kat.Expected.Finished.Client)
	clientAuth := &AuthMessage{IdentityKey: clientPub, CertVerify: cCV, Finished: cFin}
	clientAuthPlain := clientAuth.Encode()
	assertHex(t, "auth_plaintext.client", clientAuthPlain, kat.Expected.AuthPlaintext.ClientAuth)
	clientAuthFrame := sealAuthKAT(t, FrameClientAuth, cHS, DirClientToServer, clientAuthPlain, p)
	if !bytes.Equal(clientAuthFrame, mustHex(t, "client_auth", kat.Expected.Frames.ClientAuth)) {
		t.Fatalf("CLIENT_AUTH frame != expected")
	}

	// Master + application-phase traffic keys.
	master, err := DeriveMasterSecret(hs, thCCV, p)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "master_secret", master, kat.Expected.Secrets.MasterSecret)

	assertTrafficKeyIV(t, "c_hs", cHS, DirClientToServer, p,
		kat.Expected.Secrets.CHSTrafficSecret, kat.Expected.Secrets.CHSKey, kat.Expected.Secrets.CHSIV)
	assertTrafficKeyIV(t, "s_hs", sHS, DirServerToClient, p,
		kat.Expected.Secrets.SHSTrafficSecret, kat.Expected.Secrets.SHSKey, kat.Expected.Secrets.SHSIV)
	assertTrafficKeyIV(t, "app_c2s", master, DirClientToServer, p,
		kat.Expected.Secrets.AppC2STrafficSecret, kat.Expected.Secrets.AppC2SKey, kat.Expected.Secrets.AppC2SIV)
	assertTrafficKeyIV(t, "app_s2c", master, DirServerToClient, p,
		kat.Expected.Secrets.AppS2CTrafficSecret, kat.Expected.Secrets.AppS2CKey, kat.Expected.Secrets.AppS2CIV)

	// --- Mutation guard 1: a one-bit flip in the server CertVerify signature
	// must REJECT (the flipped copy must not verify). ---
	badCV := append([]byte(nil), sCV...)
	badCV[len(badCV)-1] ^= 0x01 // flip a signature bit (last octet)
	if err := VerifyCertVerify(serverPub, RoleServer, thSID, badCV); err == nil {
		t.Fatalf("mutation guard: a one-bit-flipped server CertVerify signature VERIFIED")
	}

	// --- Mutation guard 2: a one-bit flip in the client Finished MAC must
	// REJECT. ---
	badFin := append([]byte(nil), cFin...)
	badFin[0] ^= 0x01
	if err := VerifyFinished(cFinKey, thCCV, badFin, p); err == nil {
		t.Fatalf("mutation guard: a one-bit-flipped client Finished MAC VERIFIED")
	}

	// Sanity: the untouched signature and MAC still verify.
	if err := VerifyCertVerify(serverPub, RoleServer, thSID, sCV); err != nil {
		t.Fatalf("unmutated server CertVerify should verify: %v", err)
	}
	if err := VerifyFinished(cFinKey, thCCV, cFin, p); err != nil {
		t.Fatalf("unmutated client Finished should verify: %v", err)
	}

	// Guard against unused imports / dead server-side X25519 wiring.
	if _, err := ecdh.X25519().NewPrivateKey(serverX25519Priv); err != nil {
		t.Fatalf("pinned server X25519 private is invalid: %v", err)
	}
}

// marshalFrameKAT builds a cleartext handshake frame (Control channel, seq 0)
// through the impl's real record path.
func marshalFrameKAT(t *testing.T, ft FrameType, payload []byte) []byte {
	t.Helper()
	f := Frame{Type: uint16(ft), Channel: uint16(ChanControl), Seq: 0, Payload: payload}
	wire, err := f.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// sealAuthKAT seals an AUTH plaintext into a wire frame through the impl's real
// key-schedule + record path.
func sealAuthKAT(t *testing.T, ft FrameType, baseSecret []byte, dir Direction, plaintext []byte, p Profile) []byte {
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

// assertHex fails unless got equals the expected hex string.
func assertHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	if !bytes.Equal(got, mustHex(t, name, wantHex)) {
		t.Fatalf("%s != expected", name)
	}
}

// assertTrafficKeyIV derives the traffic secret/key/iv through the impl and
// asserts each against the pinned expected hex.
func assertTrafficKeyIV(t *testing.T, name string, parent []byte, dir Direction, p Profile, tsHex, keyHex, ivHex string) {
	t.Helper()
	ts, err := DeriveTrafficSecret(parent, dir, 0, AEADAES256GCM, ChanControl, p)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, name+"_traffic_secret", ts, tsHex)
	key, iv, err := DeriveKeyIV(ts, p)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, name+"_key", key[:], keyHex)
	assertHex(t, name+"_iv", iv[:], ivHex)
}
