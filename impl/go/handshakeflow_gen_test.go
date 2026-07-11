package npamp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// TestGenHandshakeFlow generates the byte-pinned handshake-flow conformance
// vector (issue #60) and writes test-vectors/v1/handshake-flow-kat.json. It is
// gated on NPAMP_WRITE_VECTORS=1 so an ordinary `go test` never rewrites the
// frozen corpus; regeneration is a deliberate, reviewed re-pin.
//
// The test drives the REAL reference code path (NewKEMClient / EncapsulateWith,
// ClientHello.Encode / DecodeClientHello, ServerHello.Encode, the spec/10 §5
// key ladder, SignCertVerify / DeriveFinishedKey / ComputeFinished, the record
// layer seal) to PRODUCE the bytes; then an INDEPENDENT inline oracle
// re-derives every EXPECTED field a SECOND time from raw crypto/hkdf +
// crypto/hmac + crypto/sha256 + hand-built TLV/frame byte construction (never
// the npamp.* helpers), and the test FAILS on any reference-vs-oracle
// disagreement. That cross-check is what proves the vector is not a Go
// self-portrait.
func TestGenHandshakeFlow(t *testing.T) {
	if os.Getenv("NPAMP_WRITE_VECTORS") != "1" {
		t.Skip("set NPAMP_WRITE_VECTORS=1 to regenerate the frozen handshake-flow vector")
	}

	p := ProfileStandard

	// --- Fixed seeds (reused from kem-wire-kat.json) ---
	clientX25519Priv := mustHex(t, "client_x25519_private", clientX25519PrivHex)
	serverX25519Priv := mustHex(t, "server_x25519_private", serverX25519PrivHex)
	mlkemSeed := mustHex(t, "mlkem768_seed_dz", mlkem768SeedDZHex)
	clientEdSeed := mustHex(t, "client_identity_ed25519_seed", clientEdSeedHex)
	serverEdSeed := mustHex(t, "server_identity_ed25519_seed", serverEdSeedHex)

	// Self-check: the reused fixed keys really are the kem-wire-kat values.
	var kw struct {
		X struct {
			Alice string `json:"alice_private"`
			Bob   string `json:"bob_private"`
		} `json:"x25519_rfc7748_6_1"`
		M struct {
			D string `json:"d"`
			Z string `json:"z"`
		} `json:"mlkem768_keygen"`
	}
	loadKAT(t, "kem-wire-kat.json", &kw)
	eqHex := func(want string, got []byte) bool {
		w, err := hex.DecodeString(want)
		return err == nil && bytes.Equal(w, got)
	}
	if !eqHex(kw.X.Alice, clientX25519Priv) {
		t.Fatalf("client X25519 private does not match kem-wire-kat alice_private")
	}
	if !eqHex(kw.X.Bob, serverX25519Priv) {
		t.Fatalf("server X25519 private does not match kem-wire-kat bob_private")
	}
	if !eqHex(kw.M.D+kw.M.Z, mlkemSeed) {
		t.Fatalf("ML-KEM seed does not match kem-wire-kat d||z")
	}

	// --- Long-term Ed25519 identities from fixed seeds ---
	clientPriv := ed25519.NewKeyFromSeed(clientEdSeed)
	serverPriv := ed25519.NewKeyFromSeed(serverEdSeed)
	clientPub := clientPriv.Public().(ed25519.PublicKey)
	serverPub := serverPriv.Public().(ed25519.PublicKey)

	// ================= REFERENCE LEG (produces the bytes) =================

	// Flight 1: CLIENT_HELLO (cleartext) via the real client KEM state.
	kem, err := NewKEMClient(mlkemSeed, clientX25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	kemShare := kem.KEMShare()
	ch := &ClientHello{
		ProfileOffer: []Profile{ProfileStandard},
		KEMOffer:     []KEMID{KEMX25519MLKEM768},
		SigOffer:     []SigID{SigEd25519},
		AEADOffer:    []AEADID{AEADAES256GCM},
		KEMShare:     kemShare,
	}
	chPayload := ch.Encode()
	chFrame := mustMarshalFrame(t, FrameClientHello, 0, chPayload)

	clientT := NewTranscript(p)
	clientT.AddFrame(FrameClientHello, ch.TLVs())

	// Server: decode CH, encapsulate with the fixed server X25519 private.
	chRecv, err := DecodeClientHello(chPayload)
	if err != nil {
		t.Fatal(err)
	}
	serverX, err := ecdh.X25519().NewPrivateKey(serverX25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	kemCT, serverSS, err := EncapsulateWith(chRecv.KEMShare, serverX)
	if err != nil {
		t.Fatal(err)
	}
	// ML-KEM ciphertext is captured ONCE here (crypto/mlkem encaps randomness
	// is non-deterministic) and pinned as a self-validating input.
	mlkemCiphertext := kemCT[:len(kemCT)-32]

	sh := &ServerHello{
		ProfileSelect: ProfileStandard,
		KEMSelect:     KEMX25519MLKEM768,
		SigSelect:     SigEd25519,
		AEADSelect:    AEADAES256GCM,
		KEMCiphertext: kemCT,
	}
	shPayload := sh.Encode()
	shFrame := mustMarshalFrame(t, FrameServerHello, 0, shPayload)

	serverT := NewTranscript(p)
	serverT.AddFrame(FrameClientHello, chRecv.TLVs())
	serverT.AddFrame(FrameServerHello, sh.TLVs())

	// Client: decode SH, decapsulate.
	shRecv, err := DecodeServerHello(shPayload)
	if err != nil {
		t.Fatal(err)
	}
	clientT.AddFrame(FrameServerHello, shRecv.TLVs())
	clientSS, err := kem.SharedSecrets(shRecv.KEMCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientSS.MLKEM, serverSS.MLKEM) || !bytes.Equal(clientSS.X25519, serverSS.X25519) {
		t.Fatal("client and server component shared secrets differ")
	}

	// TH_kem.
	thKem := serverT.Sum()
	if !bytes.Equal(thKem, clientT.Sum()) {
		t.Fatal("TH_kem differs between peers")
	}

	// Key ladder (spec/10 §5).
	hs, err := HandshakeSecret(serverSS, p)
	if err != nil {
		t.Fatal(err)
	}
	cHS, sHS, err := DeriveHandshakeTrafficSecrets(hs, thKem, p)
	if err != nil {
		t.Fatal(err)
	}

	// Flight 3: SERVER_AUTH (encrypted under s-hs key).
	serverT.AddFrameType(FrameServerAuth)
	serverT.AddTLV(TLV{Type: TLVIdentityKey, Value: serverPub})
	thSID := serverT.Sum()
	sCV, err := SignCertVerify(serverPriv, RoleServer, thSID)
	if err != nil {
		t.Fatal(err)
	}
	serverT.AddTLV(TLV{Type: TLVCertVerify, Value: sCV})
	thSCV := serverT.Sum()
	sFinKey, err := DeriveFinishedKey(sHS, p)
	if err != nil {
		t.Fatal(err)
	}
	sFin := ComputeFinished(sFinKey, thSCV, p)
	serverT.AddTLV(TLV{Type: TLVFinished, Value: sFin})
	serverAuth := &AuthMessage{IdentityKey: serverPub, CertVerify: sCV, Finished: sFin}
	serverAuthPlain := serverAuth.Encode()
	serverAuthFrame := mustSealAuth(t, FrameServerAuth, sHS, DirServerToClient, serverAuthPlain, p)

	// Client mirrors SERVER_AUTH into its transcript.
	clientT.AddFrameType(FrameServerAuth)
	clientT.AddTLV(TLV{Type: TLVIdentityKey, Value: serverPub})
	clientT.AddTLV(TLV{Type: TLVCertVerify, Value: sCV})
	clientT.AddTLV(TLV{Type: TLVFinished, Value: sFin})

	// Flight 4: CLIENT_AUTH (encrypted under c-hs key).
	clientT.AddFrameType(FrameClientAuth)
	clientT.AddTLV(TLV{Type: TLVIdentityKey, Value: clientPub})
	thCID := clientT.Sum()
	cCV, err := SignCertVerify(clientPriv, RoleClient, thCID)
	if err != nil {
		t.Fatal(err)
	}
	clientT.AddTLV(TLV{Type: TLVCertVerify, Value: cCV})
	thCCV := clientT.Sum()
	cFinKey, err := DeriveFinishedKey(cHS, p)
	if err != nil {
		t.Fatal(err)
	}
	cFin := ComputeFinished(cFinKey, thCCV, p)
	clientAuth := &AuthMessage{IdentityKey: clientPub, CertVerify: cCV, Finished: cFin}
	clientAuthPlain := clientAuth.Encode()
	clientAuthFrame := mustSealAuth(t, FrameClientAuth, cHS, DirClientToServer, clientAuthPlain, p)

	// Server mirrors CLIENT_AUTH and confirms TH_cCV agreement.
	serverT.AddFrameType(FrameClientAuth)
	serverT.AddTLV(TLV{Type: TLVIdentityKey, Value: clientPub})
	serverT.AddTLV(TLV{Type: TLVCertVerify, Value: cCV})
	if !bytes.Equal(serverT.Sum(), thCCV) {
		t.Fatal("TH_cCV differs between peers")
	}

	// Master secret at the client-auth boundary.
	master, err := DeriveMasterSecret(hs, thCCV, p)
	if err != nil {
		t.Fatal(err)
	}

	// Handshake-phase traffic secrets/keys/ivs (epoch 0, Control channel).
	cHSTraffic, cHSKey, cHSIV := mustTrafficKeyIV(t, cHS, DirClientToServer, p)
	sHSTraffic, sHSKey, sHSIV := mustTrafficKeyIV(t, sHS, DirServerToClient, p)
	// Application-phase traffic secrets/keys/ivs from master.
	appC2STraffic, appC2SKey, appC2SIV := mustTrafficKeyIV(t, master, DirClientToServer, p)
	appS2CTraffic, appS2CKey, appS2CIV := mustTrafficKeyIV(t, master, DirServerToClient, p)

	// ============= ORACLE LEG (independent re-derivation) =============
	// The oracle NEVER calls npamp.* crypto helpers. It reconstructs every
	// expected field from raw crypto/hkdf + crypto/hmac + crypto/sha256 and a
	// hand-built TLV/frame byte constructor, then asserts equality with the
	// reference bytes above.

	// Oracle KEM wire (assembled from raw component bytes, ML-KEM-first).
	oClientX, err := ecdh.X25519().NewPrivateKey(clientX25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	oServerX, err := ecdh.X25519().NewPrivateKey(serverX25519Priv)
	if err != nil {
		t.Fatal(err)
	}
	// Oracle recovers the ML-KEM ek from the reference KEMShare front (1184) and
	// checks the X25519 tail equals the fixed client public independently.
	oClientXPub := oClientX.PublicKey().Bytes()
	if !bytes.Equal(kemShare[1184:], oClientXPub) {
		t.Fatal("oracle: KEMShare X25519 tail != client public")
	}
	// Oracle X25519 shared secret (client_priv x server_pub), independent path.
	oXSS, err := oClientX.ECDH(oServerX.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oXSS, serverSS.X25519) {
		t.Fatalf("oracle X25519 shared secret != reference")
	}
	// combined_secret = ML-KEM_SS || X25519_SS (ML-KEM-first).
	oCombined := append(append([]byte{}, serverSS.MLKEM...), oXSS...)

	// Oracle transcript: hand-built frame-type(2 BE) + per-TLV Type(2)||Len(2)||Value.
	var oBuf []byte
	oAppendType := func(ft FrameType) { oBuf = append(oBuf, byte(uint16(ft)>>8), byte(uint16(ft))) }
	oAppendTLV := func(typ TLVType, val []byte) {
		oBuf = append(oBuf, byte(uint16(typ)>>8), byte(uint16(typ)), byte(len(val)>>8), byte(len(val)))
		oBuf = append(oBuf, val...)
	}
	oSHA := func() []byte { d := sha256.Sum256(oBuf); return d[:] }

	profilesVal := []byte{byte(ProfileStandard)}
	kemOfferVal := be16(uint16(KEMX25519MLKEM768))
	sigOfferVal := be16(uint16(SigEd25519))
	aeadOfferVal := be16(uint16(AEADAES256GCM))
	oAppendType(FrameClientHello)
	oAppendTLV(TLVProfileOffer, profilesVal)
	oAppendTLV(TLVKEMOffer, kemOfferVal)
	oAppendTLV(TLVSigOffer, sigOfferVal)
	oAppendTLV(TLVAEADOffer, aeadOfferVal)
	oAppendTLV(TLVKEMShare, kemShare)

	profileSelVal := []byte{byte(ProfileStandard)}
	kemSelVal := be16(uint16(KEMX25519MLKEM768))
	sigSelVal := be16(uint16(SigEd25519))
	aeadSelVal := be16(uint16(AEADAES256GCM))
	oAppendType(FrameServerHello)
	oAppendTLV(TLVProfileSelect, profileSelVal)
	oAppendTLV(TLVKEMSelect, kemSelVal)
	oAppendTLV(TLVSigSelect, sigSelVal)
	oAppendTLV(TLVAEADSelect, aeadSelVal)
	oAppendTLV(TLVKEMCiphertext, kemCT)
	oTHKem := oSHA()
	if !bytes.Equal(oTHKem, thKem) {
		t.Fatalf("oracle TH_kem != reference")
	}

	oAppendType(FrameServerAuth)
	oAppendTLV(TLVIdentityKey, serverPub)
	oTHSID := oSHA()
	oAppendTLV(TLVCertVerify, sCV)
	oTHSCV := oSHA()
	oAppendTLV(TLVFinished, sFin)

	oAppendType(FrameClientAuth)
	oAppendTLV(TLVIdentityKey, clientPub)
	oTHCID := oSHA()
	oAppendTLV(TLVCertVerify, cCV)
	oTHCCV := oSHA()

	for _, c := range []struct {
		name       string
		oracle, ref []byte
	}{
		{"th_sid", oTHSID, thSID},
		{"th_scv", oTHSCV, thSCV},
		{"th_cid", oTHCID, thCID},
		{"th_ccv", oTHCCV, thCCV},
	} {
		if !bytes.Equal(c.oracle, c.ref) {
			t.Fatalf("oracle %s != reference", c.name)
		}
	}

	// Oracle key ladder: raw HKDF-Extract + prefix-parameterized Expand-Label.
	oHS, err := hkdf.Extract(sha256.New, oCombined, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oHS, hs) {
		t.Fatalf("oracle handshake_secret != reference")
	}
	oCHS := oExpandLabel(t, oHS, "c hs", oTHKem, 32)
	oSHS := oExpandLabel(t, oHS, "s hs", oTHKem, 32)
	oMaster := oExpandLabel(t, oHS, "master", oTHCCV, 32)
	if !bytes.Equal(oCHS, cHS) || !bytes.Equal(oSHS, sHS) || !bytes.Equal(oMaster, master) {
		t.Fatalf("oracle c_hs/s_hs/master disagree with reference")
	}

	// Oracle Finished keys + MACs (raw crypto/hmac).
	oSFinKey := oExpandLabel(t, oSHS, "finished", nil, 32)
	oCFinKey := oExpandLabel(t, oCHS, "finished", nil, 32)
	if !bytes.Equal(oSFinKey, sFinKey) || !bytes.Equal(oCFinKey, cFinKey) {
		t.Fatalf("oracle finished_keys disagree with reference")
	}
	oSFin := oHMAC(oSFinKey, oTHSCV)
	oCFin := oHMAC(oCFinKey, oTHCCV)
	if !bytes.Equal(oSFin, sFin) || !bytes.Equal(oCFin, cFin) {
		t.Fatalf("oracle finished verify_data disagree with reference")
	}

	// Oracle CertVerify verification (independent ed25519.Verify against the
	// hand-built signing input) — proves the pinned sigs are valid.
	if !oVerifyCertVerify(serverPub, "N-PAMP draft-00, server CertificateVerify", oTHSID, sCV) {
		t.Fatalf("oracle: server CertVerify does not verify")
	}
	if !oVerifyCertVerify(clientPub, "N-PAMP draft-00, client CertificateVerify", oTHCID, cCV) {
		t.Fatalf("oracle: client CertVerify does not verify")
	}

	// Oracle handshake/app traffic secrets/keys/ivs.
	oCtx := func(dir Direction) []byte {
		return []byte{byte(dir), 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00}
	}
	type kiv struct{ ts, key, iv []byte }
	oKIV := func(parent []byte, dir Direction) kiv {
		ts := oExpandLabel(t, parent, "traffic", oCtx(dir), 32)
		return kiv{ts, oExpandLabel(t, ts, "key", nil, 32), oExpandLabel(t, ts, "iv", nil, 12)}
	}
	for _, c := range []struct {
		name string
		o    kiv
		ts, key, iv []byte
	}{
		{"c_hs", oKIV(oCHS, DirClientToServer), cHSTraffic, cHSKey[:], cHSIV[:]},
		{"s_hs", oKIV(oSHS, DirServerToClient), sHSTraffic, sHSKey[:], sHSIV[:]},
		{"app_c2s", oKIV(oMaster, DirClientToServer), appC2STraffic, appC2SKey[:], appC2SIV[:]},
		{"app_s2c", oKIV(oMaster, DirServerToClient), appS2CTraffic, appS2CKey[:], appS2CIV[:]},
	} {
		if !bytes.Equal(c.o.ts, c.ts) || !bytes.Equal(c.o.key, c.key) || !bytes.Equal(c.o.iv, c.iv) {
			t.Fatalf("oracle %s traffic secret/key/iv disagree with reference", c.name)
		}
	}

	// Oracle frame serialization (hand-built 36-octet header + payload; AUTH
	// frames sealed with a raw crypto/aes + cipher.NewGCM path).
	oCHFrame := oMarshalFrame(t, uint16(FrameClientHello), 0x00, 0, chPayload)
	oSHFrame := oMarshalFrame(t, uint16(FrameServerHello), 0x00, 0, shPayload)
	if !bytes.Equal(oCHFrame, chFrame) {
		t.Fatalf("oracle CLIENT_HELLO frame != reference")
	}
	if !bytes.Equal(oSHFrame, shFrame) {
		t.Fatalf("oracle SERVER_HELLO frame != reference")
	}
	oServerAuthFrame := oSealAuthFrame(t, uint16(FrameServerAuth), oSHS, DirServerToClient, serverAuthPlain)
	oClientAuthFrame := oSealAuthFrame(t, uint16(FrameClientAuth), oCHS, DirClientToServer, clientAuthPlain)
	if !bytes.Equal(oServerAuthFrame, serverAuthFrame) {
		t.Fatalf("oracle SERVER_AUTH frame != reference")
	}
	if !bytes.Equal(oClientAuthFrame, clientAuthFrame) {
		t.Fatalf("oracle CLIENT_AUTH frame != reference")
	}

	// ============= ASSEMBLE + WRITE THE VECTOR =============
	h := hex.EncodeToString
	vec := map[string]any{
		"name":       "N-PAMP handshake-flow KAT",
		"class":      "golden-interop",
		"spec":       "N-PAMP draft-01 handshake binding (spec/10) §1, §3, §4, §5, §6; issue #60",
		"profile":    "Standard",
		"hash":       "SHA-256",
		"aead":       "AES-256-GCM",
		"provenance": "Go-reference-anchored, byte-pinned (class golden-interop). The four handshake frames, the AUTH plaintexts, the five transcript points, the full §5 key ladder, the Finished keys/MACs, and the CertVerify signatures were PRODUCED by the real reference code path (NewKEMClient/EncapsulateWith, ClientHello.Encode/DecodeClientHello, ServerHello.Encode, HandshakeSecret/DeriveHandshakeTrafficSecrets/SignCertVerify/DeriveFinishedKey/ComputeFinished/DeriveMasterSecret/DeriveTrafficSecret/DeriveKeyIV, the record-layer seal) from the six fixed seeds, and then RE-DERIVED a second time by an independent inline oracle (hand-built TLV/frame byte construction + raw crypto/hkdf + crypto/hmac + crypto/sha256 + crypto/aes; never the npamp.* helpers), which must agree byte-for-byte. The ML-KEM ciphertext is captured-once and pinned as a self-validating input (crypto/mlkem has no seed-injectable encapsulation): a verifier decapsulates it under mlkem768_seed_dz and MUST recover mlkem_shared_secret.",
		"inputs": map[string]any{
			"description":                  "Six fixed seeds fully determine the flow: client/server X25519 privates (RFC 7748 alice/bob) and the ML-KEM-768 d||z seed are reused from kem-wire-kat.json; the two Ed25519 identity seeds are fixed here. mlkem_ciphertext is captured-once (non-deterministic encaps) and self-validating.",
			"client_x25519_private":        h(clientX25519Priv),
			"server_x25519_private":        h(serverX25519Priv),
			"mlkem768_seed_dz":             h(mlkemSeed),
			"mlkem_ciphertext":             h(mlkemCiphertext),
			"client_identity_ed25519_seed": h(clientEdSeed),
			"server_identity_ed25519_seed": h(serverEdSeed),
			"mlkem_shared_secret":          h(serverSS.MLKEM),
			"x25519_shared_secret":         h(serverSS.X25519),
			"combined_secret":              h(oCombined),
		},
		"expected": map[string]any{
			"frames": map[string]any{
				"client_hello": h(chFrame),
				"server_hello": h(shFrame),
				"server_auth":  h(serverAuthFrame),
				"client_auth":  h(clientAuthFrame),
			},
			"auth_plaintext": map[string]any{
				"server_auth": h(serverAuthPlain),
				"client_auth": h(clientAuthPlain),
			},
			"transcript": map[string]any{
				"th_kem": h(thKem),
				"th_sid": h(thSID),
				"th_scv": h(thSCV),
				"th_cid": h(thCID),
				"th_ccv": h(thCCV),
			},
			"secrets": map[string]any{
				"handshake_secret":       h(hs),
				"c_hs_secret":            h(cHS),
				"s_hs_secret":            h(sHS),
				"master_secret":          h(master),
				"c_hs_traffic_secret":    h(cHSTraffic),
				"c_hs_key":               h(cHSKey[:]),
				"c_hs_iv":                h(cHSIV[:]),
				"s_hs_traffic_secret":    h(sHSTraffic),
				"s_hs_key":               h(sHSKey[:]),
				"s_hs_iv":                h(sHSIV[:]),
				"app_c2s_traffic_secret": h(appC2STraffic),
				"app_c2s_key":            h(appC2SKey[:]),
				"app_c2s_iv":             h(appC2SIV[:]),
				"app_s2c_traffic_secret": h(appS2CTraffic),
				"app_s2c_key":            h(appS2CKey[:]),
				"app_s2c_iv":             h(appS2CIV[:]),
			},
			"finished_keys": map[string]any{
				"server": h(sFinKey),
				"client": h(cFinKey),
			},
			"finished": map[string]any{
				"server": h(sFin),
				"client": h(cFin),
			},
			"cert_verify": map[string]any{
				"server": h(sCV),
				"client": h(cCV),
			},
			"kem": map[string]any{
				"kem_share":      h(kemShare),
				"kem_ciphertext": h(kemCT),
			},
		},
	}

	out, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	path := filepath.Join(katDir, "handshake-flow-kat.json")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s (%d bytes); reference==oracle cross-check PASSED for all frames, transcript points, secrets, finished, and certverify", path, len(out))
}

// ---- fixed seed hex (reused from kem-wire-kat.json; the two Ed25519 seeds are
// fixed here for this vector) ----

const (
	clientX25519PrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a" // RFC 7748 alice_private
	serverX25519PrivHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb" // RFC 7748 bob_private
	mlkem768SeedDZHex   = "E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0" +
		"1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0" // kem-wire-kat d||z
	// Fixed Ed25519 identity seeds for this vector (32 octets = 64 hex each).
	clientEdSeedHex = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	serverEdSeedHex = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
)

// be16 returns a 2-octet big-endian encoding.
func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

// oExpandLabel is the oracle's own RFC 8446 §7.1 HKDF-Expand-Label with the
// N-PAMP "n-pamp " prefix, independent of HkdfExpandLabel.
func oExpandLabel(t *testing.T, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	full := "n-pamp " + label
	info := []byte{byte(length >> 8), byte(length)}
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		t.Fatalf("oracle expand-label %q: %v", label, err)
	}
	return out
}

// oHMAC is the oracle's raw HMAC-SHA256.
func oHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// oVerifyCertVerify rebuilds the RFC 8446 §4.4.3-style signing input by hand and
// checks the Ed25519 signature carried in the CertVerify TLV value
// (SignatureScheme uint16 0x0807 || 64-octet signature).
func oVerifyCertVerify(pub ed25519.PublicKey, context string, transcriptHash, certVerifyValue []byte) bool {
	if len(certVerifyValue) != 2+ed25519.SignatureSize {
		return false
	}
	if binary.BigEndian.Uint16(certVerifyValue[:2]) != uint16(SigEd25519) {
		return false
	}
	input := make([]byte, 0, 64+len(context)+1+len(transcriptHash))
	for range 64 {
		input = append(input, 0x20)
	}
	input = append(input, context...)
	input = append(input, 0x00)
	input = append(input, transcriptHash...)
	return ed25519.Verify(pub, input, certVerifyValue[2:])
}

// mustMarshalFrame builds a cleartext frame through the reference record path.
func mustMarshalFrame(t *testing.T, ft FrameType, seq uint64, payload []byte) []byte {
	t.Helper()
	f := Frame{Type: uint16(ft), Channel: uint16(ChanControl), Seq: seq, Payload: payload}
	wire, err := f.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// mustSealAuth seals an AUTH plaintext into a wire frame through the reference
// key-schedule + record path (mirrors handshake_test.go sealAuth).
func mustSealAuth(t *testing.T, ft FrameType, baseSecret []byte, dir Direction, plaintext []byte, p Profile) []byte {
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

// mustTrafficKeyIV runs the reference traffic-secret + key/iv derivation.
func mustTrafficKeyIV(t *testing.T, parent []byte, dir Direction, p Profile) (ts []byte, key [32]byte, iv [12]byte) {
	t.Helper()
	ts, err := DeriveTrafficSecret(parent, dir, 0, AEADAES256GCM, ChanControl, p)
	if err != nil {
		t.Fatal(err)
	}
	key, iv, err = DeriveKeyIV(ts, p)
	if err != nil {
		t.Fatal(err)
	}
	return ts, key, iv
}

// oMarshalFrame is the oracle's hand-built 36-octet frame serializer (magic
// NPAM, version 0x2, flags in the low nibble, type/channel/seq/payloadLen big
// endian, CRC32C over octets 0..20, reserved 25..35 zero).
func oMarshalFrame(t *testing.T, ftype uint16, flags uint8, seq uint64, payload []byte) []byte {
	t.Helper()
	out := make([]byte, 36+len(payload))
	copy(out[0:4], []byte{0x4E, 0x50, 0x41, 0x4D})
	out[4] = (0x2 << 4) | (flags & 0x0F)
	binary.BigEndian.PutUint16(out[5:7], ftype)
	binary.BigEndian.PutUint16(out[7:9], uint16(ChanControl))
	binary.BigEndian.PutUint64(out[9:17], seq)
	binary.BigEndian.PutUint32(out[17:21], uint32(len(payload)))
	crc := crc32.Checksum(out[0:21], crc32.MakeTable(crc32.Castagnoli))
	binary.BigEndian.PutUint32(out[21:25], crc)
	// octets 25..35 already zero
	copy(out[36:], payload)
	return out
}

// oSealAuthFrame is the oracle's independent AUTH-frame sealer: it derives the
// traffic key/iv via the oracle expand-label, builds the nonce and AAD by hand,
// seals with a raw crypto/aes + cipher.NewGCM, and serializes with oMarshalFrame.
func oSealAuthFrame(t *testing.T, ftype uint16, baseSecret []byte, dir Direction, plaintext []byte) []byte {
	t.Helper()
	ctx := []byte{byte(dir), 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00}
	ts := oExpandLabel(t, baseSecret, "traffic", ctx, 32)
	key := oExpandLabel(t, ts, "key", nil, 32)
	iv := oExpandLabel(t, ts, "iv", nil, 12)

	// AAD = 21-octet header prefix with payloadLen = len(plaintext)+16 (tag).
	var aad [21]byte
	copy(aad[0:4], []byte{0x4E, 0x50, 0x41, 0x4D})
	aad[4] = (0x2 << 4) | (0x02 & 0x0F) // FlagENC in low nibble
	binary.BigEndian.PutUint16(aad[5:7], ftype)
	binary.BigEndian.PutUint16(aad[7:9], uint16(ChanControl))
	binary.BigEndian.PutUint64(aad[9:17], 0)
	binary.BigEndian.PutUint32(aad[17:21], uint32(len(plaintext)+16))

	// Nonce = iv XOR left-zero-padded seq(=0), so nonce == iv here.
	var nonce [12]byte
	copy(nonce[:], iv)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := g.Seal(nil, nonce[:], plaintext, aad[:])
	return oMarshalFrame(t, ftype, 0x02, 0, sealed)
}
