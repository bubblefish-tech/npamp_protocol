package npamp

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"testing"
)

// keyScheduleKAT mirrors test-vectors/v1/key-schedule-kat.json (ADR-0008). The
// file carries NO N-PAMP output bytes — only external RFC anchors and fixed
// inputs. The test proves its own HKDF-Expand-Label oracle against RFC 8448
// ("tls13 " prefix) and RFC 5869, then checks the implementation's key
// schedule against that proven oracle applied with the "n-pamp " prefix.
type keyScheduleKAT struct {
	RFC8448 struct {
		ClientHandshakeTrafficSecret string `json:"client_handshake_traffic_secret"`
		WriteKey                     string `json:"write_key"`
		WriteIV                      string `json:"write_iv"`
		FinishedKey                  string `json:"finished_key"`
	} `json:"rfc8448_expand_label"`
	RFC5869 struct {
		IKM  string `json:"ikm"`
		Salt string `json:"salt"`
		Info string `json:"info"`
		L    int    `json:"L"`
		PRK  string `json:"prk"`
		OKM  string `json:"okm"`
	} `json:"rfc5869_tc1"`
	Inputs struct {
		Profile     string `json:"profile"`
		LabelPrefix string `json:"label_prefix"`
		MLKEMSS     string `json:"ikm_mlkem_ss"`
		X25519SS    string `json:"ikm_x25519_ss"`
		THKem       string `json:"th_kem"`
		THCCV       string `json:"th_ccv"`
	} `json:"npamp_inputs"`
}

// oracleExpandLabel is the test's own RFC 8446 section 7.1 HKDF-Expand-Label
// constructor, prefix-parameterized and independent of the implementation's
// HkdfLabel assembly. It is proven against RFC 8448 (with "tls13 ") before
// being trusted with "n-pamp ".
func oracleExpandLabel(t *testing.T, secret []byte, prefix, label string, context []byte, length int) []byte {
	t.Helper()
	full := prefix + label
	info := []byte{byte(length >> 8), byte(length)}
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		t.Fatalf("oracle expand: %v", err)
	}
	return out
}

func TestKeyScheduleKAT(t *testing.T) {
	var kat keyScheduleKAT
	loadKAT(t, "key-schedule-kat.json", &kat)
	if kat.Inputs.Profile != "Standard" {
		t.Fatalf("vector profile = %q, want Standard", kat.Inputs.Profile)
	}
	if kat.Inputs.LabelPrefix != LabelPrefix {
		t.Fatalf("label prefix: vector %q, impl %q", kat.Inputs.LabelPrefix, LabelPrefix)
	}

	// Anchor 1 (RFC 5869 TC1): the raw HKDF Extract/Expand primitive.
	prk, err := hkdf.Extract(sha256.New, mustHex(t, "ikm", kat.RFC5869.IKM), mustHex(t, "salt", kat.RFC5869.Salt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prk, mustHex(t, "prk", kat.RFC5869.PRK)) {
		t.Fatal("HKDF-Extract does not reproduce RFC 5869 TC1 prk")
	}
	okm, err := hkdf.Expand(sha256.New, prk, string(mustHex(t, "info", kat.RFC5869.Info)), kat.RFC5869.L)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(okm, mustHex(t, "okm", kat.RFC5869.OKM)) {
		t.Fatal("HKDF-Expand does not reproduce RFC 5869 TC1 okm")
	}

	// Anchor 2 (RFC 8448 section 3): prove the Expand-Label oracle mechanism
	// with the TLS 1.3 prefix before trusting it with the N-PAMP prefix.
	hts := mustHex(t, "client_handshake_traffic_secret", kat.RFC8448.ClientHandshakeTrafficSecret)
	if !bytes.Equal(oracleExpandLabel(t, hts, "tls13 ", "key", nil, 16), mustHex(t, "write_key", kat.RFC8448.WriteKey)) {
		t.Fatal("oracle Expand-Label does not reproduce the RFC 8448 write_key")
	}
	if !bytes.Equal(oracleExpandLabel(t, hts, "tls13 ", "iv", nil, 12), mustHex(t, "write_iv", kat.RFC8448.WriteIV)) {
		t.Fatal("oracle Expand-Label does not reproduce the RFC 8448 write_iv")
	}
	if !bytes.Equal(oracleExpandLabel(t, hts, "tls13 ", "finished", nil, 32), mustHex(t, "finished_key", kat.RFC8448.FinishedKey)) {
		t.Fatal("oracle Expand-Label does not reproduce the RFC 8448 finished_key")
	}

	// Impl primitive vs proven oracle: HkdfExpandLabel is the oracle with the
	// "n-pamp " prefix.
	if !bytes.Equal(mustExpand(t, hts, "key", nil, 16), oracleExpandLabel(t, hts, LabelPrefix, "key", nil, 16)) {
		t.Fatal("HkdfExpandLabel disagrees with the RFC-8448-proven oracle under the n-pamp prefix")
	}

	// N-PAMP key schedule (spec/10 section 5), impl vs oracle.
	mlkemSS := mustHex(t, "ikm_mlkem_ss", kat.Inputs.MLKEMSS)
	xSS := mustHex(t, "ikm_x25519_ss", kat.Inputs.X25519SS)
	thKem := mustHex(t, "th_kem", kat.Inputs.THKem)
	thCCV := mustHex(t, "th_ccv", kat.Inputs.THCCV)

	hsOracle, err := hkdf.Extract(sha256.New, concat(mlkemSS, xSS), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	hs, err := HandshakeSecret(SharedSecrets{MLKEM: mlkemSS, X25519: xSS}, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hs, hsOracle) {
		t.Fatal("HandshakeSecret != HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS)")
	}
	// Mutation guard (ADR-0005): the X25519-first IKM order MUST fail.
	reversed, err := hkdf.Extract(sha256.New, concat(xSS, mlkemSS), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hs, reversed) {
		t.Fatal("HandshakeSecret matches the X25519-first IKM order")
	}

	cHS, sHS, err := DeriveHandshakeTrafficSecrets(hs, thKem, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cHS, oracleExpandLabel(t, hs, LabelPrefix, "c hs", thKem, 32)) {
		t.Fatal("c_hs_secret disagrees with the proven oracle")
	}
	if !bytes.Equal(sHS, oracleExpandLabel(t, hs, LabelPrefix, "s hs", thKem, 32)) {
		t.Fatal("s_hs_secret disagrees with the proven oracle")
	}

	master, err := DeriveMasterSecret(hs, thCCV, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(master, oracleExpandLabel(t, hs, LabelPrefix, "master", thCCV, 32)) {
		t.Fatal("master disagrees with the proven oracle")
	}

	for name, base := range map[string][]byte{"c_hs": cHS, "s_hs": sHS} {
		finKey, err := DeriveFinishedKey(base, ProfileStandard)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(finKey, oracleExpandLabel(t, base, LabelPrefix, "finished", nil, 32)) {
			t.Fatalf("finished_key(%s) disagrees with the proven oracle", name)
		}
	}

	// Handshake-phase traffic keys: parent c_hs/s_hs, dir per sender, epoch 0,
	// suite AES-256-GCM (0x0001, registries/aead.csv), channel Control 0x0000.
	// ctx = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE).
	ctx := []byte{byte(DirClientToServer), 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x00}
	tsOracle := oracleExpandLabel(t, cHS, LabelPrefix, "traffic", ctx, 32)
	ts, err := DeriveTrafficSecret(cHS, DirClientToServer, 0, AEADAES256GCM, ChanControl, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ts, tsOracle) {
		t.Fatal("handshake-phase traffic secret disagrees with the proven oracle")
	}
	key, iv, err := DeriveKeyIV(ts, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[:], oracleExpandLabel(t, ts, LabelPrefix, "key", nil, 32)) {
		t.Fatal("traffic key disagrees with the proven oracle")
	}
	if !bytes.Equal(iv[:], oracleExpandLabel(t, ts, LabelPrefix, "iv", nil, 12)) {
		t.Fatal("traffic iv disagrees with the proven oracle")
	}

	// Phase separation: the identical (dir, epoch, suite, channel) tuple under
	// the application-phase parent (master) MUST NOT reproduce the
	// handshake-phase secret (spec/10 section 5).
	tsApp, err := DeriveTrafficSecret(master, DirClientToServer, 0, AEADAES256GCM, ChanControl, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ts, tsApp) {
		t.Fatal("handshake-phase and application-phase traffic secrets collide")
	}
}

// mustExpand calls the implementation's HkdfExpandLabel at Standard/SHA-256.
func mustExpand(t *testing.T, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	out, err := HkdfExpandLabel(secret, label, context, length, sha256.New)
	if err != nil {
		t.Fatalf("HkdfExpandLabel: %v", err)
	}
	return out
}
