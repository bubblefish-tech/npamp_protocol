package npamp

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

// certVerifyKAT mirrors test-vectors/v1/certverify-kat.json (ADR-0011):
// CertVerify value = u16(0x0807) || Ed25519(priv, signing_input), with
// signing_input = 0x20 x 64 || context || 0x00 || transcript_hash (spec/10
// section 6.1). The Ed25519 primitive is anchored to RFC 8032 section 7.1
// TEST 1/TEST 2; the keys are the RFC 8032 test keypairs; the transcript
// hashes are the Transcript KAT's TH_sId / TH_cId.
type certVerifyKAT struct {
	Contexts struct {
		Client string `json:"client"`
		Server string `json:"server"`
	} `json:"contexts"`
	Expected struct {
		ValueClient  string `json:"certverify_value_client"`
		ValueServer  string `json:"certverify_value_server"`
		SigClient    string `json:"signature_client"`
		SigServer    string `json:"signature_server"`
		InputClient  string `json:"signing_input_client"`
		InputServer  string `json:"signing_input_server"`
	} `json:"expected"`
	Inputs struct {
		ClientPub  string `json:"client_pub"`
		ClientSeed string `json:"client_seed"`
		ServerPub  string `json:"server_pub"`
		ServerSeed string `json:"server_seed"`
		THCID      string `json:"th_cid"`
		THSID      string `json:"th_sid"`
	} `json:"npamp_inputs"`
	RFC8032 struct {
		Test1 struct {
			Message   string `json:"message"`
			PublicKey string `json:"public_key"`
			Seed      string `json:"seed"`
			Signature string `json:"signature"`
		} `json:"test1"`
		Test2 struct {
			Message   string `json:"message"`
			PublicKey string `json:"public_key"`
			Seed      string `json:"seed"`
			Signature string `json:"signature"`
		} `json:"test2"`
	} `json:"rfc8032_ed25519"`
}

func TestCertVerifyKAT(t *testing.T) {
	var kat certVerifyKAT
	loadKAT(t, "certverify-kat.json", &kat)

	// Anchor (RFC 8032 section 7.1 TEST 1/TEST 2): prove the Ed25519
	// primitive — public-key derivation and the deterministic signature.
	for name, tv := range map[string]struct{ Message, PublicKey, Seed, Signature string }{
		"test1": {kat.RFC8032.Test1.Message, kat.RFC8032.Test1.PublicKey, kat.RFC8032.Test1.Seed, kat.RFC8032.Test1.Signature},
		"test2": {kat.RFC8032.Test2.Message, kat.RFC8032.Test2.PublicKey, kat.RFC8032.Test2.Seed, kat.RFC8032.Test2.Signature},
	} {
		priv := ed25519.NewKeyFromSeed(mustHex(t, name+".seed", tv.Seed))
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), mustHex(t, name+".public_key", tv.PublicKey)) {
			t.Fatalf("Ed25519 public key does not reproduce RFC 8032 %s", name)
		}
		sig := ed25519.Sign(priv, mustHex(t, name+".message", tv.Message))
		if !bytes.Equal(sig, mustHex(t, name+".signature", tv.Signature)) {
			t.Fatalf("Ed25519 signature does not reproduce RFC 8032 %s", name)
		}
	}

	serverPriv := ed25519.NewKeyFromSeed(mustHex(t, "server_seed", kat.Inputs.ServerSeed))
	clientPriv := ed25519.NewKeyFromSeed(mustHex(t, "client_seed", kat.Inputs.ClientSeed))
	serverPub := mustHex(t, "server_pub", kat.Inputs.ServerPub)
	clientPub := mustHex(t, "client_pub", kat.Inputs.ClientPub)
	thSID := mustHex(t, "th_sid", kat.Inputs.THSID)
	thCID := mustHex(t, "th_cid", kat.Inputs.THCID)

	cases := []struct {
		roleName  string
		role      Role
		priv      ed25519.PrivateKey
		pub       []byte
		th        []byte
		context   string
		wantInput []byte
		wantSig   []byte
		wantValue []byte
	}{
		{"server", RoleServer, serverPriv, serverPub, thSID, kat.Contexts.Server,
			mustHex(t, "signing_input_server", kat.Expected.InputServer),
			mustHex(t, "signature_server", kat.Expected.SigServer),
			mustHex(t, "certverify_value_server", kat.Expected.ValueServer)},
		{"client", RoleClient, clientPriv, clientPub, thCID, kat.Contexts.Client,
			mustHex(t, "signing_input_client", kat.Expected.InputClient),
			mustHex(t, "signature_client", kat.Expected.SigClient),
			mustHex(t, "certverify_value_client", kat.Expected.ValueClient)},
	}
	for _, c := range cases {
		// Oracle leg: build the signing input independently of the impl —
		// 64 x 0x20 || context || 0x00 || transcript_hash — and sign with
		// crypto/ed25519 directly.
		oracleInput := append(bytes.Repeat([]byte{0x20}, 64), []byte(c.context)...)
		oracleInput = append(oracleInput, 0x00)
		oracleInput = append(oracleInput, c.th...)
		if !bytes.Equal(oracleInput, c.wantInput) {
			t.Fatalf("%s: oracle signing input does not reproduce the vector", c.roleName)
		}
		if got := ed25519.Sign(c.priv, oracleInput); !bytes.Equal(got, c.wantSig) {
			t.Fatalf("%s: oracle Ed25519 signature does not reproduce the vector", c.roleName)
		}
		if got := concat([]byte{0x08, 0x07}, c.wantSig); !bytes.Equal(got, c.wantValue) {
			t.Fatalf("%s: certverify_value is not u16(0x0807) || signature", c.roleName)
		}

		// Impl leg: the real signing-input builder, signer, and verifier.
		implInput, err := CertVerifySigningInput(c.role, c.th)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(implInput, c.wantInput) {
			t.Fatalf("%s: CertVerifySigningInput = %x, want %x", c.roleName, implInput, c.wantInput)
		}
		value, err := SignCertVerify(c.priv, c.role, c.th)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(value, c.wantValue) {
			t.Fatalf("%s: SignCertVerify = %x, want %x", c.roleName, value, c.wantValue)
		}
		if err := VerifyCertVerify(c.pub, c.role, c.th, value); err != nil {
			t.Fatalf("%s: VerifyCertVerify rejected the correct value: %v", c.roleName, err)
		}

		// Domain separation: the same value presented under the OTHER role's
		// context MUST be rejected (spec/10 section 6.1).
		otherRole := RoleClient
		if c.role == RoleClient {
			otherRole = RoleServer
		}
		if err := VerifyCertVerify(c.pub, otherRole, c.th, value); !errors.Is(err, ErrCertVerifySignature) {
			t.Fatalf("%s: role-mismatched CertVerify not rejected (err=%v)", c.roleName, err)
		}

		// Transcript binding: a different transcript hash MUST be rejected.
		otherTH := thCID
		if c.role == RoleClient {
			otherTH = thSID
		}
		if err := VerifyCertVerify(c.pub, c.role, otherTH, value); !errors.Is(err, ErrCertVerifySignature) {
			t.Fatalf("%s: wrong-transcript CertVerify not rejected (err=%v)", c.roleName, err)
		}

		// Scheme pinning: a non-negotiated SignatureScheme MUST be rejected.
		badScheme := bytes.Clone(value)
		badScheme[0], badScheme[1] = 0x09, 0x05 // ML-DSA-87 code point, not negotiated at Standard
		if err := VerifyCertVerify(c.pub, c.role, c.th, badScheme); !errors.Is(err, ErrCertVerifyScheme) {
			t.Fatalf("%s: non-negotiated scheme not rejected (err=%v)", c.roleName, err)
		}
	}
}
