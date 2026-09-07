package npamp

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha512"
	"errors"
	"testing"
)

// mldsa87PrimitivesKAT mirrors test-vectors/v1/mldsa87-primitives-kat.json
// (P2.10): two INDEPENDENT third-party sources, neither produced by this
// repository's Go or Rust implementations and neither derived from the
// other — an ACVP-derived ML-DSA-87 KeyGen KAT (BoringSSL FIPS 204 corpus,
// vendored via apple/swift-crypto) for seed->pk, and a Project Wycheproof
// ML-DSA-87 verify test group (also vendored via apple/swift-crypto) for a
// valid and a tampered signature. This file does NOT vector N-PAMP's own
// CertVerifySigningInput context/transcript wrapping (no third-party corpus
// covers that N-PAMP-specific pre-image) — the wrapping is instead proven
// correct by TestCertVerifyMLDSA87 below, using a key whose PUBLIC part was
// itself just proven to reproduce the independent keygen oracle.
type mldsa87PrimitivesKAT struct {
	KeygenSeedToPK struct {
		Seed string `json:"seed"`
		PK   string `json:"pk"`
	} `json:"keygen_seed_to_pk"`
	VerifyGroupPublicKey         string `json:"verify_group_public_key"`
	VerifyGroupPKMatchesKeygenPK bool   `json:"verify_group_pk_matches_keygen_pk"`
	ValidCase                    struct {
		TcID    int    `json:"tcId"`
		Comment string `json:"comment"`
		Msg     string `json:"msg"`
		Sig     string `json:"sig"`
		Result  string `json:"result"`
	} `json:"valid_case"`
	InvalidCase struct {
		TcID    int      `json:"tcId"`
		Comment string   `json:"comment"`
		Msg     string   `json:"msg"`
		Sig     string   `json:"sig"`
		Result  string   `json:"result"`
		Flags   []string `json:"flags"`
	} `json:"invalid_case"`
}

// TestMLDSA87Primitives proves Go 1.27 stdlib crypto/mldsa's MLDSA87
// keygen and Verify reproduce two independent, non-circular oracles before
// either is trusted by N-PAMP's High/Sovereign CertVerify path.
func TestMLDSA87Primitives(t *testing.T) {
	var kat mldsa87PrimitivesKAT
	loadKAT(t, "mldsa87-primitives-kat.json", &kat)

	if kat.VerifyGroupPKMatchesKeygenPK {
		t.Fatalf("fixture invariant broken: the vectored keygen and verify oracles were assumed to use different keys")
	}

	// Keygen leg: an independent ACVP-derived seed->pk MUST reproduce under
	// Go's stdlib NewPrivateKey (FIPS 204 KeyGen_internal, Algorithm 16).
	seed := mustHex(t, "keygen_seed_to_pk.seed", kat.KeygenSeedToPK.Seed)
	wantPK := mustHex(t, "keygen_seed_to_pk.pk", kat.KeygenSeedToPK.PK)
	priv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey: %v", err)
	}
	gotPK := priv.PublicKey().Bytes()
	if !bytes.Equal(gotPK, wantPK) {
		t.Fatalf("ML-DSA-87 keygen does not reproduce the independent ACVP-derived KAT:\n got  %x\n want %x", gotPK, wantPK)
	}

	// Verify leg: independent Project Wycheproof valid/invalid signatures
	// MUST be accepted/rejected identically by Go's stdlib Verify.
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA87(), mustHex(t, "verify_group_public_key", kat.VerifyGroupPublicKey))
	if err != nil {
		t.Fatalf("mldsa.NewPublicKey: %v", err)
	}
	validMsg := mustHex(t, "valid_case.msg", kat.ValidCase.Msg)
	validSig := mustHex(t, "valid_case.sig", kat.ValidCase.Sig)
	if kat.ValidCase.Result != "valid" {
		t.Fatalf("fixture invariant broken: valid_case.result = %q, want valid", kat.ValidCase.Result)
	}
	if err := mldsa.Verify(pub, validMsg, validSig, nil); err != nil {
		t.Fatalf("Verify rejected the independently sourced VALID signature (tcId %d, %s): %v", kat.ValidCase.TcID, kat.ValidCase.Comment, err)
	}

	invalidMsg := mustHex(t, "invalid_case.msg", kat.InvalidCase.Msg)
	invalidSig := mustHex(t, "invalid_case.sig", kat.InvalidCase.Sig)
	if kat.InvalidCase.Result != "invalid" {
		t.Fatalf("fixture invariant broken: invalid_case.result = %q, want invalid", kat.InvalidCase.Result)
	}
	if err := mldsa.Verify(pub, invalidMsg, invalidSig, nil); err == nil {
		t.Fatalf("Verify ACCEPTED the independently sourced INVALID signature (tcId %d, %s) — fail-open", kat.InvalidCase.TcID, kat.InvalidCase.Comment)
	}
}

// TestCertVerifyMLDSA87 demonstrates SignCertVerifyMLDSA87/
// VerifyCertVerifyMLDSA87 in isolation (A9), using a key whose public part
// was just proven (TestMLDSA87Primitives, same seed) to reproduce the
// independent ACVP keygen oracle — so the key material itself is not
// self-asserted, only the wrapping (CertVerifySigningInput || ML-DSA-87
// sign/verify) is exercised here, exactly as TestCertVerifyKAT exercises
// the Ed25519 wrapping separately from its RFC 8032 primitive anchor.
func TestCertVerifyMLDSA87(t *testing.T) {
	var kat mldsa87PrimitivesKAT
	loadKAT(t, "mldsa87-primitives-kat.json", &kat)

	seed := mustHex(t, "keygen_seed_to_pk.seed", kat.KeygenSeedToPK.Seed)
	serverPriv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey: %v", err)
	}
	// A second, distinct oracled key for the client side: flip the seed's
	// first octet (still a valid 32-octet seed, just a different key) so
	// client and server are provably NOT the same key.
	clientSeed := bytes.Clone(seed)
	clientSeed[0] ^= 0xFF
	clientPriv, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), clientSeed)
	if err != nil {
		t.Fatalf("mldsa.NewPrivateKey (client): %v", err)
	}
	if bytes.Equal(clientPriv.PublicKey().Bytes(), serverPriv.PublicKey().Bytes()) {
		t.Fatalf("test setup bug: client and server ML-DSA-87 keys are identical")
	}

	// Synthetic, deterministic transcript hashes (SHA-384, matching the
	// High/Sovereign KDFHash, spec/10 section 6 invariants) — NOT a full
	// handshake transcript, only enough to exercise
	// CertVerifySigningInput/SignCertVerifyMLDSA87/VerifyCertVerifyMLDSA87
	// in isolation with concrete input producing concrete output (A9).
	thSID := sha384(t, "N-PAMP mldsa87 certverify test: TH_sId")
	thCID := sha384(t, "N-PAMP mldsa87 certverify test: TH_cId")

	cases := []struct {
		roleName string
		role     Role
		priv     *mldsa.PrivateKey
		pub      *mldsa.PublicKey
		th       []byte
	}{
		{"server", RoleServer, serverPriv, serverPriv.PublicKey(), thSID},
		{"client", RoleClient, clientPriv, clientPriv.PublicKey(), thCID},
	}
	for _, c := range cases {
		value, err := SignCertVerifyMLDSA87(c.priv, c.role, c.th)
		if err != nil {
			t.Fatalf("%s: SignCertVerifyMLDSA87: %v", c.roleName, err)
		}
		wantLen := 2 + mldsa.MLDSA87SignatureSize
		if len(value) != wantLen {
			t.Fatalf("%s: SignCertVerifyMLDSA87 produced %d octets, want %d", c.roleName, len(value), wantLen)
		}
		if value[0] != 0x09 || value[1] != 0x06 {
			t.Fatalf("%s: CertVerify value scheme prefix = %02x%02x, want 0906 (SigMLDSA87)", c.roleName, value[0], value[1])
		}
		if err := VerifyCertVerifyMLDSA87(c.pub, c.role, c.th, value); err != nil {
			t.Fatalf("%s: VerifyCertVerifyMLDSA87 rejected the correct value: %v", c.roleName, err)
		}

		// Domain separation: the same value under the OTHER role's context
		// MUST be rejected (spec/10 section 6.1).
		otherRole := RoleClient
		if c.role == RoleClient {
			otherRole = RoleServer
		}
		if err := VerifyCertVerifyMLDSA87(c.pub, otherRole, c.th, value); !errors.Is(err, ErrCertVerifySignature) {
			t.Fatalf("%s: role-mismatched CertVerify not rejected (err=%v)", c.roleName, err)
		}

		// Transcript binding: a different transcript hash MUST be rejected.
		otherTH := thCID
		if c.role == RoleClient {
			otherTH = thSID
		}
		if err := VerifyCertVerifyMLDSA87(c.pub, c.role, otherTH, value); !errors.Is(err, ErrCertVerifySignature) {
			t.Fatalf("%s: wrong-transcript CertVerify not rejected (err=%v)", c.roleName, err)
		}

		// Scheme pinning: a non-negotiated SignatureScheme MUST be
		// rejected — here, presenting the value under the Ed25519 code
		// point (0x0807) instead of ML-DSA-87 (0x0906).
		badScheme := bytes.Clone(value)
		badScheme[0], badScheme[1] = 0x08, 0x07
		if err := VerifyCertVerifyMLDSA87(c.pub, c.role, c.th, badScheme); !errors.Is(err, ErrCertVerifyScheme) {
			t.Fatalf("%s: non-negotiated scheme not rejected (err=%v)", c.roleName, err)
		}

		// Tamper: flip a byte inside the signature; MUST be rejected.
		tampered := bytes.Clone(value)
		tampered[len(tampered)-1] ^= 0x01
		if err := VerifyCertVerifyMLDSA87(c.pub, c.role, c.th, tampered); !errors.Is(err, ErrCertVerifySignature) {
			t.Fatalf("%s: tampered signature not rejected (err=%v)", c.roleName, err)
		}
	}

	// Cross-check: the wrapped signing input is byte-identical to
	// CertVerifySigningInput's own output (the same function Ed25519
	// CertVerify uses) — the ML-DSA-87 path adds no separate pre-image
	// construction.
	input, err := CertVerifySigningInput(RoleServer, thSID)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := serverPriv.SignDeterministic(input, nil)
	if err != nil {
		t.Fatalf("SignDeterministic: %v", err)
	}
	if err := mldsa.Verify(serverPriv.PublicKey(), input, sig, nil); err != nil {
		t.Fatalf("raw stdlib Verify rejected a signature produced over CertVerifySigningInput's own output: %v", err)
	}
}

// sha384 returns the SHA-384 digest of msg (High/Sovereign KDFHash, spec/10
// section 6 invariants).
func sha384(t *testing.T, msg string) []byte {
	t.Helper()
	sum := sha512.Sum384([]byte(msg))
	return sum[:]
}
