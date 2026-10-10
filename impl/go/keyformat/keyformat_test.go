// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package keyformat

// keyformat_test.go exercises the round-trip and typed-accessor behavior of
// the versioned key-storage format against REAL key material produced by the
// same stdlib crypto types the rest of this module uses (crypto/mlkem,
// crypto/ecdh, crypto/ed25519) — not fixtures invented for this test —
// except where a group has no provider here (the opaque-material tests). Each
// provider-backed round trip additionally reconstructs a live, USABLE key from
// the decoded bytes (a fresh mlkem.DecapsulationKey / ecdh.PrivateKey /
// ed25519 sign-verify) to prove the format carries genuinely reusable key
// material, not merely bytes that happen to compare equal.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestRoundTripEd25519SigPrivateAndPublic encodes and decodes a real Ed25519
// identity key pair (the same crypto/ed25519 type impl/go/handshake.go and
// impl/go/sdk use for CertVerify), then proves the decoded keys are still
// live and correct by signing with the decoded private key and verifying
// with the decoded public key.
func TestRoundTripEd25519SigPrivateAndPublic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	privData, err := EncodeSigPrivate(npamp.SigEd25519, priv)
	if err != nil {
		t.Fatalf("EncodeSigPrivate: %v", err)
	}
	pubData, err := EncodeSigPublic(npamp.SigEd25519, pub)
	if err != nil {
		t.Fatalf("EncodeSigPublic: %v", err)
	}

	gotAlg, gotPriv, err := DecodeSigPrivate(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPrivate: %v", err)
	}
	if gotAlg != npamp.SigEd25519 {
		t.Fatalf("decoded algorithm = 0x%04x, want SigEd25519 (0x%04x)", uint16(gotAlg), uint16(npamp.SigEd25519))
	}
	if !bytes.Equal(gotPriv, priv) {
		t.Fatal("decoded Ed25519 private key material is not byte-identical to the original")
	}

	// Explicit metadata check via the low-level Decode, not just the typed
	// accessor's algorithm return: FormatVersion and Generation must round
	// trip correctly too, not merely "decode without error".
	privRec, err := Decode(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("Decode(privData): %v", err)
	}
	if privRec.FormatVersion != CurrentFormatVersion {
		t.Fatalf("decoded FormatVersion = %d, want %d", privRec.FormatVersion, CurrentFormatVersion)
	}
	if privRec.Generation != npamp.ALPN {
		t.Fatalf("decoded Generation = %q, want %q", privRec.Generation, npamp.ALPN)
	}
	if privRec.Role != RoleSigPrivate {
		t.Fatalf("decoded Role = %v, want %v", privRec.Role, RoleSigPrivate)
	}

	gotAlg2, gotPub, err := DecodeSigPublic(pubData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPublic: %v", err)
	}
	if gotAlg2 != npamp.SigEd25519 {
		t.Fatalf("decoded algorithm = 0x%04x, want SigEd25519 (0x%04x)", uint16(gotAlg2), uint16(npamp.SigEd25519))
	}
	if !bytes.Equal(gotPub, pub) {
		t.Fatal("decoded Ed25519 public key material is not byte-identical to the original")
	}

	// Functional proof, not just byte comparison: the decoded private key
	// must still produce signatures the decoded public key verifies.
	msg := []byte("keyformat round-trip probe")
	sig := ed25519.Sign(ed25519.PrivateKey(gotPriv), msg)
	if !ed25519.Verify(ed25519.PublicKey(gotPub), msg, sig) {
		t.Fatal("signature made with the decoded private key does not verify under the decoded public key")
	}
}

// TestRoundTripX25519MLKEM768KEMPrivateAndPublic encodes and decodes a real
// X25519MLKEM768 hybrid-KEM key pair built directly from crypto/mlkem and
// crypto/ecdh (the same providers impl/go/kem.go wraps), then proves the
// decoded private key reconstructs the identical live decapsulation key
// (its re-derived encapsulation key matches the original byte-for-byte).
func TestRoundTripX25519MLKEM768KEMPrivateAndPublic(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("mlkem.GenerateKey768: %v", err)
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh X25519 GenerateKey: %v", err)
	}

	privData, err := EncodeKEMPrivate(npamp.KEMX25519MLKEM768, dk.Bytes(), xk.Bytes())
	if err != nil {
		t.Fatalf("EncodeKEMPrivate: %v", err)
	}
	pubData, err := EncodeKEMPublic(npamp.KEMX25519MLKEM768, dk.EncapsulationKey().Bytes(), xk.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("EncodeKEMPublic: %v", err)
	}

	group, seed2, xpriv2, err := DecodeKEMPrivate(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeKEMPrivate: %v", err)
	}
	if group != npamp.KEMX25519MLKEM768 {
		t.Fatalf("decoded group = 0x%04x, want 0x%04x", uint16(group), uint16(npamp.KEMX25519MLKEM768))
	}
	if !bytes.Equal(seed2, dk.Bytes()) {
		t.Fatal("decoded ML-KEM-768 seed is not byte-identical to the original")
	}
	if !bytes.Equal(xpriv2, xk.Bytes()) {
		t.Fatal("decoded X25519 private key is not byte-identical to the original")
	}

	// Functional proof: reconstruct live keys from the decoded bytes and
	// confirm they reproduce the identical public materials.
	dk2, err := mlkem.NewDecapsulationKey768(seed2)
	if err != nil {
		t.Fatalf("mlkem.NewDecapsulationKey768(decoded seed): %v", err)
	}
	if !bytes.Equal(dk2.EncapsulationKey().Bytes(), dk.EncapsulationKey().Bytes()) {
		t.Fatal("decapsulation key reconstructed from the decoded seed has a different encapsulation key")
	}
	xk2, err := ecdh.X25519().NewPrivateKey(xpriv2)
	if err != nil {
		t.Fatalf("ecdh X25519 NewPrivateKey(decoded bytes): %v", err)
	}
	if !bytes.Equal(xk2.PublicKey().Bytes(), xk.PublicKey().Bytes()) {
		t.Fatal("X25519 private key reconstructed from the decoded bytes has a different public key")
	}

	group2, mlkemEK2, xpub2, err := DecodeKEMPublic(pubData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeKEMPublic: %v", err)
	}
	if group2 != npamp.KEMX25519MLKEM768 {
		t.Fatalf("decoded public-record group = 0x%04x, want 0x%04x", uint16(group2), uint16(npamp.KEMX25519MLKEM768))
	}
	if !bytes.Equal(mlkemEK2, dk.EncapsulationKey().Bytes()) {
		t.Fatal("decoded ML-KEM-768 encapsulation key is not byte-identical to the original")
	}
	if !bytes.Equal(xpub2, xk.PublicKey().Bytes()) {
		t.Fatal("decoded X25519 public key is not byte-identical to the original")
	}
}

// TestKEMGroup0x11edKeyMaterialIsRefused: the SecP384r1MLKEM1024 group (0x11ed) is a known code
// point whose key material this package refuses to store or load. Every typed and untyped
// entry point returns ErrGroupNotSupported and no bytes or components, including for
// component sizes that group's keys would have had (ML-KEM-1024 seed 64 / encapsulation key
// 1568, P-384 private 48 / public 97) and for sizes that match no group at all, because the
// refusal comes from the group and not from a size check. A record carrying 0x11ed that was
// written elsewhere is refused on Decode too.
func TestKEMGroup0x11edKeyMaterialIsRefused(t *testing.T) {
	const group = npamp.KEMSecP384r1MLKEM1024
	sized := func(n int) []byte { return bytes.Repeat([]byte{0x42}, n) }

	t.Run("EncodeKEMPrivate", func(t *testing.T) {
		for _, c := range [][2]int{{64, 48}, {64, 32}, {1, 1}, {0, 0}} {
			data, err := EncodeKEMPrivate(group, sized(c[0]), sized(c[1]))
			if !errors.Is(err, ErrGroupNotSupported) || data != nil {
				t.Fatalf("EncodeKEMPrivate sizes %v: data %d octets, err = %v; want nil and ErrGroupNotSupported", c, len(data), err)
			}
		}
	})
	t.Run("EncodeKEMPublic", func(t *testing.T) {
		for _, c := range [][2]int{{1568, 97}, {1184, 32}, {1, 1}, {0, 0}} {
			data, err := EncodeKEMPublic(group, sized(c[0]), sized(c[1]))
			if !errors.Is(err, ErrGroupNotSupported) || data != nil {
				t.Fatalf("EncodeKEMPublic sizes %v: data %d octets, err = %v; want nil and ErrGroupNotSupported", c, len(data), err)
			}
		}
	})
	t.Run("Encode", func(t *testing.T) {
		for _, role := range []Role{RoleKEMPrivate, RoleKEMPublic} {
			data, err := Encode(KeyRecord{FormatVersion: CurrentFormatVersion, Generation: npamp.ALPN, Role: role, Algorithm: uint64(group), Components: [][]byte{sized(64), sized(48)}})
			if !errors.Is(err, ErrGroupNotSupported) || data != nil {
				t.Fatalf("Encode role %v: data %d octets, err = %v; want nil and ErrGroupNotSupported", role, len(data), err)
			}
		}
	})
	// A record produced by another writer: marshalRecord builds it without the Encode check.
	privRec := marshalRecord(KeyRecord{FormatVersion: CurrentFormatVersion, Generation: npamp.ALPN, Role: RoleKEMPrivate, Algorithm: uint64(group), Components: [][]byte{sized(64), sized(48)}})
	pubRec := marshalRecord(KeyRecord{FormatVersion: CurrentFormatVersion, Generation: npamp.ALPN, Role: RoleKEMPublic, Algorithm: uint64(group), Components: [][]byte{sized(1568), sized(97)}})
	t.Run("Decode", func(t *testing.T) {
		for name, data := range map[string][]byte{"private": privRec, "public": pubRec} {
			rec, err := Decode(data, npamp.ALPN)
			if !errors.Is(err, ErrGroupNotSupported) || !isZeroRecord(rec) {
				t.Fatalf("Decode %s record: rec zero = %v, err = %v; want zero record and ErrGroupNotSupported", name, isZeroRecord(rec), err)
			}
		}
	})
	t.Run("DecodeKEMPrivate", func(t *testing.T) {
		g, seed, classical, err := DecodeKEMPrivate(privRec, npamp.ALPN)
		if !errors.Is(err, ErrGroupNotSupported) || g != 0 || seed != nil || classical != nil {
			t.Fatalf("DecodeKEMPrivate: group %#04x seed %d classical %d err %v; want zero values and ErrGroupNotSupported", uint16(g), len(seed), len(classical), err)
		}
	})
	t.Run("DecodeKEMPublic", func(t *testing.T) {
		g, ek, classical, err := DecodeKEMPublic(pubRec, npamp.ALPN)
		if !errors.Is(err, ErrGroupNotSupported) || g != 0 || ek != nil || classical != nil {
			t.Fatalf("DecodeKEMPublic: group %#04x ek %d classical %d err %v; want zero values and ErrGroupNotSupported", uint16(g), len(ek), len(classical), err)
		}
	})
	// The refusal is specific to the group: the other defined group still encodes.
	if _, err := EncodeKEMPrivate(npamp.KEMX25519MLKEM768, sized(64), sized(32)); err != nil {
		t.Fatalf("EncodeKEMPrivate(X25519MLKEM768) after the refusal change: %v", err)
	}
	// A code point that is not defined at all stays ErrUnknownAlgorithm, not the refusal.
	if _, err := EncodeKEMPrivate(npamp.KEMID(0x11ee), sized(64), sized(32)); !errors.Is(err, ErrUnknownAlgorithm) || errors.Is(err, ErrGroupNotSupported) {
		t.Fatalf("EncodeKEMPrivate(0x11ee) err = %v, want ErrUnknownAlgorithm and not ErrGroupNotSupported", err)
	}
}

// TestKEMGroup0x11edRefusedUnderEveryAcceptedGeneration: Decode validates a record against the
// registry only for npamp.ALPN, so a record under any other generation the caller accepts is
// not size-checked. The 0x11ed refusal comes from the group and must not depend on that
// generation branch: a KEM-private and a KEM-public record carrying 0x11ed under a
// non-ALPN generation the caller accepted must still return ErrGroupNotSupported and no key
// material from Decode, DecodeKEMPrivate and DecodeKEMPublic. A generation the caller did not
// accept keeps its own error.
func TestKEMGroup0x11edRefusedUnderEveryAcceptedGeneration(t *testing.T) {
	sized := func(n int) []byte { return bytes.Repeat([]byte{0x42}, n) }
	const group = uint64(npamp.KEMSecP384r1MLKEM1024)
	for _, gen := range []string{"n-pamp/2", "n-pamp/9"} {
		priv := marshalRecord(KeyRecord{FormatVersion: CurrentFormatVersion, Generation: gen, Role: RoleKEMPrivate, Algorithm: group, Components: [][]byte{sized(64), sized(48)}})
		pub := marshalRecord(KeyRecord{FormatVersion: CurrentFormatVersion, Generation: gen, Role: RoleKEMPublic, Algorithm: group, Components: [][]byte{sized(1568), sized(97)}})
		for name, data := range map[string][]byte{"private": priv, "public": pub} {
			if rec, err := Decode(data, gen); !errors.Is(err, ErrGroupNotSupported) || !isZeroRecord(rec) {
				t.Fatalf("Decode %s record under accepted generation %q: rec zero = %v, err = %v; want zero record and ErrGroupNotSupported", name, gen, isZeroRecord(rec), err)
			}
		}
		if g, seed, classical, err := DecodeKEMPrivate(priv, gen); !errors.Is(err, ErrGroupNotSupported) || g != 0 || seed != nil || classical != nil {
			t.Fatalf("DecodeKEMPrivate under accepted generation %q: group %#04x seed %d classical %d err %v; want zero values and ErrGroupNotSupported", gen, uint16(g), len(seed), len(classical), err)
		}
		if g, ek, classical, err := DecodeKEMPublic(pub, gen); !errors.Is(err, ErrGroupNotSupported) || g != 0 || ek != nil || classical != nil {
			t.Fatalf("DecodeKEMPublic under accepted generation %q: group %#04x ek %d classical %d err %v; want zero values and ErrGroupNotSupported", gen, uint16(g), len(ek), len(classical), err)
		}
		// A generation the caller did not accept is still ErrGenerationNotAccepted.
		if _, err := Decode(priv, npamp.ALPN); !errors.Is(err, ErrGenerationNotAccepted) {
			t.Fatalf("Decode of %q record accepting only %q: err = %v, want ErrGenerationNotAccepted", gen, npamp.ALPN, err)
		}
		// The refusal is the group's: the same record shape under the other group is returned.
		other := marshalRecord(KeyRecord{FormatVersion: CurrentFormatVersion, Generation: gen, Role: RoleKEMPrivate, Algorithm: uint64(npamp.KEMX25519MLKEM768), Components: [][]byte{sized(64), sized(32)}})
		if _, err := Decode(other, gen); err != nil {
			t.Fatalf("Decode of X25519MLKEM768 record under accepted generation %q: %v", gen, err)
		}
	}
}

// TestRoundTripMLDSA87OpaqueMaterial confirms the format can carry ML-DSA-87
// key material at its registered FIPS 204 sizes even though this Go
// toolchain has no stdlib ML-DSA type to construct a live key from — this is
// the documented "opaque bytes" case (see keyformat.go's registry doc
// comment and doc.go). The bytes here are NOT a real ML-DSA key pair (there
// is nothing in this Go tree that can generate one); this test proves only
// that the size-gated storage round trip is honest for this algorithm
// family, not that this package can sign or verify with it.
func TestRoundTripMLDSA87OpaqueMaterial(t *testing.T) {
	pub := make([]byte, 2592) // FIPS 204 Table 2 ML-DSA-87 public-key size
	if _, err := rand.Read(pub); err != nil {
		t.Fatalf("rand.Read(pub): %v", err)
	}
	priv := make([]byte, 4896) // FIPS 204 Table 2 ML-DSA-87 private-key size
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand.Read(priv): %v", err)
	}

	pubData, err := EncodeSigPublic(npamp.SigMLDSA87, pub)
	if err != nil {
		t.Fatalf("EncodeSigPublic(SigMLDSA87): %v", err)
	}
	privData, err := EncodeSigPrivate(npamp.SigMLDSA87, priv)
	if err != nil {
		t.Fatalf("EncodeSigPrivate(SigMLDSA87): %v", err)
	}

	gotPubAlg, gotPub, err := DecodeSigPublic(pubData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPublic(SigMLDSA87): %v", err)
	}
	if gotPubAlg != npamp.SigMLDSA87 || !bytes.Equal(gotPub, pub) {
		t.Fatal("ML-DSA-87 public-key round trip did not reproduce the original algorithm/bytes")
	}

	gotPrivAlg, gotPriv, err := DecodeSigPrivate(privData, npamp.ALPN)
	if err != nil {
		t.Fatalf("DecodeSigPrivate(SigMLDSA87): %v", err)
	}
	if gotPrivAlg != npamp.SigMLDSA87 || !bytes.Equal(gotPriv, priv) {
		t.Fatal("ML-DSA-87 private-key round trip did not reproduce the original algorithm/bytes")
	}

	// Wrong size for the algorithm MUST be rejected, not silently accepted.
	if _, err := EncodeSigPublic(npamp.SigMLDSA87, pub[:len(pub)-1]); err != ErrComponentSize {
		t.Fatalf("EncodeSigPublic(SigMLDSA87, short key): err = %v, want %v", err, ErrComponentSize)
	}
}

// TestEncodeIsDeterministic confirms re-encoding a decoded record reproduces
// the exact original wire bytes — the property a "deterministic CBOR" claim
// actually promises, checked directly rather than assumed.
func TestEncodeIsDeterministic(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	data, err := EncodeSigPublic(npamp.SigEd25519, pub)
	if err != nil {
		t.Fatalf("EncodeSigPublic: %v", err)
	}
	rec, err := Decode(data, npamp.ALPN)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	reEncoded, err := Encode(rec)
	if err != nil {
		t.Fatalf("Encode(decoded record): %v", err)
	}
	if !bytes.Equal(data, reEncoded) {
		t.Fatal("re-encoding a decoded record did not reproduce the original bytes")
	}
}
