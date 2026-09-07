// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

// mlkem1024ACVPKAT mirrors test-vectors/v1/mlkem1024-acvp-kat.json (E3.3):
// a NIST-ACVP-derived ML-KEM-1024 keygen known-answer vector, vendored via
// BoringSSL's crypto/mlkem/mlkem1024_nist_keygen_tests.txt. Produced by
// neither this repository's Go nor Rust implementation (F3 non-circularity).
type mlkem1024ACVPKAT struct {
	D  string `json:"d"`
	Z  string `json:"z"`
	EK string `json:"ek"`
}

// TestMLKEM1024KeygenACVP proves Go 1.27 stdlib crypto/mlkem's ML-KEM-1024
// deterministic keygen (NewDecapsulationKey1024, a 64-octet "d || z" seed)
// reproduces the independent NIST/ACVP seed -> encapsulation-key mapping
// byte-exactly, closing the gap kem1024_kat_test.go names ("its NIST-ACVP
// (d,z,ek) value anchor is Phase-4 corpus work (T18.3), tracked") before
// this KEM is trusted as the ML-KEM-1024 leg of SecP384r1MLKEM1024
// (High/Sovereign profiles).
//
// The mutation anchor for the red-evidence ledger is the seed's field
// order: NewDecapsulationKey1024 requires "d || z" (per its own doc
// comment). Swapping to "z || d" here MUST fail the ek comparison, because
// the seed halves feed two cryptographically distinct roles in FIPS 203's
// KeyGen_internal — reversing them is not a value-preserving transform.
func TestMLKEM1024KeygenACVP(t *testing.T) {
	var kat mlkem1024ACVPKAT
	loadKAT(t, "mlkem1024-acvp-kat.json", &kat)

	d := mustHex(t, "d", kat.D)
	z := mustHex(t, "z", kat.Z)
	wantEK := mustHex(t, "ek", kat.EK)
	if len(d) != 32 || len(z) != 32 {
		t.Fatalf("fixture invariant broken: d/z must each be 32 octets, got %d/%d", len(d), len(z))
	}
	if len(wantEK) != mlkem.EncapsulationKeySize1024 {
		t.Fatalf("fixture invariant broken: ek is %d octets, want %d", len(wantEK), mlkem.EncapsulationKeySize1024)
	}

	seed := concat(d, z) // NewDecapsulationKey1024 requires exactly "d || z"
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		t.Fatalf("mlkem.NewDecapsulationKey1024(d||z): %v", err)
	}
	gotEK := dk.EncapsulationKey().Bytes()
	if !bytes.Equal(gotEK, wantEK) {
		t.Fatalf("ML-KEM-1024 keygen does not reproduce the independent NIST/ACVP KAT:\n got  %x\n want %x", gotEK, wantEK)
	}

	// Functional round trip on the ACVP-anchored key pair: encapsulate
	// against the (now-proven-correct) public key, decapsulate with the
	// corresponding private key, and confirm the shared secrets agree. This
	// does not re-check the keygen anchor above; it proves the resulting
	// key pair actually functions, the same property TestKEMWireKAT1024
	// exercises for the full hybrid wire format.
	ek, err := mlkem.NewEncapsulationKey1024(gotEK)
	if err != nil {
		t.Fatalf("mlkem.NewEncapsulationKey1024: %v", err)
	}
	encapSS, ct := ek.Encapsulate()
	if len(encapSS) != mlkem.SharedKeySize {
		t.Fatalf("Encapsulate shared key is %d octets, want %d", len(encapSS), mlkem.SharedKeySize)
	}
	decapSS, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("dk.Decapsulate: %v", err)
	}
	if !bytes.Equal(encapSS, decapSS) {
		t.Fatal("ML-KEM-1024 encapsulate/decapsulate round trip mismatch on the ACVP-anchored key pair")
	}
}
