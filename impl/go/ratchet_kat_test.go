package npamp

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// This file holds the two NON-CIRCULAR master-ratchet KATs (spec/10 section 5,
// Hybrid Tree Ratchet). Both follow the exact discipline of TestKeyScheduleKAT
// (ADR-0008): the EXPECTED root is NOT produced by calling the implementation
// under test (RatchetMasterTier1 / RatchetMasterTier2). It is produced by an
// INDEPENDENT oracle — the test's own hand-assembled HKDF-Expand-Label
// constructor (oracleExpandLabel, defined in keyschedule_kat_test.go) plus the
// Go standard library crypto/hkdf.Extract — whose MECHANISM is first re-proven
// against the published RFC 5869 (Extract/Expand) and RFC 8448 (Expand-Label)
// anchors within this test, then applied with the N-PAMP "n-pamp " prefix. A KAT
// that derived its expected root by calling the SDK's own ratchet would be
// circular and worthless; these do not.

// RFC anchors, identical constants to test-vectors/v1/key-schedule-kat.json
// (RFC 5869 Appendix A.1 TC1; RFC 8448 section 3). Re-pinned here so the ratchet
// KAT re-proves the oracle mechanism standalone rather than trusting a value the
// implementation produced.
const (
	rfc5869IKM  = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	rfc5869Salt = "000102030405060708090a0b0c"
	rfc5869Info = "f0f1f2f3f4f5f6f7f8f9"
	rfc5869PRK  = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
	rfc5869OKM  = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	rfc8448HandshakeTrafficSecret = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
	rfc8448WriteKey               = "dbfaa693d1762c5b666af5d950258d01"
	rfc8448WriteIV                = "5bd3c71b836e0b76bb73265f"
	rfc8448FinishedKey            = "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4"
)

// proveOracleMechanism re-anchors the independent oracle used by both ratchet
// KATs: HKDF-Extract/Expand against RFC 5869 TC1 and the Expand-Label assembly
// against RFC 8448 (with the TLS "tls13 " prefix). Only after these pass is
// oracleExpandLabel trusted to compute expected N-PAMP roots with the "n-pamp "
// prefix. This makes the two KATs self-contained and non-circular.
func proveOracleMechanism(t *testing.T) {
	t.Helper()
	// RFC 5869 TC1: raw Extract then Expand.
	prk, err := hkdf.Extract(sha256.New, mustHex(t, "ikm", rfc5869IKM), mustHex(t, "salt", rfc5869Salt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prk, mustHex(t, "prk", rfc5869PRK)) {
		t.Fatal("oracle HKDF-Extract does not reproduce RFC 5869 TC1 prk")
	}
	okm, err := hkdf.Expand(sha256.New, prk, string(mustHex(t, "info", rfc5869Info)), len(mustHex(t, "okm", rfc5869OKM)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(okm, mustHex(t, "okm", rfc5869OKM)) {
		t.Fatal("oracle HKDF-Expand does not reproduce RFC 5869 TC1 okm")
	}
	// RFC 8448 section 3: prove the Expand-Label ASSEMBLY with the TLS 1.3 prefix.
	hts := mustHex(t, "hts", rfc8448HandshakeTrafficSecret)
	if !bytes.Equal(oracleExpandLabel(t, hts, "tls13 ", "key", nil, 16), mustHex(t, "write_key", rfc8448WriteKey)) {
		t.Fatal("oracle Expand-Label does not reproduce the RFC 8448 write_key")
	}
	if !bytes.Equal(oracleExpandLabel(t, hts, "tls13 ", "iv", nil, 12), mustHex(t, "write_iv", rfc8448WriteIV)) {
		t.Fatal("oracle Expand-Label does not reproduce the RFC 8448 write_iv")
	}
	if !bytes.Equal(oracleExpandLabel(t, hts, "tls13 ", "finished", nil, 32), mustHex(t, "finished_key", rfc8448FinishedKey)) {
		t.Fatal("oracle Expand-Label does not reproduce the RFC 8448 finished_key")
	}
}

// genBE returns the 8-octet big-endian generation context used by the Tier-1
// ratchet label — computed here in the test, independently of the impl.
func genBE(g uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], g)
	return b[:]
}

// Fixed, standards-derived inputs for the ratchet KATs. masterG is a synthetic
// 32-octet root (same shape as a Standard/SHA-256 master). newSS reuses the real
// standard shared secrets from the KEM-wire / key-schedule KAT (ML-KEM_SS ||
// X25519_SS, ML-KEM-first) so the Tier-2 IKM is a genuine 64-octet KEM output.
// thRekem is a fixed synthetic 32-octet transcript-hash input (the transcript
// CONSTRUCTION is exercised separately by the SDK Tier-2 e2e test).
const (
	katMasterG  = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	katMLKEMSS  = "11B62291B1A9D307C8240D70BE0B45436DB445793173F6E79FCD2B273D7F3B01"
	katX25519SS = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	katTHRekem  = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

// TestMasterRatchetTier1KAT is the NON-CIRCULAR Tier-1 (symmetric forward step)
// known-answer test: master_{G+1} = HKDF-Expand-Label(master_G, "master ratchet",
// gen(8 BE, G+1), 32). The expected root comes from the RFC-anchored oracle, not
// from RatchetMasterTier1.
func TestMasterRatchetTier1KAT(t *testing.T) {
	proveOracleMechanism(t)

	masterG := mustHex(t, "master_g", katMasterG)
	if len(masterG) != 32 {
		t.Fatalf("master_g is %d octets, want 32", len(masterG))
	}

	// Cover several generations, including a large one, so the 8-octet BE context
	// is exercised across byte boundaries.
	for _, targetGen := range []uint64{1, 2, 7, 0x0102030405060708} {
		// Independent expected value: oracle Expand-Label with the n-pamp prefix.
		want := oracleExpandLabel(t, masterG, LabelPrefix, "master ratchet", genBE(targetGen), 32)

		got, err := RatchetMasterTier1(masterG, targetGen, ProfileStandard)
		if err != nil {
			t.Fatalf("RatchetMasterTier1(gen=%d): %v", targetGen, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Tier-1 root at gen %d\n got  %x\n want %x", targetGen, got, want)
		}
		// A5 mutation guard: the forward step must actually consume its inputs.
		if bytes.Equal(got, masterG) {
			t.Fatalf("Tier-1 root at gen %d equals master_G (no forward step taken)", targetGen)
		}
		// The generation is bound into the root: a different target gen MUST yield a
		// different root (defeats a same-input replay).
		wrong := oracleExpandLabel(t, masterG, LabelPrefix, "master ratchet", genBE(targetGen+1), 32)
		if bytes.Equal(got, wrong) {
			t.Fatalf("Tier-1 root at gen %d collides with gen %d", targetGen, targetGen+1)
		}
	}

	// One-wayness at the schedule level: chaining G->1->2 must not reproduce G, and
	// each generation is distinct.
	g1, _ := RatchetMasterTier1(masterG, 1, ProfileStandard)
	g2, _ := RatchetMasterTier1(g1, 2, ProfileStandard)
	if bytes.Equal(g1, masterG) || bytes.Equal(g2, g1) || bytes.Equal(g2, masterG) {
		t.Fatal("Tier-1 chain produced a repeated root")
	}
}

// TestMasterRatchetTier2KAT is the NON-CIRCULAR Tier-2 (asymmetric re-KEM step)
// known-answer test:
//
//	rekem_secret = HKDF-Extract(salt = master_G, IKM = new_ss)
//	master_{G+1} = HKDF-Expand-Label(rekem_secret, "master ratchet rekem", TH_rekem, 32)
//
// The expected root comes from the RFC-anchored oracle (stdlib hkdf.Extract +
// oracleExpandLabel), not from RatchetMasterTier2. The salt/IKM placement is
// verified: master_G is the SALT, new_ss is the IKM.
func TestMasterRatchetTier2KAT(t *testing.T) {
	proveOracleMechanism(t)

	masterG := mustHex(t, "master_g", katMasterG)
	newSS := concat(mustHex(t, "mlkem_ss", katMLKEMSS), mustHex(t, "x25519_ss", katX25519SS))
	if len(newSS) != CombinedSecretSize {
		t.Fatalf("new_ss is %d octets, want %d", len(newSS), CombinedSecretSize)
	}
	thRekem := mustHex(t, "th_rekem", katTHRekem)

	// Independent expected value: Extract(salt=master_G, IKM=new_ss) then oracle
	// Expand-Label with the n-pamp prefix. crypto/hkdf.Extract(h, secret, salt) —
	// secret is the IKM, salt is the salt.
	rekemSecret, err := hkdf.Extract(sha256.New, newSS, masterG)
	if err != nil {
		t.Fatal(err)
	}
	want := oracleExpandLabel(t, rekemSecret, LabelPrefix, "master ratchet rekem", thRekem, 32)

	got, err := RatchetMasterTier2(masterG, newSS, thRekem, ProfileStandard)
	if err != nil {
		t.Fatalf("RatchetMasterTier2: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Tier-2 root\n got  %x\n want %x", got, want)
	}

	// Self-heal property (D3): without the correct new_ss the attacker cannot
	// reproduce master_{G+1}. A single flipped bit in new_ss MUST diverge the root.
	badSS := append([]byte(nil), newSS...)
	badSS[0] ^= 0x01
	healed, err := RatchetMasterTier2(masterG, badSS, thRekem, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(healed, got) {
		t.Fatal("Tier-2 root unchanged when new_ss differs — fresh KEM entropy is not mixed (inert self-heal)")
	}

	// Placement guard: SWAPPING salt and IKM (Extract(salt=new_ss, IKM=master_G))
	// MUST yield a different root. This proves the impl puts the OLD root in the
	// salt and the FRESH secret in the IKM (RFC 5869 / Signal placement), the
	// property that makes master_{G+1} uniform even when master_G is known.
	swappedSecret, err := hkdf.Extract(sha256.New, masterG, newSS)
	if err != nil {
		t.Fatal(err)
	}
	swapped := oracleExpandLabel(t, swappedSecret, LabelPrefix, "master ratchet rekem", thRekem, 32)
	if bytes.Equal(got, swapped) {
		t.Fatal("Tier-2 root matches the salt/IKM-swapped derivation — old root is not in the salt position")
	}

	// Transcript binding: a different TH_rekem MUST diverge the root (defeats
	// splicing/reflection of the REKEM/REKEM_ACK exchange).
	otherTH := append([]byte(nil), thRekem...)
	otherTH[31] ^= 0x01
	spliced, err := RatchetMasterTier2(masterG, newSS, otherTH, ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spliced, got) {
		t.Fatal("Tier-2 root unchanged when TH_rekem differs — exchange is not transcript-bound")
	}

	// The re-KEM step must move the root off master_G.
	if bytes.Equal(got, masterG) {
		t.Fatal("Tier-2 root equals master_G (no step taken)")
	}
}
