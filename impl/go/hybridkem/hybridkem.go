// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package hybridkem is the standalone, provider-agnostic hybrid-KEM combiner
// adapter for N-PAMP (draft-bubblefish-npamp-02, Part 2 Requirement 2 acc.crit.2;
// spec/companion/90_hybrid_kem_adapter.md).
//
// It performs exactly one job: given the two RAW component shared secrets of a
// hybrid-KEM group — an ML-KEM shared secret and a classical (X25519 or P-384)
// shared secret, however a caller's ML-KEM/ECDH provider produced them — it
// returns the octet string a caller feeds to HKDF-Extract as IKM, in the
// PER-GROUP order fixed by Part-1 R1.5 / spec/06_cryptographic_suites.md. That
// order is NOT universal: X25519MLKEM768 is ML-KEM-first; SecP384r1MLKEM1024 is
// classical(P-384)-first. Encoding both groups the same way produces a
// self-consistent but wrong Sovereign/High key schedule.
//
// This package takes no dependency on any specific ML-KEM or ECDH provider
// (no crypto/mlkem, no crypto/ecdh, no liboqs binding) — it operates on raw
// []byte component secrets only, so the same combiner logic serves any
// language's provider binding (design.md Tier-2 PQC provider map, R2.1) without
// a per-language reimplementation of the ordering rule. The sibling root
// package (github.com/bubblefish-tech/npamp_protocol/impl/go) already performs
// this same combining inline inside SharedSecrets.Combined() and
// SharedSecrets1024.Combined() using its own stdlib-provider types; this
// package extracts that per-group ordering logic into a form usable outside
// the wire-only reference implementation. The two MUST stay byte-identical for
// the same inputs — enforced by a cross-check test in this package.
package hybridkem

import "errors"

// Group identifies which N-PAMP hybrid-KEM group's combiner order to apply.
// The numeric values are the N-PAMP KEM code points (spec/06_cryptographic_suites.md;
// draft-bubblefish-npamp-latest.md §7), so a caller already holding the
// negotiated KEM code point can pass it directly without translation.
type Group uint16

const (
	// X25519MLKEM768 (code point 0x11ec, Standard/High profiles) combines
	// X25519 with ML-KEM-768. Its combiner order is ML-KEM-first: the suite
	// NAME lists X25519 first, but the concatenated BYTES are ML-KEM-first
	// (RFC 10024, formerly draft-ietf-tls-ecdhe-mlkem, records this reversed
	// order as historical; the Go reference's ADR-0005).
	X25519MLKEM768 Group = 0x11ec

	// SecP384r1MLKEM1024 (code point 0x11ed, High/Sovereign profiles)
	// combines secp384r1 (P-384) with ML-KEM-1024. Its combiner order is
	// classical(P-384)-first — the REVERSE of X25519MLKEM768 — because the
	// FIPS-approved component leads per NIST SP 800-56C Rev. 2 as applied by
	// RFC 10024's (formerly draft-ietf-tls-ecdhe-mlkem) SecP384r1MLKEM1024 construction.
	SecP384r1MLKEM1024 Group = 0x11ed
)

// Component and combined shared-secret sizes, in octets, per
// spec/06_cryptographic_suites.md. These match FIPS 203 (ML-KEM shared-secret
// size is fixed at 32 octets for every parameter set), RFC 7748 (X25519
// shared secret, 32 octets), and RFC 9846 §4.3.8.2 (secp384r1 ECDH shared
// secret x-coordinate, 48 octets).
const (
	// MLKEMSharedSecretSize is the FIPS 203 ML-KEM shared-secret size (fixed
	// for ML-KEM-768 and ML-KEM-1024 alike).
	MLKEMSharedSecretSize = 32

	// X25519SharedSecretSize is the RFC 7748 X25519 shared-secret size.
	X25519SharedSecretSize = 32

	// P384SharedSecretSize is the secp384r1 ECDH shared-secret size (the
	// x-coordinate of the shared point as an octet string; RFC 9846
	// §4.3.8.2).
	P384SharedSecretSize = 48

	// CombinedSecretSizeX25519MLKEM768 is the X25519MLKEM768 combined-secret
	// (HKDF-Extract IKM) size: ML-KEM shared secret (32) || X25519 shared
	// secret (32).
	CombinedSecretSizeX25519MLKEM768 = MLKEMSharedSecretSize + X25519SharedSecretSize // 64

	// CombinedSecretSizeSecP384r1MLKEM1024 is the SecP384r1MLKEM1024
	// combined-secret (HKDF-Extract IKM) size: secp384r1 shared secret (48)
	// || ML-KEM shared secret (32).
	CombinedSecretSizeSecP384r1MLKEM1024 = P384SharedSecretSize + MLKEMSharedSecretSize // 80
)

// Errors returned by Combine.
var (
	// ErrUnknownGroup is returned for a Group value that is not one of the
	// two N-PAMP hybrid-KEM groups this adapter knows how to combine.
	ErrUnknownGroup = errors.New("hybridkem: unknown hybrid-KEM group")

	// ErrMLKEMSecretSize is returned when the ML-KEM component secret is not
	// exactly MLKEMSharedSecretSize octets.
	ErrMLKEMSecretSize = errors.New("hybridkem: ML-KEM shared secret is not 32 octets")

	// ErrClassicalSecretSize is returned when the classical (X25519/P-384)
	// component secret does not match the size the named group requires.
	ErrClassicalSecretSize = errors.New("hybridkem: classical shared secret has the wrong size for this group")
)

// Combine concatenates the ML-KEM and classical (X25519 or P-384) component
// shared secrets into the raw HKDF-Extract input keying material for the
// named hybrid-KEM group, in the PER-GROUP order fixed by Part-1 R1.5 /
// spec/06_cryptographic_suites.md — the order is NOT universal across groups:
//
//   - X25519MLKEM768:     mlkemSS || classicalSS   (ML-KEM first)
//   - SecP384r1MLKEM1024: classicalSS || mlkemSS   (P-384 / classical first)
//
// mlkemSS and classicalSS are the RAW component shared secrets exactly as
// produced by any ML-KEM and ECDH/ECDHE provider (this adapter does not care
// which one) — it performs no key exchange or encapsulation itself, only the
// combiner-order concatenation. The returned slice is freshly allocated and
// aliases neither input.
func Combine(group Group, mlkemSS, classicalSS []byte) ([]byte, error) {
	if len(mlkemSS) != MLKEMSharedSecretSize {
		return nil, ErrMLKEMSecretSize
	}
	switch group {
	case X25519MLKEM768:
		if len(classicalSS) != X25519SharedSecretSize {
			return nil, ErrClassicalSecretSize
		}
		return concat(mlkemSS, classicalSS), nil
	case SecP384r1MLKEM1024:
		if len(classicalSS) != P384SharedSecretSize {
			return nil, ErrClassicalSecretSize
		}
		return concat(classicalSS, mlkemSS), nil
	default:
		return nil, ErrUnknownGroup
	}
}

// concat returns a || b in a freshly allocated slice (no aliasing of either
// input), mirroring the allocation shape of the root package's
// SharedSecrets.Combined() / SharedSecrets1024.Combined().
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}
