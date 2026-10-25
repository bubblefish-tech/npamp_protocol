// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package hybridkem is the standalone, provider-agnostic hybrid-KEM combiner
// adapter for N-PAMP (draft-bubblefish-npamp-02, Part 2 Requirement 2 acc.crit.2;
// spec/companion/90_hybrid_kem_adapter.md).
//
// It performs exactly one job: given the two RAW component shared secrets of the
// X25519MLKEM768 hybrid-KEM group — an ML-KEM-768 shared secret and an X25519
// shared secret, however a caller's ML-KEM/ECDH provider produced them — it
// returns the octet string a caller feeds to HKDF-Extract as IKM, in the
// ML-KEM-first order fixed by spec/06_cryptographic_suites.md.
//
// The SecP384r1MLKEM1024 group (code point 0x11ed) is a defined code point in
// this package so callers can name it, but this reference implementation does
// not combine its secrets: Combine returns ErrGroupNotSupported and no output
// for it. That group's combiner order (classical P-384 first, the reverse of
// X25519MLKEM768) is specified in spec/06_cryptographic_suites.md and
// spec/companion/90_hybrid_kem_adapter.md; this package neither implements nor
// tests it.
//
// This package takes no dependency on any specific ML-KEM or ECDH provider
// (no crypto/mlkem, no crypto/ecdh, no liboqs binding) — it operates on raw
// []byte component secrets only, so the same combiner logic serves any
// language's provider binding (the per-language provider map) without
// a per-language reimplementation of the ordering rule. The sibling root
// package (github.com/bubblefish-tech/npamp_protocol/impl/go) already performs
// this same combining inline inside SharedSecrets.Combined() using its own
// stdlib-provider types; this package extracts that ordering logic into a form
// usable outside the wire-only reference implementation. The two MUST stay
// byte-identical for the same inputs — enforced by a cross-check test in this
// package.
package hybridkem

import "errors"

// Group identifies which N-PAMP hybrid-KEM group a caller names.
// The numeric values are the N-PAMP KEM code points (spec/06_cryptographic_suites.md;
// draft-bubblefish-npamp-latest.md §7), so a caller already holding the
// negotiated KEM code point can pass it directly without translation.
type Group uint16

const (
	// X25519MLKEM768 (code point 0x11ec, Standard/High profiles) combines
	// X25519 with ML-KEM-768. Its combiner order is ML-KEM-first: the suite
	// NAME lists X25519 first, but the concatenated BYTES are ML-KEM-first
	// (RFC 10024, formerly draft-ietf-tls-ecdhe-mlkem, records this reversed
	// order as historical).
	X25519MLKEM768 Group = 0x11ec

	// SecP384r1MLKEM1024 (code point 0x11ed, High/Sovereign profiles) names the
	// secp384r1 (P-384) with ML-KEM-1024 group. It is defined so a caller can
	// name the group; Combine refuses it with ErrGroupNotSupported.
	SecP384r1MLKEM1024 Group = 0x11ed
)

// Component and combined shared-secret sizes of the supported group, in octets,
// per spec/06_cryptographic_suites.md. These match FIPS 203 (ML-KEM shared-secret
// size is fixed at 32 octets for every parameter set) and RFC 7748 (X25519
// shared secret, 32 octets).
const (
	// MLKEMSharedSecretSize is the FIPS 203 ML-KEM shared-secret size (fixed
	// for ML-KEM-768 and ML-KEM-1024 alike).
	MLKEMSharedSecretSize = 32

	// X25519SharedSecretSize is the RFC 7748 X25519 shared-secret size.
	X25519SharedSecretSize = 32

	// CombinedSecretSizeX25519MLKEM768 is the X25519MLKEM768 combined-secret
	// (HKDF-Extract IKM) size: ML-KEM shared secret (32) || X25519 shared
	// secret (32).
	CombinedSecretSizeX25519MLKEM768 = MLKEMSharedSecretSize + X25519SharedSecretSize // 64
)

// Errors returned by Combine.
var (
	// ErrUnknownGroup is returned for a Group value that is not a defined N-PAMP
	// hybrid-KEM group code point.
	ErrUnknownGroup = errors.New("hybridkem: unknown hybrid-KEM group")

	// ErrGroupNotSupported is returned for SecP384r1MLKEM1024 (0x11ed), a defined
	// code point whose key material this reference implementation does not
	// combine. It is distinct from ErrUnknownGroup: the group is known and named,
	// and is refused.
	ErrGroupNotSupported = errors.New("hybridkem: SecP384r1MLKEM1024 (0x11ed) is not supported by this reference implementation")

	// ErrMLKEMSecretSize is returned when the ML-KEM component secret is not
	// exactly MLKEMSharedSecretSize octets.
	ErrMLKEMSecretSize = errors.New("hybridkem: ML-KEM shared secret is not 32 octets")

	// ErrClassicalSecretSize is returned when the classical (X25519) component
	// secret is not exactly X25519SharedSecretSize octets.
	ErrClassicalSecretSize = errors.New("hybridkem: classical shared secret has the wrong size for this group")
)

// Combine concatenates the ML-KEM and X25519 component shared secrets into the
// raw HKDF-Extract input keying material for X25519MLKEM768, in the
// ML-KEM-first order fixed by spec/06_cryptographic_suites.md:
//
//   - X25519MLKEM768: mlkemSS || classicalSS   (ML-KEM first)
//
// For SecP384r1MLKEM1024 it returns ErrGroupNotSupported and nil, whatever the
// secrets are; for any other Group value it returns ErrUnknownGroup and nil.
//
// mlkemSS and classicalSS are the RAW component shared secrets exactly as
// produced by any ML-KEM and ECDH/ECDHE provider (this adapter does not care
// which one) — it performs no key exchange or encapsulation itself, only the
// combiner-order concatenation. The returned slice is freshly allocated and
// aliases neither input.
func Combine(group Group, mlkemSS, classicalSS []byte) ([]byte, error) {
	switch group {
	case X25519MLKEM768:
	case SecP384r1MLKEM1024:
		return nil, ErrGroupNotSupported
	default:
		return nil, ErrUnknownGroup
	}
	if len(mlkemSS) != MLKEMSharedSecretSize {
		return nil, ErrMLKEMSecretSize
	}
	if len(classicalSS) != X25519SharedSecretSize {
		return nil, ErrClassicalSecretSize
	}
	return concat(mlkemSS, classicalSS), nil
}

// concat returns a || b in a freshly allocated slice (no aliasing of either
// input), mirroring the allocation shape of the root package's
// SharedSecrets.Combined().
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}
