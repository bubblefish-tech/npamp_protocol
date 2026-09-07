// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package keyformat

import (
	"errors"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// FormatVersion identifies the versioned key-storage format's OWN schema
// version. It is independent of both the N-PAMP wire-format version (the
// frame header Ver nibble, frozen per decisions/adr/0014) and the crypto
// generation carried in KeyRecord.Generation: this format's own on-disk
// layout could change (a sixth field added, say) without either of those
// other axes moving, and vice versa.
type FormatVersion uint16

// CurrentFormatVersion is the only key-storage format version this package
// knows how to encode or decode. Encode always writes it; Decode refuses any
// other value with ErrUnknownFormatVersion.
const CurrentFormatVersion FormatVersion = 1

// Role identifies which half of which algorithm class a KeyRecord's key
// material is: a KEM or a signature key, public or private half. Role
// selects which registry namespace (npamp.KEMID or npamp.SigID) Algorithm is
// resolved against, and how many key-material Components are expected.
type Role uint8

const (
	// RoleKEMPublic is a hybrid-KEM public (encapsulation) key: Algorithm is
	// an npamp.KEMID.
	RoleKEMPublic Role = 1
	// RoleKEMPrivate is a hybrid-KEM private (decapsulation) key: Algorithm
	// is an npamp.KEMID.
	RoleKEMPrivate Role = 2
	// RoleSigPublic is a signature public (verification) key: Algorithm is
	// an npamp.SigID.
	RoleSigPublic Role = 3
	// RoleSigPrivate is a signature private (signing) key: Algorithm is an
	// npamp.SigID.
	RoleSigPrivate Role = 4
)

// String renders Role for diagnostics and error messages.
func (r Role) String() string {
	switch r {
	case RoleKEMPublic:
		return "kem-public"
	case RoleKEMPrivate:
		return "kem-private"
	case RoleSigPublic:
		return "sig-public"
	case RoleSigPrivate:
		return "sig-private"
	default:
		return fmt.Sprintf("role(%d)", uint8(r))
	}
}

// KeyRecord is the decoded, versioned, self-describing key-storage record.
//
// Generation is the ALPN-style N-PAMP crypto-generation token (e.g. the
// current npamp.ALPN, "n-pamp/3") that Algorithm must be resolved against.
// It is REQUIRED and load-bearing, not cosmetic: per decisions/adr/0014,
// N-PAMP's KEM and signature code points have been re-anchored across crypto
// generations, so an Algorithm value has no fixed meaning without knowing
// which generation's registry to read it under. Decode refuses to resolve a
// record's Algorithm against any Generation the caller has not explicitly
// opted into (ErrGenerationNotAccepted) — the same generation-confusion
// defense ADR-0014 requires of a live wire endpoint, applied here to a
// stored key.
type KeyRecord struct {
	FormatVersion FormatVersion
	Generation    string
	Role          Role
	// Algorithm is an npamp.KEMID (Role == RoleKEMPublic/RoleKEMPrivate) or
	// an npamp.SigID (Role == RoleSigPublic/RoleSigPrivate) code point,
	// meaningful only paired with Generation.
	Algorithm uint64
	// Components holds the raw key-material component(s) in a FIXED storage
	// order that is INDEPENDENT of the wire hybrid-KEM combiner order
	// (hybridkem.Combine, which orders SHARED SECRETS during a live
	// handshake): component[0] is always the post-quantum (ML-KEM) half of a
	// hybrid KEM key, component[1] (when present) is always the classical
	// (X25519 or P-384) half. A plain, non-hybrid algorithm (Ed25519 or an
	// ML-DSA parameter set) has exactly one component.
	Components [][]byte
}

// Errors returned by Encode and Decode. Every one is a distinct, named
// sentinel so a caller (and a test) can assert exactly which fail-closed
// check rejected a record.
var (
	// ErrUnknownFormatVersion is returned when a record's format_version is
	// not CurrentFormatVersion.
	ErrUnknownFormatVersion = errors.New("keyformat: unknown key-storage format version")

	// ErrNoAcceptedGenerations is returned by Decode when called with zero
	// accepted generations: an empty accept-set can never legitimately admit
	// a record, and requiring at least one makes that an explicit, visible
	// caller error rather than a silent universal refusal.
	ErrNoAcceptedGenerations = errors.New("keyformat: Decode requires at least one accepted generation")

	// ErrGenerationNotAccepted is returned when a record's Generation is not
	// one of the caller's accepted generations for Decode, or (for Encode)
	// is not the one crypto generation this Go reference can mint records
	// for (npamp.ALPN).
	ErrGenerationNotAccepted = errors.New("keyformat: crypto generation not in the caller's accepted set")

	// ErrUnknownAlgorithm is returned when a record's (Generation, Role,
	// Algorithm) tuple is not in this package's registry — either the
	// algorithm code point is not registered for that role at all, or it
	// belongs to the other namespace (a Sig code point presented under a KEM
	// role, or vice versa).
	ErrUnknownAlgorithm = errors.New("keyformat: algorithm code point not registered for this role in this generation")

	// ErrComponentCount is returned when a record's Components slice does
	// not have the number of components its (Generation, Role, Algorithm)
	// registry entry requires.
	ErrComponentCount = errors.New("keyformat: wrong number of key-material components for this algorithm")

	// ErrComponentSize is returned when a key-material component's length
	// disagrees with the registered size for its position and algorithm.
	ErrComponentSize = errors.New("keyformat: key-material component has the wrong size for this algorithm")

	// ErrRoleMismatch is returned by the typed accessor functions (e.g.
	// DecodeKEMPrivate) when a record decodes cleanly but carries a
	// different Role than the accessor requires.
	ErrRoleMismatch = errors.New("keyformat: decoded record's role does not match the requested accessor")
)

// algSpec is one registered (role, algorithm) entry: the expected byte
// length of each key-material component, in Components order.
type algSpec struct {
	sizes []int
}

// registry maps crypto generation -> role -> algorithm code point -> algSpec.
//
// Only npamp.ALPN ("n-pamp/3", the current N-PAMP crypto generation) has a
// populated entry here. N-PAMP's prior generation, "n-pamp/2", was never
// implemented as working Go code in this tree — it was superseded (per
// decisions/adr/0014) before this package existed — so this reference cannot
// honestly claim to validate an "n-pamp/2"-tagged record's algorithm/size
// pairing. Decode reflects that honestly: a caller MAY explicitly accept a
// non-npamp.ALPN generation (e.g. to structurally recognize an old key for a
// migration tool), but such a record is returned unvalidated beyond the
// structural CBOR decode — see Decode's doc comment.
//
// Sizes are taken from the code points this module's own registries define
// (registries/kem.csv, registries/signatures.csv) and from the underlying
// providers' own published sizes:
//   - ML-KEM-768/1024 seed (64) and encapsulation-key sizes, and X25519/P-384
//     private/public key sizes, are the exact byte lengths crypto/mlkem and
//     crypto/ecdh (Go 1.26) produce — see keyformat_test.go, which measures
//     them from the real stdlib types rather than restating a constant.
//   - crypto/ed25519 private/public key sizes are ed25519.PrivateKeySize
//     (64, the stdlib's seed||public-key form) and ed25519.PublicKeySize
//     (32).
//   - ML-DSA-44/65/87 public-key, private-key sizes are the FIPS 204
//     Table 2 parameter-set sizes, cross-checked against the Open Quantum
//     Safe project's liboqs ML-DSA algorithm datasheet
//     (openquantumsafe.org/liboqs/algorithms/sig/ml-dsa) on 2026-08-27: no Go
//     stdlib ML-DSA type exists yet in this toolchain to measure them from,
//     so these four are the one set of sizes in this table taken from a
//     published specification rather than measured from a live Go type.
var registry = map[string]map[Role]map[uint64]algSpec{
	npamp.ALPN: {
		RoleKEMPrivate: {
			uint64(npamp.KEMX25519MLKEM768):     {sizes: []int{64, 32}},  // ML-KEM-768 seed || X25519 private
			uint64(npamp.KEMSecP384r1MLKEM1024): {sizes: []int{64, 48}},  // ML-KEM-1024 seed || P-384 private
		},
		RoleKEMPublic: {
			uint64(npamp.KEMX25519MLKEM768):     {sizes: []int{1184, 32}}, // ML-KEM-768 ek || X25519 public
			uint64(npamp.KEMSecP384r1MLKEM1024): {sizes: []int{1568, 97}}, // ML-KEM-1024 ek || P-384 public
		},
		RoleSigPrivate: {
			uint64(npamp.SigEd25519): {sizes: []int{64}},   // crypto/ed25519.PrivateKey (seed || public key)
			uint64(npamp.SigMLDSA44): {sizes: []int{2560}}, // FIPS 204 Table 2 ML-DSA-44 private key
			uint64(npamp.SigMLDSA65): {sizes: []int{4032}}, // FIPS 204 Table 2 ML-DSA-65 private key
			uint64(npamp.SigMLDSA87): {sizes: []int{4896}}, // FIPS 204 Table 2 ML-DSA-87 private key
		},
		RoleSigPublic: {
			uint64(npamp.SigEd25519): {sizes: []int{32}},   // crypto/ed25519.PublicKey
			uint64(npamp.SigMLDSA44): {sizes: []int{1312}}, // FIPS 204 Table 2 ML-DSA-44 public key
			uint64(npamp.SigMLDSA65): {sizes: []int{1952}}, // FIPS 204 Table 2 ML-DSA-65 public key
			uint64(npamp.SigMLDSA87): {sizes: []int{2592}}, // FIPS 204 Table 2 ML-DSA-87 public key
		},
	},
}

// Encode validates rec against the algorithm registry and returns its
// canonical CBOR encoding. Encode is fail-closed: it returns a named error
// and no bytes for an unsupported format version, a Generation other than
// npamp.ALPN (this Go reference mints records only for the crypto generation
// it actually implements), an unregistered (Role, Algorithm) pair, or a
// Components slice whose count or component sizes disagree with that
// algorithm's registered shape.
func Encode(rec KeyRecord) ([]byte, error) {
	if rec.FormatVersion != CurrentFormatVersion {
		return nil, ErrUnknownFormatVersion
	}
	if rec.Generation != npamp.ALPN {
		return nil, ErrGenerationNotAccepted
	}
	if err := validateAgainstRegistry(rec); err != nil {
		return nil, err
	}
	return marshalRecord(rec), nil
}

// Decode parses a versioned key-storage record and refuses to return one
// unless:
//
//  1. its format_version is CurrentFormatVersion (else ErrUnknownFormatVersion);
//  2. its Generation is one of acceptedGenerations — a generation the caller
//     did not explicitly opt into is refused even if the record structurally
//     decodes cleanly (else ErrGenerationNotAccepted); and
//  3. when Generation == npamp.ALPN (the one generation this Go reference has
//     a populated registry for), its (Role, Algorithm) pair is registered and
//     every component's length matches (else ErrUnknownAlgorithm /
//     ErrComponentCount / ErrComponentSize).
//
// acceptedGenerations MUST be non-empty (ErrNoAcceptedGenerations otherwise):
// there is no default accept-set, so a caller cannot forget to state one.
//
// A record accepted under a Generation OTHER than npamp.ALPN is returned
// with its five fields structurally decoded but WITHOUT algorithm/size
// validation (this package has no registry for any other generation — see
// the registry doc comment). Callers that opt into a non-current generation
// are choosing to treat its key material as opaque pending their own
// migration handling; Decode never fabricates a validation result it cannot
// actually perform.
func Decode(data []byte, acceptedGenerations ...string) (KeyRecord, error) {
	if len(acceptedGenerations) == 0 {
		return KeyRecord{}, ErrNoAcceptedGenerations
	}
	rec, err := unmarshalRecord(data)
	if err != nil {
		return KeyRecord{}, err
	}
	if rec.FormatVersion != CurrentFormatVersion {
		return KeyRecord{}, ErrUnknownFormatVersion
	}
	accepted := false
	for _, g := range acceptedGenerations {
		if g == rec.Generation {
			accepted = true
			break
		}
	}
	if !accepted {
		return KeyRecord{}, ErrGenerationNotAccepted
	}
	if rec.Generation == npamp.ALPN {
		if err := validateAgainstRegistry(rec); err != nil {
			return KeyRecord{}, err
		}
	}
	return rec, nil
}

// validateAgainstRegistry checks rec's (Generation, Role, Algorithm) against
// registry and, if found, that every component's length matches.
func validateAgainstRegistry(rec KeyRecord) error {
	genReg, ok := registry[rec.Generation]
	if !ok {
		// No populated registry for this generation. Reachable only from
		// Decode when Generation == npamp.ALPN is guaranteed by the caller
		// above; kept as an explicit, honest branch rather than a silent
		// pass so a future registry addition cannot accidentally start
		// short-circuiting validation for a generation gaining an entry.
		return ErrUnknownAlgorithm
	}
	roleReg, ok := genReg[rec.Role]
	if !ok {
		return ErrUnknownAlgorithm
	}
	spec, ok := roleReg[rec.Algorithm]
	if !ok {
		return ErrUnknownAlgorithm
	}
	if len(rec.Components) != len(spec.sizes) {
		return ErrComponentCount
	}
	for i, want := range spec.sizes {
		if len(rec.Components[i]) != want {
			return ErrComponentSize
		}
	}
	return nil
}

// marshalRecord encodes rec as the canonical five-field CBOR map:
//
//	{1: format_version, 2: generation, 3: role, 4: algorithm, 5: components}
//
// Keys 1..5 are single-byte immediate CBOR unsigned integers, so ascending
// numeric key order is also ascending bytewise-canonical key order (RFC 8949
// section 4.2.1); no separate key-sorting step is needed.
func marshalRecord(rec KeyRecord) []byte {
	var out []byte
	out = append(out, encodeUint(cborMajorMap, 5)...)

	out = append(out, encodeUint(cborMajorUint, 1)...)
	out = append(out, encodeUint(cborMajorUint, uint64(rec.FormatVersion))...)

	out = append(out, encodeUint(cborMajorUint, 2)...)
	out = append(out, encodeTextItem(rec.Generation)...)

	out = append(out, encodeUint(cborMajorUint, 3)...)
	out = append(out, encodeUint(cborMajorUint, uint64(rec.Role))...)

	out = append(out, encodeUint(cborMajorUint, 4)...)
	out = append(out, encodeUint(cborMajorUint, rec.Algorithm)...)

	out = append(out, encodeUint(cborMajorUint, 5)...)
	out = append(out, encodeUint(cborMajorArray, uint64(len(rec.Components)))...)
	for _, c := range rec.Components {
		out = append(out, encodeBytesItem(c)...)
	}
	return out
}

// unmarshalRecord parses the canonical five-field CBOR map marshalRecord
// produces, REJECTING: a map with other than exactly 5 entries, an unknown
// map key, a duplicate or out-of-order map key, any indefinite-length or
// non-shortest-form item, a wrong major type at any position, and trailing
// bytes after the top-level item.
func unmarshalRecord(data []byte) (KeyRecord, error) {
	d := &cborReader{buf: data}
	n, err := d.readMapLen()
	if err != nil {
		return KeyRecord{}, err
	}
	if n != 5 {
		return KeyRecord{}, fmt.Errorf("keyformat: top-level map has %d entries, want exactly 5", n)
	}

	var rec KeyRecord
	seen := make(map[uint64]bool, 5)
	var lastKey uint64
	for i := uint64(0); i < n; i++ {
		key, err := d.readUint()
		if err != nil {
			return KeyRecord{}, err
		}
		if i > 0 && key <= lastKey {
			return KeyRecord{}, errCBORWrongKeyOrder
		}
		if seen[key] {
			return KeyRecord{}, errCBORWrongKeyOrder
		}
		seen[key] = true
		lastKey = key

		switch key {
		case 1:
			v, err := d.readUint()
			if err != nil {
				return KeyRecord{}, err
			}
			rec.FormatVersion = FormatVersion(v)
		case 2:
			s, err := d.readText()
			if err != nil {
				return KeyRecord{}, err
			}
			rec.Generation = s
		case 3:
			v, err := d.readUint()
			if err != nil {
				return KeyRecord{}, err
			}
			rec.Role = Role(v)
		case 4:
			v, err := d.readUint()
			if err != nil {
				return KeyRecord{}, err
			}
			rec.Algorithm = v
		case 5:
			alen, err := d.readArrayLen()
			if err != nil {
				return KeyRecord{}, err
			}
			// A hostile or corrupt record can claim an enormous array
			// length (e.g. 2^40) that still passes the shortest-form
			// check. Every element costs at least 1 byte on the wire, so
			// alen can never legitimately exceed the remaining buffer —
			// bound it BEFORE allocating, or a crafted ~30-byte input
			// drives make() into a multi-gigabyte allocation (an OOM/
			// panic, not a named error) rather than being refused.
			if alen > uint64(len(d.buf)-d.pos) {
				return KeyRecord{}, errCBORTruncated
			}
			comps := make([][]byte, alen)
			for j := uint64(0); j < alen; j++ {
				b, err := d.readBytes()
				if err != nil {
					return KeyRecord{}, err
				}
				comps[j] = b
			}
			rec.Components = comps
		default:
			return KeyRecord{}, fmt.Errorf("keyformat: unknown map key %d", key)
		}
	}
	if d.pos != len(d.buf) {
		return KeyRecord{}, errCBORTrailing
	}
	return rec, nil
}
