// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package keyformat

// fail_closed_test.go exercises Decode's and Encode's fail-closed surface.
// It crafts records marshalRecord would never legitimately produce (an
// out-of-range format version, an unregistered or wrong-namespace algorithm
// code point, a generation the test's own Decode call did not accept) by
// calling the unexported marshalRecord directly — the only way to construct
// such inputs, since Encode itself refuses to build them. Each test asserts
// the SPECIFIC named sentinel error, not merely "an error occurred", per
// this repository's red-evidence discipline.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

func mustEd25519Priv(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return priv
}

// isZeroRecord reports whether rec is the zero KeyRecord — every error path
// in Decode must return exactly this. KeyRecord embeds a [][]byte field, so
// it is not a comparable type (Go rejects rec == KeyRecord{} at compile
// time); this checks the same thing field-by-field instead.
func isZeroRecord(rec KeyRecord) bool {
	return rec.FormatVersion == 0 && rec.Generation == "" && rec.Role == 0 && rec.Algorithm == 0 && rec.Components == nil
}

// TestDecodeRejectsUnknownFormatVersion is fail-closed test 1: an unknown
// format_version MUST be refused with ErrUnknownFormatVersion, before any
// other field is examined, and no key is returned.
func TestDecodeRejectsUnknownFormatVersion(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: FormatVersion(99), // not CurrentFormatVersion (1)
		Generation:    npamp.ALPN,
		Role:          RoleSigPrivate,
		Algorithm:     uint64(npamp.SigEd25519),
		Components:    [][]byte{mustEd25519Priv(t)},
	}
	data := marshalRecord(rec)

	got, err := Decode(data, npamp.ALPN)
	if !errors.Is(err, ErrUnknownFormatVersion) {
		t.Fatalf("Decode(format_version=99): err = %v, want %v", err, ErrUnknownFormatVersion)
	}
	if !isZeroRecord(got) {
		t.Fatalf("Decode(format_version=99) returned a non-zero record: %+v", got)
	}
}

// TestEncodeRejectsUnknownFormatVersion mirrors the Decode check on the
// Encode side: Encode MUST refuse to mint a record under any format version
// other than CurrentFormatVersion.
func TestEncodeRejectsUnknownFormatVersion(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: FormatVersion(2),
		Generation:    npamp.ALPN,
		Role:          RoleSigPrivate,
		Algorithm:     uint64(npamp.SigEd25519),
		Components:    [][]byte{mustEd25519Priv(t)},
	}
	if data, err := Encode(rec); !errors.Is(err, ErrUnknownFormatVersion) || data != nil {
		t.Fatalf("Encode(format_version=2): data=%v err=%v, want nil/%v", data, err, ErrUnknownFormatVersion)
	}
}

// TestDecodeRejectsUnknownAlgorithm is fail-closed test 2: an algorithm code
// point with no registry entry for the record's role MUST be refused with
// ErrUnknownAlgorithm and no key returned — covering both an entirely
// unregistered code point and a code point that belongs to the OTHER
// namespace (a SigID presented under a KEM role).
func TestDecodeRejectsUnknownAlgorithm(t *testing.T) {
	cases := []struct {
		name string
		rec  KeyRecord
	}{
		{
			name: "entirely unregistered KEM code point",
			rec: KeyRecord{
				FormatVersion: CurrentFormatVersion,
				Generation:    npamp.ALPN,
				Role:          RoleKEMPrivate,
				Algorithm:     0xffff,
				Components:    [][]byte{make([]byte, 64), make([]byte, 32)},
			},
		},
		{
			name: "SigID presented under a KEM role",
			rec: KeyRecord{
				FormatVersion: CurrentFormatVersion,
				Generation:    npamp.ALPN,
				Role:          RoleKEMPrivate,
				Algorithm:     uint64(npamp.SigEd25519), // valid Sig code point, wrong namespace
				Components:    [][]byte{make([]byte, 64), make([]byte, 32)},
			},
		},
		{
			name: "KEMID presented under a Sig role",
			rec: KeyRecord{
				FormatVersion: CurrentFormatVersion,
				Generation:    npamp.ALPN,
				Role:          RoleSigPrivate,
				Algorithm:     uint64(npamp.KEMX25519MLKEM768), // valid KEM code point, wrong namespace
				Components:    [][]byte{make([]byte, 64)},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := marshalRecord(c.rec)
			got, err := Decode(data, npamp.ALPN)
			if !errors.Is(err, ErrUnknownAlgorithm) {
				t.Fatalf("Decode(%s): err = %v, want %v", c.name, err, ErrUnknownAlgorithm)
			}
			if !isZeroRecord(got) {
				t.Fatalf("Decode(%s) returned a non-zero record: %+v", c.name, got)
			}
		})
	}
}

// TestEncodeRejectsUnknownAlgorithm mirrors the same check on Encode.
func TestEncodeRejectsUnknownAlgorithm(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleKEMPrivate,
		Algorithm:     0xffff,
		Components:    [][]byte{make([]byte, 64), make([]byte, 32)},
	}
	if data, err := Encode(rec); !errors.Is(err, ErrUnknownAlgorithm) || data != nil {
		t.Fatalf("Encode(unknown algorithm): data=%v err=%v, want nil/%v", data, err, ErrUnknownAlgorithm)
	}
}

// TestDecodeRejectsUnacceptedGeneration is fail-closed test 3: a record
// whose Generation the caller did not include in its accepted set MUST be
// refused with ErrGenerationNotAccepted and no key returned — even when the
// record is otherwise perfectly well-formed for a generation this package
// DOES have a registry for (the record here claims "n-pamp/2", the deprecated
// generation ADR-0014 describes; the caller only accepts npamp.ALPN,
// "n-pamp/3").
func TestDecodeRejectsUnacceptedGeneration(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    "n-pamp/2", // deprecated generation; caller below only accepts n-pamp/3
		Role:          RoleSigPrivate,
		Algorithm:     uint64(npamp.SigEd25519),
		Components:    [][]byte{mustEd25519Priv(t)},
	}
	data := marshalRecord(rec)

	got, err := Decode(data, npamp.ALPN)
	if !errors.Is(err, ErrGenerationNotAccepted) {
		t.Fatalf("Decode(generation=n-pamp/2, accepted={n-pamp/3}): err = %v, want %v", err, ErrGenerationNotAccepted)
	}
	if !isZeroRecord(got) {
		t.Fatalf("Decode(unaccepted generation) returned a non-zero record: %+v", got)
	}

	// The same record, explicitly opted into, decodes structurally (this
	// package has no registry for "n-pamp/2" — see keyformat.go — so no
	// algorithm/size validation is claimed or performed for it).
	got2, err := Decode(data, "n-pamp/2")
	if err != nil {
		t.Fatalf("Decode(generation=n-pamp/2, accepted={n-pamp/2}): unexpected err = %v", err)
	}
	if got2.Generation != "n-pamp/2" || got2.Role != RoleSigPrivate {
		t.Fatalf("Decode(explicitly accepted n-pamp/2) = %+v, fields do not match the encoded record", got2)
	}
}

// TestEncodeRejectsNonCurrentGeneration mirrors the same check on Encode:
// this Go reference mints records only for npamp.ALPN.
func TestEncodeRejectsNonCurrentGeneration(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    "n-pamp/2",
		Role:          RoleSigPrivate,
		Algorithm:     uint64(npamp.SigEd25519),
		Components:    [][]byte{mustEd25519Priv(t)},
	}
	if data, err := Encode(rec); !errors.Is(err, ErrGenerationNotAccepted) || data != nil {
		t.Fatalf("Encode(generation=n-pamp/2): data=%v err=%v, want nil/%v", data, err, ErrGenerationNotAccepted)
	}
}

// TestDecodeRequiresAtLeastOneAcceptedGeneration confirms Decode refuses to
// silently reject-everything by omission: calling it with zero accepted
// generations is a distinct, named caller error.
func TestDecodeRequiresAtLeastOneAcceptedGeneration(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleSigPrivate,
		Algorithm:     uint64(npamp.SigEd25519),
		Components:    [][]byte{mustEd25519Priv(t)},
	}
	data := marshalRecord(rec)
	if _, err := Decode(data); !errors.Is(err, ErrNoAcceptedGenerations) {
		t.Fatalf("Decode(no accepted generations): err = %v, want %v", err, ErrNoAcceptedGenerations)
	}
}

// TestDecodeRejectsWrongComponentCount and TestDecodeRejectsWrongComponentSize
// confirm the registry's shape check is real: a record naming a valid,
// registered algorithm but carrying the wrong number of components, or a
// component of the wrong length, MUST be refused.
func TestDecodeRejectsWrongComponentCount(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleKEMPrivate,
		Algorithm:     uint64(npamp.KEMX25519MLKEM768), // registered; needs 2 components
		Components:    [][]byte{make([]byte, 64)},      // only 1 supplied
	}
	data := marshalRecord(rec)
	if _, err := Decode(data, npamp.ALPN); !errors.Is(err, ErrComponentCount) {
		t.Fatalf("Decode(wrong component count): err = %v, want %v", err, ErrComponentCount)
	}
}

func TestDecodeRejectsWrongComponentSize(t *testing.T) {
	rec := KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleKEMPrivate,
		Algorithm:     uint64(npamp.KEMX25519MLKEM768),
		Components:    [][]byte{make([]byte, 63), make([]byte, 32)}, // seed one byte short
	}
	data := marshalRecord(rec)
	if _, err := Decode(data, npamp.ALPN); !errors.Is(err, ErrComponentSize) {
		t.Fatalf("Decode(wrong component size): err = %v, want %v", err, ErrComponentSize)
	}
}

// TestTypedAccessorsRejectRoleMismatch confirms the typed accessor functions
// refuse a structurally valid record of the WRONG role rather than silently
// reinterpreting it.
func TestTypedAccessorsRejectRoleMismatch(t *testing.T) {
	data, err := EncodeSigPrivate(npamp.SigEd25519, mustEd25519Priv(t))
	if err != nil {
		t.Fatalf("EncodeSigPrivate: %v", err)
	}
	if _, _, _, err := DecodeKEMPrivate(data, npamp.ALPN); !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("DecodeKEMPrivate(a sig-private record): err = %v, want %v", err, ErrRoleMismatch)
	}
	if _, _, err := DecodeSigPublic(data, npamp.ALPN); !errors.Is(err, ErrRoleMismatch) {
		t.Fatalf("DecodeSigPublic(a sig-private record): err = %v, want %v", err, ErrRoleMismatch)
	}
}

// TestDecodeRejectsMalformedCBOR exercises the CBOR layer's own fail-closed
// checks directly: a wrong top-level entry count, a non-shortest-form
// length, and trailing bytes after the top-level item must all be refused
// rather than silently truncated or ignored.
func TestDecodeRejectsMalformedCBOR(t *testing.T) {
	valid, err := EncodeSigPublic(npamp.SigEd25519, make([]byte, 32))
	if err != nil {
		t.Fatalf("EncodeSigPublic: %v", err)
	}

	t.Run("trailing bytes", func(t *testing.T) {
		tampered := append(append([]byte{}, valid...), 0x00)
		if _, err := Decode(tampered, npamp.ALPN); !errors.Is(err, errCBORTrailing) {
			t.Fatalf("Decode(trailing byte): err = %v, want %v", err, errCBORTrailing)
		}
	})

	t.Run("wrong top-level entry count", func(t *testing.T) {
		// A definite-length map header claiming 4 entries instead of 5.
		tampered := append([]byte{}, valid...)
		tampered[0] = cborMajorMap<<5 | 4
		if _, err := Decode(tampered, npamp.ALPN); err == nil {
			t.Fatal("Decode(map header claiming 4 entries) unexpectedly succeeded")
		}
	})

	t.Run("non-shortest-form length", func(t *testing.T) {
		// A 1-byte-follows length encoding (additional info 24) of a value
		// that fits in the immediate 0-23 range is not shortest-form.
		bad := []byte{cborMajorMap<<5 | 24, 5}
		bad = append(bad, valid[1:]...)
		if _, err := Decode(bad, npamp.ALPN); !errors.Is(err, errCBORNotShortest) {
			t.Fatalf("Decode(non-shortest map length): err = %v, want %v", err, errCBORNotShortest)
		}
	})
}

// TestDecodeRejectsHostileComponentArrayLength crafts a record whose
// components array claims an enormous element count (2^40) with NO element
// data following it at all — a well-formed map/key/uint/text prefix (map
// header, keys 1-4, all valid) followed by an array-length claim designed to
// drive naive decoding into a multi-terabyte allocation (`make([][]byte,
// 1<<40)`) rather than a clean refusal. This is exactly the crash-on-hostile-
// input case a key-at-rest format's own migration/inventory tooling
// (section 2 of docs/crypto-agility-migration.md) must survive when
// scanning a possibly-corrupt key store: a truncated/tampered record must
// return a named error, never panic or OOM the scanning process.
func TestDecodeRejectsHostileComponentArrayLength(t *testing.T) {
	var hostile []byte
	hostile = append(hostile, encodeUint(cborMajorMap, 5)...)
	hostile = append(hostile, encodeUint(cborMajorUint, 1)...)
	hostile = append(hostile, encodeUint(cborMajorUint, uint64(CurrentFormatVersion))...)
	hostile = append(hostile, encodeUint(cborMajorUint, 2)...)
	hostile = append(hostile, encodeTextItem(npamp.ALPN)...)
	hostile = append(hostile, encodeUint(cborMajorUint, 3)...)
	hostile = append(hostile, encodeUint(cborMajorUint, uint64(RoleSigPublic))...)
	hostile = append(hostile, encodeUint(cborMajorUint, 4)...)
	hostile = append(hostile, encodeUint(cborMajorUint, uint64(npamp.SigEd25519))...)
	hostile = append(hostile, encodeUint(cborMajorUint, 5)...)
	hostile = append(hostile, encodeUint(cborMajorArray, 1<<40)...) // the hostile claim; no element bytes follow

	if _, err := Decode(hostile, npamp.ALPN); !errors.Is(err, errCBORTruncated) {
		t.Fatalf("Decode(hostile 2^40-element components claim): err = %v, want %v", err, errCBORTruncated)
	}
}

// TestComponentsOrderIsPQCFirstRegardlessOfWireCombinerOrder confirms the
// storage-format Components order (component[0]=ML-KEM, component[1]=
// classical) is applied uniformly to BOTH hybrid-KEM groups, even though
// their WIRE combiner orders differ (X25519MLKEM768 is ML-KEM-first;
// SecP384r1MLKEM1024 is classical-first, per hybridkem.Combine) — the two
// orderings are independent axes and this format does not mirror the wire
// combiner's per-group flip.
func TestComponentsOrderIsPQCFirstRegardlessOfWireCombinerOrder(t *testing.T) {
	mlkemSeed := bytes.Repeat([]byte{0xAA}, 64)
	classicalPriv384 := bytes.Repeat([]byte{0xBB}, 48)

	data, err := EncodeKEMPrivate(npamp.KEMSecP384r1MLKEM1024, mlkemSeed, classicalPriv384)
	if err != nil {
		t.Fatalf("EncodeKEMPrivate(SecP384r1MLKEM1024): %v", err)
	}
	rec, err := Decode(data, npamp.ALPN)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(rec.Components[0], mlkemSeed) {
		t.Fatal("Components[0] is not the ML-KEM component for SecP384r1MLKEM1024 (storage order must be PQC-first for both groups)")
	}
	if !bytes.Equal(rec.Components[1], classicalPriv384) {
		t.Fatal("Components[1] is not the classical (P-384) component for SecP384r1MLKEM1024")
	}
}
