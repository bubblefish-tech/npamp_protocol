// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package keyformat is the versioned, self-describing KEY-STORAGE format for
// N-PAMP (draft-bubblefish-npamp-02, Part 2 Requirement 2 acc.crit.3: "The PQC
// modules SHALL address the documented production gap: versioned key formats,
// a crypto-agility/migration runbook, and a hybrid-by-default posture.").
//
// It is a KEY-AT-REST / KEY-TRANSPORT format, unrelated to the on-wire
// handshake: N-PAMP's frame layout, TLV registries, and KEM/CertVerify wire
// bytes (spec/, impl/go/kem.go, impl/go/kem1024.go, impl/go/hybridkem) are
// Part-1 frozen and this package neither reads nor changes them. What it
// serializes is how a KEM or signature KEY PAIR is stored on disk or carried
// between a key-management system and an N-PAMP endpoint, so that:
//
//   - a stored key is self-describing (format version, crypto generation,
//     role, algorithm code point, and key material all travel together), and
//   - a crypto migration is DETECTABLE: a reader presented with a key minted
//     under an older N-PAMP crypto generation can recognize that fact and
//     refuse or migrate deliberately, rather than silently misinterpreting
//     the algorithm code point under the wrong generation's registry.
//
// The second point is not decorative. Per decisions/adr/0014 (crypto
// generation and wire-format version are decoupled, independent axes),
// N-PAMP's own KEM and signature code points have been RE-ANCHORED across
// crypto generations — historically the same SigID numeric value has named a
// different ML-DSA parameter set from one generation to the next. A stored
// key's Algorithm field therefore has no fixed meaning without knowing which
// generation's registry to resolve it against; this package makes that
// generation an explicit, required field (KeyRecord.Generation) and refuses
// to resolve Algorithm against any generation the caller has not explicitly
// opted into (see Decode).
//
// Key material is delegated to the existing stdlib crypto types the rest of
// this module already uses — crypto/mlkem (ML-KEM seeds and encapsulation
// keys), crypto/ecdh (X25519 and P-384 private/public keys), and
// crypto/ed25519 (identity signature keys) — this package stores and
// validates their raw byte encodings; it performs no cryptographic
// operations of its own. ML-DSA-44/65/87 key material (SigID 0x0904/0x0905/
// 0x0906) is likewise stored and size-validated against the registered FIPS
// 204 sizes, but as OPAQUE raw bytes: no Go standard-library ML-DSA
// implementation exists yet in this toolchain, so this package cannot mint or
// verify a live ML-DSA key pair — it can only carry one honestly, ready for
// the day a Go ML-DSA type exists to hand its bytes to.
//
// See docs/crypto-agility-migration.md for the deployment-facing migration
// runbook this format exists to support.
package keyformat
