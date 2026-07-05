// Package npamp is the open reference implementation of the N-PAMP wire format,
// draft-bubblefish-npamp-00.
//
// It implements the OPEN protocol layer only: the 36-octet frame header, the
// channel/frame-type/TLV registries, the AEAD record layer (nonce derivation and
// authenticated encryption), the HKDF-Expand-Label key schedule, and the draft-00
// 1.5-RTT handshake binding at the Standard profile (X25519MLKEM768 hybrid KEM,
// Ed25519 CertVerify/Finished, per-TLV transcript; spec/10_handshake_binding.md).
// It contains no proprietary scoring, detection, or generation methods, no tuned
// parameters, and no model weights.
//
// Conformance: every value restates draft-bubblefish-npamp-00; where any value
// disagrees with the draft, the draft governs.
package npamp
