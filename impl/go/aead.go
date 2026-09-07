package npamp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// DeriveNonce computes the per-frame AEAD nonce per draft-00 section 7.5: the AEAD
// IV exclusive-ORed with the left-zero-padded sequence number, identical in form
// to TLS 1.3 and QUIC. The 8-octet big-endian sequence number occupies the low 8
// octets of the 12-octet field (the high 4 octets are zero before the XOR). The
// Channel ID is NOT part of the nonce.
func DeriveNonce(iv [12]byte, seq uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:12], seq)
	for i := range n {
		n[i] ^= iv[i]
	}
	return n
}

// SealAES256GCM encrypts plaintext under AES-256-GCM (suite 0x0001) using the
// draft-00 nonce and aad (the 21-octet header prefix) as associated data. It
// returns ciphertext||tag with a 16-octet authentication tag.
func SealAES256GCM(key [32]byte, iv [12]byte, seq uint64, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := DeriveNonce(iv, seq)
	return g.Seal(nil, n[:], plaintext, aad), nil
}

// OpenAES256GCM reverses SealAES256GCM, returning the plaintext or an error if the
// tag does not verify.
func OpenAES256GCM(key [32]byte, iv [12]byte, seq uint64, aad, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := DeriveNonce(iv, seq)
	return g.Open(nil, n[:], sealed, aad)
}

// NOTE: ChaCha20-Poly1305 (suite 0x0002) uses the same nonce construction and is
// added in the golang.org/x/crypto increment; AES-256-GCM is the stdlib-only path.

// ErrNoAEADSuite is returned when a per-frame AEAD selection is attempted with an
// empty selectable-suite list. Selection fails closed.
var ErrNoAEADSuite = errors.New("npamp: AEADSelect list is empty (no AEAD suite to select)")

// SelectAEAD returns the AEAD suite for a frame with the given sequence number,
// diversifying deterministically across the negotiated selectable suites with no
// per-frame wire flag (spec/06 §Per-frame AEAD selection). suites is the AEADSelect
// list, primary first; the frame's suite is suites[seq mod len(suites)]. With one
// suite (Standard, diversification off) every frame uses the primary; with two
// (High/Sovereign) frames alternate by sequence parity. Both peers derive the same
// suite from the shared sequence number, so no per-frame suite indicator is on the
// wire.
func SelectAEAD(suites []AEADID, seq uint64) (AEADID, error) {
	if len(suites) == 0 {
		return 0, ErrNoAEADSuite
	}
	return suites[seq%uint64(len(suites))], nil
}
