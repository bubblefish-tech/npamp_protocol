// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
)

// SecP384r1MLKEM1024 (KEM 0x11ed) wire sizes, per the handshake binding
// (spec/10 section 4) and RFC 10024 (formerly draft-ietf-tls-ecdhe-mlkem) SecP384r1MLKEM1024.
// Component sizes are per FIPS 203 (ML-KEM-1024) and the secp384r1 uncompressed
// point encoding of RFC 9846 section 4.3.8.2.
//
// Unlike X25519MLKEM768 (which is ML-KEM-first "for historical reasons"), the
// SecP* hybrid groups place the ECDHE component FIRST — on the wire AND in the
// combined shared secret — because the FIPS-approved ordering (NIST SP 800-56C
// Rev. 2) applied to this group's defining document puts the classical share
// ahead of ML-KEM. This is the Sovereign/High KEM.
const (
	// P384PublicKeySize is the secp384r1 uncompressed point size (0x04 || X || Y),
	// per RFC 9846 section 4.3.8.2: 1 + 48 + 48 octets.
	P384PublicKeySize = 97

	// P384SharedSecretSize is the secp384r1 ECDH shared secret: the x-coordinate
	// of the shared point as an octet string (48 octets).
	P384SharedSecretSize = 48

	// KEMShareSize1024 is the TLV 0x07 value size for SecP384r1MLKEM1024:
	// secp384r1 public key (97) || ML-KEM-1024 encapsulation key (1568), ECDHE-first.
	KEMShareSize1024 = P384PublicKeySize + mlkem.EncapsulationKeySize1024 // 1665

	// KEMCiphertextSize1024 is the TLV 0x08 value size for SecP384r1MLKEM1024:
	// server secp384r1 public key (97) || ML-KEM-1024 ciphertext (1568), ECDHE-first.
	KEMCiphertextSize1024 = P384PublicKeySize + mlkem.CiphertextSize1024 // 1665

	// CombinedSecretSize1024 is the raw HKDF-Extract IKM size:
	// secp384r1 shared secret (48) || ML-KEM-1024 shared secret (32), ECDHE-first.
	CombinedSecretSize1024 = P384SharedSecretSize + mlkem.SharedKeySize // 80
)

var (
	ErrKEMShare1024Size      = errors.New("npamp: KEMShare is not 1665 octets (secp384r1 pub || ML-KEM-1024 ek)")
	ErrKEMCiphertext1024Size = errors.New("npamp: KEMCiphertext is not 1665 octets (server secp384r1 pub || ML-KEM-1024 ct)")
)

// SharedSecrets1024 holds the two component shared secrets of the
// SecP384r1MLKEM1024 hybrid KEM. There is no hybrid-layer KDF: the key
// schedule's HKDF-Extract is the combiner, and its IKM is the ECDHE-first
// concatenation (spec/10 section 4; RFC 10024, formerly draft-ietf-tls-ecdhe-mlkem).
type SharedSecrets1024 struct {
	ECDHE []byte // 48 octets, secp384r1 ECDH shared secret (x-coordinate)
	MLKEM []byte // 32 octets, FIPS 203 ML-KEM-1024 shared secret
}

// Combined returns ECDHE_SS || ML-KEM_SS (80 octets), the raw IKM fed to
// HKDF-Extract. ECDHE-first (P-384 first), per RFC 10024 (formerly draft-ietf-tls-ecdhe-mlkem)
// SecP384r1MLKEM1024 — the reverse of the X25519MLKEM768 order.
func (s SharedSecrets1024) Combined() []byte {
	out := make([]byte, 0, len(s.ECDHE)+len(s.MLKEM))
	out = append(out, s.ECDHE...)
	return append(out, s.MLKEM...)
}

// KEMClient1024 is the client (initiator) side of the SecP384r1MLKEM1024
// exchange: it generates the two component key pairs, publishes the KEMShare,
// and decapsulates the server's KEMCiphertext.
type KEMClient1024 struct {
	mlkemKey *mlkem.DecapsulationKey1024
	p384Key  *ecdh.PrivateKey
}

// GenerateKEMClient1024 generates a fresh client KEM state from a secure random
// source.
func GenerateKEMClient1024() (*KEMClient1024, error) {
	mk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	xk, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KEMClient1024{mlkemKey: mk, p384Key: xk}, nil
}

// NewKEMClient1024 builds a client KEM state from fixed key material: a 64-octet
// ML-KEM-1024 seed in FIPS 203 "d || z" form and a secp384r1 private key (a
// big-endian scalar accepted by crypto/ecdh). Deterministic construction exists
// so standards-anchored known-answer vectors can drive the real code path; live
// handshakes use GenerateKEMClient1024.
func NewKEMClient1024(mlkemSeed, p384PrivateKey []byte) (*KEMClient1024, error) {
	mk, err := mlkem.NewDecapsulationKey1024(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("npamp: ML-KEM-1024 seed: %w", err)
	}
	xk, err := ecdh.P384().NewPrivateKey(p384PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("npamp: secp384r1 private key: %w", err)
	}
	return &KEMClient1024{mlkemKey: mk, p384Key: xk}, nil
}

// KEMShare returns the TLV 0x07 value: secp384r1 public key (97) || ML-KEM-1024
// encapsulation key (1568), 1665 octets, ECDHE-first (spec/10 section 4).
func (c *KEMClient1024) KEMShare() []byte {
	out := make([]byte, 0, KEMShareSize1024)
	out = append(out, c.p384Key.PublicKey().Bytes()...)
	return append(out, c.mlkemKey.EncapsulationKey().Bytes()...)
}

// SharedSecrets decapsulates a TLV 0x08 KEMCiphertext value (server secp384r1
// public key (97) || ML-KEM-1024 ciphertext (1568)) into the two component
// shared secrets. A corrupt ML-KEM ciphertext body yields a pseudorandom secret
// via FIPS 203 implicit rejection (it fails the Finished MAC later, not here);
// an invalid or identity secp384r1 point is rejected with an error, per spec/10
// section 4.
func (c *KEMClient1024) SharedSecrets(kemCiphertext []byte) (SharedSecrets1024, error) {
	if len(kemCiphertext) != KEMCiphertextSize1024 {
		return SharedSecrets1024{}, ErrKEMCiphertext1024Size
	}
	serverPub := kemCiphertext[:P384PublicKeySize]
	ct := kemCiphertext[P384PublicKeySize:]
	pub, err := ecdh.P384().NewPublicKey(serverPub)
	if err != nil {
		return SharedSecrets1024{}, fmt.Errorf("npamp: server secp384r1 public key: %w", err)
	}
	eSS, err := c.p384Key.ECDH(pub) // errors on an invalid/identity result
	if err != nil {
		return SharedSecrets1024{}, fmt.Errorf("npamp: secp384r1 exchange: %w", err)
	}
	mlkemSS, err := c.mlkemKey.Decapsulate(ct)
	if err != nil {
		return SharedSecrets1024{}, fmt.Errorf("npamp: ML-KEM-1024 decapsulate: %w", err)
	}
	return SharedSecrets1024{ECDHE: eSS, MLKEM: mlkemSS}, nil
}

// Encapsulate1024 is the server (responder) side of the SecP384r1MLKEM1024
// exchange: it parses the client's KEMShare, generates a fresh server secp384r1
// key, performs ECDH, encapsulates to the ML-KEM-1024 key, and returns the TLV
// 0x08 KEMCiphertext value plus the component shared secrets.
func Encapsulate1024(kemShare []byte) (kemCiphertext []byte, ss SharedSecrets1024, err error) {
	xk, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		return nil, SharedSecrets1024{}, err
	}
	return EncapsulateWith1024(kemShare, xk)
}

// EncapsulateWith1024 is Encapsulate1024 with a caller-supplied server secp384r1
// private key (the ML-KEM encapsulation randomness still comes from the secure
// random source inside crypto/mlkem). It exists so known-answer vectors can pin
// the secp384r1 half to published values through the real server code path.
func EncapsulateWith1024(kemShare []byte, serverP384 *ecdh.PrivateKey) (kemCiphertext []byte, ss SharedSecrets1024, err error) {
	if len(kemShare) != KEMShareSize1024 {
		return nil, SharedSecrets1024{}, ErrKEMShare1024Size
	}
	clientPubBytes := kemShare[:P384PublicKeySize]
	ekBytes := kemShare[P384PublicKeySize:]
	clientPub, err := ecdh.P384().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, SharedSecrets1024{}, fmt.Errorf("npamp: client secp384r1 public key: %w", err)
	}
	ek, err := mlkem.NewEncapsulationKey1024(ekBytes)
	if err != nil {
		return nil, SharedSecrets1024{}, fmt.Errorf("npamp: ML-KEM-1024 encapsulation key: %w", err)
	}
	eSS, err := serverP384.ECDH(clientPub) // errors on an invalid/identity result
	if err != nil {
		return nil, SharedSecrets1024{}, fmt.Errorf("npamp: secp384r1 exchange: %w", err)
	}
	mlkemSS, ct := ek.Encapsulate()
	out := make([]byte, 0, KEMCiphertextSize1024)
	out = append(out, serverP384.PublicKey().Bytes()...)
	out = append(out, ct...)
	return out, SharedSecrets1024{ECDHE: eSS, MLKEM: mlkemSS}, nil
}
