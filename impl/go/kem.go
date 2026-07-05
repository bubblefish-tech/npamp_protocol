package npamp

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
)

// X25519MLKEM768 (KEM 0x11ec) wire sizes, per the handshake binding
// (spec/10 section 4). Component sizes are per FIPS 203 (ML-KEM-768) and
// RFC 7748 (X25519). The wire layout is ML-KEM-first (ADR-0005): the suite
// NAME lists X25519 first, the BYTES are ML-KEM-first.
const (
	// KEMShareSize768 is the TLV 0x07 value size:
	// ML-KEM-768 encapsulation key (1184) || X25519 public key (32).
	KEMShareSize768 = mlkem.EncapsulationKeySize768 + 32 // 1216

	// KEMCiphertextSize768 is the TLV 0x08 value size:
	// ML-KEM-768 ciphertext (1088) || server X25519 public key (32).
	KEMCiphertextSize768 = mlkem.CiphertextSize768 + 32 // 1120

	// CombinedSecretSize is the size of the raw HKDF-Extract IKM:
	// ML-KEM shared secret (32) || X25519 shared secret (32).
	CombinedSecretSize = 2 * mlkem.SharedKeySize // 64
)

var (
	ErrKEMShareSize      = errors.New("npamp: KEMShare is not 1216 octets (ML-KEM-768 ek || X25519 public)")
	ErrKEMCiphertextSize = errors.New("npamp: KEMCiphertext is not 1120 octets (ML-KEM-768 ct || X25519 public)")
)

// SharedSecrets holds the two component shared secrets of the X25519MLKEM768
// hybrid KEM. There is no hybrid-layer KDF: the key schedule's HKDF-Extract is
// the combiner, and its IKM is the ML-KEM-first concatenation (spec/10 section
// 4, ADR-0005).
type SharedSecrets struct {
	MLKEM  []byte // 32 octets, FIPS 203 ML-KEM-768 shared secret
	X25519 []byte // 32 octets, RFC 7748 X25519 shared secret
}

// Combined returns ML-KEM_SS || X25519_SS (64 octets), the raw IKM fed to
// HKDF-Extract by HandshakeSecret. ML-KEM-first, per ADR-0005 / SP 800-56C
// Rev. 2 (the FIPS-approved secret leads the KDF input).
func (s SharedSecrets) Combined() []byte {
	out := make([]byte, 0, len(s.MLKEM)+len(s.X25519))
	out = append(out, s.MLKEM...)
	return append(out, s.X25519...)
}

// KEMClient is the client (initiator) side of the X25519MLKEM768 exchange: it
// generates the two component key pairs, publishes the KEMShare, and
// decapsulates the server's KEMCiphertext.
type KEMClient struct {
	mlkemKey  *mlkem.DecapsulationKey768
	x25519Key *ecdh.PrivateKey
}

// GenerateKEMClient generates a fresh client KEM state from a secure random
// source.
func GenerateKEMClient() (*KEMClient, error) {
	mk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KEMClient{mlkemKey: mk, x25519Key: xk}, nil
}

// NewKEMClient builds a client KEM state from fixed key material: a 64-octet
// ML-KEM-768 seed in FIPS 203 "d || z" form and a 32-octet X25519 private key
// (RFC 7748; clamping is applied by crypto/ecdh). Deterministic construction
// exists so standards-anchored known-answer vectors can drive the real code
// path; live handshakes use GenerateKEMClient.
func NewKEMClient(mlkemSeed, x25519PrivateKey []byte) (*KEMClient, error) {
	mk, err := mlkem.NewDecapsulationKey768(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("npamp: ML-KEM-768 seed: %w", err)
	}
	xk, err := ecdh.X25519().NewPrivateKey(x25519PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("npamp: X25519 private key: %w", err)
	}
	return &KEMClient{mlkemKey: mk, x25519Key: xk}, nil
}

// KEMShare returns the TLV 0x07 value: ML-KEM-768 encapsulation key (1184) ||
// X25519 public key (32), 1216 octets, ML-KEM-first (spec/10 section 4).
func (c *KEMClient) KEMShare() []byte {
	ek := c.mlkemKey.EncapsulationKey().Bytes()
	out := make([]byte, 0, KEMShareSize768)
	out = append(out, ek...)
	return append(out, c.x25519Key.PublicKey().Bytes()...)
}

// SharedSecrets decapsulates a TLV 0x08 KEMCiphertext value (ML-KEM-768
// ciphertext (1088) || server X25519 public key (32)) into the two component
// shared secrets. A corrupt ML-KEM ciphertext body yields a pseudorandom
// secret via FIPS 203 implicit rejection (it fails the Finished MAC later, not
// here); an all-zero (low-order) X25519 result is rejected with an error, per
// spec/10 section 4.
func (c *KEMClient) SharedSecrets(kemCiphertext []byte) (SharedSecrets, error) {
	if len(kemCiphertext) != KEMCiphertextSize768 {
		return SharedSecrets{}, ErrKEMCiphertextSize
	}
	ct := kemCiphertext[:mlkem.CiphertextSize768]
	serverPub := kemCiphertext[mlkem.CiphertextSize768:]
	mlkemSS, err := c.mlkemKey.Decapsulate(ct)
	if err != nil {
		return SharedSecrets{}, fmt.Errorf("npamp: ML-KEM-768 decapsulate: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return SharedSecrets{}, fmt.Errorf("npamp: server X25519 public key: %w", err)
	}
	xSS, err := c.x25519Key.ECDH(pub) // errors on the all-zero (low-order) result
	if err != nil {
		return SharedSecrets{}, fmt.Errorf("npamp: X25519 exchange: %w", err)
	}
	return SharedSecrets{MLKEM: mlkemSS, X25519: xSS}, nil
}

// Encapsulate is the server (responder) side of the X25519MLKEM768 exchange:
// it parses the client's KEMShare, encapsulates to the ML-KEM-768 key,
// performs X25519 with a freshly generated server key, and returns the TLV
// 0x08 KEMCiphertext value plus the component shared secrets.
func Encapsulate(kemShare []byte) (kemCiphertext []byte, ss SharedSecrets, err error) {
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, SharedSecrets{}, err
	}
	return EncapsulateWith(kemShare, xk)
}

// EncapsulateWith is Encapsulate with a caller-supplied server X25519 private
// key (the ML-KEM encapsulation randomness still comes from the secure random
// source inside crypto/mlkem). It exists so known-answer vectors can pin the
// X25519 half to RFC 7748 values through the real server code path.
func EncapsulateWith(kemShare []byte, serverX25519 *ecdh.PrivateKey) (kemCiphertext []byte, ss SharedSecrets, err error) {
	if len(kemShare) != KEMShareSize768 {
		return nil, SharedSecrets{}, ErrKEMShareSize
	}
	ekBytes := kemShare[:mlkem.EncapsulationKeySize768]
	clientPubBytes := kemShare[mlkem.EncapsulationKeySize768:]
	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		return nil, SharedSecrets{}, fmt.Errorf("npamp: ML-KEM-768 encapsulation key: %w", err)
	}
	clientPub, err := ecdh.X25519().NewPublicKey(clientPubBytes)
	if err != nil {
		return nil, SharedSecrets{}, fmt.Errorf("npamp: client X25519 public key: %w", err)
	}
	mlkemSS, ct := ek.Encapsulate()
	xSS, err := serverX25519.ECDH(clientPub) // errors on the all-zero (low-order) result
	if err != nil {
		return nil, SharedSecrets{}, fmt.Errorf("npamp: X25519 exchange: %w", err)
	}
	out := make([]byte, 0, KEMCiphertextSize768)
	out = append(out, ct...)
	out = append(out, serverX25519.PublicKey().Bytes()...)
	return out, SharedSecrets{MLKEM: mlkemSS, X25519: xSS}, nil
}
