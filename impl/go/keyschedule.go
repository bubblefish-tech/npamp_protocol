package npamp

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// LabelPrefix is the N-PAMP protocol-specific HKDF-Expand-Label prefix (draft-00
// section 7.4). It provides domain separation from TLS 1.3 (which uses "tls13 ")
// and from QUIC. A literal "tls13 " prefix is non-conformant.
const LabelPrefix = "n-pamp "

// Direction identifies the sender side for per-direction key derivation.
type Direction uint8

const (
	DirClientToServer Direction = 0
	DirServerToClient Direction = 1
)

func hashForProfile(p Profile) func() hash.Hash {
	if p == ProfileStandard {
		return sha256.New
	}
	return sha512.New384
}

// HkdfExpandLabel implements the TLS-1.3-style HKDF-Expand-Label with the N-PAMP
// label prefix (draft-00 section 7.4). The HkdfLabel structure is:
//
//	uint16 length
//	opaque label<7..255>   = LabelPrefix || label
//	opaque context<0..255>
func HkdfExpandLabel(secret []byte, label string, context []byte, length int, h func() hash.Hash) ([]byte, error) {
	full := LabelPrefix + label
	info := make([]byte, 0, 2+1+len(full)+1+len(context))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdf.Expand(h, secret, string(info), length)
}

// DeriveTrafficSecret binds the (direction, epoch, AEAD suite, channel) tuple into
// the key schedule (draft-00 section 7.5) so that no two distinct contexts share a
// key, preventing cross-direction, cross-suite, and cross-channel nonce reuse.
func DeriveTrafficSecret(master []byte, dir Direction, epoch uint64, suite AEADID, channel ChannelID, p Profile) ([]byte, error) {
	ctx := make([]byte, 0, 1+8+2+2)
	ctx = append(ctx, byte(dir))
	ctx = binary.BigEndian.AppendUint64(ctx, epoch)
	ctx = binary.BigEndian.AppendUint16(ctx, uint16(suite))
	ctx = binary.BigEndian.AppendUint16(ctx, uint16(channel))
	h := hashForProfile(p)
	return HkdfExpandLabel(master, "traffic", ctx, h().Size(), h)
}

// HandshakeSecret is the single HKDF-Extract at the root of the handshake key
// schedule (spec/10 section 5):
//
//	handshake_secret = HKDF-Extract(salt = HashLen x 0x00, IKM = ML-KEM_SS || X25519_SS)
//
// The salt is HashLen zero octets (the RFC 5869 section 2.2 default); the IKM
// is the ML-KEM-first combined KEM output (ADR-0005) — the Extract is the
// hybrid combiner (a dual-PRF), with no hybrid-layer KDF before it.
func HandshakeSecret(ss SharedSecrets, p Profile) ([]byte, error) {
	h := hashForProfile(p)
	return hkdf.Extract(h, ss.Combined(), make([]byte, h().Size()))
}

// DeriveHandshakeTrafficSecrets derives the per-direction handshake secrets
// from handshake_secret and the TH_kem transcript point (spec/10 section 5):
//
//	c_hs_secret = HKDF-Expand-Label(handshake_secret, "c hs", TH_kem, HashLen)
//	s_hs_secret = HKDF-Expand-Label(handshake_secret, "s hs", TH_kem, HashLen)
//
// Handshake-phase traffic keys descend from these via DeriveTrafficSecret
// (epoch 0, Control channel).
func DeriveHandshakeTrafficSecrets(handshakeSecret, thKEM []byte, p Profile) (cHS, sHS []byte, err error) {
	h := hashForProfile(p)
	cHS, err = HkdfExpandLabel(handshakeSecret, "c hs", thKEM, h().Size(), h)
	if err != nil {
		return nil, nil, err
	}
	sHS, err = HkdfExpandLabel(handshakeSecret, "s hs", thKEM, h().Size(), h)
	if err != nil {
		return nil, nil, err
	}
	return cHS, sHS, nil
}

// DeriveMasterSecret derives the master secret at the client-auth boundary
// (spec/10 section 5):
//
//	master = HKDF-Expand-Label(handshake_secret, "master", TH_cCV, HashLen)
//
// TH_cCV is the transcript through the client CertVerify (excluding the client
// Finished). Application-phase traffic keys descend from master.
func DeriveMasterSecret(handshakeSecret, thCCV []byte, p Profile) ([]byte, error) {
	h := hashForProfile(p)
	return HkdfExpandLabel(handshakeSecret, "master", thCCV, h().Size(), h)
}

// DeriveFinishedKey derives the Finished MAC key from a per-direction
// handshake traffic secret (spec/10 section 6.2, per RFC 8446 section 4.4.4):
//
//	finished_key = HKDF-Expand-Label(BaseKey, "finished", "", HashLen)
//
// BaseKey is c_hs_secret or s_hs_secret, per the sender's direction.
func DeriveFinishedKey(handshakeTrafficSecret []byte, p Profile) ([]byte, error) {
	h := hashForProfile(p)
	return HkdfExpandLabel(handshakeTrafficSecret, "finished", nil, h().Size(), h)
}

// DeriveKeyIV derives the 32-octet AEAD key and 12-octet AEAD IV from a traffic
// secret (draft-00 section 7.5).
func DeriveKeyIV(secret []byte, p Profile) (key [32]byte, iv [12]byte, err error) {
	h := hashForProfile(p)
	k, err := HkdfExpandLabel(secret, "key", nil, 32, h)
	if err != nil {
		return key, iv, err
	}
	v, err := HkdfExpandLabel(secret, "iv", nil, 12, h)
	if err != nil {
		return key, iv, err
	}
	copy(key[:], k)
	copy(iv[:], v)
	return key, iv, nil
}
