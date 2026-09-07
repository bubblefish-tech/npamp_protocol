package npamp

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
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
//	handshake_secret = HKDF-Extract(salt = HashLen x 0x00, IKM = ss.Combined())
//
// The salt is HashLen zero octets (the RFC 5869 section 2.2 default); the IKM is the
// per-group combined KEM shared secret (ss.Combined()) — the Extract is itself the
// hybrid combiner (a dual-PRF), with no hybrid-layer KDF before it. The concatenation
// order is per-group per RFC 10024 (formerly draft-ietf-tls-ecdhe-mlkem; decision D2, superseding the
// ADR-0005 universal ML-KEM-first): this SharedSecrets value is the X25519MLKEM768
// group, whose Combined() is ML-KEM_SS || X25519_SS; SecP384r1MLKEM1024 uses
// SharedSecrets1024.Combined() (ECDHE_SS || ML-KEM_SS). The public KEM material is
// bound via the transcript (TH_kem), not folded into this Extract input.
func HandshakeSecret(ss SharedSecrets, p Profile) ([]byte, error) {
	h := hashForProfile(p)
	return hkdf.Extract(h, ss.Combined(), make([]byte, h().Size()))
}

// ErrHandshakeSecret1024StandardProfile is returned by HandshakeSecret1024
// when called with ProfileStandard. SecP384r1MLKEM1024 (kem1024.go) is the
// High/Sovereign minimum KEM (spec/05_profiles.md "Minimum KEM"); Standard
// uses X25519MLKEM768 and HandshakeSecret, never this function — a Standard
// session that reached this call would be a protocol-layer bug upstream
// (the SDK's KEM-group selection is profile-derived), so this is fail-closed
// rather than a silent fallback to the wrong combiner/hash.
var ErrHandshakeSecret1024StandardProfile = errors.New("npamp: HandshakeSecret1024 called with ProfileStandard (SecP384r1MLKEM1024 is High/Sovereign only, spec/05_profiles.md)")

// HandshakeSecret1024 is HandshakeSecret for the SecP384r1MLKEM1024 KEM
// (High, Sovereign), identical construction over the wider 1024 shared-secret
// type (spec/10 section 5, spec/10 section 4a):
//
//	handshake_secret = HKDF-Extract(salt = HashLen x 0x00, IKM = ss.Combined())
//
// ss.Combined() is ECDHE_SS || ML-KEM_SS (kem1024.go: SecP384r1MLKEM1024 is
// ECDHE-first, the reverse of X25519MLKEM768's ML-KEM-first order). p selects
// H/HashLen exactly as HandshakeSecret does (SHA-384/48 at High and Sovereign,
// the only profiles p may be here). Fail-closed for ProfileStandard: see
// ErrHandshakeSecret1024StandardProfile.
func HandshakeSecret1024(ss SharedSecrets1024, p Profile) ([]byte, error) {
	if p == ProfileStandard {
		return nil, ErrHandshakeSecret1024StandardProfile
	}
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
// handshake traffic secret (spec/10 section 6.2, per RFC 9846 section 4.4.4):
//
//	finished_key = HKDF-Expand-Label(BaseKey, "finished", "", HashLen)
//
// BaseKey is c_hs_secret or s_hs_secret, per the sender's direction.
func DeriveFinishedKey(handshakeTrafficSecret []byte, p Profile) ([]byte, error) {
	h := hashForProfile(p)
	return HkdfExpandLabel(handshakeTrafficSecret, "finished", nil, h().Size(), h)
}

// RatchetMasterTier1 performs the cheap symmetric forward step of the master
// ratchet (spec/10 section 9.1, Hybrid Tree Ratchet Tier 1):
//
//	master_{G+1} = HKDF-Expand-Label(master_G, "master ratchet", gen(8 BE, value targetGen), HashLen)
//
// targetGen is the NEW generation index (G+1). The full wire label is
// "n-pamp master ratchet". HKDF-Expand is one-way, so master_G cannot be
// reconstructed from the result: this step provides forward secrecy, not
// self-healing (the chain is deterministic — an attacker holding master_G can
// compute every future Tier-1 root). The caller zeroizes master_G in place after
// the step so the pre-step root does not linger.
func RatchetMasterTier1(master []byte, targetGen uint64, p Profile) ([]byte, error) {
	h := hashForProfile(p)
	var ctx [8]byte
	binary.BigEndian.PutUint64(ctx[:], targetGen)
	return HkdfExpandLabel(master, "master ratchet", ctx[:], h().Size(), h)
}

// RatchetMasterTier2 performs the periodic asymmetric re-KEM step of the master
// ratchet (spec/10 section 9.2, Hybrid Tree Ratchet Tier 2):
//
//	rekem_secret = HKDF-Extract(salt = master_G, IKM = new_ss)
//	master_{G+1} = HKDF-Expand-Label(rekem_secret, "master ratchet rekem", TH_rekem, HashLen)
//
// new_ss is the 64-octet ML-KEM_SS || X25519_SS from a fresh X25519MLKEM768
// exchange (SharedSecrets.Combined()). The full wire label is
// "n-pamp master ratchet rekem". The old root sits in the salt position and the
// fresh secret in the IKM position (RFC 5869 section 2.2 / the Signal root-KDF
// placement), so master_{G+1} is uniform even if master_G is fully known to the
// attacker: without new_ss the attacker cannot compute master_{G+1}, and the
// direction self-heals (post-compromise security). TH_rekem binds the exact
// REKEM/REKEM_ACK exchange bytes into the new root, defeating splicing. The
// intermediate rekem_secret is wiped in place before return; the caller wipes
// master_G, new_ss, and the ephemeral KEM private keys.
func RatchetMasterTier2(master, newSS, thRekem []byte, p Profile) ([]byte, error) {
	h := hashForProfile(p)
	// HKDF-Extract(secret = IKM = new_ss, salt = master_G): the dual-PRF combiner
	// with the OLD root as a non-zero salt (unlike the handshake's zero salt).
	rekemSecret, err := hkdf.Extract(h, newSS, master)
	if err != nil {
		return nil, err
	}
	out, err := HkdfExpandLabel(rekemSecret, "master ratchet rekem", thRekem, h().Size(), h)
	for i := range rekemSecret {
		rekemSecret[i] = 0
	}
	return out, err
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
