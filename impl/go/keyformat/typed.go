// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package keyformat

import (
	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// EncodeKEMPrivate builds and encodes a versioned KEM private-key record for
// the named hybrid-KEM group (npamp.KEMX25519MLKEM768 or
// npamp.KEMSecP384r1MLKEM1024), storing the two component private keys in
// the fixed post-quantum-first Components order: mlkemSeed (the FIPS 203
// "d || z" seed crypto/mlkem's DecapsulationKey768/1024.Bytes() returns),
// then classicalPriv (the raw crypto/ecdh private-key bytes for X25519 or
// P-384, per group). This storage order is independent of the wire
// hybrid-KEM combiner order — see KeyRecord's doc comment.
func EncodeKEMPrivate(group npamp.KEMID, mlkemSeed, classicalPriv []byte) ([]byte, error) {
	return Encode(KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleKEMPrivate,
		Algorithm:     uint64(group),
		Components:    [][]byte{mlkemSeed, classicalPriv},
	})
}

// EncodeKEMPublic builds and encodes a versioned KEM public-key record for
// the named hybrid-KEM group, storing the two component public keys
// post-quantum-first: mlkemEncap (the crypto/mlkem encapsulation-key bytes),
// then classicalPub (the raw crypto/ecdh public-key bytes for X25519 or
// P-384, per group).
func EncodeKEMPublic(group npamp.KEMID, mlkemEncap, classicalPub []byte) ([]byte, error) {
	return Encode(KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleKEMPublic,
		Algorithm:     uint64(group),
		Components:    [][]byte{mlkemEncap, classicalPub},
	})
}

// DecodeKEMPrivate decodes a KEM private-key record, requiring rec.Role ==
// RoleKEMPrivate (ErrRoleMismatch otherwise), and returns the negotiated
// group and the two component private keys in the same post-quantum-first
// order EncodeKEMPrivate wrote them.
func DecodeKEMPrivate(data []byte, acceptedGenerations ...string) (group npamp.KEMID, mlkemSeed, classicalPriv []byte, err error) {
	rec, err := Decode(data, acceptedGenerations...)
	if err != nil {
		return 0, nil, nil, err
	}
	if rec.Role != RoleKEMPrivate {
		return 0, nil, nil, ErrRoleMismatch
	}
	if len(rec.Components) != 2 {
		return 0, nil, nil, ErrComponentCount
	}
	return npamp.KEMID(rec.Algorithm), rec.Components[0], rec.Components[1], nil
}

// DecodeKEMPublic decodes a KEM public-key record, requiring rec.Role ==
// RoleKEMPublic (ErrRoleMismatch otherwise), and returns the negotiated
// group and the two component public keys in the same post-quantum-first
// order EncodeKEMPublic wrote them.
func DecodeKEMPublic(data []byte, acceptedGenerations ...string) (group npamp.KEMID, mlkemEncap, classicalPub []byte, err error) {
	rec, err := Decode(data, acceptedGenerations...)
	if err != nil {
		return 0, nil, nil, err
	}
	if rec.Role != RoleKEMPublic {
		return 0, nil, nil, ErrRoleMismatch
	}
	if len(rec.Components) != 2 {
		return 0, nil, nil, ErrComponentCount
	}
	return npamp.KEMID(rec.Algorithm), rec.Components[0], rec.Components[1], nil
}

// EncodeSigPrivate builds and encodes a versioned signature private-key
// record for the named algorithm (npamp.SigEd25519, or one of the ML-DSA
// code points), storing raw as its single key-material component. For
// npamp.SigEd25519, raw is the crypto/ed25519.PrivateKey encoding (64
// octets, seed || public key). For an ML-DSA code point, raw is the FIPS 204
// private-key encoding; this package validates only its length (see
// keyformat.go's registry doc comment — no Go stdlib ML-DSA type exists yet
// to construct or verify one from).
func EncodeSigPrivate(alg npamp.SigID, raw []byte) ([]byte, error) {
	return Encode(KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleSigPrivate,
		Algorithm:     uint64(alg),
		Components:    [][]byte{raw},
	})
}

// EncodeSigPublic builds and encodes a versioned signature public-key
// record for the named algorithm, storing raw as its single key-material
// component (a crypto/ed25519.PublicKey encoding for npamp.SigEd25519, or a
// FIPS 204 public-key encoding for an ML-DSA code point).
func EncodeSigPublic(alg npamp.SigID, raw []byte) ([]byte, error) {
	return Encode(KeyRecord{
		FormatVersion: CurrentFormatVersion,
		Generation:    npamp.ALPN,
		Role:          RoleSigPublic,
		Algorithm:     uint64(alg),
		Components:    [][]byte{raw},
	})
}

// DecodeSigPrivate decodes a signature private-key record, requiring
// rec.Role == RoleSigPrivate (ErrRoleMismatch otherwise), and returns the
// algorithm and its raw key-material bytes.
func DecodeSigPrivate(data []byte, acceptedGenerations ...string) (alg npamp.SigID, raw []byte, err error) {
	rec, err := Decode(data, acceptedGenerations...)
	if err != nil {
		return 0, nil, err
	}
	if rec.Role != RoleSigPrivate {
		return 0, nil, ErrRoleMismatch
	}
	if len(rec.Components) != 1 {
		return 0, nil, ErrComponentCount
	}
	return npamp.SigID(rec.Algorithm), rec.Components[0], nil
}

// DecodeSigPublic decodes a signature public-key record, requiring rec.Role
// == RoleSigPublic (ErrRoleMismatch otherwise), and returns the algorithm
// and its raw key-material bytes.
func DecodeSigPublic(data []byte, acceptedGenerations ...string) (alg npamp.SigID, raw []byte, err error) {
	rec, err := Decode(data, acceptedGenerations...)
	if err != nil {
		return 0, nil, err
	}
	if rec.Role != RoleSigPublic {
		return 0, nil, ErrRoleMismatch
	}
	if len(rec.Components) != 1 {
		return 0, nil, ErrComponentCount
	}
	return npamp.SigID(rec.Algorithm), rec.Components[0], nil
}
