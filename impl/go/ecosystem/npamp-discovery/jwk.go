// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// OKPJWK is an Octet Key Pair JSON Web Key representing an Ed25519 public key, per RFC
// 8037 ("CFRG ECDH and Signatures in JOSE") Appendix A.1's public-key-only shape:
// {"kty":"OKP","crv":"Ed25519","x":base64url(pubkey)}. D, if present, carries the RFC
// 8037 §2 private-key octets — this package rejects any JWK carrying it wherever a public
// verification key is expected (ErrPrivateKeyJWK).
type OKPJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"`
}

// BuildOKPJWK encodes an Ed25519 public key as an RFC 8037 OKP JWK. pubkey must be
// exactly ed25519.PublicKeySize (32) bytes (ErrKeySize otherwise) — checked before any
// encoding work.
func BuildOKPJWK(pubkey ed25519.PublicKey) (OKPJWK, error) {
	if len(pubkey) != ed25519.PublicKeySize {
		return OKPJWK{}, ErrKeySize
	}
	return OKPJWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pubkey),
	}, nil
}

// ParseOKPJWK decodes and validates an RFC 8037 OKP JWK, returning the Ed25519 public key
// it carries. Fail-closed: a private-key JWK (D present), a non-"OKP" kty, a non-"Ed25519"
// crv, an unparsable x, or an x whose decoded length is not ed25519.PublicKeySize is
// rejected whole with a named error — no partial result.
func ParseOKPJWK(jwk OKPJWK) (ed25519.PublicKey, error) {
	if jwk.D != "" {
		return nil, ErrPrivateKeyJWK
	}
	if jwk.Kty != "OKP" {
		return nil, ErrUnsupportedKty
	}
	if jwk.Crv != "Ed25519" {
		return nil, ErrUnsupportedCurve
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, ErrMalformedJWK
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, ErrKeySize
	}
	return ed25519.PublicKey(raw), nil
}

// ParseOKPJWKBytes is ParseOKPJWK for raw JSON bytes rather than an already-decoded
// OKPJWK value — used when a JWK arrives embedded in a larger document (e.g. a DID
// Document's verificationMethod.publicKeyJwk).
func ParseOKPJWKBytes(raw json.RawMessage) (ed25519.PublicKey, error) {
	if len(raw) == 0 {
		return nil, ErrMalformedJWK
	}
	var jwk OKPJWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, ErrMalformedJWK
	}
	return ParseOKPJWK(jwk)
}
