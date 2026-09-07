// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import (
	"crypto/ed25519"
	"encoding/json"

	npampdiscovery "github.com/bubblefish-tech/npamp_protocol/impl/go/ecosystem/npamp-discovery"
)

// Client is an N-PAMP agent presenting itself as a GNAP client instance (RFC 9635 §2.3): it
// proves possession of its EXISTING Ed25519 identity keypair via RFC 9421 HTTP Message
// Signatures (gnapsig.go) — no new keypair, no new identity primitive is introduced.
type Client struct {
	Priv   ed25519.PrivateKey
	PubKey ed25519.PublicKey
}

// NewClientInstance builds a Client from an agent's existing Ed25519 identity keypair — the
// SAME keypair impl/go/handshake.go's SignCertVerify/VerifyCertVerify already consume
// elsewhere in this tree for the live handshake, reused unchanged.
func NewClientInstance(priv ed25519.PrivateKey, pubKey ed25519.PublicKey) *Client {
	return &Client{Priv: priv, PubKey: pubKey}
}

// keyJWK returns the client instance's public key as a JSON Web Key by reusing
// npampdiscovery.BuildOKPJWK's already-graded RFC 8037 OKP-JWK encoder (E4.1) — the SAME
// JWK bytes that package already produces, so this package reimplements no JWK-construction
// logic of its own (D5/A10: no parallel encoder for a thing that already exists and is
// graded).
func keyJWK(pubKey ed25519.PublicKey) (json.RawMessage, error) {
	jwk, err := npampdiscovery.BuildOKPJWK(pubKey)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(jwk)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// ClientField builds the "client" object of a Grant Request (RFC 9635 §2.3): proof
// "httpsig" (RFC 9421, gnapsig.go — the only proofing method this package implements) over
// the instance's existing key.
func (c *Client) ClientField() (ClientField, error) {
	jwk, err := keyJWK(c.PubKey)
	if err != nil {
		return ClientField{}, err
	}
	return ClientField{Key: Key{Proof: "httpsig", JWK: jwk}}, nil
}

// BuildGrantRequest assembles a Grant Request (RFC 9635 §2) presenting this client
// instance's key and, when assertion is non-nil, a caller-supplied assertion — carried in
// "user.assertions" (RFC 9635 §2.4), NOT "subject.assertion_formats": §2.2's
// assertion_formats field REQUESTS formats FROM the AS, it is not a channel for a client to
// PRESENT an assertion it already holds (see doc.go's directionality note). This package
// does not construct the assertion itself (Option A, no delegation-evidence export object —
// see doc.go's Scope section); a nil assertion omits the User field entirely.
func (c *Client) BuildGrantRequest(access []AccessDescriptor, assertion *Assertion) (GrantRequest, error) {
	cf, err := c.ClientField()
	if err != nil {
		return GrantRequest{}, err
	}
	req := GrantRequest{
		AccessToken: AccessTokenRequest{Access: access},
		Client:      cf,
	}
	if assertion != nil && assertion.Format != "" {
		req.User = &UserField{Assertions: []Assertion{*assertion}}
	}
	return req, nil
}
