// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

// SignedDiscoveryEnvelope carries an AgentDiscoveryDocument, the signer's self-asserted
// public key (as an OKP JWK), and a detached Ed25519 signature over the document's
// canonical JSON bytes. The self-asserted SignerJWK exists for legibility (so a reader of
// the raw JSON can see who claims to have signed it) — it is NEVER, by itself, a trust
// input: VerifyAgentDiscoveryDocument requires the caller to supply the authenticated
// N-PAMP signer key independently (e.g. from a completed CertVerify handshake,
// npamp.VerifyCertVerify) and rejects the envelope (ErrKeyMismatch) if SignerJWK does not
// byte-equal it — see doc.go and VerifyAgentDiscoveryDocument's doc comment.
type SignedDiscoveryEnvelope struct {
	Document  json.RawMessage `json:"document"`
	SignerJWK OKPJWK          `json:"signerJwk"`
	Signature string          `json:"signature"`
}

// SignAgentDiscoveryDocument marshals doc to its canonical JSON bytes, signs them with
// priv (crypto/ed25519.Sign — deterministic, RFC 8032: no randomizer input, so signing the
// same document twice with the same key produces byte-identical envelopes), and returns
// the resulting SignedDiscoveryEnvelope's canonical JSON.
func SignAgentDiscoveryDocument(doc *AgentDiscoveryDocument, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrKeySize
	}
	docBytes, err := MarshalAgentDiscoveryDocument(doc)
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		// Unreachable: ed25519.PrivateKey.Public() always returns ed25519.PublicKey. Kept
		// as an explicit, honest branch (fail-closed) rather than a blind type assertion.
		return nil, ErrKeySize
	}
	jwk, err := BuildOKPJWK(pub)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, docBytes)
	env := SignedDiscoveryEnvelope{
		Document:  docBytes,
		SignerJWK: jwk,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	return json.Marshal(env)
}

// VerifyAgentDiscoveryDocument parses envelopeJSON as a SignedDiscoveryEnvelope and
// returns the embedded AgentDiscoveryDocument only if ALL of the following hold, checked
// in this order:
//
//  1. The envelope is structurally complete (document, signerJwk, and signature all
//     present) — ErrEnvelopeInvalid otherwise.
//  2. The envelope's self-asserted SignerJWK decodes to a valid Ed25519 public key —
//     ErrPrivateKeyJWK / ErrUnsupportedKty / ErrUnsupportedCurve / ErrKeySize otherwise.
//  3. FAIL-CLOSED (the property this package exists to enforce): that self-asserted key
//     byte-equals authenticatedSignerPubKey, a key the caller obtained independently of
//     this envelope (e.g. from a completed N-PAMP CertVerify handshake) — ErrKeyMismatch
//     otherwise. A document is never trusted about who signed it; only an
//     independently-authenticated key is trusted.
//  4. The signature verifies under authenticatedSignerPubKey (not the self-asserted key —
//     step 3 already forces them to be equal when this step is reached, but verifying
//     against the caller-supplied key rather than the envelope's own field is the
//     defense-in-depth choice: even if step 3's equality check were ever weakened, this
//     step alone still refuses to trust an unauthenticated key) over the envelope's own
//     document bytes — ErrSignatureInvalid otherwise.
//  5. The embedded document parses and structurally validates
//     (ParseAgentDiscoveryDocument) — its own named errors otherwise.
//
// authenticatedSignerPubKey must be exactly ed25519.PublicKeySize bytes.
func VerifyAgentDiscoveryDocument(envelopeJSON []byte, authenticatedSignerPubKey ed25519.PublicKey) (*AgentDiscoveryDocument, error) {
	if len(authenticatedSignerPubKey) != ed25519.PublicKeySize {
		return nil, ErrKeySize
	}
	var env SignedDiscoveryEnvelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, ErrEnvelopeInvalid
	}
	if len(env.Document) == 0 || env.Signature == "" || env.SignerJWK.Kty == "" {
		return nil, ErrEnvelopeInvalid
	}
	claimedKey, err := ParseOKPJWK(env.SignerJWK)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(claimedKey, authenticatedSignerPubKey) {
		return nil, ErrKeyMismatch
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrSignatureInvalid
	}
	if !ed25519.Verify(authenticatedSignerPubKey, env.Document, sig) {
		return nil, ErrSignatureInvalid
	}
	return ParseAgentDiscoveryDocument(env.Document)
}
