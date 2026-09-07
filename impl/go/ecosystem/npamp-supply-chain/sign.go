// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

// ProvenanceSigner signs a provenance Statement inside a DSSE v1 envelope using
// crypto/ed25519 — the same stdlib signature primitive npamp.SignCertVerify /
// ed25519.Sign use for N-PAMP's own live CertVerify handshake message (npamp.SigEd25519 =
// 0x0807, "all profiles"; see certverify_kat_test.go and handshake.go's SignCertVerify).
// It does NOT construct an N-PAMP wire frame or reuse the CertVerify signing_input shape
// (spec/10 section 6.1's `0x20 x 64 || context || 0x00 || transcript_hash`), because a
// supply-chain provenance statement is not a handshake message and has no transcript hash
// to bind to — reusing that construction here would either require inventing a fake
// transcript (a protocol misuse) or silently mislabeling a generic attestation as an
// N-PAMP handshake artifact. crypto/ed25519.Sign directly, over the DSSE PAE encoding of
// the statement JSON (see dsse.go), is the correct, already-generic seam: it signs
// arbitrary message bytes with no frame/channel coupling, exactly the same underlying
// primitive npamp.SignCertVerify is a thin, protocol-specific wrapper over.
//
// This package does not use N-PAMP's SigMLDSA87 code point: see doc.go's "Why Ed25519, not
// ML-DSA" section — no Go stdlib ML-DSA type exists yet in this toolchain (documented
// honestly in impl/go/keyformat/keyformat.go), so Ed25519 is this Go reference's only
// signature primitive that actually runs end-to-end today.
type ProvenanceSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewProvenanceSigner derives a ProvenanceSigner from a 32-byte Ed25519 seed
// (ed25519.SeedSize). A seed of the wrong length is rejected (ErrSeedSize) before any key
// is created.
func NewProvenanceSigner(seed []byte) (*ProvenanceSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrSeedSize
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		// Unreachable: ed25519.PrivateKey.Public() always returns ed25519.PublicKey. Kept
		// as an explicit, honest branch (fail-closed) rather than a blind type assertion.
		return nil, ErrSeedSize
	}
	return &ProvenanceSigner{priv: priv, pub: pub}, nil
}

// GenerateProvenanceSigner creates a fresh Ed25519 identity from crypto/rand.
func GenerateProvenanceSigner() (*ProvenanceSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ProvenanceSigner{priv: priv, pub: pub}, nil
}

// PublicKey returns the raw 32-byte Ed25519 public-key bytes to hand to a verifier.
func (s *ProvenanceSigner) PublicKey() []byte {
	out := make([]byte, len(s.pub))
	copy(out, s.pub)
	return out
}

// SignStatement wraps statementJSON in a DSSE v1 envelope
// (https://github.com/secure-systems-lab/dsse), signing PAE(InTotoPayloadType,
// statementJSON) with this signer's Ed25519 key, and returns the envelope's canonical JSON
// bytes (encoding/json sorts struct field order deterministically — see sign_test.go's
// determinism test). Ed25519 signing is itself deterministic (RFC 8032: no randomizer
// input — signing the same message twice with the same key always produces the same
// signature bytes), so SignStatement(x) called twice produces byte-identical envelopes.
func (s *ProvenanceSigner) SignStatement(statementJSON []byte) ([]byte, error) {
	pae := PAE(InTotoPayloadType, statementJSON)
	sig := ed25519.Sign(s.priv, pae)
	env := Envelope{
		Payload:     base64.StdEncoding.EncodeToString(statementJSON),
		PayloadType: InTotoPayloadType,
		Signatures:  []Signature{{Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
	return json.Marshal(env)
}

// VerifyStatementSignature parses envelopeJSON as a DSSE v1 envelope and checks that: (1)
// it is structurally complete and carries the expected in-toto payloadType; (2) at least
// one of its signatures cryptographically verifies under pub over PAE(payloadType, the
// envelope's OWN embedded payload) — a check independent of what the caller expects the
// payload to be; and (3) the envelope's embedded payload is byte-identical to
// expectedStatementJSON (ErrPayloadMismatch otherwise). Checks run in that order
// deliberately: a structurally/cryptographically invalid envelope is rejected before the
// payload is even compared, because a signature can be cryptographically valid over SOME
// payload while still not being a signature over the statement the caller actually cares
// about — both checks are required.
func VerifyStatementSignature(pub []byte, envelopeJSON []byte, expectedStatementJSON []byte) error {
	var env Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return ErrEnvelopeInvalid
	}
	return VerifyEnvelope(pub, &env, expectedStatementJSON)
}

// VerifyEnvelope is VerifyStatementSignature's core, operating on an already-parsed
// *Envelope rather than raw JSON bytes (used directly by pipeline_test.go's round-trip
// assertions).
func VerifyEnvelope(pub []byte, env *Envelope, expectedPayload []byte) error {
	if env == nil || env.Payload == "" || env.PayloadType == "" || len(env.Signatures) == 0 {
		return ErrEnvelopeInvalid
	}
	if len(pub) != ed25519.PublicKeySize {
		// crypto/ed25519.Verify PANICS on a wrong-length public key; this fail-closed
		// check turns that into a named error instead of a runtime panic.
		return ErrSignatureInvalid
	}
	if env.PayloadType != InTotoPayloadType {
		return ErrPayloadTypeMismatch
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return ErrEnvelopeInvalid
	}

	pae := PAE(env.PayloadType, payload)
	pubKey := ed25519.PublicKey(pub)
	verified := false
	for _, sig := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil || len(raw) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pubKey, pae, raw) {
			verified = true
			break
		}
	}
	if !verified {
		return ErrSignatureInvalid
	}
	if !bytes.Equal(payload, expectedPayload) {
		return ErrPayloadMismatch
	}
	return nil
}
