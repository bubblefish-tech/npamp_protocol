// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import "errors"

// Named, fail-closed errors, in this repository's own ecosystem-package convention (see
// e.g. supplychain.ErrSeedSize — a plain errors.New sentinel, not a custom error struct
// type). Every rejection returns exactly one of these — no partial result, no silent
// fallback.
var (
	// ErrKeySize is returned when a public key's length does not match
	// ed25519.PublicKeySize.
	ErrKeySize = errors.New("npamp/discovery: public key length does not match Ed25519 (32 bytes)")

	// ErrMalformedJWK is returned when decoded bytes are not a well-formed JWK object, or
	// a required field is missing or not the expected JSON type.
	ErrMalformedJWK = errors.New("npamp/discovery: value is not a valid OKP JWK object")

	// ErrPrivateKeyJWK is returned when a decoded JWK carries private-key material ("d",
	// RFC 8037 §2). did-jwk/JOSE security guidance: a JWK carrying private material MUST
	// be rejected wherever only a public identifier is expected. Checked BEFORE any
	// public-key field is trusted.
	ErrPrivateKeyJWK = errors.New("npamp/discovery: a private-key JWK ('d' present) MUST NOT be used as a public verification key")

	// ErrUnsupportedKty is returned when a JWK's "kty" is not "OKP" — the only key type
	// this package (Ed25519-only, see doc.go) recognizes.
	ErrUnsupportedKty = errors.New("npamp/discovery: kty is not OKP")

	// ErrUnsupportedCurve is returned when an OKP JWK's "crv" is not "Ed25519".
	ErrUnsupportedCurve = errors.New("npamp/discovery: OKP crv is not Ed25519")

	// ErrBadDIDPrefix is returned when a string handed to a did:web parser does not start
	// with the "did:web:" method prefix.
	ErrBadDIDPrefix = errors.New("npamp/discovery: identifier does not start with did:web:")

	// ErrEmptyDIDID is returned when BuildDIDWebDocument is given an empty domain.
	ErrEmptyDIDID = errors.New("npamp/discovery: did:web domain must not be empty")

	// ErrMalformedDIDDocument is returned when a decoded DID Document is missing a
	// DID-Core-required field (id, or a non-empty verificationMethod set) or a
	// verification method is missing id/type/controller/publicKeyJwk.
	ErrMalformedDIDDocument = errors.New("npamp/discovery: DID Document is missing a DID-Core-required field")

	// ErrVerificationMethodNotFound is returned when the requested verification method id
	// is not present in the DID Document.
	ErrVerificationMethodNotFound = errors.New("npamp/discovery: verification method id not found in DID Document")

	// ErrUnsupportedVerificationMethodType is returned when a verification method's type
	// is not "JsonWebKey2020" (the only type this package emits and consumes; see doc.go).
	ErrUnsupportedVerificationMethodType = errors.New("npamp/discovery: verification method type is not JsonWebKey2020")

	// ErrEmptyAgentURL is returned by BuildAgentDiscoveryDocument when the agent's N-PAMP
	// endpoint URL is empty — a discovery document that advertises no reachable endpoint
	// asserts nothing.
	ErrEmptyAgentURL = errors.New("npamp/discovery: agent discovery document must carry a non-empty url")

	// ErrEmptyAgentDID is returned by BuildAgentDiscoveryDocument when the did field is
	// empty — a discovery document exists specifically to bind an endpoint to a DID.
	ErrEmptyAgentDID = errors.New("npamp/discovery: agent discovery document must carry a non-empty did")

	// ErrMalformedDiscoveryDocument is returned when a decoded AgentDiscoveryDocument is
	// missing a required field.
	ErrMalformedDiscoveryDocument = errors.New("npamp/discovery: agent discovery document is missing a required field")

	// ErrEnvelopeInvalid is returned when a SignedDiscoveryEnvelope is structurally
	// incomplete (missing document, signerJwk, or signature) before any signature check
	// runs.
	ErrEnvelopeInvalid = errors.New("npamp/discovery: signed discovery envelope is missing a required field")

	// ErrKeyMismatch is returned by VerifyAgentDiscoveryDocument when the envelope's
	// self-asserted signer key does not byte-equal the independently supplied,
	// authenticated N-PAMP signer key. This is the fail-closed check this package exists
	// to enforce: a document's claim about its own signer is NEVER trusted on its own —
	// see envelope.go.
	ErrKeyMismatch = errors.New("npamp/discovery: document's self-asserted signer key does not match the authenticated N-PAMP signer")

	// ErrSignatureInvalid is returned when the envelope's signature does not verify under
	// the authenticated signer key over the envelope's document bytes.
	ErrSignatureInvalid = errors.New("npamp/discovery: signature does not verify under the authenticated signer key")

	// ErrFetchFailed is returned by a resolver when the HTTP fetch itself fails (transport
	// error, non-2xx status, or a response exceeding the resolver's size cap).
	ErrFetchFailed = errors.New("npamp/discovery: fetch of the well-known document failed")
)
