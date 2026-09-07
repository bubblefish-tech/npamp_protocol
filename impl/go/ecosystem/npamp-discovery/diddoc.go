// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import (
	"crypto/ed25519"
	"encoding/json"
	"net/url"
	"strings"
)

// DIDCoreContext is the JSON-LD context DID Core §5.1 requires every conforming DID
// Document to declare (https://www.w3.org/TR/did-1.0/, "@context").
const DIDCoreContext = "https://www.w3.org/ns/did/v1"

// VerificationMethodType is the only verification method type this package emits and
// consumes: "JsonWebKey2020", DID Core §5.2's RFC-7517-anchored publicKeyJwk path (see
// doc.go for why this was chosen over publicKeyMultibase/Multikey).
const VerificationMethodType = "JsonWebKey2020"

// VerificationMethod is a DID Core §5.2 verification method map, restricted to this
// package's supported shape (type "JsonWebKey2020", verification material in
// publicKeyJwk). id, type, controller, and publicKeyJwk are all DID-Core-required for
// this type.
type VerificationMethod struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyJWK OKPJWK `json:"publicKeyJwk"`
}

// DIDDocument is a DID Core §4/§5 DID Document, restricted to the fields this package
// builds and consumes: the required @context and id, one verification method carrying
// the subject's Ed25519 key, and authentication/assertionMethod references to it (DID
// Core §5.3/§5.4 — "MAY reference a verification method" by embedding the DID URL id
// rather than repeating the method inline, which is what this package does).
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
}

// BuildDIDWebDocument builds a did:web DID Document (DID Core §4/§5, did:web method
// "Create" — see doc.go) binding domain to pubkey. domain must be non-empty (ErrEmptyDIDID)
// and pubkey must be exactly ed25519.PublicKeySize bytes (ErrKeySize) — both checked
// before any document is constructed. The single verification method's id is
// "<did>#key-1" and is referenced by both authentication and assertionMethod, matching
// how a self-controlled identity (the same key that IS the subject also authenticates and
// asserts as the subject) is conventionally expressed.
func BuildDIDWebDocument(domain string, pubkey ed25519.PublicKey) (*DIDDocument, error) {
	if domain == "" {
		return nil, ErrEmptyDIDID
	}
	jwk, err := BuildOKPJWK(pubkey)
	if err != nil {
		return nil, err
	}
	did := "did:web:" + domain
	vmID := did + "#key-1"
	return &DIDDocument{
		Context: []string{DIDCoreContext},
		ID:      did,
		VerificationMethod: []VerificationMethod{{
			ID:           vmID,
			Type:         VerificationMethodType,
			Controller:   did,
			PublicKeyJWK: jwk,
		}},
		Authentication:  []string{vmID},
		AssertionMethod: []string{vmID},
	}, nil
}

// MarshalDIDDocument returns the DID Document's canonical JSON bytes (encoding/json
// marshals struct fields in fixed declared field order, so this is deterministic for a
// given DIDDocument value — see envelope.go's determinism test for the same reliance).
func MarshalDIDDocument(doc *DIDDocument) ([]byte, error) {
	return json.Marshal(doc)
}

// ParseDIDDocument decodes and structurally validates a DID Document. Fail-closed: a
// document missing id, carrying zero verification methods, or carrying a verification
// method missing id/type/controller/publicKeyJwk, or whose type is not
// VerificationMethodType, or whose embedded JWK does not decode to a valid Ed25519 public
// key, is rejected whole with a named error — no partial result. It does not require
// @context/authentication/assertionMethod to be present (DID Core makes @context
// RECOMMENDED, not required for internal representations, and authentication/
// assertionMethod are optional per-relationship references), matching DID Core's own
// minimality.
func ParseDIDDocument(raw []byte) (*DIDDocument, error) {
	var doc DIDDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, ErrMalformedDIDDocument
	}
	if doc.ID == "" || len(doc.VerificationMethod) == 0 {
		return nil, ErrMalformedDIDDocument
	}
	for _, vm := range doc.VerificationMethod {
		if vm.ID == "" || vm.Type == "" || vm.Controller == "" {
			return nil, ErrMalformedDIDDocument
		}
		if vm.Type != VerificationMethodType {
			return nil, ErrUnsupportedVerificationMethodType
		}
		if _, err := ParseOKPJWK(vm.PublicKeyJWK); err != nil {
			return nil, err
		}
	}
	return &doc, nil
}

// VerificationKey looks up vmID in doc's verification methods and returns the Ed25519
// public key it carries. ErrVerificationMethodNotFound if vmID is not present (the
// document was already structurally validated by ParseDIDDocument or BuildDIDWebDocument,
// so the embedded JWK is re-parsed here rather than re-validated from scratch, but the
// re-parse itself still fails closed on a malformed key — defense in depth, not a trust
// assumption on the caller having called ParseDIDDocument first).
func VerificationKey(doc *DIDDocument, vmID string) (ed25519.PublicKey, error) {
	if doc == nil {
		return nil, ErrVerificationMethodNotFound
	}
	for _, vm := range doc.VerificationMethod {
		if vm.ID == vmID {
			if vm.Type != VerificationMethodType {
				return nil, ErrUnsupportedVerificationMethodType
			}
			return ParseOKPJWK(vm.PublicKeyJWK)
		}
	}
	return nil, ErrVerificationMethodNotFound
}

// DIDWebURL implements the did:web method's "Read (Resolve)" transform (see doc.go): a
// did:web identifier, without a path component, resolves to
// "https://<domain>/.well-known/did.json"; with one or more ":"-separated path segments
// after the domain, each segment is percent-decoded and joined with "/", and it resolves
// to "https://<domain>/<segments>/did.json" (no "/.well-known/" — the did:web method spec
// reserves that form for the no-path case only). did must start with "did:web:"
// (ErrBadDIDPrefix) and the domain segment must not be empty (ErrEmptyDIDID).
func DIDWebURL(did string) (string, error) {
	const prefix = "did:web:"
	if !strings.HasPrefix(did, prefix) {
		return "", ErrBadDIDPrefix
	}
	rest := strings.TrimPrefix(did, prefix)
	if rest == "" {
		return "", ErrEmptyDIDID
	}
	parts := strings.Split(rest, ":")
	for i, p := range parts {
		if p == "" {
			return "", ErrEmptyDIDID
		}
		decoded, err := url.PathUnescape(p)
		if err != nil {
			return "", ErrMalformedDIDDocument
		}
		parts[i] = decoded
	}
	domain := parts[0]
	if len(parts) == 1 {
		return "https://" + domain + "/.well-known/did.json", nil
	}
	return "https://" + strings.Join(parts, "/") + "/did.json", nil
}
