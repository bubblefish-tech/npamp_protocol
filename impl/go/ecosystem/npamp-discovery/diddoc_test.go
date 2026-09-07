// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import "testing"

func TestBuildDIDWebDocumentRoundTrips(t *testing.T) {
	pub, _ := testKeypair(t)
	doc, err := BuildDIDWebDocument("agent.npamp.invalid", pub)
	if err != nil {
		t.Fatalf("BuildDIDWebDocument: %v", err)
	}
	if doc.ID != "did:web:agent.npamp.invalid" {
		t.Fatalf("doc.ID = %q, want did:web:agent.npamp.invalid", doc.ID)
	}
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("len(VerificationMethod) = %d, want 1", len(doc.VerificationMethod))
	}
	raw, err := MarshalDIDDocument(doc)
	if err != nil {
		t.Fatalf("MarshalDIDDocument: %v", err)
	}
	got, err := ParseDIDDocument(raw)
	if err != nil {
		t.Fatalf("ParseDIDDocument: %v", err)
	}
	key, err := VerificationKey(got, got.VerificationMethod[0].ID)
	if err != nil {
		t.Fatalf("VerificationKey: %v", err)
	}
	if !key.Equal(pub) {
		t.Fatal("round-tripped verification key does not equal original")
	}
}

func TestBuildDIDWebDocumentRejectsEmptyDomain(t *testing.T) {
	pub, _ := testKeypair(t)
	if _, err := BuildDIDWebDocument("", pub); err != ErrEmptyDIDID {
		t.Fatalf("BuildDIDWebDocument(\"\") error = %v, want ErrEmptyDIDID", err)
	}
}

func TestBuildDIDWebDocumentRejectsBadKey(t *testing.T) {
	if _, err := BuildDIDWebDocument("agent.npamp.invalid", make([]byte, 4)); err != ErrKeySize {
		t.Fatalf("BuildDIDWebDocument(bad key) error = %v, want ErrKeySize", err)
	}
}

// TestBuildDIDWebDocumentChangesWithDomain is the A4 mutation-surviving test: the
// document's id must actually depend on the domain argument.
func TestBuildDIDWebDocumentChangesWithDomain(t *testing.T) {
	pub, _ := testKeypair(t)
	docA, err := BuildDIDWebDocument("a.npamp.invalid", pub)
	if err != nil {
		t.Fatalf("BuildDIDWebDocument(a): %v", err)
	}
	docB, err := BuildDIDWebDocument("b.npamp.invalid", pub)
	if err != nil {
		t.Fatalf("BuildDIDWebDocument(b): %v", err)
	}
	if docA.ID == docB.ID {
		t.Fatal("BuildDIDWebDocument produced the same id for two different domains")
	}
}

func TestParseDIDDocumentRejectsMissingID(t *testing.T) {
	if _, err := ParseDIDDocument([]byte(`{"@context":["https://www.w3.org/ns/did/v1"],"verificationMethod":[]}`)); err != ErrMalformedDIDDocument {
		t.Fatalf("ParseDIDDocument(no id) error = %v, want ErrMalformedDIDDocument", err)
	}
}

func TestParseDIDDocumentRejectsNoVerificationMethods(t *testing.T) {
	if _, err := ParseDIDDocument([]byte(`{"id":"did:web:x.invalid","verificationMethod":[]}`)); err != ErrMalformedDIDDocument {
		t.Fatalf("ParseDIDDocument(no vm) error = %v, want ErrMalformedDIDDocument", err)
	}
}

func TestParseDIDDocumentRejectsWrongVerificationMethodType(t *testing.T) {
	raw := []byte(`{"id":"did:web:x.invalid","verificationMethod":[{"id":"did:web:x.invalid#key-1","type":"Ed25519VerificationKey2020","controller":"did:web:x.invalid","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"AAAA"}}]}`)
	if _, err := ParseDIDDocument(raw); err != ErrUnsupportedVerificationMethodType {
		t.Fatalf("ParseDIDDocument(wrong vm type) error = %v, want ErrUnsupportedVerificationMethodType", err)
	}
}

func TestParseDIDDocumentRejectsMalformedJSON(t *testing.T) {
	if _, err := ParseDIDDocument([]byte(`not json`)); err != ErrMalformedDIDDocument {
		t.Fatalf("ParseDIDDocument(bad json) error = %v, want ErrMalformedDIDDocument", err)
	}
}

func TestVerificationKeyNotFound(t *testing.T) {
	pub, _ := testKeypair(t)
	doc, err := BuildDIDWebDocument("agent.npamp.invalid", pub)
	if err != nil {
		t.Fatalf("BuildDIDWebDocument: %v", err)
	}
	if _, err := VerificationKey(doc, "did:web:agent.npamp.invalid#no-such-key"); err != ErrVerificationMethodNotFound {
		t.Fatalf("VerificationKey(missing) error = %v, want ErrVerificationMethodNotFound", err)
	}
}

func TestDIDWebURLNoPath(t *testing.T) {
	got, err := DIDWebURL("did:web:agent.npamp.invalid")
	if err != nil {
		t.Fatalf("DIDWebURL: %v", err)
	}
	want := "https://agent.npamp.invalid/.well-known/did.json"
	if got != want {
		t.Fatalf("DIDWebURL = %q, want %q", got, want)
	}
}

func TestDIDWebURLWithPath(t *testing.T) {
	got, err := DIDWebURL("did:web:agent.npamp.invalid:agents:alice")
	if err != nil {
		t.Fatalf("DIDWebURL: %v", err)
	}
	want := "https://agent.npamp.invalid/agents/alice/did.json"
	if got != want {
		t.Fatalf("DIDWebURL = %q, want %q", got, want)
	}
}

func TestDIDWebURLRejectsBadPrefix(t *testing.T) {
	if _, err := DIDWebURL("did:jwk:xyz"); err != ErrBadDIDPrefix {
		t.Fatalf("DIDWebURL(did:jwk:...) error = %v, want ErrBadDIDPrefix", err)
	}
}

func TestDIDWebURLRejectsEmptyDomain(t *testing.T) {
	if _, err := DIDWebURL("did:web:"); err != ErrEmptyDIDID {
		t.Fatalf("DIDWebURL(did:web:) error = %v, want ErrEmptyDIDID", err)
	}
}

// TestDIDWebURLChangesWithPathSegments is the A4 mutation-surviving test: the resolved
// URL must actually depend on the path segments, not just the domain.
func TestDIDWebURLChangesWithPathSegments(t *testing.T) {
	a, err := DIDWebURL("did:web:agent.npamp.invalid:alice")
	if err != nil {
		t.Fatalf("DIDWebURL(alice): %v", err)
	}
	b, err := DIDWebURL("did:web:agent.npamp.invalid:bob")
	if err != nil {
		t.Fatalf("DIDWebURL(bob): %v", err)
	}
	if a == b {
		t.Fatal("DIDWebURL produced the same URL for two different path segments")
	}
}
