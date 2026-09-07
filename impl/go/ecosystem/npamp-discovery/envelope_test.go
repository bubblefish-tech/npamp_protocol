// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import (
	"crypto/ed25519"
	"testing"
)

func testDiscoveryDoc(t *testing.T, did string) *AgentDiscoveryDocument {
	t.Helper()
	doc, err := BuildAgentDiscoveryDocument("test-agent", "a test agent", "npamp://agent.npamp.invalid:8443", "1.0.0", did, did+"#key-1")
	if err != nil {
		t.Fatalf("BuildAgentDiscoveryDocument: %v", err)
	}
	return doc
}

func TestSignAndVerifyAgentDiscoveryDocumentRoundTrips(t *testing.T) {
	pub, priv := testKeypair(t)
	doc := testDiscoveryDoc(t, "did:web:agent.npamp.invalid")
	env, err := SignAgentDiscoveryDocument(doc, priv)
	if err != nil {
		t.Fatalf("SignAgentDiscoveryDocument: %v", err)
	}
	got, err := VerifyAgentDiscoveryDocument(env, pub)
	if err != nil {
		t.Fatalf("VerifyAgentDiscoveryDocument: %v", err)
	}
	if got.URL != doc.URL || got.DID != doc.DID {
		t.Fatalf("verified doc mismatch: got %+v want %+v", got, doc)
	}
}

func TestSignAgentDiscoveryDocumentIsDeterministic(t *testing.T) {
	_, priv := testKeypair(t)
	doc := testDiscoveryDoc(t, "did:web:agent.npamp.invalid")
	a, err := SignAgentDiscoveryDocument(doc, priv)
	if err != nil {
		t.Fatalf("sign a: %v", err)
	}
	b, err := SignAgentDiscoveryDocument(doc, priv)
	if err != nil {
		t.Fatalf("sign b: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("Ed25519 signing over the same document with the same key produced different envelope bytes")
	}
}

// TestVerifyAgentDiscoveryDocumentRejectsForgedSelfAssertedKey is the load-bearing
// fail-closed test: an envelope whose document+signature are internally self-consistent
// (signed by attacker's own key, self-asserted as attacker's own key) MUST still be
// rejected when the caller's independently-authenticated key is a DIFFERENT, legitimate
// signer's key. This is exactly the "never trust a key the document asserts about
// itself" property this package exists to enforce.
func TestVerifyAgentDiscoveryDocumentRejectsForgedSelfAssertedKey(t *testing.T) {
	legitimatePub, _ := testKeypair(t)
	attackerPub, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	doc := testDiscoveryDoc(t, "did:web:agent.npamp.invalid")
	env, err := SignAgentDiscoveryDocument(doc, attackerPriv)
	if err != nil {
		t.Fatalf("SignAgentDiscoveryDocument: %v", err)
	}
	// Sanity: the forged envelope verifies fine against the attacker's OWN key (it is a
	// well-formed, self-consistent envelope) — the rejection below is specifically about
	// the caller's authenticated key differing from what the document claims, not about
	// the envelope being malformed.
	if _, err := VerifyAgentDiscoveryDocument(env, attackerPub); err != nil {
		t.Fatalf("sanity check: envelope should verify against its own signer, got %v", err)
	}
	if _, err := VerifyAgentDiscoveryDocument(env, legitimatePub); err != ErrKeyMismatch {
		t.Fatalf("VerifyAgentDiscoveryDocument(forged, wrong authenticated key) error = %v, want ErrKeyMismatch", err)
	}
}

func TestVerifyAgentDiscoveryDocumentRejectsTamperedDocument(t *testing.T) {
	pub, priv := testKeypair(t)
	doc := testDiscoveryDoc(t, "did:web:agent.npamp.invalid")
	env, err := SignAgentDiscoveryDocument(doc, priv)
	if err != nil {
		t.Fatalf("SignAgentDiscoveryDocument: %v", err)
	}
	tampered := []byte(string(env))
	// Flip a byte inside the embedded "document" field's URL value without touching the
	// JSON structure enough to break parsing — this exercises the signature check, not
	// the JSON-decode error path.
	idx := indexOf(tampered, []byte("agent.npamp.invalid:8443"))
	if idx < 0 {
		t.Fatal("test setup: expected substring not found in envelope")
	}
	tampered[idx] = 'X'
	if _, err := VerifyAgentDiscoveryDocument(tampered, pub); err != ErrSignatureInvalid {
		t.Fatalf("VerifyAgentDiscoveryDocument(tampered) error = %v, want ErrSignatureInvalid", err)
	}
}

func TestVerifyAgentDiscoveryDocumentRejectsIncompleteEnvelope(t *testing.T) {
	pub, _ := testKeypair(t)
	if _, err := VerifyAgentDiscoveryDocument([]byte(`{"document":{}}`), pub); err != ErrEnvelopeInvalid {
		t.Fatalf("VerifyAgentDiscoveryDocument(incomplete) error = %v, want ErrEnvelopeInvalid", err)
	}
}

func TestVerifyAgentDiscoveryDocumentRejectsBadAuthenticatedKeySize(t *testing.T) {
	_, priv := testKeypair(t)
	doc := testDiscoveryDoc(t, "did:web:agent.npamp.invalid")
	env, err := SignAgentDiscoveryDocument(doc, priv)
	if err != nil {
		t.Fatalf("SignAgentDiscoveryDocument: %v", err)
	}
	if _, err := VerifyAgentDiscoveryDocument(env, make([]byte, 4)); err != ErrKeySize {
		t.Fatalf("VerifyAgentDiscoveryDocument(bad key size) error = %v, want ErrKeySize", err)
	}
}

// TestEndToEndDIDAndDiscoveryFlow demonstrates the whole package working together in
// isolation (A9): build a DID Document for an N-PAMP agent's Ed25519 key, build and sign
// an agent discovery document bound to that DID, and verify it against the
// (independently-authenticated, here simulated) signer key — the exact flow this
// package's E4 task exists to deliver.
func TestEndToEndDIDAndDiscoveryFlow(t *testing.T) {
	pub, priv := testKeypair(t)

	didDoc, err := BuildDIDWebDocument("agent.npamp.invalid", pub)
	if err != nil {
		t.Fatalf("BuildDIDWebDocument: %v", err)
	}

	discoveryDoc, err := BuildAgentDiscoveryDocument(
		"npamp-e2e-agent", "end-to-end test agent",
		"npamp://agent.npamp.invalid:8443",
		"1.0.0",
		didDoc.ID, didDoc.VerificationMethod[0].ID,
	)
	if err != nil {
		t.Fatalf("BuildAgentDiscoveryDocument: %v", err)
	}

	envelope, err := SignAgentDiscoveryDocument(discoveryDoc, priv)
	if err != nil {
		t.Fatalf("SignAgentDiscoveryDocument: %v", err)
	}

	// A relying party independently authenticates pub (e.g. via a completed N-PAMP
	// CertVerify handshake, npamp.VerifyCertVerify) and only THEN trusts the envelope.
	verified, err := VerifyAgentDiscoveryDocument(envelope, pub)
	if err != nil {
		t.Fatalf("VerifyAgentDiscoveryDocument: %v", err)
	}
	if verified.DID != didDoc.ID {
		t.Fatalf("verified.DID = %q, want %q", verified.DID, didDoc.ID)
	}

	// The relying party can also independently resolve the DID Document's verification
	// key and confirm it agrees with the authenticated signer.
	didKey, err := VerificationKey(didDoc, verified.VerificationMethodID)
	if err != nil {
		t.Fatalf("VerificationKey: %v", err)
	}
	if !didKey.Equal(pub) {
		t.Fatal("DID Document's verification key does not equal the authenticated signer")
	}
}

func indexOf(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
