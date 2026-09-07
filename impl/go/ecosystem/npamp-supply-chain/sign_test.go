// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"encoding/json"
	"testing"
)

// A fixed 32-byte seed for deterministic tests (arbitrary bytes — determinism, not
// secrecy, is what these tests need).
var testSeed = []byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

func TestSignStatementRoundTrips(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	signed, err := signer.SignStatement(statement)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("SignStatement returned no bytes")
	}
	if err := VerifyStatementSignature(signer.PublicKey(), signed, statement); err != nil {
		t.Fatalf("VerifyStatementSignature: %v", err)
	}
}

func TestSignStatementIsDeterministic(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1"}`)
	a, err := signer.SignStatement(statement)
	if err != nil {
		t.Fatalf("sign a: %v", err)
	}
	b, err := signer.SignStatement(statement)
	if err != nil {
		t.Fatalf("sign b: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("Ed25519 signing over the same payload with the same key produced different bytes — determinism is broken")
	}
}

// TestSignStatementChangesWithPayload is the A4 mutation-surviving test for SignStatement.
func TestSignStatementChangesWithPayload(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	a, err := signer.SignStatement([]byte("payload A"))
	if err != nil {
		t.Fatalf("sign a: %v", err)
	}
	b, err := signer.SignStatement([]byte("payload B"))
	if err != nil {
		t.Fatalf("sign b: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("two different payloads produced the same signed envelope — payload is being ignored")
	}
}

func TestVerifyStatementSignatureRejectsWrongKey(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	other, err := GenerateProvenanceSigner()
	if err != nil {
		t.Fatalf("GenerateProvenanceSigner: %v", err)
	}
	statement := []byte("some statement bytes")
	signed, err := signer.SignStatement(statement)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	if err := VerifyStatementSignature(other.PublicKey(), signed, statement); err == nil {
		t.Fatal("VerifyStatementSignature accepted a signature under the WRONG public key")
	}
}

func TestVerifyStatementSignatureRejectsPayloadMismatch(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	signed, err := signer.SignStatement([]byte("real statement"))
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	err = VerifyStatementSignature(signer.PublicKey(), signed, []byte("a DIFFERENT statement, same signer"))
	if err != ErrPayloadMismatch {
		t.Fatalf("error = %v, want ErrPayloadMismatch", err)
	}
}

func TestVerifyStatementSignatureRejectsTamperedSignature(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	statement := []byte("real statement")
	signed, err := signer.SignStatement(statement)
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	tampered := append([]byte(nil), signed...)
	// Flip the last byte before the closing brace/quote — inside the base64 "sig" value —
	// so the envelope still parses as valid JSON but the embedded signature no longer
	// verifies.
	for i := len(tampered) - 1; i >= 0; i-- {
		if tampered[i] >= 'a' && tampered[i] <= 'z' {
			tampered[i] ^= 0x20 // flip a letter's case — still ASCII, still valid JSON
			break
		}
	}
	if err := VerifyStatementSignature(signer.PublicKey(), tampered, statement); err == nil {
		t.Fatal("VerifyStatementSignature accepted a tampered DSSE envelope")
	}
}

func TestNewProvenanceSignerRejectsBadSeedSize(t *testing.T) {
	_, err := NewProvenanceSigner([]byte{1, 2, 3})
	if err != ErrSeedSize {
		t.Fatalf("error = %v, want ErrSeedSize", err)
	}
}

func TestGenerateProvenanceSignerProducesDistinctIdentities(t *testing.T) {
	a, err := GenerateProvenanceSigner()
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := GenerateProvenanceSigner()
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if string(a.PublicKey()) == string(b.PublicKey()) {
		t.Fatal("two independently generated signers produced the same public key")
	}
}

func TestVerifyEnvelopeRejectsStructurallyIncomplete(t *testing.T) {
	if err := VerifyEnvelope(make([]byte, 32), nil, nil); err != ErrEnvelopeInvalid {
		t.Fatalf("nil envelope: error = %v, want ErrEnvelopeInvalid", err)
	}
	if err := VerifyEnvelope(make([]byte, 32), &Envelope{}, nil); err != ErrEnvelopeInvalid {
		t.Fatalf("empty envelope: error = %v, want ErrEnvelopeInvalid", err)
	}
}

func TestVerifyEnvelopeRejectsWrongPayloadType(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	signed, err := signer.SignStatement([]byte("x"))
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.PayloadType = "application/json"
	if err := VerifyEnvelope(signer.PublicKey(), &env, []byte("x")); err != ErrPayloadTypeMismatch {
		t.Fatalf("error = %v, want ErrPayloadTypeMismatch", err)
	}
}

func TestVerifyEnvelopeRejectsBadPublicKeySize(t *testing.T) {
	signer, err := NewProvenanceSigner(testSeed)
	if err != nil {
		t.Fatalf("NewProvenanceSigner: %v", err)
	}
	signed, err := signer.SignStatement([]byte("x"))
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	if err := VerifyStatementSignature([]byte{1, 2, 3}, signed, []byte("x")); err != ErrSignatureInvalid {
		t.Fatalf("error = %v, want ErrSignatureInvalid (never a panic)", err)
	}
}
