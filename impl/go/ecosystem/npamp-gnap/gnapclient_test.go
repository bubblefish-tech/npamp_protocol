// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func clientTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(sigTestSeed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("priv.Public() did not return ed25519.PublicKey")
	}
	return pub, priv
}

func TestClientFieldEmitsHttpsigProofAndValidJWK(t *testing.T) {
	pub, priv := clientTestKeypair(t)
	c := NewClientInstance(priv, pub)
	cf, err := c.ClientField()
	if err != nil {
		t.Fatalf("ClientField: %v", err)
	}
	if cf.Key.Proof != "httpsig" {
		t.Fatalf("ClientField().Key.Proof = %q, want httpsig", cf.Key.Proof)
	}
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(cf.Key.JWK, &jwk); err != nil {
		t.Fatalf("json.Unmarshal(jwk): %v", err)
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		t.Fatalf("ClientField().Key.JWK decoded to %+v, want kty=OKP crv=Ed25519 x=non-empty", jwk)
	}
}

// TestClientFieldChangesWithKey is the A4 mutation-surviving test: the emitted JWK must
// actually depend on the client's public key.
func TestClientFieldChangesWithKey(t *testing.T) {
	pubA, privA := clientTestKeypair(t)
	pubB, privB, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	cfA, err := NewClientInstance(privA, pubA).ClientField()
	if err != nil {
		t.Fatalf("ClientField(A): %v", err)
	}
	cfB, err := NewClientInstance(privB, pubB).ClientField()
	if err != nil {
		t.Fatalf("ClientField(B): %v", err)
	}
	if string(cfA.Key.JWK) == string(cfB.Key.JWK) {
		t.Fatal("ClientField produced the same JWK for two different keys")
	}
}

func TestBuildGrantRequestOmitsUserWhenAssertionNil(t *testing.T) {
	pub, priv := clientTestKeypair(t)
	c := NewClientInstance(priv, pub)
	req, err := c.BuildGrantRequest([]AccessDescriptor{{Type: "npamp-relay"}}, nil)
	if err != nil {
		t.Fatalf("BuildGrantRequest: %v", err)
	}
	if req.User != nil {
		t.Fatalf("BuildGrantRequest(nil assertion).User = %+v, want nil", req.User)
	}
}

func TestBuildGrantRequestCarriesCallerSuppliedAssertionInUserAssertions(t *testing.T) {
	pub, priv := clientTestKeypair(t)
	c := NewClientInstance(priv, pub)
	assertion := &Assertion{Format: "example-format", Value: `{"claim":"value"}`}
	req, err := c.BuildGrantRequest([]AccessDescriptor{{Type: "npamp-relay"}}, assertion)
	if err != nil {
		t.Fatalf("BuildGrantRequest: %v", err)
	}
	if req.Subject != nil {
		t.Fatalf("BuildGrantRequest set req.Subject = %+v, want nil (assertions go in user.assertions per RFC 9635 §2.4, not subject.assertion_formats per §2.2)", req.Subject)
	}
	if req.User == nil || len(req.User.Assertions) != 1 || req.User.Assertions[0].Format != "example-format" {
		t.Fatalf("BuildGrantRequest().User = %+v, want one assertion with Format=example-format", req.User)
	}
}

func TestBuildGrantRequestRequestedAccessIsCarriedThrough(t *testing.T) {
	pub, priv := clientTestKeypair(t)
	c := NewClientInstance(priv, pub)
	req, err := c.BuildGrantRequest([]AccessDescriptor{{Type: "npamp-relay", Actions: []string{"connect"}}}, nil)
	if err != nil {
		t.Fatalf("BuildGrantRequest: %v", err)
	}
	if len(req.AccessToken.Access) != 1 || req.AccessToken.Access[0].Type != "npamp-relay" {
		t.Fatalf("BuildGrantRequest().AccessToken.Access = %+v, want one npamp-relay descriptor", req.AccessToken.Access)
	}
}
