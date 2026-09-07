// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import (
	"encoding/json"
	"testing"
)

func TestEncodeGrantRequestRoundTrips(t *testing.T) {
	req := GrantRequest{
		AccessToken: AccessTokenRequest{Access: []AccessDescriptor{{Type: "npamp-relay"}}},
		Client:      ClientField{Key: Key{Proof: "httpsig", JWK: json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`)}},
	}
	b, err := EncodeGrantRequest(req)
	if err != nil {
		t.Fatalf("EncodeGrantRequest: %v", err)
	}
	var got GrantRequest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got.AccessToken.Access[0].Type != "npamp-relay" {
		t.Fatalf("round-tripped access_token.access[0].type = %q, want npamp-relay", got.AccessToken.Access[0].Type)
	}
	if got.Client.Key.Proof != "httpsig" {
		t.Fatalf("round-tripped client.key.proof = %q, want httpsig", got.Client.Key.Proof)
	}
}

func TestEncodeGrantRequestRejectsEmptyAccess(t *testing.T) {
	req := GrantRequest{
		Client: ClientField{Key: Key{Proof: "httpsig", JWK: json.RawMessage(`{}`)}},
	}
	if _, err := EncodeGrantRequest(req); err != ErrMalformedRequest {
		t.Fatalf("EncodeGrantRequest(no access) error = %v, want ErrMalformedRequest", err)
	}
}

// TestEncodeGrantRequestRejectsNonHttpsigProof is the A4 mutation-surviving check for the
// proof-method gate: this bridge implements exactly one proofing method and must refuse to
// emit a request claiming any other.
func TestEncodeGrantRequestRejectsNonHttpsigProof(t *testing.T) {
	req := GrantRequest{
		AccessToken: AccessTokenRequest{Access: []AccessDescriptor{{Type: "npamp-relay"}}},
		Client:      ClientField{Key: Key{Proof: "dpop", JWK: json.RawMessage(`{}`)}},
	}
	if _, err := EncodeGrantRequest(req); err != ErrMalformedRequest {
		t.Fatalf("EncodeGrantRequest(proof=dpop) error = %v, want ErrMalformedRequest", err)
	}
}

func TestGrantResponseUnmarshalsAccessToken(t *testing.T) {
	body := []byte(`{"access_token":{"value":"tok-1","access":[{"type":"npamp-relay"}]}}`)
	var r GrantResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if r.AccessToken == nil || r.AccessToken.Value != "tok-1" {
		t.Fatalf("unmarshaled access_token = %+v, want value=tok-1", r.AccessToken)
	}
}

func TestGrantResponseUnmarshalsContinue(t *testing.T) {
	body := []byte(`{"continue":{"access_token":{"value":"cont-tok"},"uri":"https://as.example/continue","wait":5}}`)
	var r GrantResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if r.Continue == nil || r.Continue.URI != "https://as.example/continue" || r.Continue.Wait != 5 {
		t.Fatalf("unmarshaled continue = %+v, want uri set and wait=5", r.Continue)
	}
}

func TestContinuationRequestMarshalsInteractRef(t *testing.T) {
	b, err := json.Marshal(ContinuationRequest{InteractRef: "ref-1"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(b) != `{"interact_ref":"ref-1"}` {
		t.Fatalf("Marshal(ContinuationRequest{InteractRef:ref-1}) = %s, want {\"interact_ref\":\"ref-1\"}", b)
	}
}
