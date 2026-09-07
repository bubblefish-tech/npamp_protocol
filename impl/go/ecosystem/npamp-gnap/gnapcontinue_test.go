// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import "testing"

func TestParseGrantResponseRejectsMalformedJSON(t *testing.T) {
	if _, err := ParseGrantResponse([]byte("not json")); err != ErrMalformedResponse {
		t.Fatalf("ParseGrantResponse(malformed) error = %v, want ErrMalformedResponse", err)
	}
}

func TestParseGrantResponseRejectsNeitherAccessTokenNorContinue(t *testing.T) {
	if _, err := ParseGrantResponse([]byte(`{"instance_id":"x"}`)); err != ErrMalformedResponse {
		t.Fatalf("ParseGrantResponse(no access_token/continue) error = %v, want ErrMalformedResponse", err)
	}
}

func TestParseGrantResponseSurfacesGrantError(t *testing.T) {
	r, err := ParseGrantResponse([]byte(`{"error":{"code":"invalid_request","description":"bad"}}`))
	if err != ErrGrantDenied {
		t.Fatalf("ParseGrantResponse(error) error = %v, want ErrGrantDenied", err)
	}
	if r == nil || r.Error == nil || r.Error.Code != "invalid_request" {
		t.Fatalf("ParseGrantResponse(error) response = %+v, want Error.Code=invalid_request", r)
	}
}

func TestParseGrantResponseAcceptsFinalAccessToken(t *testing.T) {
	r, err := ParseGrantResponse([]byte(`{"access_token":{"value":"tok-1"}}`))
	if err != nil {
		t.Fatalf("ParseGrantResponse: %v", err)
	}
	if r.AccessToken == nil || r.AccessToken.Value != "tok-1" {
		t.Fatalf("ParseGrantResponse().AccessToken = %+v, want value=tok-1", r.AccessToken)
	}
}

func TestNewPollerRejectsIncompleteContinue(t *testing.T) {
	if _, err := NewPoller(Continue{}); err != ErrContinuationMissing {
		t.Fatalf("NewPoller(empty) error = %v, want ErrContinuationMissing", err)
	}
	if _, err := NewPoller(Continue{URI: "https://as.example/continue"}); err != ErrContinuationMissing {
		t.Fatalf("NewPoller(no access token value) error = %v, want ErrContinuationMissing", err)
	}
}

func TestPollerNextRequestBuildsBearerAuthorizationAndBody(t *testing.T) {
	p, err := NewPoller(Continue{
		AccessToken: ContinueAccessToken{Value: "cont-tok"},
		URI:         "https://as.example/continue",
	})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	uri, auth, body, err := p.NextRequest("interact-ref-1")
	if err != nil {
		t.Fatalf("NextRequest: %v", err)
	}
	if uri != "https://as.example/continue" {
		t.Fatalf("NextRequest uri = %q, want https://as.example/continue", uri)
	}
	if auth != "GNAP cont-tok" {
		t.Fatalf("NextRequest authorization = %q, want %q", auth, "GNAP cont-tok")
	}
	if string(body) != `{"interact_ref":"interact-ref-1"}` {
		t.Fatalf("NextRequest body = %s, want interact_ref carried", body)
	}
}

func TestPollerAdvanceTerminatesOnFinalAccessToken(t *testing.T) {
	p, err := NewPoller(Continue{AccessToken: ContinueAccessToken{Value: "cont-tok"}, URI: "https://as.example/continue"})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	resp := &GrantResponse{AccessToken: &AccessTokenResponse{Value: "final-tok"}}
	if err := p.Advance(resp); err != nil {
		t.Fatalf("Advance(final access_token) = %v, want nil", err)
	}
}

func TestPollerAdvanceUpdatesContinuationState(t *testing.T) {
	p, err := NewPoller(Continue{AccessToken: ContinueAccessToken{Value: "cont-tok-1"}, URI: "https://as.example/continue"})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	resp := &GrantResponse{Continue: &Continue{AccessToken: ContinueAccessToken{Value: "cont-tok-2"}, URI: "https://as.example/continue2"}}
	if err := p.Advance(resp); err != nil {
		t.Fatalf("Advance(new continue): %v", err)
	}
	if p.Continue.AccessToken.Value != "cont-tok-2" || p.Continue.URI != "https://as.example/continue2" {
		t.Fatalf("Advance did not update continuation state: got %+v", p.Continue)
	}
}

// TestPollerAdvanceRejectsResponseWithNeitherAccessTokenNorContinue is the A4
// mutation-surviving check for the fail-closed "flow can neither proceed nor terminate"
// gate.
func TestPollerAdvanceRejectsResponseWithNeitherAccessTokenNorContinue(t *testing.T) {
	p, err := NewPoller(Continue{AccessToken: ContinueAccessToken{Value: "cont-tok"}, URI: "https://as.example/continue"})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if err := p.Advance(&GrantResponse{}); err != ErrContinuationMissing {
		t.Fatalf("Advance(empty response) = %v, want ErrContinuationMissing", err)
	}
}
