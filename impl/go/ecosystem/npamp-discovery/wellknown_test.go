// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildAgentDiscoveryDocumentRoundTrips(t *testing.T) {
	doc, err := BuildAgentDiscoveryDocument("test-agent", "a test agent", "npamp://agent.npamp.invalid:8443", "1.0.0", "did:web:agent.npamp.invalid", "did:web:agent.npamp.invalid#key-1")
	if err != nil {
		t.Fatalf("BuildAgentDiscoveryDocument: %v", err)
	}
	raw, err := MarshalAgentDiscoveryDocument(doc)
	if err != nil {
		t.Fatalf("MarshalAgentDiscoveryDocument: %v", err)
	}
	got, err := ParseAgentDiscoveryDocument(raw)
	if err != nil {
		t.Fatalf("ParseAgentDiscoveryDocument: %v", err)
	}
	if got.URL != doc.URL || got.DID != doc.DID {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, doc)
	}
}

func TestBuildAgentDiscoveryDocumentRejectsEmptyURL(t *testing.T) {
	if _, err := BuildAgentDiscoveryDocument("n", "d", "", "1", "did:web:x.invalid", "did:web:x.invalid#key-1"); err != ErrEmptyAgentURL {
		t.Fatalf("BuildAgentDiscoveryDocument(empty url) error = %v, want ErrEmptyAgentURL", err)
	}
}

func TestBuildAgentDiscoveryDocumentRejectsEmptyDID(t *testing.T) {
	if _, err := BuildAgentDiscoveryDocument("n", "d", "npamp://x.invalid", "1", "", "key-1"); err != ErrEmptyAgentDID {
		t.Fatalf("BuildAgentDiscoveryDocument(empty did) error = %v, want ErrEmptyAgentDID", err)
	}
}

// TestBuildAgentDiscoveryDocumentChangesWithURL is the A4 mutation-surviving test.
func TestBuildAgentDiscoveryDocumentChangesWithURL(t *testing.T) {
	a, err := BuildAgentDiscoveryDocument("n", "d", "npamp://a.invalid", "1", "did:web:x.invalid", "did:web:x.invalid#key-1")
	if err != nil {
		t.Fatalf("build a: %v", err)
	}
	b, err := BuildAgentDiscoveryDocument("n", "d", "npamp://b.invalid", "1", "did:web:x.invalid", "did:web:x.invalid#key-1")
	if err != nil {
		t.Fatalf("build b: %v", err)
	}
	if a.URL == b.URL {
		t.Fatal("BuildAgentDiscoveryDocument produced the same url for two different inputs")
	}
}

func TestParseAgentDiscoveryDocumentRejectsMissingFields(t *testing.T) {
	if _, err := ParseAgentDiscoveryDocument([]byte(`{"name":"x"}`)); err != ErrMalformedDiscoveryDocument {
		t.Fatalf("ParseAgentDiscoveryDocument(no url/did) error = %v, want ErrMalformedDiscoveryDocument", err)
	}
}

func TestResolveWellKnownAgentDocumentFetchesExpectedPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"document":"x"}`))
	}))
	defer srv.Close()

	client := srv.Client()
	// Rewrite the request to hit the test server's actual address rather than a literal
	// "https://" host this test does not control (srv is HTTP, not HTTPS) — use a
	// transport-level RoundTripper redirect instead of changing ResolveWellKnownAgentDocument's
	// own https:// construction, since that construction is exactly what the function is
	// meant to be tested against.
	client.Transport = redirectTransport{target: srv.URL}

	body, err := ResolveWellKnownAgentDocument(context.Background(), client, "agent.npamp.invalid")
	if err != nil {
		t.Fatalf("ResolveWellKnownAgentDocument: %v", err)
	}
	if !strings.Contains(string(body), "document") {
		t.Fatalf("unexpected body: %s", body)
	}
	wantPath := "/.well-known/" + WellKnownSuffix
	if gotPath != wantPath {
		t.Fatalf("fetched path = %q, want %q", gotPath, wantPath)
	}
}

func TestResolveWellKnownAgentDocumentRejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client := srv.Client()
	client.Transport = redirectTransport{target: srv.URL}

	if _, err := ResolveWellKnownAgentDocument(context.Background(), client, "agent.npamp.invalid"); err != ErrFetchFailed {
		t.Fatalf("ResolveWellKnownAgentDocument(404) error = %v, want ErrFetchFailed", err)
	}
}

func TestResolveWellKnownAgentDocumentRejectsOversized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxDiscoveryDocumentBytes+1))
	}))
	defer srv.Close()
	client := srv.Client()
	client.Transport = redirectTransport{target: srv.URL}

	if _, err := ResolveWellKnownAgentDocument(context.Background(), client, "agent.npamp.invalid"); err != ErrFetchFailed {
		t.Fatalf("ResolveWellKnownAgentDocument(oversized) error = %v, want ErrFetchFailed", err)
	}
}

func TestResolveDIDWebDocumentEndToEnd(t *testing.T) {
	pub, _ := testKeypair(t)
	doc, err := BuildDIDWebDocument("agent.npamp.invalid", pub)
	if err != nil {
		t.Fatalf("BuildDIDWebDocument: %v", err)
	}
	raw, err := MarshalDIDDocument(doc)
	if err != nil {
		t.Fatalf("MarshalDIDDocument: %v", err)
	}

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write(raw)
	}))
	defer srv.Close()
	client := srv.Client()
	client.Transport = redirectTransport{target: srv.URL}

	got, err := ResolveDIDWebDocument(context.Background(), client, "did:web:agent.npamp.invalid")
	if err != nil {
		t.Fatalf("ResolveDIDWebDocument: %v", err)
	}
	if got.ID != doc.ID {
		t.Fatalf("resolved doc.ID = %q, want %q", got.ID, doc.ID)
	}
	if gotPath != "/.well-known/did.json" {
		t.Fatalf("fetched path = %q, want /.well-known/did.json", gotPath)
	}
}

// redirectTransport rewrites every outbound request's scheme/host to target (an
// httptest.Server address), preserving the path/query the function under test computed —
// this is how these tests exercise ResolveWellKnownAgentDocument / ResolveDIDWebDocument's
// REAL "https://<domain>/..." URL construction against a local, non-TLS test server
// without needing a live network or a self-signed cert.
type redirectTransport struct {
	target string
}

func (rt redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := http.NewRequest(req.Method, rt.target+req.URL.Path, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(target.WithContext(req.Context()))
}
