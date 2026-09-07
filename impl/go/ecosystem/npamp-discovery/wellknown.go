// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampdiscovery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// WellKnownSuffix is the well-known URI suffix this package serves an
// AgentDiscoveryDocument at, per RFC 8615 §3's "/.well-known/<suffix>" convention. It is
// NOT IANA-registered as of this session — see doc.go's "Grounding" section.
const WellKnownSuffix = "npamp-agent.json"

// maxDiscoveryDocumentBytes caps a fetched well-known document's size before it is even
// parsed, so a resolver can never be made to buffer an unbounded response
// (fail-closed: ErrFetchFailed, not a panic or an OOM, on an oversized response).
const maxDiscoveryDocumentBytes = 1 << 20 // 1 MiB

// AgentDiscoveryDocument is the payload this package's well-known document carries.
// protocolVersion/name/description/url/version borrow the Agent2Agent (A2A) AgentCard's
// current field-naming convention (see doc.go's grounding note); did and
// verificationMethodID are N-PAMP-specific, binding the advertised endpoint to a DID
// Document verification method an independent resolver can fetch and check the signer
// against (see envelope.go).
type AgentDiscoveryDocument struct {
	ProtocolVersion      string `json:"protocolVersion"`
	Name                 string `json:"name"`
	Description          string `json:"description,omitempty"`
	URL                  string `json:"url"`
	Version              string `json:"version,omitempty"`
	DID                  string `json:"did"`
	VerificationMethodID string `json:"verificationMethodId"`
}

// BuildAgentDiscoveryDocument constructs an AgentDiscoveryDocument. url and did must be
// non-empty (ErrEmptyAgentURL / ErrEmptyAgentDID) — a discovery document that advertises
// no reachable endpoint, or that is not bound to a DID, asserts nothing this package
// exists to assert.
func BuildAgentDiscoveryDocument(name, description, agentURL, version, did, verificationMethodID string) (*AgentDiscoveryDocument, error) {
	if agentURL == "" {
		return nil, ErrEmptyAgentURL
	}
	if did == "" {
		return nil, ErrEmptyAgentDID
	}
	return &AgentDiscoveryDocument{
		ProtocolVersion:      "npamp-discovery/1",
		Name:                 name,
		Description:          description,
		URL:                  agentURL,
		Version:              version,
		DID:                  did,
		VerificationMethodID: verificationMethodID,
	}, nil
}

// MarshalAgentDiscoveryDocument returns doc's canonical JSON bytes (deterministic —
// encoding/json marshals struct fields in fixed declared order).
func MarshalAgentDiscoveryDocument(doc *AgentDiscoveryDocument) ([]byte, error) {
	return json.Marshal(doc)
}

// ParseAgentDiscoveryDocument decodes and structurally validates a raw
// AgentDiscoveryDocument. Fail-closed: a document missing url or did is rejected whole
// (ErrMalformedDiscoveryDocument) before any field is trusted.
func ParseAgentDiscoveryDocument(raw []byte) (*AgentDiscoveryDocument, error) {
	var doc AgentDiscoveryDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, ErrMalformedDiscoveryDocument
	}
	if doc.URL == "" || doc.DID == "" {
		return nil, ErrMalformedDiscoveryDocument
	}
	return &doc, nil
}

// httpGetter is the subset of *http.Client this package's resolvers depend on, so tests
// can substitute an httptest.Server-backed client without any network access, and a
// caller can inject a client with its own timeout/proxy/TLS policy.
type httpGetter interface {
	Do(req *http.Request) (*http.Response, error)
}

// fetchCapped performs an HTTP GET against url using client, enforcing a 2xx status and
// the maxDiscoveryDocumentBytes cap. It is the single fetch primitive both
// ResolveWellKnownAgentDocument and ResolveDIDWebDocument build on.
func fetchCapped(ctx context.Context, client httpGetter, targetURL string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, ErrFetchFailed
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ErrFetchFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrFetchFailed
	}
	limited := io.LimitReader(resp.Body, maxDiscoveryDocumentBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, ErrFetchFailed
	}
	if len(body) > maxDiscoveryDocumentBytes {
		return nil, ErrFetchFailed
	}
	return body, nil
}

// ResolveWellKnownAgentDocument fetches "https://<domain>/.well-known/npamp-agent.json"
// (WellKnownSuffix, RFC 8615 §3) and returns the raw bytes. It deliberately returns raw
// bytes rather than an already-verified AgentDiscoveryDocument: callers MUST run
// VerifyAgentDiscoveryDocument (envelope.go) against an independently-authenticated
// signer key before trusting anything the fetched document claims about itself — a
// resolver that returned a trusted-looking value here would invite exactly the
// self-assertion trust bug this package exists to prevent (see doc.go / envelope.go).
func ResolveWellKnownAgentDocument(ctx context.Context, client httpGetter, domain string) ([]byte, error) {
	if domain == "" {
		return nil, ErrFetchFailed
	}
	return fetchCapped(ctx, client, "https://"+domain+"/.well-known/"+WellKnownSuffix)
}

// ResolveDIDWebDocument computes did's did:web URL (DIDWebURL) and fetches it, returning
// the parsed and structurally-validated *DIDDocument (ParseDIDDocument runs on the fetched
// bytes before this function returns — a DID Document that fails DID Core structural
// validation is never handed back to the caller).
func ResolveDIDWebDocument(ctx context.Context, client httpGetter, did string) (*DIDDocument, error) {
	targetURL, err := DIDWebURL(did)
	if err != nil {
		return nil, err
	}
	body, err := fetchCapped(ctx, client, targetURL)
	if err != nil {
		return nil, err
	}
	return ParseDIDDocument(body)
}
