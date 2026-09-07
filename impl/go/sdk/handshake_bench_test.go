// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// BenchmarkHandshakeLatency measures the end-to-end wall-clock cost of ONE complete,
// mutually-authenticated N-PAMP handshake at the Standard profile (Ed25519 identities,
// X25519MLKEM768 hybrid KEM) between a real sdk.DialRaw client and a real sdk.AcceptRaw
// server over a fresh net.Pipe pair each iteration -- the same DialRaw/AcceptRaw pair the
// package's own TestDialRaw_AcceptRaw_RoundTrip and ../relay/e2e_test.go's
// TestE2E_HandshakeAndDataRoundTrip_ThroughRelay drive directly, not a synthetic stand-in.
// This is the "handshake latency" figure the other handshake benchmarks in
// ../handshake_bench_test.go (KEM exchange, TLV codec, CertVerify/Finished, key schedule)
// each measure a PIECE of; this benchmark measures the sum a caller actually experiences:
// dial-to-authenticated-connection, both directions, including TLV encode/decode, the KEM
// exchange, the key schedule, and both peers' CertVerify+Finished authentication steps.
//
// Each iteration constructs a fresh net.Pipe pair and fresh Ed25519 identities: reusing a
// completed connection across iterations would benchmark nothing (a completed handshake
// cannot be re-run), and reusing one identity pair across iterations would hide any
// per-iteration identity-generation cost that is honestly part of a real caller's first
// connection. Server-side AcceptRaw runs concurrently in a goroutine (net.Pipe is
// unbuffered: a Write blocks until a matching Read consumes it, so the client and server
// handshake drivers MUST run concurrently -- the same net.Pipe concurrent-I/O requirement
// ../relay/e2e_test.go's own TestE2E_HandshakeAndDataRoundTrip_ThroughRelay and this
// package's own dialraw_test.go already follow).
//
// Measure with a NON-race build: `cd impl/go && GOWORK=off go test -bench=BenchmarkHandshakeLatency
// -benchmem -run=^$ ./sdk/...`. Do not pin a headline ns/op captured under `go test -race`
// -- race instrumentation distorts handshake timings (the same convention
// ../handshake_bench_test.go and ../aead_bench_test.go document).
func BenchmarkHandshakeLatency(b *testing.B) {
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate client identity: %v", err)
	}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate server identity: %v", err)
	}
	_ = clientPub
	_ = serverPub

	b.ReportAllocs()
	for b.Loop() {
		clientConn, serverConn := net.Pipe()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		type acceptResult struct {
			conn *sdk.Conn
			err  error
		}
		acceptCh := make(chan acceptResult, 1)
		go func() {
			c, err := sdk.AcceptRaw(ctx, serverConn, sdk.Config{Identity: serverPriv})
			acceptCh <- acceptResult{c, err}
		}()

		clientResult, clientErr := sdk.DialRaw(ctx, clientConn, sdk.Config{Identity: clientPriv})
		if clientErr != nil {
			cancel()
			b.Fatalf("DialRaw: %v", clientErr)
		}
		ar := <-acceptCh
		if ar.err != nil {
			cancel()
			b.Fatalf("AcceptRaw: %v", ar.err)
		}

		_ = clientResult.Close()
		_ = ar.conn.Close()
		_ = clientConn.Close()
		_ = serverConn.Close()
		cancel()
	}
}
