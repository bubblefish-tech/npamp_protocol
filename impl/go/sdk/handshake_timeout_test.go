// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// TestAcceptHandshakeTimeout proves Config.HandshakeTimeout bounds a stalled
// post-accept handshake. A client completes TCP + TLS with the required ALPN but
// never sends the N-PAMP CLIENT_HELLO frame; without a per-connection handshake
// deadline the server's Accept would block forever in the record read (the
// pre-authentication stalled-handshake DoS). With HandshakeTimeout set, Accept
// returns a bounded error even though it is given a deadline-LESS context — the
// only thing that can end it is the HandshakeTimeout. If the timeout did not fire,
// this test hangs until the 3s guard and fails.
func TestAcceptHandshakeTimeout(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	ln, err := sdk.Listen("127.0.0.1:0", sdk.Config{
		TLSConfig:        tlsCfg,
		HandshakeTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan error, 1)
	go func() {
		// Deadline-LESS context: only HandshakeTimeout can bound this Accept.
		_, aerr := ln.Accept(context.Background())
		done <- aerr
	}()

	// Client: complete TCP + TLS with the required ALPN, then stall — never send the
	// N-PAMP CLIENT_HELLO frame.
	cliCfg := tlsCfg.Clone()
	cliCfg.NextProtos = []string{"n-pamp/2"}
	cliCfg.MinVersion = tls.VersionTLS13
	conn, err := tls.Dial("tcp", ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("client tls dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Handshake(); err != nil {
		t.Fatalf("client tls handshake: %v", err)
	}
	// Deliberately write nothing further; hold the connection open to stall the
	// server's N-PAMP handshake read.

	select {
	case aerr := <-done:
		if aerr == nil {
			t.Fatal("Accept returned nil; expected a bounded handshake-timeout error")
		}
		t.Logf("Accept returned a bounded error as expected: %v", aerr)
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not return within 3s — HandshakeTimeout did not fire; the stalled-handshake DoS is not closed")
	}
}
