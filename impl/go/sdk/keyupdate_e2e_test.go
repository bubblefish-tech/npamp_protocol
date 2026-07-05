// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/sdk"
)

// TestKeyUpdateLoopback drives a real loopback session through key-update epoch
// rotations and asserts application traffic keeps flowing across epochs in both
// directions. A rotation that failed to re-key symmetrically, reset the sequence
// space, or process the transparent KEY_UPDATE/KEY_UPDATE_ACK control frames
// would surface here as an AEAD-open or out-of-sequence failure.
func TestKeyUpdateLoopback(t *testing.T) {
	tlsCfg := loopbackTLS(t)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	ln, err := sdk.Listen("127.0.0.1:0", sdk.Config{TLSConfig: tlsCfg, Identity: serverPriv})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		conn *sdk.Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		accCh <- accepted{c, err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := sdk.Dial(ctx, ln.Addr().String(), sdk.Config{TLSConfig: tlsCfg, Identity: clientPriv})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("accept: %v", acc.err)
	}
	server := acc.conn
	defer server.Close()

	const ft npamp.FrameType = 0x0120
	roundtrip := func(from, to *sdk.Conn, msg string) {
		t.Helper()
		if err := from.Send(ctx, npamp.ChanMemory, ft, []byte(msg)); err != nil {
			t.Fatalf("send %q: %v", msg, err)
		}
		_, _, got, err := to.Recv(ctx)
		if err != nil {
			t.Fatalf("recv %q: %v", msg, err)
		}
		if !bytes.Equal(got, []byte(msg)) {
			t.Fatalf("recv %q: got %q", msg, got)
		}
	}

	// Epoch 0, both directions.
	roundtrip(client, server, "epoch-0 c->s")
	roundtrip(server, client, "epoch-0 s->c")

	// Client rotates its send key (c->s: epoch 0 -> 1). The server's Recv
	// transparently advances its matching recv epoch and ACKs.
	if err := client.KeyUpdate(ctx, npamp.ChanMemory); err != nil {
		t.Fatalf("client KeyUpdate: %v", err)
	}
	roundtrip(client, server, "epoch-1 c->s")     // must decrypt under the new epoch
	roundtrip(server, client, "still-epoch-0 s->c") // reverse direction is unaffected

	// Both sides rotate repeatedly; traffic must survive every rotation and the
	// per-epoch sequence must restart cleanly.
	for i := 0; i < 3; i++ {
		if err := client.KeyUpdate(ctx, npamp.ChanMemory); err != nil {
			t.Fatalf("client KeyUpdate %d: %v", i, err)
		}
		if err := server.KeyUpdate(ctx, npamp.ChanMemory); err != nil {
			t.Fatalf("server KeyUpdate %d: %v", i, err)
		}
		roundtrip(client, server, "c->s after rotation")
		roundtrip(server, client, "s->c after rotation")
	}

	// Several frames within one epoch (no rotation) to confirm the sequence
	// counter keeps advancing correctly post-rotation.
	for i := 0; i < 4; i++ {
		roundtrip(client, server, "steady c->s")
	}
}
