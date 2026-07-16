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

// dialPair establishes a real loopback session and returns (client, server).
func dialPair(t *testing.T, ctx context.Context) (*sdk.Conn, *sdk.Conn) {
	t.Helper()
	tlsCfg := loopbackTLS(t)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	ln, err := sdk.Listen("127.0.0.1:0", sdk.Config{TLSConfig: tlsCfg, Identity: serverPriv})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type accepted struct {
		conn *sdk.Conn
		err  error
	}
	accCh := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept(ctx)
		accCh <- accepted{c, err}
	}()
	client, err := sdk.Dial(ctx, ln.Addr().String(), sdk.Config{TLSConfig: tlsCfg, Identity: clientPriv})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	acc := <-accCh
	if acc.err != nil {
		t.Fatalf("accept: %v", acc.err)
	}
	return client, acc.conn
}

// TestTier1RatchetTrafficFlowsLoopback drives the EXPORTED Conn.RatchetSend across
// a real loopback session and asserts application traffic keeps flowing across the
// Tier-1 boundary in both directions, through several steps, and composes with the
// per-channel KeyUpdate. A boundary that failed to re-derive symmetrically off the
// new root, reset the sequence space, or process the transparent
// MASTER_RATCHET/MASTER_RATCHET_ACK control frames would surface here as an
// AEAD-open or out-of-sequence failure.
func TestTier1RatchetTrafficFlowsLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, server := dialPair(t, ctx)
	defer client.Close()
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

	// Generation 0 baseline, both directions.
	roundtrip(client, server, "gen0 c->s")
	roundtrip(server, client, "gen0 s->c")

	// Client Tier-1 step on its send direction. The server's Recv transparently
	// advances its matching receive root and ACKs; the client's next Recv swallows
	// the ACK.
	if err := client.RatchetSend(ctx); err != nil {
		t.Fatalf("client.RatchetSend: %v", err)
	}
	roundtrip(client, server, "gen1 c->s") // opens under the new root
	roundtrip(server, client, "s->c after client step (swallows ACK)")

	// Both directions ratchet repeatedly; traffic must survive every boundary, and
	// a KeyUpdate within a generation must still compose (leaf FS under root FS).
	for i := 0; i < 3; i++ {
		if err := client.RatchetSend(ctx); err != nil {
			t.Fatalf("client.RatchetSend %d: %v", i, err)
		}
		if err := server.RatchetSend(ctx); err != nil {
			t.Fatalf("server.RatchetSend %d: %v", i, err)
		}
		roundtrip(client, server, "c->s after both steps")
		roundtrip(server, client, "s->c after both steps")

		if err := client.KeyUpdate(ctx, npamp.ChanMemory); err != nil {
			t.Fatalf("client.KeyUpdate %d: %v", i, err)
		}
		roundtrip(client, server, "c->s after KeyUpdate within generation")
	}

	// Steady-state frames within the current generation confirm the sequence space
	// keeps advancing after the last boundary.
	for i := 0; i < 4; i++ {
		roundtrip(client, server, "steady c->s")
	}
}

// TestTier2ReKEMTrafficFlowsLoopback drives the EXPORTED Conn.ReKEM across a real
// loopback session using a full-duplex Recv pump on each side (the way an
// application consumes the SDK), and asserts application traffic keeps flowing
// after the Tier-2 hybrid re-KEM self-heal on the healed direction. The re-KEM
// runs the real X25519MLKEM768 exchange; traffic surviving the REKEM/REKEM_ACK
// boundary is behavioral evidence both peers advanced to the fresh root
// symmetrically (a divergent or inert heal would break AEAD-open).
func TestTier2ReKEMTrafficFlowsLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, server := dialPair(t, ctx)
	defer client.Close()
	defer server.Close()

	const ft npamp.FrameType = 0x0120

	// Full-duplex Recv pumps: each forwards application plaintext and swallows
	// control frames transparently, as a real Recv-loop would.
	type rx struct {
		msgs chan string
		done chan error
	}
	pump := func(c *sdk.Conn) *rx {
		r := &rx{msgs: make(chan string, 32), done: make(chan error, 1)}
		go func() {
			for {
				_, _, pt, err := c.Recv(ctx)
				if err != nil {
					r.done <- err
					return
				}
				r.msgs <- string(pt)
			}
		}()
		return r
	}
	crx := pump(client)
	srx := pump(server)

	expect := func(r *rx, want string) {
		t.Helper()
		select {
		case got := <-r.msgs:
			if got != want {
				t.Fatalf("pump got %q, want %q", got, want)
			}
		case err := <-r.done:
			t.Fatalf("pump ended awaiting %q: %v", want, err)
		case <-time.After(10 * time.Second):
			t.Fatalf("timeout awaiting %q", want)
		}
	}

	// Baseline both directions.
	if err := client.Send(ctx, npamp.ChanMemory, ft, []byte("base c->s")); err != nil {
		t.Fatal(err)
	}
	expect(srx, "base c->s")
	if err := server.Send(ctx, npamp.ChanMemory, ft, []byte("base s->c")); err != nil {
		t.Fatal(err)
	}
	expect(crx, "base s->c")

	// Client heals its RECEIVE direction via Tier-2 re-KEM. The server's pump
	// transparently spawns the responder; the client's pump transparently
	// finalizes on REKEM_ACK. Application traffic on the healed direction after the
	// exchange must still open.
	if err := client.ReKEM(ctx); err != nil {
		t.Fatalf("client.ReKEM: %v", err)
	}
	// A frame on the initiator's send direction lets the server's pump make forward
	// progress (process the REKEM request) and confirms that direction is intact.
	if err := client.Send(ctx, npamp.ChanMemory, ft, []byte("c->s during heal")); err != nil {
		t.Fatal(err)
	}
	expect(srx, "c->s during heal")

	// Several frames on the HEALED direction (server -> client) after the heal.
	// These traverse the REKEM_ACK boundary; the client's pump processes the
	// boundary then opens each under the fresh root.
	for i, msg := range []string{"healed 1", "healed 2", "healed 3"} {
		if err := server.Send(ctx, npamp.ChanMemory, ft, []byte(msg)); err != nil {
			t.Fatalf("server.Send healed %d: %v", i, err)
		}
		expect(crx, msg)
	}

	// A second, independent heal initiated by the SERVER (heals the other
	// direction) proves bidirectional PCS and that repeated re-KEMs compose.
	if err := server.ReKEM(ctx); err != nil {
		t.Fatalf("server.ReKEM: %v", err)
	}
	if err := server.Send(ctx, npamp.ChanMemory, ft, []byte("s->c during heal2")); err != nil {
		t.Fatal(err)
	}
	expect(crx, "s->c during heal2")
	for i, msg := range []string{"healed2 1", "healed2 2"} {
		if err := client.Send(ctx, npamp.ChanMemory, ft, []byte(msg)); err != nil {
			t.Fatalf("client.Send healed2 %d: %v", i, err)
		}
		expect(srx, msg)
	}
}
