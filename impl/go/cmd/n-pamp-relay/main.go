// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Command n-pamp-relay is the reference frame-delimiting N-PAMP forwarder
// (task E2.1, requirements R1.1/R1.2/DES-10; see impl/go/relay for the
// forwarding logic and the design rationale). It listens on two TCP
// addresses, accepts exactly one connection on each, and forwards
// self-delimiting N-PAMP frames between them in both directions until the
// flow ends — WITHOUT ever deriving an AEAD key or decrypting a payload:
// the two agents that dial in run their own end-to-end N-PAMP handshake and
// authenticate EACH OTHER, never the relay.
//
// Usage:
//
//	n-pamp-relay -addr-a 127.0.0.1:47720 -addr-b 127.0.0.1:47721
//
// Agent A connects to -addr-a, agent B connects to -addr-b (in either
// order); once both have connected, the relay forwards frames between them
// until one side closes, a malformed/oversized/truncated frame is seen, or
// the process is interrupted. It then exits.
//
// This binary carries no inspection policy of its own: relay.Relay.Hook is
// left nil, so every well-formed frame is forwarded (this package's own
// default). A later policy layer (E2.2, a frame-inspecting firewall) plugs
// into that same seam without changing anything here.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
	"github.com/bubblefish-tech/npamp_protocol/impl/go/relay"
)

func main() {
	addrA := flag.String("addr-a", "127.0.0.1:47720", "listen address for agent A")
	addrB := flag.String("addr-b", "127.0.0.1:47721", "listen address for agent B")
	maxFrameSize := flag.Uint("max-frame-size", npamp.MaxFrameSize, "maximum accepted frame size (header+payload) in octets")
	flag.Parse()

	if err := run(*addrA, *addrB, uint32(*maxFrameSize)); err != nil {
		fmt.Fprintf(os.Stderr, "n-pamp-relay: %v\n", err)
		os.Exit(1)
	}
}

func run(addrA, addrB string, maxFrameSize uint32) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connA, err := acceptOne(ctx, addrA, "A")
	if err != nil {
		return err
	}
	defer connA.Close()

	connB, err := acceptOne(ctx, addrB, "B")
	if err != nil {
		return err
	}
	defer connB.Close()

	fmt.Fprintf(os.Stderr, "n-pamp-relay: agent A (%s) and agent B (%s) connected; forwarding frames (max %d octets/frame)\n",
		connA.RemoteAddr(), connB.RemoteAddr(), maxFrameSize)

	rl := &relay.Relay{A: connA, B: connB, MaxFrameSize: maxFrameSize}
	err = rl.Run(ctx)
	if err != nil {
		return fmt.Errorf("flow ended: %w", err)
	}
	fmt.Fprintln(os.Stderr, "n-pamp-relay: flow ended cleanly")
	return nil
}

// acceptOne listens on addr, accepts exactly one connection, and closes the
// listener (this reference relay forwards a single flow per invocation; a
// production deployment would loop Accept and spawn a Relay per accepted
// pair, reusing the same relay.Relay type unchanged).
func acceptOne(ctx context.Context, addr, label string) (net.Conn, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen (agent %s) on %s: %w", label, addr, err)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "n-pamp-relay: waiting for agent %s on %s\n", label, ln.Addr())

	type result struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- result{conn, err}
	}()

	select {
	case r := <-acceptCh:
		if r.err != nil {
			return nil, fmt.Errorf("accept (agent %s) on %s: %w", label, addr, r.err)
		}
		return r.conn, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("accept (agent %s) on %s: %w", label, addr, ctx.Err())
	}
}
