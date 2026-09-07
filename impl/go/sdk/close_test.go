// SPDX-License-Identifier: Apache-2.0

package sdk

// Acknowledged-teardown (CLOSE / CLOSE_ACK) tests, the CLOSER side of the state machine's
// ESTABLISHED -> CLOSING -> CLOSED path (D7). The deviant-trace suite (statetrace_test.go)
// covers the RECEIVER reaction (a peer CLOSE yields a sealed CLOSE_ACK and ErrPeerClosed);
// these cover CloseGraceful itself: the full round-trip against an active peer, and the
// close_incomplete timer fallback when the peer never acknowledges.

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestCloseGraceful_RoundTrip: the closer sends CLOSE and reaches CLOSED only after the peer
// replies CLOSE_ACK. Both endpoints run a Recv loop (the full-duplex case CloseGraceful
// targets): the peer's Recv reacts to CLOSE with CLOSE_ACK + ErrPeerClosed, and the closer's
// Recv consumes the CLOSE_ACK (signalCloseAck), waking CloseGraceful. Mutation-surviving:
// dropping the CLOSE_ACK reaction leaves CloseGraceful blocked until its timer, and dropping
// signalCloseAck's wake makes the closer's Recv treat the ack as unsolicited.
func TestCloseGraceful_RoundTrip(t *testing.T) {
	a, b := net.Pipe()
	master := guardTestMaster()
	client := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)
	server := newConn(b, master, nil, npamp.DirServerToClient, npamp.DirClientToServer)

	ctx, cancel := context.WithTimeout(context.Background(), stTestTimeout)
	defer cancel()

	serverRecv := make(chan error, 1)
	go func() { _, _, _, e := server.Recv(ctx); serverRecv <- e }()

	clientRecv := make(chan error, 1)
	go func() { _, _, _, e := client.Recv(ctx); clientRecv <- e }()

	// Assert CloseGraceful returns PROMPTLY on the CLOSE_ACK, not after the 5 s
	// CLOSE_ACK-wait timer: both select arms return nil, so a dead signalCloseAck wake path
	// would still pass (just slowly). The promptness IS D7's acknowledged-teardown property.
	start := time.Now()
	if err := client.CloseGraceful(ctx); err != nil {
		t.Fatalf("CloseGraceful returned %v, want nil (clean acknowledged teardown)", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("CloseGraceful took %v — it waited the CLOSE_ACK-wait timer instead of waking on the ack (signalCloseAck path dead?)", elapsed)
	}

	// The peer observed the CLOSE and acknowledged it; its Recv returns ErrPeerClosed.
	select {
	case e := <-serverRecv:
		if !errors.Is(e, ErrPeerClosed) {
			t.Fatalf("peer Recv after CLOSE = %v, want ErrPeerClosed", e)
		}
	case <-time.After(stTestTimeout):
		t.Fatal("peer Recv did not return after CLOSE")
	}

	// The closer consumed the CLOSE_ACK; its Recv returns ErrPeerClosed (CLOSING -> CLOSED).
	select {
	case e := <-clientRecv:
		if !errors.Is(e, ErrPeerClosed) {
			t.Fatalf("closer Recv after CLOSE_ACK = %v, want ErrPeerClosed", e)
		}
	case <-time.After(stTestTimeout):
		t.Fatal("closer Recv did not observe CLOSE_ACK")
	}

	// After a graceful close the association is torn down: no further send is possible.
	if err := client.Send(context.Background(), npamp.ChanMemory, npamp.FrameType(0x0120), []byte("x")); err == nil {
		t.Fatal("Send succeeded after CloseGraceful — the connection was not torn down")
	}
}

// TestCloseGraceful_TimeoutTearsDown: the closer sends CLOSE (the peer reads it, so the send
// succeeds) but the peer never replies CLOSE_ACK. CloseGraceful MUST NOT hang: it forces
// teardown on the caller's deadline (the close_incomplete outcome — no ERROR is sent) and
// returns promptly. Mutation-surviving: removing the timer/ctx arm of the select makes this
// block until stTestTimeout and fail.
func TestCloseGraceful_TimeoutTearsDown(t *testing.T) {
	a, b := net.Pipe()
	master := guardTestMaster()
	client := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)

	// A raw peer that consumes the CLOSE frame but deliberately sends no CLOSE_ACK.
	consumed := make(chan struct{})
	go func() {
		_ = b.SetReadDeadline(time.Now().Add(stTestTimeout))
		if _, err := readFrame(b); err == nil {
			close(consumed)
		}
	}()

	// A short deadline so the missing CLOSE_ACK forces teardown quickly (independent of the
	// 5 s CLOSE_ACK-wait timer, via the ctx arm of CloseGraceful's select).
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := client.CloseGraceful(ctx); err != nil {
		t.Fatalf("CloseGraceful returned %v, want nil after a forced teardown", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("CloseGraceful blocked %v — it did not honor the close_incomplete deadline", elapsed)
	}

	select {
	case <-consumed:
	case <-time.After(time.Second):
		t.Fatal("peer never received the CLOSE frame — CloseGraceful did not send it")
	}

	// The connection is torn down after the forced close.
	if err := client.Send(context.Background(), npamp.ChanMemory, npamp.FrameType(0x0120), []byte("x")); err == nil {
		t.Fatal("Send succeeded after a timed-out CloseGraceful — connection not torn down")
	}
	_ = a.Close()
}
