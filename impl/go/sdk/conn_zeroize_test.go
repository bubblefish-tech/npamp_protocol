// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// failWriteConn wraps a net.Conn but forces every Write to fail, to drive the
// ACK-write-error teardown path in sendKeyUpdateAck deterministically.
type failWriteConn struct{ net.Conn }

func (failWriteConn) Write(b []byte) (int, error) {
	return 0, errors.New("forced write failure")
}

// allZero reports whether every octet of b is zero.
func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// TestZeroizeWipesMasterAndEpochKeys asserts Zeroize wipes BOTH per-direction
// ratchet roots (masterSend and masterRecv) and every cached per-epoch traffic
// key from memory, and is idempotent. It builds a Conn directly (no handshake)
// with a known non-zero master so the wipe is observable on the unexported
// fields. (Step 8 of the HTR build map extends Zeroize from one master to two
// roots.)
func TestZeroizeWipesMasterAndEpochKeys(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0xAB
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)

	// The two roots are seeded from copies of the master and must be non-zero.
	if allZero(c.masterSend) || allZero(c.masterRecv) {
		t.Fatal("precondition: both ratchet roots should be non-zero before Zeroize")
	}

	// Populate a cached send + recv epoch key so we can prove they are wiped too.
	sst, err := c.sendState(npamp.ChanMemory)
	if err != nil {
		t.Fatalf("sendState: %v", err)
	}
	rst, err := c.recvState(npamp.ChanMemory)
	if err != nil {
		t.Fatalf("recvState: %v", err)
	}
	if allZero(sst.key[:]) || allZero(rst.key[:]) {
		t.Fatal("precondition: derived epoch keys should be non-zero before Zeroize")
	}

	c.Zeroize()

	if !allZero(c.masterSend) {
		t.Errorf("masterSend root not zeroized: %x", c.masterSend)
	}
	if !allZero(c.masterRecv) {
		t.Errorf("masterRecv root not zeroized: %x", c.masterRecv)
	}
	if !allZero(sst.key[:]) {
		t.Error("send epoch key not zeroized")
	}
	if !allZero(rst.key[:]) {
		t.Error("recv epoch key not zeroized")
	}

	// Idempotent: a second Zeroize must not panic.
	c.Zeroize()
}

// TestCloseZeroizesMaster asserts Close wipes the master secret (defense-in-depth
// memory hygiene on teardown) and is safe to call more than once.
func TestCloseZeroizesMaster(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0xCD
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)

	_ = c.Close()
	if !allZero(c.masterSend) || !allZero(c.masterRecv) {
		t.Errorf("Close did not zeroize both roots: send=%x recv=%x", c.masterSend, c.masterRecv)
	}
	// Second Close is safe (teardown + wipe each run once via closeOnce).
	_ = c.Close()
}

// TestSendKeyUpdateAckWriteErrorDoesNotDeadlock is a regression test for the
// mutex-reentrancy self-deadlock: on an ACK write failure, sendKeyUpdateAck tears
// the connection down via Close, and Close acquires wmu to zeroize. If the teardown
// ran while sendKeyUpdateAck still held wmu, the non-reentrant mutex would deadlock
// forever — and, worse, leave closeOnce.Do permanently stuck so every later Close
// hangs too. Both must complete under a bound.
func TestSendKeyUpdateAckWriteErrorDoesNotDeadlock(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x11
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := newConn(failWriteConn{a}, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)

	done := make(chan struct{})
	go func() {
		c.sendKeyUpdateAck(npamp.ChanMemory, 1)
		close(done)
	}()
	select {
	case <-done:
		// No deadlock: Close ran on the write-error path, so the roots must be wiped.
		if !allZero(c.masterSend) || !allZero(c.masterRecv) {
			t.Error("expected both roots wiped after the ACK-write-error teardown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sendKeyUpdateAck deadlocked on the ACK-write-error path (reentrant wmu via Close)")
	}

	// closeOnce must not be permanently stuck: a later Close still completes.
	d := make(chan struct{})
	go func() {
		_ = c.Close()
		close(d)
	}()
	select {
	case <-d:
	case <-time.After(2 * time.Second):
		t.Fatal("second Close hung — closeOnce.Do never completed")
	}
}

// TestSendAfterCloseReturnsErrClosed asserts the closed guard makes Send fail with
// errClosed BEFORE deriving a key, so no frame is ever sealed under the wiped
// (all-zero) master after teardown.
func TestSendAfterCloseReturnsErrClosed(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x22
	}
	a, b := net.Pipe()
	defer func() { _ = b.Close() }()
	c := newConn(a, master, nil, npamp.DirClientToServer, npamp.DirServerToClient)

	_ = c.Close() // wipes master + marks the connection closed

	err := c.Send(context.Background(), npamp.ChanMemory, npamp.FrameType(0x0120), []byte("x"))
	if err == nil {
		t.Fatal("Send after Close returned nil; expected errClosed")
	}
	if !errors.Is(err, errClosed) {
		t.Errorf("Send after Close = %v; want wrapped errClosed", err)
	}
}
