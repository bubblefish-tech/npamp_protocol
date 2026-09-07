// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"fmt"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// closeAckWaitTimeout bounds how long CloseGraceful waits for the peer's CLOSE_ACK before
// it forces teardown and records the outcome as close_incomplete (draft §... CLOSE Frame;
// the numeric bound is profile-set, 1 s .. 60 s — this is a value inside that range). It is
// independent of the caller's context so the bound holds even for a deadline-less ctx.
const closeAckWaitTimeout = 5 * time.Second

// sendSessionError seals and writes an ERROR frame carrying code on the Control channel,
// off the receive path (it takes wmu alone, bounded by ackWriteTimeout). It is the POST-KEY
// reaction of the keyed-session total default: Recv detects an unexpected frame in
// ESTABLISHED, releases rmu, and calls this before tearing the connection down. The context
// field is zero-length — the ERROR reports only the code, never diagnostic text that could
// leak internal state onto the wire. A closed/zeroized connection makes sendState return
// errClosed, so this never seals under a wiped key; a seal/derive/write failure is swallowed
// because the caller tears down regardless.
func (c *Conn) sendSessionError(code npamp.SessionErrorCode) {
	ctx, cancel := context.WithTimeout(context.Background(), ackWriteTimeout)
	defer cancel()

	c.wmu.Lock()
	defer c.wmu.Unlock()
	st, err := c.sendState(npamp.ChanControl)
	if err != nil {
		return
	}
	wire, err := sealWith(st, npamp.ChanControl, npamp.FrameError, npamp.EncodeErrorBody(code, nil))
	if err != nil {
		return
	}
	if c.writeWire(ctx, wire) == nil {
		st.seq++
	}
}

// sendCloseAck seals and writes a CLOSE_ACK frame (no payload) on the Control channel, off
// the receive path (wmu alone, bounded by ackWriteTimeout). It is the reaction to a received
// authenticated CLOSE: the peer's in-flight frames have already been drained in sequence
// order, so this acknowledges the teardown. After CLOSE_ACK the endpoint MUST send no further
// frame (draft) — the caller (Recv) enforces that by tearing the connection down (Close
// zeroizes) immediately after this returns.
func (c *Conn) sendCloseAck() {
	ctx, cancel := context.WithTimeout(context.Background(), ackWriteTimeout)
	defer cancel()

	c.wmu.Lock()
	defer c.wmu.Unlock()
	st, err := c.sendState(npamp.ChanControl)
	if err != nil {
		return
	}
	wire, err := sealWith(st, npamp.ChanControl, npamp.FrameCloseAck, nil)
	if err != nil {
		return
	}
	if c.writeWire(ctx, wire) == nil {
		st.seq++
	}
}

// signalCloseAck is called by the receive path when a CLOSE_ACK arrives on Control. If this
// endpoint is CLOSING (it sent a CLOSE via CloseGraceful and is awaiting the ack), it clears
// the CLOSING state, wakes the waiter, and reports true; otherwise it reports false and the
// CLOSE_ACK is treated as unsolicited (the total default). Guarded by cmu so it touches
// neither direction lock.
func (c *Conn) signalCloseAck() bool {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	if !c.closing {
		return false
	}
	c.closing = false
	if c.closeAckCh != nil {
		close(c.closeAckCh)
		c.closeAckCh = nil
	}
	return true
}

// CloseGraceful performs the acknowledged teardown (draft §... CLOSE Frame): it seals and
// sends a CLOSE frame on Control (moving this endpoint to CLOSING), then awaits the peer's
// CLOSE_ACK under the CLOSE_ACK-wait timer before it tears the connection down. On CLOSE_ACK
// it reaches CLOSED cleanly; on the timer's (or ctx's) expiry it forces teardown and the
// outcome is close_incomplete — no ERROR is sent, because the peer is by then unresponsive
// (draft). If the CLOSE itself cannot be sealed or written (a closed or exhausted
// connection), it falls back to the abrupt local teardown.
//
// The CLOSE_ACK is consumed by the peer's-ack path in an ACTIVE Recv loop
// (signalCloseAck): a full-duplex caller runs Send and Recv concurrently, and the Recv loop
// signals this wait. A caller with no Recv loop cannot receive the CLOSE_ACK, so
// CloseGraceful will time out to close_incomplete and tear down — for that caller the abrupt
// Close is the right tool. Either way the underlying transport is closed and the keys are
// zeroized exactly once (Close is idempotent).
func (c *Conn) CloseGraceful(ctx context.Context) error {
	ackCh, sent, err := c.sendClose(ctx)
	if err != nil || !sent {
		// Could not send CLOSE (already closed, sequence exhausted, or a write error): the
		// only honest teardown left is the abrupt local one.
		return c.Close()
	}

	timer := time.NewTimer(closeAckWaitTimeout)
	defer timer.Stop()

	// Wait on the channel sendClose returned — NOT a re-read of c.closeAckCh, which
	// signalCloseAck may have already nil'd after closing it. Holding our own reference means
	// the close() still unblocks this select even when the CLOSE_ACK arrives before we wait.
	select {
	case <-ackCh: // peer acknowledged -> CLOSED
	case <-timer.C: // close_incomplete: the peer did not ack in time
		c.clearClosing()
	case <-ctx.Done(): // caller gave up waiting
		c.clearClosing()
	}
	return c.Close()
}

// sendClose seals and writes a CLOSE frame (no payload) on Control under wmu and registers
// the CLOSING state (a fresh closeAckCh the receive path will signal). It returns that
// channel so the caller can wait on it directly (see CloseGraceful). It reports sent=true
// only when the CLOSE actually reached the wire. A closed or sequence-exhausted connection
// reports sent=false so CloseGraceful can fall back to abrupt teardown.
func (c *Conn) sendClose(ctx context.Context) (chan struct{}, bool, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil, false, nil
	}
	st, err := c.sendState(npamp.ChanControl)
	if err != nil {
		return nil, false, err
	}
	if st.seq == ^uint64(0) {
		return nil, false, fmt.Errorf("npamp/sdk: Control channel epoch %d sequence space exhausted", st.epoch)
	}
	wire, err := sealWith(st, npamp.ChanControl, npamp.FrameClose, nil)
	if err != nil {
		return nil, false, err
	}
	// Register CLOSING BEFORE the write, so a fast CLOSE_ACK the peer returns cannot race
	// ahead of the waiter's registration and be seen as unsolicited.
	ackCh := make(chan struct{})
	c.cmu.Lock()
	c.closing = true
	c.closeAckCh = ackCh
	c.cmu.Unlock()

	if err := c.writeWire(ctx, wire); err != nil {
		c.clearClosing()
		return nil, false, err
	}
	st.seq++
	return ackCh, true, nil
}

// clearClosing drops the CLOSING state without signaling the waiter (used on a send failure
// or a wait timeout). Idempotent.
func (c *Conn) clearClosing() {
	c.cmu.Lock()
	c.closing = false
	c.closeAckCh = nil
	c.cmu.Unlock()
}
