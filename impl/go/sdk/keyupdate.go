// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// ackWriteTimeout bounds how long a KEY_UPDATE_ACK write may block the receive
// loop when a peer stalls its socket. Without it, a peer that sends KEY_UPDATE
// then stops reading could wedge Recv indefinitely (the ACK is written while the
// receive lock is held). It is independent of the caller's Recv context so the
// bound holds even when Recv is called with a deadline-less context.
const ackWriteTimeout = 30 * time.Second

// KeyUpdate rotates the send-direction traffic key for channel to the next
// epoch, giving forward secrecy: it sends a KEY_UPDATE control frame (sealed
// under the CURRENT epoch key, carrying the next epoch as an 8-octet
// KeyUpdateMarker TLV), then zeroizes the retired key material and derives the
// new epoch's key. Subsequent Send calls on the channel use the new key from
// sequence 0. The peer advances its matching receive epoch and replies with
// KEY_UPDATE_ACK — both handled transparently inside the peer's Recv.
//
// Key update is per (channel, direction): KeyUpdate affects only the caller's
// send direction on the given channel, and each (channel, direction) rotates
// independently (spec/04 frame types 0x0006/0x0007; spec/06 "Key Schedule and
// Nonces"; spec/07 TLV 0x17 KeyUpdateMarker).
func (c *Conn) KeyUpdate(ctx context.Context, channel npamp.ChannelID) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	st, err := c.sendState(channel)
	if err != nil {
		return fmt.Errorf("npamp/sdk: derive send key: %w", err)
	}
	// The KEY_UPDATE frame is the last frame at the current epoch, so the peer —
	// still at its current receive epoch — can open it; the marker announces the
	// epoch both sides move to.
	wire, err := sealWith(st, channel, npamp.FrameKeyUpdate, keyUpdateMarker(st.epoch+1))
	if err != nil {
		return fmt.Errorf("npamp/sdk: seal KEY_UPDATE: %w", err)
	}
	if err := c.writeWire(ctx, wire); err != nil {
		return err
	}
	st.seq++
	// Rotate: zeroize the retired key, bump epoch, reset seq, derive the new key.
	if err := st.advance(c.master, c.sendDir, channel, c.profile); err != nil {
		return fmt.Errorf("npamp/sdk: advance send epoch: %w", err)
	}
	return nil
}

// handleKeyUpdate processes a received KEY_UPDATE control frame: it validates the
// marker announces exactly the next epoch, advances the receive epoch (zeroizing
// the retired recv key), and replies with KEY_UPDATE_ACK on the local send
// direction under a bounded write deadline (ackWriteTimeout), so a peer that
// stalls its socket cannot wedge the receive loop indefinitely. The ACK is sent
// OFF the receive path, on its own goroutine (sendKeyUpdateAck), which takes wmu
// alone; Recv holds rmu alone. No single goroutine holds both locks, so there is
// no lock nesting to deadlock on.
func (c *Conn) handleKeyUpdate(channel npamp.ChannelID, st *epochKeys, plaintext []byte) error {
	next, err := parseKeyUpdateMarker(plaintext)
	if err != nil {
		return fmt.Errorf("npamp/sdk: KEY_UPDATE on channel %d: %w", channel, err)
	}
	if next != st.epoch+1 {
		return fmt.Errorf("npamp/sdk: KEY_UPDATE on channel %d announced epoch %d, want %d", channel, next, st.epoch+1)
	}
	if err := st.advance(c.master, c.recvDir, channel, c.profile); err != nil {
		return fmt.Errorf("npamp/sdk: advance recv epoch: %w", err)
	}

	// Reply with KEY_UPDATE_ACK OFF the receive path (its own goroutine), so a
	// peer that stalls its socket cannot wedge Recv: the receive loop returns
	// immediately and keeps draining. The ACK still serializes with Send/KeyUpdate
	// via wmu (preserving seq == wire order) and is bounded by ackWriteTimeout.
	go c.sendKeyUpdateAck(channel, next)
	return nil
}

// sendKeyUpdateAck seals + writes a KEY_UPDATE_ACK on channel, off the receive
// path. It takes wmu (serializing with Send/KeyUpdate so wire order matches
// sequence order) and bounds the write by ackWriteTimeout. A failed or partial
// write corrupts our send stream, so it closes the connection; the ACK is
// informational (the peer ignores it), so a derivation/seal error simply skips
// it without tearing the connection down.
func (c *Conn) sendKeyUpdateAck(channel npamp.ChannelID, epoch uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), ackWriteTimeout)
	defer cancel()

	// Seal + write under wmu (serializing with Send/KeyUpdate so wire order matches
	// sequence order). Capture whether the write failed inside the locked region,
	// but tear the connection down only AFTER releasing wmu: Close acquires wmu (to
	// zeroize the master), so calling it while still holding wmu would self-deadlock
	// on the non-reentrant mutex. A closed/zeroized connection makes sendState
	// return errClosed here, so this never seals under a wiped key.
	c.wmu.Lock()
	st, err := c.sendState(channel)
	if err != nil {
		c.wmu.Unlock()
		return
	}
	ack, err := sealWith(st, channel, npamp.FrameKeyUpdateAck, keyUpdateMarker(epoch))
	if err != nil {
		c.wmu.Unlock()
		return
	}
	werr := c.writeWire(ctx, ack)
	if werr == nil {
		st.seq++
	}
	c.wmu.Unlock()

	// A failed or partial ACK write corrupts our send stream; tear the connection
	// down — now that wmu is released, Close's zeroize can acquire it. The ACK is
	// informational (the peer ignores it), so a seal/derive error above simply skips
	// the ACK without a teardown.
	if werr != nil {
		_ = c.Close()
	}
}

// keyUpdateMarker encodes the TLV 0x17 KeyUpdateMarker carrying the epoch as an
// 8-octet big-endian value (spec/07 TLV registry).
func keyUpdateMarker(epoch uint64) []byte {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], epoch)
	return npamp.TLV{Type: npamp.TLVKeyUpdateMarker, Value: v[:]}.Encode(nil)
}

// parseKeyUpdateMarker decodes a KEY_UPDATE / KEY_UPDATE_ACK payload into its
// announced epoch, enforcing the single-TLV 8-octet KeyUpdateMarker layout.
func parseKeyUpdateMarker(payload []byte) (uint64, error) {
	tlvs, err := npamp.DecodeTLVs(payload)
	if err != nil {
		return 0, err
	}
	if len(tlvs) != 1 || tlvs[0].Type != npamp.TLVKeyUpdateMarker {
		return 0, fmt.Errorf("expected a single KeyUpdateMarker TLV")
	}
	if len(tlvs[0].Value) != 8 {
		return 0, fmt.Errorf("KeyUpdateMarker is %d octets, want 8", len(tlvs[0].Value))
	}
	return binary.BigEndian.Uint64(tlvs[0].Value), nil
}
