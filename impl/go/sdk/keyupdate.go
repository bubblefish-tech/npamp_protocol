// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"context"
	"encoding/binary"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

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
// direction. The caller (Recv) holds rmu; the ACK acquires wmu. This rmu→wmu
// order is the only nesting in the type (Send/KeyUpdate take wmu alone), so it
// cannot deadlock.
func (c *Conn) handleKeyUpdate(ctx context.Context, channel npamp.ChannelID, st *epochKeys, plaintext []byte) error {
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

	c.wmu.Lock()
	defer c.wmu.Unlock()
	sst, err := c.sendState(channel)
	if err != nil {
		return fmt.Errorf("npamp/sdk: derive send key for ACK: %w", err)
	}
	ack, err := sealWith(sst, channel, npamp.FrameKeyUpdateAck, keyUpdateMarker(next))
	if err != nil {
		return fmt.Errorf("npamp/sdk: seal KEY_UPDATE_ACK: %w", err)
	}
	if err := c.writeWire(ctx, ack); err != nil {
		return err
	}
	sst.seq++
	return nil
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
