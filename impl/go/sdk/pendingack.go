// SPDX-License-Identifier: Apache-2.0

package sdk

import npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"

// Pending-ACK correlation for the two control-frame acknowledgements —
// KEY_UPDATE_ACK (per channel, keyed by the announced epoch) and MASTER_RATCHET_ACK
// (conn-scope Control, keyed by the announced generation). Each is a SET, not a queue:
// the peer emits each ACK from its own goroutine (sendKeyUpdateAck / sendMasterRatchetAck),
// which race for wmu, so ACKs for two rapidly-pipelined updates can legitimately reach the
// wire out of order. Matching by epoch/generation (delete-from-set) tolerates that
// reordering, where a FIFO or single-slot tracker would flag a conformant peer.
//
// An ACK that matches a set entry was SOLICITED (this endpoint sent the corresponding
// KEY_UPDATE / MASTER_RATCHET): it is consumed and the receive path stays SILENT. An ACK
// with no matching entry is UNSOLICITED: the receive path treats it as the state machine's
// total default (unexpected_message), exactly as it already treats an unsolicited CLOSE_ACK.
//
// All entries are added ONLY by this endpoint's own KeyUpdate/RatchetSend calls, so a peer
// cannot inflate the sets (no bound needed), and they hold no key material (no wipe owed).
// All methods take pmu as a leaf: the add/remove callers hold wmu, the consume callers hold
// rmu, and pmu never nests either (canonical order wmu->pmu, rmu->pmu).

// addPendingKeyUpdateAck records that a KEY_UPDATE_ACK announcing epoch on channel is now
// expected. Called from KeyUpdate (holds wmu) BEFORE the KEY_UPDATE write, so a fast ACK the
// peer returns cannot race ahead of registration and be misread as unsolicited.
func (c *Conn) addPendingKeyUpdateAck(channel npamp.ChannelID, epoch uint64) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	if c.pendingKUAck == nil {
		c.pendingKUAck = make(map[npamp.ChannelID]map[uint64]struct{})
	}
	set := c.pendingKUAck[channel]
	if set == nil {
		set = make(map[uint64]struct{})
		c.pendingKUAck[channel] = set
	}
	set[epoch] = struct{}{}
}

// removePendingKeyUpdateAck rolls back a registration when the KEY_UPDATE write failed (the
// peer never saw it, so no ACK will come). Caller holds wmu.
func (c *Conn) removePendingKeyUpdateAck(channel npamp.ChannelID, epoch uint64) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	if set := c.pendingKUAck[channel]; set != nil {
		delete(set, epoch)
		if len(set) == 0 {
			delete(c.pendingKUAck, channel)
		}
	}
}

// consumePendingKeyUpdateAck reports whether a KEY_UPDATE_ACK announcing epoch on channel was
// SOLICITED. If so it removes the entry (single-use) and returns true; otherwise it returns
// false and the caller rejects the ACK as unsolicited. Caller holds rmu.
func (c *Conn) consumePendingKeyUpdateAck(channel npamp.ChannelID, epoch uint64) bool {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	set := c.pendingKUAck[channel]
	if set == nil {
		return false
	}
	if _, ok := set[epoch]; !ok {
		return false
	}
	delete(set, epoch)
	if len(set) == 0 {
		delete(c.pendingKUAck, channel)
	}
	return true
}

// addPendingRatchetAck records that a MASTER_RATCHET_ACK announcing gen is now expected.
// Called from RatchetSend (holds wmu) BEFORE the MASTER_RATCHET write (register-before-write,
// as for KEY_UPDATE).
func (c *Conn) addPendingRatchetAck(gen uint64) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	if c.pendingMRAck == nil {
		c.pendingMRAck = make(map[uint64]struct{})
	}
	c.pendingMRAck[gen] = struct{}{}
}

// removePendingRatchetAck rolls back a registration when the MASTER_RATCHET write failed.
// Caller holds wmu.
func (c *Conn) removePendingRatchetAck(gen uint64) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	delete(c.pendingMRAck, gen)
}

// consumePendingRatchetAck reports whether a MASTER_RATCHET_ACK announcing gen was SOLICITED,
// removing the entry (single-use) if so. Caller holds rmu.
func (c *Conn) consumePendingRatchetAck(gen uint64) bool {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	if _, ok := c.pendingMRAck[gen]; !ok {
		return false
	}
	delete(c.pendingMRAck, gen)
	return true
}
