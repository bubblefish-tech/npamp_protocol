// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestPendingAckSet_ReorderTolerantAndSingleUse pins the properties the pending-ACK
// correlation depends on — the two concurrency traps the design has to survive:
//
//   - REORDER TOLERANCE (Race 1): the peer emits each ACK from its own goroutine racing for
//     wmu (sendKeyUpdateAck / sendMasterRatchetAck), so ACK(epoch 2) can reach the wire before
//     ACK(epoch 1) for two pipelined updates. Matching is by a SET keyed on epoch/generation,
//     so consuming out of registration order still succeeds; a FIFO or single-slot tracker
//     would wrongly reject the reordered ACK and tear down a conformant peer.
//   - SINGLE USE: a consumed entry is gone, so a REPLAYED ACK (same epoch/gen a second time)
//     is treated as unsolicited.
//   - PER-CHANNEL scope for KEY_UPDATE_ACK and ROLLBACK on a write failure.
//
// A zero-value Conn suffices: these leaf methods touch only pmu and the two maps.
func TestPendingAckSet_ReorderTolerantAndSingleUse(t *testing.T) {
	c := &Conn{}

	// KEY_UPDATE_ACK: two pipelined updates on one channel, ACKed OUT of order.
	ch := npamp.ChanMemory
	c.addPendingKeyUpdateAck(ch, 1)
	c.addPendingKeyUpdateAck(ch, 2)
	if !c.consumePendingKeyUpdateAck(ch, 2) {
		t.Fatal("reordered KEY_UPDATE_ACK (epoch 2 before 1) must be accepted — set, not FIFO")
	}
	if !c.consumePendingKeyUpdateAck(ch, 1) {
		t.Fatal("KEY_UPDATE_ACK epoch 1 must still be accepted after 2 was consumed")
	}
	if c.consumePendingKeyUpdateAck(ch, 1) {
		t.Fatal("a REPLAYED KEY_UPDATE_ACK (epoch 1 again) must be rejected as unsolicited")
	}
	if c.consumePendingKeyUpdateAck(ch, 9) {
		t.Fatal("an unregistered KEY_UPDATE_ACK (epoch 9) must be rejected as unsolicited")
	}

	// Per-channel scope: a pending on ChanMemory does not satisfy an ACK on ChanControl.
	c.addPendingKeyUpdateAck(ch, 5)
	if c.consumePendingKeyUpdateAck(npamp.ChanControl, 5) {
		t.Fatal("KEY_UPDATE_ACK is per-channel: epoch 5 pending on ChanMemory must NOT match ChanControl")
	}
	if !c.consumePendingKeyUpdateAck(ch, 5) {
		t.Fatal("epoch 5 on ChanMemory must still be pending after the wrong-channel probe")
	}

	// Write-failure rollback: a registered-then-removed epoch is no longer pending.
	c.addPendingKeyUpdateAck(ch, 7)
	c.removePendingKeyUpdateAck(ch, 7)
	if c.consumePendingKeyUpdateAck(ch, 7) {
		t.Fatal("a rolled-back KEY_UPDATE_ACK registration must not be consumable")
	}

	// MASTER_RATCHET_ACK: conn-scope, same reorder + single-use + rollback semantics.
	c.addPendingRatchetAck(10)
	c.addPendingRatchetAck(11)
	if !c.consumePendingRatchetAck(11) {
		t.Fatal("reordered MASTER_RATCHET_ACK (gen 11 before 10) must be accepted")
	}
	if !c.consumePendingRatchetAck(10) {
		t.Fatal("MASTER_RATCHET_ACK gen 10 must still be accepted after 11")
	}
	if c.consumePendingRatchetAck(10) {
		t.Fatal("a REPLAYED MASTER_RATCHET_ACK (gen 10 again) must be rejected as unsolicited")
	}
	if c.consumePendingRatchetAck(99) {
		t.Fatal("an unregistered MASTER_RATCHET_ACK (gen 99) must be rejected as unsolicited")
	}
	c.addPendingRatchetAck(12)
	c.removePendingRatchetAck(12)
	if c.consumePendingRatchetAck(12) {
		t.Fatal("a rolled-back MASTER_RATCHET_ACK registration must not be consumable")
	}
}

// TestPendingKeyUpdateAck_MultisetToleratesSameEpochAcrossGenerations pins the same-epoch-across-generations correlation. A
// master-ratchet resets each channel's leaf epoch to 0 (dropSendKeys), so a KeyUpdate in
// generation G and one in G+1 both announce the SAME epoch, and — because each ACK is emitted
// from a detached goroutine — their ACKs can be outstanding simultaneously. The tracker is a
// per-epoch COUNT (multiset), so BOTH ACKs are accepted while a further ACK for that epoch (a
// replay, or a truly unsolicited one) is still rejected. On the PRE-FIX SET this test FAILS at
// the second consume: the set collapsed the two same-epoch registrations into one entry, so the
// second ACK read as unsolicited — the loopback teardown.
func TestPendingKeyUpdateAck_MultisetToleratesSameEpochAcrossGenerations(t *testing.T) {
	c := &Conn{}
	ch := npamp.ChanMemory

	// Two KeyUpdates announce the SAME epoch (1) in adjacent generations; both ACKs outstanding.
	c.addPendingKeyUpdateAck(ch, 1)
	c.addPendingKeyUpdateAck(ch, 1)
	if !c.consumePendingKeyUpdateAck(ch, 1) {
		t.Fatal("first same-epoch KEY_UPDATE_ACK must be accepted")
	}
	if !c.consumePendingKeyUpdateAck(ch, 1) {
		t.Fatal("SECOND same-epoch KEY_UPDATE_ACK (adjacent generation) must be accepted; a SET rejects it as unsolicited")
	}
	if c.consumePendingKeyUpdateAck(ch, 1) {
		t.Fatal("a THIRD epoch-1 ACK (no outstanding KeyUpdate; replay/unsolicited) must be rejected")
	}

	// Rollback decrements the count and must NOT wipe a co-outstanding same-epoch registration.
	c.addPendingKeyUpdateAck(ch, 2)
	c.addPendingKeyUpdateAck(ch, 2)
	c.removePendingKeyUpdateAck(ch, 2) // one write failed; the other is still outstanding
	if !c.consumePendingKeyUpdateAck(ch, 2) {
		t.Fatal("after rolling back ONE of two same-epoch registrations, the other must still be consumable")
	}
	if c.consumePendingKeyUpdateAck(ch, 2) {
		t.Fatal("after the surviving epoch-2 registration is consumed, a further ACK must be rejected")
	}
}
