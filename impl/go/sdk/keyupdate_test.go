// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// TestEpochKeysRotation white-box-tests the forward-secrecy core: advancing an
// epoch must zeroize the retired key, derive a genuinely different key that
// matches an independent epoch-N derivation, and reset the sequence space.
func TestEpochKeysRotation(t *testing.T) {
	master := bytes.Repeat([]byte{0x2b}, 32)
	p := npamp.ProfileStandard
	dir := npamp.DirClientToServer
	ch := npamp.ChanMemory

	k := &epochKeys{}
	if err := k.derive(master, dir, ch, p); err != nil {
		t.Fatal(err)
	}
	if k.epoch != 0 {
		t.Fatalf("initial epoch = %d, want 0", k.epoch)
	}
	e0key := k.key // value copy of the epoch-0 key

	k.seq = 5 // pretend we sent some frames
	if err := k.advance(master, dir, ch, p); err != nil {
		t.Fatal(err)
	}
	if k.epoch != 1 {
		t.Fatalf("epoch after advance = %d, want 1", k.epoch)
	}
	if k.seq != 0 {
		t.Fatalf("seq after advance = %d, want 0 (fresh nonce space)", k.seq)
	}
	if k.key == e0key {
		t.Fatal("epoch-1 key equals epoch-0 key — rotation did not change the key")
	}

	// The rotated key/iv must equal an independent derivation at epoch 1.
	want := &epochKeys{epoch: 1}
	if err := want.derive(master, dir, ch, p); err != nil {
		t.Fatal(err)
	}
	if k.key != want.key || k.iv != want.iv {
		t.Fatal("epoch-1 key/iv != DeriveTrafficSecret(master, dir, epoch=1, ...)")
	}

	// zeroize wipes key + iv in place.
	k.zeroize()
	if k.key != ([32]byte{}) || k.iv != ([12]byte{}) {
		t.Fatal("zeroize did not wipe the key/iv")
	}
}

// TestKeyUpdateMarkerRoundTrip checks the KeyUpdateMarker TLV codec + its
// validation of the single-TLV, 8-octet layout.
func TestKeyUpdateMarkerRoundTrip(t *testing.T) {
	for _, epoch := range []uint64{0, 1, 42, 1 << 40} {
		got, err := parseKeyUpdateMarker(keyUpdateMarker(epoch))
		if err != nil {
			t.Fatalf("epoch %d: %v", epoch, err)
		}
		if got != epoch {
			t.Fatalf("round-trip epoch = %d, want %d", got, epoch)
		}
	}
	if _, err := parseKeyUpdateMarker([]byte{0x00}); err == nil {
		t.Fatal("expected error on a malformed marker payload")
	}
}
