// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npamp

import (
	"errors"
	"testing"
)

// TestSelectAEADSeqDerived is the R5.2 per-frame AEAD selector KAT: it freezes the
// deterministic, sequence-number-derived selection (no per-frame wire flag). With
// one suite every frame uses the primary; with two suites frames alternate by
// sequence parity, primary first. Mutation-surviving: a selector that ignored the
// sequence number (always suites[0]) fails the two-suite case at seq 1.
func TestSelectAEADSeqDerived(t *testing.T) {
	// Standard: one suite (diversification off) -> always the primary.
	std := []AEADID{AEADAES256GCM}
	for _, seq := range []uint64{0, 1, 7, 1 << 40} {
		got, err := SelectAEAD(std, seq)
		if err != nil {
			t.Fatalf("SelectAEAD(std, %d): %v", seq, err)
		}
		if got != AEADAES256GCM {
			t.Fatalf("SelectAEAD(std, %d) = 0x%04x, want AES-256-GCM (0x0001)", seq, uint16(got))
		}
	}

	// High/Sovereign: two suites (diversification on) -> alternate by seq parity.
	div := []AEADID{AEADAES256GCM, AEADChaCha20Poly1305}
	want := []AEADID{
		AEADAES256GCM, AEADChaCha20Poly1305, AEADAES256GCM,
		AEADChaCha20Poly1305, AEADAES256GCM, AEADChaCha20Poly1305,
	}
	for seq := uint64(0); seq < uint64(len(want)); seq++ {
		got, err := SelectAEAD(div, seq)
		if err != nil {
			t.Fatalf("SelectAEAD(div, %d): %v", seq, err)
		}
		if got != want[seq] {
			t.Fatalf("SelectAEAD(div, %d) = 0x%04x, want 0x%04x", seq, uint16(got), uint16(want[seq]))
		}
	}

	// Fail closed on an empty selectable-suite list.
	if _, err := SelectAEAD(nil, 0); !errors.Is(err, ErrNoAEADSuite) {
		t.Fatalf("SelectAEAD(nil): got %v, want ErrNoAEADSuite", err)
	}
}
