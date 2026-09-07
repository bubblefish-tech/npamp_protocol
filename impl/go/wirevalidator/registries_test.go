// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package wirevalidator

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultRegistryRoot_ResolvesRealTree proves DefaultRegistryRoot lands
// on the actual repository root, not an arbitrary or stub directory.
func TestDefaultRegistryRoot_ResolvesRealTree(t *testing.T) {
	root, err := DefaultRegistryRoot()
	if err != nil {
		t.Fatalf("DefaultRegistryRoot: %v", err)
	}
	for _, rel := range []string{
		filepath.Join("registries", "channels.csv"),
		filepath.Join("registries", "frame_types_reserved.csv"),
		filepath.Join("registries", "frame_types_channel.csv"),
		filepath.Join("registries", "tlv_tags.csv"),
		filepath.Join("registries", "error_codes.csv"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("resolved root %s is missing %s: %v", root, rel, err)
		}
	}
}

// TestLoadDefault_PopulatesFromRealRegistries proves Load actually parses
// the on-disk CSVs into non-empty, content-correct maps -- not a stub that
// returns an empty-but-non-nil Registries regardless of what is on disk.
// Every assertion below cross-checks against a value read directly from the
// registries in this task's grounding pass (an independent authority: the
// CSV content, not this package's own logic).
func TestLoadDefault_PopulatesFromRealRegistries(t *testing.T) {
	reg, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	// channels.csv: 20 channels, 0x0000 (Control) .. 0x0013 (Spatial).
	if len(reg.channels) != 20 {
		t.Fatalf("loaded %d channels, want 20 (registries/channels.csv)", len(reg.channels))
	}
	if reg.channels[0x0000] != "Control" {
		t.Fatalf("channel 0x0000 = %q, want Control", reg.channels[0x0000])
	}
	if reg.channels[0x0013] != "Spatial" {
		t.Fatalf("channel 0x0013 = %q, want Spatial", reg.channels[0x0013])
	}
	if _, ok := reg.channels[0x0014]; ok {
		t.Fatal("channel 0x0014 (reserved future-core) loaded as registered -- should not be")
	}
	if _, ok := reg.channels[0xFFFF]; ok {
		t.Fatal("channel 0xFFFF (forbidden) loaded as registered -- should not be")
	}

	// frame_types_reserved.csv: system band is exactly 0x0001..0x000A (10 entries).
	if len(reg.systemFrames) != 10 {
		t.Fatalf("loaded %d system frame types, want 10 (0x0001-0x000A)", len(reg.systemFrames))
	}
	if reg.systemFrames[0x0001] != "PING" {
		t.Fatalf("system frame 0x0001 = %q, want PING", reg.systemFrames[0x0001])
	}
	if reg.systemFrames[0x000A] != "FLOW_UPDATE" {
		t.Fatalf("system frame 0x000A = %q, want FLOW_UPDATE", reg.systemFrames[0x000A])
	}
	if _, ok := reg.systemFrames[0x0000]; ok {
		t.Fatal("frame type 0x0000 (reserved, MUST NOT be used) loaded as a system frame -- should not be")
	}

	// frame_types_channel.csv: 0x0100 is a PER-CHANNEL namespace, not a
	// single global frame type -- (Control, 0x0100) is CLIENT_HELLO while
	// (Memory, 0x0100) is the UNRELATED MEMORY_CREATE_REQ (the composite
	// key is (channel_id, frame_type); frame_type alone recurs across
	// channels, exactly as scripts/validate-frame-types-channel.py's own
	// docstring documents). Both must load as registered, distinctly.
	if _, ok := reg.chanFrames[chanFrameKey{channel: 0x0000, frameType: 0x0100}]; !ok {
		t.Fatal("(Control, 0x0100=CLIENT_HELLO) not loaded from frame_types_channel.csv")
	}
	if _, ok := reg.chanFrames[chanFrameKey{channel: 0x0001, frameType: 0x0100}]; !ok {
		t.Fatal("(Memory, 0x0100=MEMORY_CREATE_REQ) not loaded from frame_types_channel.csv")
	}
	if _, ok := reg.chanFrames[chanFrameKey{channel: 0x0001, frameType: 0x0102}]; !ok {
		t.Fatal("(Memory, 0x0102=MEMORY_READ_REQ) not loaded from frame_types_channel.csv")
	}
	// Governance (0x0004) is a registered channel (channels.csv) but has
	// ZERO rows in frame_types_channel.csv (no companion/application frame
	// types assigned to it yet) -- a channel-specific frame type must NOT
	// be registered for it.
	if _, ok := reg.chanFrames[chanFrameKey{channel: 0x0004, frameType: 0x0100}]; ok {
		t.Fatal("(Governance, 0x0100) loaded as registered -- Governance has no frame_types_channel.csv rows at all")
	}

	// tlv_tags.csv: 0x0A (CertVerify) is assigned; 0x0E, 0x0F, 0x11 are
	// documented registry gaps (npamp-wire.cddl §6: "tags 0x0E, 0x0F, 0x11
	// have no assignment"); 0x14 is reserved-for-companion (no real name).
	if reg.tlvTags[0x0A] != "CertVerify" {
		t.Fatalf("TLV tag 0x0A = %q, want CertVerify", reg.tlvTags[0x0A])
	}
	for _, gap := range []uint16{0x0E, 0x0F, 0x11, 0x14} {
		if _, ok := reg.tlvTags[gap]; ok {
			t.Fatalf("TLV tag 0x%02X loaded as assigned -- it is an unassigned/reserved gap", gap)
		}
	}

	// error_codes.csv: codes 1-10 assigned; 0 is reserved and excluded.
	if len(reg.errorCodes) != 10 {
		t.Fatalf("loaded %d error codes, want 10 (codes 1-10)", len(reg.errorCodes))
	}
	if reg.errorCodes[1] != "unexpected_message" {
		t.Fatalf("error code 1 = %q, want unexpected_message", reg.errorCodes[1])
	}
	if reg.errorCodes[10] != "flow_control_error" {
		t.Fatalf("error code 10 = %q, want flow_control_error", reg.errorCodes[10])
	}
	if _, ok := reg.errorCodes[0]; ok {
		t.Fatal("error code 0 (reserved, MUST NOT be sent) loaded as assigned -- should not be")
	}
}

// TestParseCodePoint proves the shared hex/decimal parser handles both
// forms error_codes.csv mixes, and correctly rejects hyphenated ranges.
func TestParseCodePoint(t *testing.T) {
	cases := []struct {
		tok     string
		wantVal uint64
		wantOK  bool
	}{
		{"0x0001", 1, true},
		{"0x000A", 10, true},
		{"1", 1, true},
		{"10", 10, true},
		{"0", 0, true},
		{"0x0030-0x0034", 0, false},
		{"0x000B-0x00FF", 0, false},
		{"", 0, false},
		{"(reserved)", 0, false},
	}
	for _, c := range cases {
		v, ok := parseCodePoint(c.tok)
		if ok != c.wantOK || (ok && v != c.wantVal) {
			t.Errorf("parseCodePoint(%q) = (%d, %v), want (%d, %v)", c.tok, v, ok, c.wantVal, c.wantOK)
		}
	}
}

// TestLoad_MissingRegistryFails proves Load fails closed when the
// registries directory does not exist, rather than returning a
// falsely-empty-but-successful Registries.
func TestLoad_MissingRegistryFails(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("Load accepted a root with no registries/ subdirectory")
	}
}
