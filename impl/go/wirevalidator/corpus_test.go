// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package wirevalidator

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// This file drives EVERY full-wire-frame vector in the two pinned test
// vector files that carry one (test-vectors/v1/conformance-corpus.json and
// test-vectors/v1/handshake-flow-kat.json; MANIFEST.sha256-covered,
// independent of this package's own logic) through ValidateBytes, loaded at
// TEST TIME from the on-disk file rather than hand-copied piecemeal -- so
// "accepts every valid frame in the corpus" is enumerated exhaustively and
// stays true if either file's vector set grows, and "rejects every
// MUST-reject frame with the CORRECT structural error" is checked by
// identity (errors.Is against the exact npamp.Err* sentinel the vector's
// own "flags" name), not merely "returned some error".

// ---------------------------------------------------------------------------
// conformance-corpus.json: header.decode group (the only group whose
// vectors are full wire frames -- tlv.decode/crc32c groups carry field-level
// values, not frames).
// ---------------------------------------------------------------------------

type corpusFile struct {
	TestGroups []struct {
		Op    string `json:"op"`
		Tests []struct {
			TcID    int    `json:"tcId"`
			Comment string `json:"comment"`
			In      struct {
				Frame string `json:"frame"`
			} `json:"in"`
			Result string   `json:"result"`
			Flags  []string `json:"flags"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// corpusStructuralError maps a header.decode vector's second flag (its
// specific defect name; the first flag is always the generic "MustReject")
// to the exact npamp sentinel error UnmarshalBinary must return for it, so
// this test asserts identity, not merely non-nil.
var corpusStructuralError = map[string]error{
	"ReservedNonZero": npamp.ErrReservedNonzero,
	"BadCRC":          npamp.ErrBadCRC,
	"BadMagic":        npamp.ErrBadMagic,
	"BadVersion":      npamp.ErrBadVersion,
	"ShortHeader":     npamp.ErrShortHeader,
}

// TestValidateBytes_AllConformanceCorpusHeaderDecodeVectors loads
// test-vectors/v1/conformance-corpus.json at test time and drives EVERY
// header.decode vector through ValidateBytes: tc1 (result=valid) must be
// accepted, and tc2-tc5 (result=invalid) must each be rejected with the
// SPECIFIC npamp structural sentinel its flags name -- proving both halves
// of the F3 accept/reject claim against every full-frame vector this
// corpus file contains, not a hand-picked subset.
func TestValidateBytes_AllConformanceCorpusHeaderDecodeVectors(t *testing.T) {
	root, err := DefaultRegistryRoot()
	if err != nil {
		t.Fatalf("DefaultRegistryRoot: %v", err)
	}
	reg := testRegistries(t)

	raw, err := os.ReadFile(filepath.Join(root, "test-vectors", "v1", "conformance-corpus.json"))
	if err != nil {
		t.Fatalf("read conformance-corpus.json: %v", err)
	}
	var corpus corpusFile
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse conformance-corpus.json: %v", err)
	}

	seenValid, seenInvalid := 0, 0
	for _, group := range corpus.TestGroups {
		if group.Op != "header.decode" {
			continue // the only op whose "in" carries a full wire frame
		}
		for _, tc := range group.Tests {
			if tc.In.Frame == "" {
				t.Fatalf("tcId=%d (%s): header.decode vector has no in.frame", tc.TcID, tc.Comment)
			}
			buf, err := hex.DecodeString(tc.In.Frame)
			if err != nil {
				t.Fatalf("tcId=%d: decode hex frame: %v", tc.TcID, err)
			}
			gotErr := ValidateBytes(reg, buf)

			switch tc.Result {
			case "valid":
				seenValid++
				if gotErr != nil {
					t.Errorf("tcId=%d (%s): ValidateBytes rejected a corpus-valid frame: %v", tc.TcID, tc.Comment, gotErr)
				}
			case "invalid":
				seenInvalid++
				if gotErr == nil {
					t.Errorf("tcId=%d (%s): ValidateBytes accepted a corpus-invalid frame", tc.TcID, tc.Comment)
					continue
				}
				matched := false
				for _, flag := range tc.Flags {
					if want, ok := corpusStructuralError[flag]; ok {
						matched = true
						if !errors.Is(gotErr, want) {
							t.Errorf("tcId=%d (%s): ValidateBytes error = %v, want errors.Is(_, %v) per flag %q", tc.TcID, tc.Comment, gotErr, want, flag)
						}
					}
				}
				if !matched {
					t.Errorf("tcId=%d (%s): no recognized structural-error flag in %v to check against; got error %v", tc.TcID, tc.Comment, tc.Flags, gotErr)
				}
			default:
				t.Fatalf("tcId=%d: unrecognized result %q", tc.TcID, tc.Result)
			}
		}
	}

	if seenValid == 0 {
		t.Fatal("no header.decode result=valid vectors were exercised -- the corpus or the loader has drifted")
	}
	if seenInvalid == 0 {
		t.Fatal("no header.decode result=invalid vectors were exercised -- the corpus or the loader has drifted")
	}
	t.Logf("exercised %d valid + %d invalid header.decode vectors from conformance-corpus.json", seenValid, seenInvalid)
}

// ---------------------------------------------------------------------------
// handshake-flow-kat.json: expected.frames carries the FOUR full wire
// frames of a real 1.5-RTT handshake (CLIENT_HELLO/SERVER_HELLO cleartext,
// SERVER_AUTH/CLIENT_AUTH AEAD-sealed), produced by the reference code path
// and independently re-derived by a from-scratch inline oracle
// (test-vectors/README / the file's own "provenance" field) -- a second,
// independent pinned source from the header.decode vectors above, and the
// ONLY corpus vectors that exercise a channel-specific application-band
// frame type (0x0100-0x0103) alongside the universal system-band vectors.
// ---------------------------------------------------------------------------

type handshakeFlowKAT struct {
	Expected struct {
		Frames struct {
			ClientHello string `json:"client_hello"`
			ServerHello string `json:"server_hello"`
			ServerAuth  string `json:"server_auth"`
			ClientAuth  string `json:"client_auth"`
		} `json:"frames"`
	} `json:"expected"`
}

// TestValidateBytes_AcceptsAllHandshakeFlowKATFrames loads
// test-vectors/v1/handshake-flow-kat.json at test time and proves
// ValidateBytes accepts all four of its pinned full wire frames, checking
// each decodes to the frame TYPE its field name promises (so the test would
// fail loudly if the fixture's field mapping were ever wrong, rather than
// silently validating the wrong frame).
func TestValidateBytes_AcceptsAllHandshakeFlowKATFrames(t *testing.T) {
	root, err := DefaultRegistryRoot()
	if err != nil {
		t.Fatalf("DefaultRegistryRoot: %v", err)
	}
	reg := testRegistries(t)

	raw, err := os.ReadFile(filepath.Join(root, "test-vectors", "v1", "handshake-flow-kat.json"))
	if err != nil {
		t.Fatalf("read handshake-flow-kat.json: %v", err)
	}
	var kat handshakeFlowKAT
	if err := json.Unmarshal(raw, &kat); err != nil {
		t.Fatalf("parse handshake-flow-kat.json: %v", err)
	}

	cases := []struct {
		name     string
		hexFrame string
		wantType uint16 // npamp.Frame.Type's own field type
	}{
		{"client_hello", kat.Expected.Frames.ClientHello, uint16(npamp.FrameClientHello)},
		{"server_hello", kat.Expected.Frames.ServerHello, uint16(npamp.FrameServerHello)},
		{"server_auth", kat.Expected.Frames.ServerAuth, uint16(npamp.FrameServerAuth)},
		{"client_auth", kat.Expected.Frames.ClientAuth, uint16(npamp.FrameClientAuth)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.hexFrame == "" {
				t.Fatalf("expected.frames.%s is empty -- the fixture or the loader has drifted", c.name)
			}
			buf, err := hex.DecodeString(c.hexFrame)
			if err != nil {
				t.Fatalf("decode hex frame: %v", err)
			}
			var f npamp.Frame
			if err := f.UnmarshalBinary(buf); err != nil {
				t.Fatalf("UnmarshalBinary: %v (the pinned KAT frame itself should be structurally valid)", err)
			}
			if f.Type != c.wantType {
				t.Fatalf("frame type = 0x%04X, want 0x%04X (%s) -- fixture field/frame mismatch", f.Type, c.wantType, c.name)
			}
			if f.Channel != uint16(npamp.ChanControl) {
				t.Fatalf("channel = 0x%04X, want Control (0x0000)", f.Channel)
			}
			if err := ValidateBytes(reg, buf); err != nil {
				t.Fatalf("ValidateBytes rejected the pinned %s frame: %v", c.name, err)
			}
		})
	}
}
