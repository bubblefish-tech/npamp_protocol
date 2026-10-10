// SPDX-License-Identifier: Apache-2.0

package npamp

import (
	"bytes"
	"errors"
	"testing"
)

// This package implements the Standard profile only. Every function whose
// result depends on the profile's KDF hash refuses High and Sovereign with
// ErrNoSuiteForProfile instead of computing anything, and the same functions
// still succeed at Standard.
func TestKeyScheduleRefusesHighAndSovereign(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, 32)
	th := bytes.Repeat([]byte{0x22}, 32)
	ss := SharedSecrets{MLKEM: bytes.Repeat([]byte{0x33}, 32), X25519: bytes.Repeat([]byte{0x44}, 32)}

	calls := []struct {
		name string
		call func(p Profile) error
	}{
		{"DeriveTrafficSecret", func(p Profile) error {
			_, err := DeriveTrafficSecret(secret, DirClientToServer, 0, AEADAES256GCM, ChanControl, p)
			return err
		}},
		{"HandshakeSecret", func(p Profile) error { _, err := HandshakeSecret(ss, p); return err }},
		{"DeriveHandshakeTrafficSecrets", func(p Profile) error {
			_, _, err := DeriveHandshakeTrafficSecrets(secret, th, p)
			return err
		}},
		{"DeriveMasterSecret", func(p Profile) error { _, err := DeriveMasterSecret(secret, th, p); return err }},
		{"DeriveFinishedKey", func(p Profile) error { _, err := DeriveFinishedKey(secret, p); return err }},
		{"RatchetMasterTier1", func(p Profile) error { _, err := RatchetMasterTier1(secret, 1, p); return err }},
		{"RatchetMasterTier2", func(p Profile) error { _, err := RatchetMasterTier2(secret, secret, th, p); return err }},
		{"DeriveKeyIV", func(p Profile) error { _, _, err := DeriveKeyIV(secret, p); return err }},
		{"NewTranscript", func(p Profile) error { _, err := NewTranscript(p); return err }},
		{"ComputeFinished", func(p Profile) error { _, err := ComputeFinished(secret, th, p); return err }},
		{"VerifyFinished", func(p Profile) error {
			return VerifyFinished(secret, th, bytes.Repeat([]byte{0}, 32), p)
		}},
	}
	for _, c := range calls {
		for _, p := range []Profile{ProfileHigh, ProfileSovereign} {
			t.Run(c.name+"/"+p.String(), func(t *testing.T) {
				if err := c.call(p); !errors.Is(err, ErrNoSuiteForProfile) {
					t.Fatalf("%s(%s) error = %v, want ErrNoSuiteForProfile", c.name, p, err)
				}
			})
		}
		t.Run(c.name+"/Standard_control", func(t *testing.T) {
			// VerifyFinished legitimately reports a mismatch for the dummy MAC; every
			// other call must succeed. Neither may report the refusal.
			if err := c.call(ProfileStandard); errors.Is(err, ErrNoSuiteForProfile) {
				t.Fatalf("%s(Standard) refused: %v", c.name, err)
			} else if err != nil && c.name != "VerifyFinished" {
				t.Fatalf("%s(Standard): %v", c.name, err)
			}
		})
	}
}

// A profile code the registry does not define is refused the same way.
func TestKeyScheduleRefusesUnknownProfile(t *testing.T) {
	if _, err := NewTranscript(Profile(0x7f)); !errors.Is(err, ErrNoSuiteForProfile) {
		t.Fatalf("NewTranscript(unknown) error = %v, want ErrNoSuiteForProfile", err)
	}
}
