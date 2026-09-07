// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package main

import (
	"crypto/ed25519"
)

// fixedSeed builds a deterministic 32-byte Ed25519 seed from a tag byte, so the driver's
// and the SUT's long-term identities are reproducible across runs. Determinism here is
// cosmetic: every SUL output is abstracted to a frame-type/error-code symbol (never raw key
// bytes), so it has no bearing on learned-model correctness — it just keeps manual debugging
// reproducible (T18.2 plan: "Determinism: use FIXED seeded identities and a FIXED KEM").
func fixedSeed(tag byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = tag
	}
	return seed
}

// driverPriv/driverPub is the scripted deviant peer's long-term Ed25519 identity (used to
// sign CertVerify when the driver completes a valid handshake flight). sutPriv/sutPub is
// handed to the real SDK via sdk.Config.Identity so the SUT's own identity is likewise fixed.
var (
	driverPriv = ed25519.NewKeyFromSeed(fixedSeed(0x11))
	driverPub  = driverPriv.Public().(ed25519.PublicKey)
	sutPriv    = ed25519.NewKeyFromSeed(fixedSeed(0x22))
	sutPub     = sutPriv.Public().(ed25519.PublicKey)
)
