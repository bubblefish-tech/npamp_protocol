module github.com/bubblefish-tech/npamp_protocol/impl/go

// N-PAMP draft-bubblefish-npamp-02 reference implementation (Go).
// Library floor is normally latest-minus-one per BubbleFish Engineering
// Policy 1. This module is a DELIBERATE, maintainer-approved exception
// (approved 2026-09-02, P2.10): the floor is pinned to go 1.27 because
// crypto/mldsa (FIPS 204 ML-DSA, incl. deterministic seed-based keygen via
// PrivateKey.NewPrivateKey + SignDeterministic) shipped as a NEW public
// stdlib package only in Go 1.27 (golang/go#77626, milestone Go1.27; Go
// 1.26 carried only an internal, non-public implementation) and there is no
// third-party PQC dependency in this module's zero-external-dependency
// convention. GOTOOLCHAIN=auto builds on the current stable toolchain.
go 1.27
