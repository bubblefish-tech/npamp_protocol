module github.com/bubblefish-tech/npamp_protocol/impl/go

// N-PAMP draft-bubblefish-npamp-02 reference implementation (Go).
// The go directive is the minimum Go version a consumer needs. It moves
// deliberately, never as a side effect of go mod tidy; GOTOOLCHAIN=auto builds
// on the current stable toolchain.
go 1.27

retract [v0.1.0, v0.2.1] // These releases carry profile code that is no longer published in this repository. Use a later release.
