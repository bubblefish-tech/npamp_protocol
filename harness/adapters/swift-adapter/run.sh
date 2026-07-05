#!/usr/bin/env bash
# Build the Swift conformance adapter once, then exec it as the runner's "testee".
# Runs natively on Linux/macOS, or inside WSL Ubuntu on a Windows host
# (Swift toolchain at ~/swift-toolchain). The .build scratch dir is kept OUT of
# the package tree so no build output is tracked in the repository.
#
# The adapter speaks the length-prefixed JSON contract on stdin/stdout; this
# wrapper must pass those bytes through untouched (no echo, no stray stdout).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/swift-toolchain/usr/bin:${PATH:-}"
scratch="${NPAMP_SWIFT_ADAPTER_SCRATCH:-$HOME/npamp-swift-adapter-build}"
# Build quietly; all build chatter goes to stderr so it never corrupts the
# stdout byte framing the runner reads.
swift build -c release --package-path "$HERE" --scratch-path "$scratch" 1>&2 || exit 1
exec "$scratch/release/npamp-adapter"
