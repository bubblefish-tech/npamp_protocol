#!/usr/bin/env bash
# Build the Swift package once and run one target executable.
# Runs natively on Linux/macOS CI, or inside WSL Ubuntu on a Windows host
# (Swift toolchain at ~/swift-toolchain). The .build scratch dir is kept OUT of the
# package tree so no build output is tracked in the repository.
#   Usage: run.sh <vectors|conformance|kat|handshake-kat> [args…]
#     kat            takes the Wycheproof TSV path
#     handshake-kat  takes the test-vectors/v1 directory (optional; auto-resolves)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export PATH="$HOME/swift-toolchain/usr/bin:${PATH:-}"
target="npamp-${1:-vectors}"; shift || true
scratch="${NPAMP_SWIFT_SCRATCH:-$HOME/npamp-swift-build}"
swift build -c release --package-path "$HERE" --scratch-path "$scratch" >/dev/null 2>&1 || exit 1
exec "$scratch/release/$target" "$@"
