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

# The handshake-kat target now also drives the byte-pinned handshake-FLOW KAT
# (issue #60): swift build already compiled every executableTarget, so run both
# executables and fold their results into one 'ALL PASS' gate. Both legs must
# exit 0 AND each must emit its own 'ALL PASS' positive token (exit-0 alone
# cannot distinguish "all legs ran and passed" from "zero legs ran"). Any other
# target keeps the original single-executable exec path.
if [ "$target" = "npamp-handshake-kat" ]; then
  o1="$("$scratch/release/npamp-handshake-kat" "$@" 2>&1)"; e1=$?
  printf '%s\n' "$o1"
  o2="$("$scratch/release/npamp-handshake-flow-kat" "$@" 2>&1)"; e2=$?
  printf '%s\n' "$o2"
  if [ "$e1" -eq 0 ] && [ "$e2" -eq 0 ] \
     && printf '%s' "$o1" | grep -q 'ALL PASS' \
     && printf '%s' "$o2" | grep -q 'ALL PASS'; then
    echo "SWIFT HANDSHAKE KAT: ALL PASS (handshake-kat + handshake-flow-kat)"
    exit 0
  else
    echo "SWIFT HANDSHAKE KAT: FAILURES (handshake-kat exit $e1, handshake-flow-kat exit $e2)"
    exit 1
  fi
fi
exec "$scratch/release/$target" "$@"
