#!/usr/bin/env bash
# run-against-peer.sh -- thin runner: stand up ONE side of an N-PAMP live
# handshake + record-layer session, against an arbitrary peer address, for a
# THIRD PARTY's own implementation to connect to (or to dial into).
#
# This is a wrapper, not new protocol code. It builds and runs the SAME
# already-graded binaries the project's interop matrix uses
# (impl/go/cmd/npamp-interop, impl/rust/examples/interop_{client,server}) --
# see impl/go/cmd/npamp-interop/README.md for the full protocol-core
# provenance of those binaries. What this script adds is packaging: a single
# invocation that a stranger to this repository can run, plus an explicit,
# separately-reported "Stage 3" step that re-runs this stack's OWN published,
# non-circular conformance test suite (the same commands CI already grades)
# immediately after a live interop pass, so a reader never confuses "our side
# interoperated with your peer" (interop) with "our side is independently
# conformant" (conformance) -- see THIRD-PARTY-QUICKSTART.md.
#
# Usage:
#   ./run-against-peer.sh --stack go|rust --role server|client --addr HOST:PORT \
#       [--profile standard|high|sovereign] [--skip-conformance]
#
# Examples:
#   ./run-against-peer.sh --stack go   --role server --addr 0.0.0.0:47700
#   ./run-against-peer.sh --stack rust --role client --addr 198.51.100.7:47700 --profile high
#
# Exit 0 iff the requested stage(s) all pass. All paths are repo-relative
# (resolved from this script's location); no absolute build path is embedded.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
run-against-peer.sh -- run one side of a live N-PAMP handshake against a peer

  --stack STACK       go | rust                                  (required)
  --role ROLE         server | client                            (required)
  --addr HOST:PORT    address to listen on (server) or dial (client)  (required)
  --profile PROFILE   standard | high | sovereign (rust only; default standard)
  --skip-conformance  run only Stage 1+2 (live interop); skip Stage 3
  -h, --help          show this message

Stage 1+2 (handshake + record layer): builds and runs the requested reference
stack in the requested role, against --addr, over raw TCP. Reports PASS/FAIL
from this process's own exit status -- a non-zero exit means the handshake,
CertVerify/Finished verification, or the AEAD-protected echo against your peer
did not succeed.

Stage 3 (independent conformance, skipped with --skip-conformance): only runs
if Stage 1+2 passed. Re-runs the SAME command CI already grades for that
stack's own test suite, and reports it as a SEPARATE result -- interoperating
with your peer does not by itself prove either side is spec-conformant.
EOF
}

STACK=""
ROLE=""
ADDR=""
PROFILE="standard"
SKIP_CONFORMANCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --stack) STACK="${2:-}"; shift 2 ;;
    --role) ROLE="${2:-}"; shift 2 ;;
    --addr) ADDR="${2:-}"; shift 2 ;;
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --skip-conformance) SKIP_CONFORMANCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "run-against-peer.sh: unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

case "$STACK" in
  go|rust) ;;
  *) echo "run-against-peer.sh: --stack must be 'go' or 'rust' (got '${STACK}')" >&2; exit 1 ;;
esac
case "$ROLE" in
  server|client) ;;
  *) echo "run-against-peer.sh: --role must be 'server' or 'client' (got '${ROLE}')" >&2; exit 1 ;;
esac
case "$PROFILE" in
  standard|high|sovereign) ;;
  *) echo "run-against-peer.sh: --profile must be standard|high|sovereign (got '${PROFILE}')" >&2; exit 1 ;;
esac
if [ -z "$ADDR" ]; then
  echo "run-against-peer.sh: --addr HOST:PORT is required" >&2; exit 1
fi
if [ "$STACK" = "go" ] && [ "$PROFILE" != "standard" ]; then
  echo "run-against-peer.sh: --stack go only speaks profile 'standard' today (the Go interop harness does not yet offer High/Sovereign); use --stack rust for High/Sovereign" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# hackathon/ -> repo root is one level up.
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GO_DIR="${REPO_ROOT}/impl/go"
RUST_DIR="${REPO_ROOT}/impl/rust"

echo "== run-against-peer: stack=${STACK} role=${ROLE} addr=${ADDR} profile=${PROFILE} =="

STAGE12_PASS=0

if [ "$STACK" = "go" ]; then
  export GOWORK=off
  BIN_DIR="$(mktemp -d)"
  trap 'rm -rf "${BIN_DIR}" 2>/dev/null || true' EXIT
  GO_BIN="${BIN_DIR}/npamp-interop"
  echo "-- Stage 0: building the Go reference interop binary --"
  ( cd "${GO_DIR}" && go build -o "${GO_BIN}" ./cmd/npamp-interop )
  echo "-- Stage 1+2: live handshake + record-layer round trip (Go, role=${ROLE}) --"
  if "${GO_BIN}" -role "${ROLE}" -addr "${ADDR}"; then
    STAGE12_PASS=1
  fi
else
  echo "-- Stage 0: building the Rust reference interop examples --"
  ( cd "${RUST_DIR}" && cargo build --example interop_client --example interop_server )
  RUST_CLIENT="${RUST_DIR}/target/debug/examples/interop_client"
  RUST_SERVER="${RUST_DIR}/target/debug/examples/interop_server"
  [ -f "${RUST_CLIENT}.exe" ] && RUST_CLIENT="${RUST_CLIENT}.exe"
  [ -f "${RUST_SERVER}.exe" ] && RUST_SERVER="${RUST_SERVER}.exe"
  echo "-- Stage 1+2: live handshake + record-layer round trip (Rust, role=${ROLE}, profile=${PROFILE}) --"
  if [ "$ROLE" = "server" ]; then
    if "${RUST_SERVER}" "${ADDR}" --profile "${PROFILE}"; then
      STAGE12_PASS=1
    fi
  else
    if "${RUST_CLIENT}" "${ADDR}" --profile "${PROFILE}"; then
      STAGE12_PASS=1
    fi
  fi
fi

if [ "${STAGE12_PASS}" -ne 1 ]; then
  echo
  echo "STAGE 1+2 (live handshake + record layer vs peer at ${ADDR}): FAIL"
  echo "run-against-peer.sh: FAIL -- see the process output above for the exact error"
  exit 1
fi
echo
echo "STAGE 1+2 (live handshake + record layer vs peer at ${ADDR}): PASS"

if [ "${SKIP_CONFORMANCE}" -eq 1 ]; then
  echo "Stage 3 (independent conformance) skipped (--skip-conformance)."
  echo "run-against-peer.sh: PASS (interop only -- record this in IMPLEMENTATION-STATUS-TEMPLATE.md; do not label it conformant)"
  exit 0
fi

echo
echo "-- Stage 3: independent conformance check of OUR side (does not test the peer) --"
STAGE3_PASS=0
if [ "$STACK" = "go" ]; then
  echo "   command: (cd impl/go && GOWORK=off go test ./... -count=1)   -- same command graded by .github/workflows/conformance.yml's impl-go job"
  if ( cd "${GO_DIR}" && GOWORK=off go test ./... -count=1 ); then
    STAGE3_PASS=1
  fi
else
  echo "   command: (cd impl/rust && cargo test)   -- same command graded by .github/workflows/conformance.yml's rust job / interop.yml's dependency chain"
  if ( cd "${RUST_DIR}" && cargo test ); then
    STAGE3_PASS=1
  fi
fi

if [ "${STAGE3_PASS}" -ne 1 ]; then
  echo
  echo "STAGE 3 (independent conformance, our side only): FAIL"
  echo "run-against-peer.sh: PARTIAL -- interop with your peer PASSED, but our own conformance suite FAILED (this would be a defect in this repository, not in your implementation)"
  exit 1
fi
echo
echo "STAGE 3 (independent conformance, our side only): PASS"
echo
echo "run-against-peer.sh: PASS (interop AND our-side conformance both green -- record the interop result in IMPLEMENTATION-STATUS-TEMPLATE.md; conformance of the PEER side is a separate claim this script cannot make)"
