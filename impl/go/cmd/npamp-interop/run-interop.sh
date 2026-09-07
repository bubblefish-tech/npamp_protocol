#!/usr/bin/env bash
# Go<->Rust<->Python N-PAMP handshake interop runner (serial, cross-process).
#
# Builds the Go interop harness (this cmd) and the Rust interop examples, then
# runs the live 1.5-RTT mutually-authenticated N-PAMP handshake + one application
# frame over TCP loopback across three independent, non-shared-codebase stacks
# (Go's crypto/mlkem+crypto/ecdh+crypto/ed25519 stdlib, Rust's ml-kem crate,
# Python's pure-Python kyber-py FIPS-203 ML-KEM + the `cryptography` package's
# X25519/Ed25519):
#   A) Go server     <-> Rust client
#   B) Rust server   <-> Go client
#   C) Go server     <-> Python client
#   D) Python server <-> Go client
# (Rust<->Python is not required: R4.3 needs only >=2 independent legs, already
# satisfied by A/B; legs C/D close the Python leg's own deferred cross-process
# clause -- a deferred cross-process interop item -- against the same Go anchor A/B already use.)
# Exit 0 iff every direction completes the handshake and the echoed frame matches.
#
# All paths are repo-relative (resolved from this script's location); no absolute
# build path is embedded. Requires a Go toolchain, a Rust toolchain, and a Python
# 3.9+ toolchain (`python3` or `python` on PATH, or set PYTHON_BIN) with the
# `session` extra installed (`pip install -e impl/python[session]` --
# `cryptography` + `kyber-py`) on PATH.
#
#   ./run-interop.sh [PORT]     # PORT defaults to 47700
set -euo pipefail

# impl/go is a STANDALONE module. If an unrelated go.work anywhere up the
# ancestor tree (or a GOWORK env var / go env setting) lists other modules,
# `go build ./cmd/...` fails with "directory ... is contained in a module that
# is not one of the workspace modules listed in go.work". Force single-module
# mode so the build is independent of any ambient workspace.
export GOWORK=off

PORT="${1:-47700}"
HOST="127.0.0.1"
ADDR="${HOST}:${PORT}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# impl/go/cmd/npamp-interop -> repo root is four levels up.
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
GO_DIR="${REPO_ROOT}/impl/go"
RUST_DIR="${REPO_ROOT}/impl/rust"
PY_DIR="${REPO_ROOT}/impl/python"
BIN_DIR="$(mktemp -d)"
GO_BIN="${BIN_DIR}/npamp-interop"
RUST_CLIENT="${RUST_DIR}/target/debug/examples/interop_client"
RUST_SERVER="${RUST_DIR}/target/debug/examples/interop_server"
[ -f "${RUST_CLIENT}.exe" ] && RUST_CLIENT="${RUST_CLIENT}.exe"
[ -f "${RUST_SERVER}.exe" ] && RUST_SERVER="${RUST_SERVER}.exe"

# Resolve the Python interpreter for legs C/D. PYTHON_BIN overrides; otherwise
# prefer python3 (the interpreter name pyproject.toml's `requires-python`
# targets), falling back to `python` (e.g. some Windows dev setups only expose
# that name). Neither present is a hard failure only once legs C/D actually run.
PYTHON_BIN="${PYTHON_BIN:-}"
if [ -z "${PYTHON_BIN}" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "run-interop.sh: no python3/python on PATH (needed for legs C/D); set PYTHON_BIN to override" >&2
    exit 1
  fi
fi

cleanup() { rm -rf "${BIN_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

echo "== building Go interop harness =="
( cd "${GO_DIR}" && go build -o "${GO_BIN}" ./cmd/npamp-interop )

echo "== building Rust interop examples =="
( cd "${RUST_DIR}" && cargo build --example interop_client --example interop_server )
RUST_CLIENT="${RUST_DIR}/target/debug/examples/interop_client"
RUST_SERVER="${RUST_DIR}/target/debug/examples/interop_server"
[ -f "${RUST_CLIENT}.exe" ] && RUST_CLIENT="${RUST_CLIENT}.exe"
[ -f "${RUST_SERVER}.exe" ] && RUST_SERVER="${RUST_SERVER}.exe"

run_pair() {
  local name="$1" server_cmd="$2" client_cmd="$3"
  echo
  echo "== ${name} =="
  ${server_cmd} &
  local srv_pid=$!

  # Readiness by RETRYING THE ACTUAL CLIENT, not a throwaway /dev/tcp probe.
  # Both interop servers do a SINGLE one-shot Accept(): a probe socket would be
  # consumed as that one accept, and the server would then run the handshake
  # against the immediately-closed probe connection — breaking the direction.
  # Instead we redial with the real client until it connects (server finished
  # binding) or the server process has exited (a genuine failure, not a
  # not-yet-listening race). The client fails fast on connection-refused, so
  # early retries are cheap; a successful dial proceeds straight to the
  # handshake and consumes the server's one accept exactly once.
  local client_rc=1 attempt
  for attempt in $(seq 1 50); do
    set +e
    ${client_cmd}
    client_rc=$?
    set -e
    [ "${client_rc}" -eq 0 ] && break
    # Server gone => stop; the failure is real (handshake/echo fail or crash),
    # not the server still coming up.
    kill -0 "${srv_pid}" 2>/dev/null || break
    sleep 0.1
  done

  local srv_rc=0
  set +e
  wait "${srv_pid}"; srv_rc=$?
  set -e
  if [ "${client_rc}" -ne 0 ] || [ "${srv_rc}" -ne 0 ]; then
    echo "FAIL: ${name} (client rc=${client_rc}, server rc=${srv_rc})"; return 1
  fi
  echo "OK: ${name}"
}

run_pair "A) Go server <-> Rust client" \
  "${GO_BIN} -role server -addr ${ADDR}" \
  "${RUST_CLIENT} ${ADDR}"

run_pair "B) Rust server <-> Go client" \
  "${RUST_SERVER} ${ADDR}" \
  "${GO_BIN} -role client -addr ${ADDR}"

run_pair "C) Go server <-> Python client" \
  "${GO_BIN} -role server -addr ${ADDR}" \
  "${PYTHON_BIN} ${PY_DIR}/examples/interop_client.py ${ADDR}"

run_pair "D) Python server <-> Go client" \
  "${PYTHON_BIN} ${PY_DIR}/examples/interop_server.py ${ADDR}" \
  "${GO_BIN} -role client -addr ${ADDR}"

echo
echo "ALL INTEROP DIRECTIONS PASSED"
