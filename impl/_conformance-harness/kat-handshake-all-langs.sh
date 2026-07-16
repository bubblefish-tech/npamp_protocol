#!/usr/bin/env bash
# Cross-language HANDSHAKE-KAT gate. Every reference impl that carries a handshake layer must pass the
# standards-anchored, NON-CIRCULAR known-answer tests for the draft-00 binding (spec/10 sections 3,
# 5, 6.2, 6.1) against the pinned vectors in test-vectors/v1 (transcript / key-schedule / finished /
# certverify). Each per-language KAT is three-leg: ANCHOR (FIPS 180-4 / RFC 5869 / RFC 8448 / RFC 4231
# / RFC 8032) + ORACLE (independent reconstruction) + IMPL. Like the AES-GCM Wycheproof gate
# (kat-all-langs.sh), the answers trace to external authorities, so a shared bug across our impls
# cannot pass. The key-schedule KAT (spec/10 §5) proves the full handshake key schedule — HKDF-Extract
# -> handshake_secret -> c_hs/s_hs/master ladder -> finished_key + traffic key/iv — against RFC 5869
# TC1 and an RFC-8448-validated HKDF-Expand-Label oracle (prefix swap "tls13 " -> "n-pamp ").
#
# COVERAGE: this gate runs the nine impls that have a handshake layer — typescript, python,
# rust, java, kotlin, ruby, php, csharp, swift (native `swift`, else via WSL Ubuntu on a Windows
# host). swift additionally executes the KEM-wire KAT's X25519/wire-order/IKM-order legs
# (test-vectors/v1/kem-wire-kat.json); its two ML-KEM-768 legs are tracked SKIPs inside the runner
# (no ML-KEM API in swift-crypto's Crypto product — same decaps deferral as Go, ADR-0007).
# One language is intentionally NOT run here:
#   * go     — the Go handshake layer + its KATs run under the module's own `go test` (impl/go),
#              not this cross-language shell harness.
#
# GATING (positive evidence, mirroring kat-all-langs.sh's '66/66 passed' check): a language is PASS
# only if its runner exits 0 AND emits its positive pass token — exit-0 alone cannot tell "all KATs
# ran and passed" from "zero KATs ran". A missing toolchain is a tracked SKIP (counted + listed in the
# summary) so an ALL-PASS banner can never mask zero coverage.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMPL="$HERE/.."
# test-vectors/ lives at the repository root (= IMPL/..); canonicalize to a clean
# absolute path (no .. segments) so languages that take it as an argument (e.g. kotlin via java.exe)
# resolve it correctly.
VEC="$(cd "$IMPL/.." && pwd)/test-vectors/v1"
[ -d "$VEC" ] || { echo "FATAL: vectors dir not found: $VEC"; exit 1; }
export GOWORK=off

fail=0; ran=0; skips=""
JT=""; JE=""; KT=""; KE=""
trap 'rm -rf "${JT:-}" "${JE:-}" "${KT:-}" "${KE:-}" 2>/dev/null' EXIT INT TERM

# chk LABEL OUTPUT EXIT TOKEN_REGEX — PASS iff exit 0 AND OUTPUT matches TOKEN_REGEX (positive evidence).
chk() {
  ran=$((ran+1))
  if [ "$3" -eq 0 ] && printf '%s' "$2" | grep -Eq "$4"; then
    echo "PASS  $1"
  else
    echo "FAIL  $1 (exit $3; positive token /$4/ not confirmed)"
    printf '%s\n' "$2" | tail -8 | sed 's/^/      /'
    fail=1
  fi
}
skip() { echo "SKIP  $1 ($2)"; skips="$skips $1"; }

# --- typescript (node built-in test runner; positive token: a nonzero 'pass N' with exit 0 => fail 0) ---
if command -v node >/dev/null; then
  o="$(node --test "$IMPL/typescript/test/transcript-kat.test.ts" "$IMPL/typescript/test/key-schedule-kat.test.ts" "$IMPL/typescript/test/finished-kat.test.ts" "$IMPL/typescript/test/certverify-kat.test.ts" "$IMPL/typescript/test/handshake-flow-kat.test.ts" 2>&1)"; ec=$?
  chk typescript "$o" "$ec" 'pass [1-9]'
else skip typescript "no node"; fi

# --- python (positive token: 'PASS test_' present) ---
if command -v python >/dev/null; then
  o=""; ec=0
  for t in transcript key_schedule finished certverify handshake_flow; do
    out="$(PYTHONPATH="$IMPL/python" python "$IMPL/python/tests/test_${t}_kat.py" 2>&1)" || ec=1
    o="$o$out"$'\n'
  done
  chk python "$o" "$ec" 'PASS test_'
else skip python "no python"; fi

# --- rust (integration tests handshake_kat.rs + handshake_flow_kat.rs; positive token: 'N passed' with N>=1) ---
if command -v cargo >/dev/null; then
  o="$(cargo test --quiet --manifest-path "$IMPL/rust/Cargo.toml" --test handshake_kat 2>&1)"; ec=$?
  of="$(cargo test --quiet --manifest-path "$IMPL/rust/Cargo.toml" --test handshake_flow_kat 2>&1)"; ecf=$?
  # Combine both legs: PASS requires BOTH exit 0 AND both emit the positive 'N passed' token.
  if [ "$ec" -ne 0 ] || [ "$ecf" -ne 0 ]; then rec=1; else rec=0; fi
  chk rust "$o"$'\n'"$of" "$rec" 'test result: ok\. [1-9][0-9]* passed'
else skip rust "no cargo"; fi

# --- java (compile main+handshake+tests to a temp dir, run each main(); token: 'ALL PASS') ---
if command -v javac >/dev/null && command -v java >/dev/null; then
  JT="$(mktemp -d)"; JE="$(mktemp)"
  if javac -d "$JT" \
      "$IMPL"/java/src/main/java/sh/bubblefish/npamp/Npamp.java \
      "$IMPL"/java/src/main/java/sh/bubblefish/npamp/Handshake.java \
      "$IMPL"/java/src/test/java/sh/bubblefish/npamp/Kat.java \
      "$IMPL"/java/src/test/java/sh/bubblefish/npamp/TranscriptKat.java \
      "$IMPL"/java/src/test/java/sh/bubblefish/npamp/KeyScheduleKat.java \
      "$IMPL"/java/src/test/java/sh/bubblefish/npamp/FinishedKat.java \
      "$IMPL"/java/src/test/java/sh/bubblefish/npamp/CertVerifyKat.java \
      "$IMPL"/java/src/test/java/sh/bubblefish/npamp/HandshakeFlowKat.java 2>"$JE"; then
    ec=0; jo=""
    for K in TranscriptKat KeyScheduleKat FinishedKat CertVerifyKat HandshakeFlowKat; do
      out="$( cd "$IMPL/java" && java -cp "$JT" "sh.bubblefish.npamp.$K" 2>&1 )" || ec=1
      jo="$jo$out"$'\n'
    done
    chk java "$jo" "$ec" 'ALL PASS'
  else chk java "$(cat "$JE")" 1 'ALL PASS'; fi
  rm -rf "$JT" "$JE"; JT=""; JE=""
else skip java "no javac/java"; fi

# --- kotlin (compile to temp, run on the JVM; cygpath the classpath for java.exe on MSYS; token: 'ALL PASS') ---
if command -v kotlinc >/dev/null && command -v java >/dev/null; then
  case "$OSTYPE" in msys*|cygwin*) KSEP=';'; kp() { cygpath -m "$1"; } ;; *) KSEP=':'; kp() { printf '%s' "$1"; } ;; esac
  KT="$(mktemp -d)"; KE="$(mktemp)"
  if kotlinc \
      "$IMPL"/kotlin/src/main/kotlin/sh/bubblefish/npamp/Npamp.kt \
      "$IMPL"/kotlin/src/main/kotlin/sh/bubblefish/npamp/Handshake.kt \
      "$IMPL"/kotlin/src/test/kotlin/sh/bubblefish/npamp/KatSupport.kt \
      "$IMPL"/kotlin/src/test/kotlin/sh/bubblefish/npamp/TranscriptKat.kt \
      "$IMPL"/kotlin/src/test/kotlin/sh/bubblefish/npamp/KeyScheduleKat.kt \
      "$IMPL"/kotlin/src/test/kotlin/sh/bubblefish/npamp/FinishedKat.kt \
      "$IMPL"/kotlin/src/test/kotlin/sh/bubblefish/npamp/CertVerifyKat.kt \
      "$IMPL"/kotlin/src/test/kotlin/sh/bubblefish/npamp/HandshakeFlowKat.kt -d "$KT/out" 2>"$KE"; then
    STDLIB="$(dirname "$(command -v kotlinc)")/../lib/kotlin-stdlib.jar"
    ec=0; ko=""
    for K in TranscriptKat KeyScheduleKat FinishedKat CertVerifyKat HandshakeFlowKat; do
      out="$( java -cp "$(kp "$KT/out")$KSEP$(kp "$STDLIB")" "sh.bubblefish.npamp.$K" "$(kp "$VEC")" 2>&1 )" || ec=1
      ko="$ko$out"$'\n'
    done
    chk kotlin "$ko" "$ec" 'ALL PASS'
  else chk kotlin "$(cat "$KE")" 1 'ALL PASS'; fi
  rm -rf "$KT" "$KE"; KT=""; KE=""
else skip kotlin "no kotlinc/java"; fi

# --- ruby (token: 'ALL PASS') ---
if command -v ruby >/dev/null; then
  o=""; ec=0
  for t in transcript key_schedule finished certverify handshake_flow; do
    out="$(ruby "$IMPL/ruby/test/${t}_kat.rb" 2>&1)" || ec=1
    o="$o$out"$'\n'
  done
  chk ruby "$o" "$ec" 'ALL PASS'
else skip ruby "no ruby"; fi

# --- php (token: 'ALL PASS') ---
if command -v php >/dev/null; then
  o=""; ec=0
  for t in transcript key_schedule finished certverify handshake_flow; do
    out="$(php "$IMPL/php/test/${t}_kat.php" 2>&1)" || ec=1
    o="$o$out"$'\n'
  done
  chk php "$o" "$ec" 'ALL PASS'
else skip php "no php"; fi

# --- csharp (BouncyCastle Ed25519; build via the dedicated script: SDK PackageReference, else csc; token: 'ALL PASS') ---
if command -v pwsh >/dev/null; then
  o="$(pwsh -NoProfile -File "$IMPL/csharp/test/build-handshake-kat.ps1" 2>&1)"; ec=$?
  chk csharp "$o" "$ec" 'ALL PASS'
else skip csharp "no pwsh (run csharp/test/build-handshake-kat.ps1 where the .NET SDK or Roslyn csc is available)"; fi

# --- swift (executable npamp-handshake-kat: all five vectors incl. KEM-wire; native `swift` on
# Linux/macOS, else via WSL Ubuntu on a Windows host — swift/run.sh builds + runs; args passed
# positionally with a Windows drive-letter to WSL-mount path conversion to avoid MSYS->WSL quoting issues; the runner
# prints its ML-KEM SKIPs and emits 'ALL PASS' only when all 15 executable legs ran and passed) ---
if command -v swift >/dev/null 2>&1; then
  o="$(bash "$IMPL/swift/run.sh" handshake-kat "$VEC" 2>&1)"; ec=$?
  chk swift "$o" "$ec" 'ALL PASS'
elif command -v wsl >/dev/null 2>&1; then
  W="$(echo "$IMPL/swift/run.sh" | sed -E 's|^/([a-zA-Z])/|/mnt/\1/|')"
  V="$(echo "$VEC" | sed -E 's|^/([a-zA-Z])/|/mnt/\1/|')"
  # tr strips the NUL bytes of wsl.exe's own UTF-16 stderr notices; the exit code kept is the KAT's.
  o="$(MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$W" handshake-kat "$V" 2>&1 | tr -d '\0'; exit "${PIPESTATUS[0]}")"; ec=$?
  chk swift "$o" "$ec" 'ALL PASS'
else skip swift "no swift toolchain (native or WSL)"; fi

# --- go: intentionally out of scope here (see header), tracked as a skip ---
skip go "handshake KATs run under go test in impl/go, not this harness"

echo "----"
echo "ran ${ran} language(s); skipped:${skips:- (none)}"
if [ "$fail" -eq 0 ]; then echo "HANDSHAKE KAT GATE: ALL PASS (${ran} ran)"; else echo "HANDSHAKE KAT GATE: FAILURES"; fi
exit $fail
