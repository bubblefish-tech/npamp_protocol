#!/usr/bin/env bash
# all-gates.sh — single entry point that runs every N-PAMP conformance / KAT gate with HONEST
# ran/skipped accounting. A gate is RUN only when its prerequisites (toolchain / corpus) are present;
# otherwise it is a tracked SKIP with a reason. "ALL PASS" is reported only if every gate that RAN
# passed — a SKIP never counts as green, so a missing toolchain or an externally-provided corpus can NOT mask
# a coverage gap. This mirrors the ran/skipped discipline of kat-handshake-all-langs.sh.
#
# Gates:
#   1. handshake-kat   — kat-handshake-all-langs.sh (transcript / key-schedule / Finished / CertVerify,
#                        in-tree vectors). Self-contained — always runnable where bash + a toolchain exist.
#   2. schema-validate — scripts/validate-schemas.py (structural JSON-Schema validation of every vector).
#                        Needs python + the jsonschema library.
#   3. verify-pins     — scripts/verify-pins.ps1 (recompute + compare every pinned SHA-256). Needs pwsh.
#   4. aesgcm-wycheproof — kat-all-langs.sh (AES-256-GCM record layer vs Project Wycheproof). Its corpus
#                        (_shared/wycheproof/aesgcm_kat.tsv) is provided outside this open repository —
#                        SKIP when absent so a published copy never silent-greens it.
#   5. conformance-drift — run-all-langs.sh (regenerate conformance vectors, compare to the pinned corpus).
#                        Its corpus (_shared/conformance-vectors/vectors.json) is also provided externally.
#
# Run: bash all-gates.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GH="$(cd "$HERE/../.." && pwd)"          # _conformance-harness -> impl -> repo root
SHARED="${NPAMP_SHARED_DIR:-$GH/_shared}"   # externally-provided corpus (see README); set NPAMP_SHARED_DIR to its location

fail=0; ran=0; skips=""

rungate() {  # rungate LABEL CMD [ARGS...]
  local label="$1"; shift
  ran=$((ran+1))
  echo "──── $label ────────────────────────────────────────"
  if "$@"; then echo "PASS  $label"; else echo "FAIL  $label"; fail=1; fi
  echo
}
skipgate() { echo "SKIP  $1 ($2)"; skips="$skips $1"; }

# 1. handshake KAT gate (self-contained)
if command -v bash >/dev/null; then
  rungate handshake-kat bash "$HERE/kat-handshake-all-langs.sh"
else
  skipgate handshake-kat "no bash"
fi

# 2. vector JSON-Schema validation (structural)
if command -v python >/dev/null && python -c "import jsonschema" >/dev/null 2>&1; then
  rungate schema-validate python "$GH/scripts/validate-schemas.py"
else
  skipgate schema-validate "no python+jsonschema"
fi

# 3. pin verification (recompute + compare SHA-256)
if command -v pwsh >/dev/null; then
  rungate verify-pins pwsh -NoProfile -File "$GH/scripts/verify-pins.ps1"
else
  skipgate verify-pins "no pwsh"
fi

# 4. AES-256-GCM Wycheproof KAT gate (corpus provided externally)
if [ -f "$SHARED/wycheproof/aesgcm_kat.tsv" ]; then
  rungate aesgcm-wycheproof bash "$HERE/kat-all-langs.sh"
else
  skipgate aesgcm-wycheproof "_shared/wycheproof corpus not present (provided outside this open repository)"
fi

# 5. conformance-vector drift gate (corpus provided externally)
if [ -f "$SHARED/conformance-vectors/vectors.json" ]; then
  rungate conformance-drift bash "$HERE/run-all-langs.sh"
else
  skipgate conformance-drift "_shared/conformance-vectors corpus not present (provided outside this open repository)"
fi

echo "════════════════════════════════════════════════════"
echo "ran ${ran} gate(s); skipped:${skips:- (none)}"
if [ "$fail" -eq 0 ]; then echo "ALL GATES: ALL PASS (${ran} ran)"; else echo "ALL GATES: FAILURES"; fi
exit $fail
