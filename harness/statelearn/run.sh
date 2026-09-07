#!/usr/bin/env bash
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# T18.2 (R18.2) run recipe for Linux/macOS/CI (GitHub Actions ubuntu-latest runners carry
# java out of the box). Windows PowerShell equivalent: README.md "Run on Windows".
#
# Builds the Go stdio SUL, compiles the Java LearnLib harness, learns BOTH roles against the
# REAL N-PAMP Go SDK, then diffs the learned models against the draft-derived reference
# table. Exits non-zero if the build/learn/diff fails OR if the diff finds ANY mismatch —
# this script IS the CI gate (wire it into conformance.yml as a single step).
#
# No Maven: the ONE verified LearnLib 0.18.0 uber-jar (lib/, SHA1-pinned — see README.md) is
# everything javac/java need on the classpath. POSIX classpath separator is ':' (Windows
# uses ';' — see the PowerShell recipe).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "=== [0/4] fetch + SHA-verify the LearnLib jar (not committed) ==="
./fetch-jar.sh

echo "=== [1/4] build the Go SUL ==="
( cd sul && GOWORK=off go build -o statelearn-sul . )

echo "=== [2/4] compile the Java LearnLib harness ==="
mkdir -p classes
javac -cp lib/learnlib-distribution-0.18.0-dependencies-bundle.jar -d classes \
    GoProcessSUL.java LearnedModel.java NpampStateLearner.java

echo "=== [3/4] learn both roles against the REAL SDK ==="
java -cp "lib/learnlib-distribution-0.18.0-dependencies-bundle.jar:classes" \
    NpampStateLearner sul/statelearn-sul .

echo "=== [4/4] diff the learned models against the draft-derived reference table ==="
python3 diff_model.py --dir .
