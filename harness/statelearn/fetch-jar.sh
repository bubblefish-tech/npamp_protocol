#!/usr/bin/env bash
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Fetch + SHA-verify the ONE LearnLib 0.18.0 uber-jar the T18.2 harness needs. The jar is
# 7.87 MB and is NOT committed (repo hygiene); this script downloads it from Maven Central
# and verifies its SHA-256 (and SHA-1) BEFORE it is used, refusing a mismatch (fail-closed).
# Run once before run.sh / the manual Windows recipe. Idempotent: a present, verified jar is
# left untouched.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

JAR="lib/learnlib-distribution-0.18.0-dependencies-bundle.jar"
URL="https://repo1.maven.org/maven2/de/learnlib/distribution/learnlib-distribution/0.18.0/learnlib-distribution-0.18.0-dependencies-bundle.jar"
# Pinned digests (verify locally with `sha256sum lib/*.jar` / `sha1sum lib/*.jar`).
SHA256="bcee286332a5bb331fe60123fe93158caa1768263c13a9bb21a197833b65e31a"
SHA1="9955436f4531f7861c21f16a977d952b6b6c5617"

mkdir -p lib

if [ -f "$JAR" ] && echo "${SHA256}  ${JAR}" | sha256sum -c - >/dev/null 2>&1; then
  echo "jar present and SHA-256 verified: ${JAR}"
  exit 0
fi

echo "fetching ${URL}"
curl -fSL -o "$JAR" "$URL"

if ! echo "${SHA256}  ${JAR}" | sha256sum -c - >/dev/null 2>&1; then
  echo "SHA-256 MISMATCH for ${JAR} — refusing the downloaded jar" >&2
  rm -f "$JAR"
  exit 1
fi
echo "fetched + SHA-256 verified: ${JAR}"
echo "  SHA-256 ${SHA256}"
echo "  SHA-1   ${SHA1}"
