#!/usr/bin/env bash
# Regenerate the conformance vectors from every reference implementation and compare
# (line-ending-normalized) against _shared/conformance-vectors/vectors.json.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VEC="${NPAMP_SHARED_DIR:-$HERE/../_shared}/conformance-vectors/vectors.json"  # externally-provided corpus (see README)
WANT="$(tr -d '\r' < "$VEC")"
fail=0
norm() { tr -d '\r'; }
chk() { if [ "$(printf '%s' "$1" | norm)" = "$WANT" ]; then echo "PASS  $2"; else echo "FAIL  $2 (vector drift)"; fail=1; fi; }

export GOWORK=off
command -v go    >/dev/null && chk "$(go -C "$HERE/../go" run ./cmd/npamp-vectors 2>/dev/null)" go       || echo "SKIP  go"
command -v cargo >/dev/null && chk "$(cargo run --quiet --manifest-path "$HERE/../rust/Cargo.toml" --bin npamp-vectors 2>/dev/null)" rust || echo "SKIP  rust"
command -v python>/dev/null && chk "$(PYTHONPATH="$HERE/../python" python "$HERE/../python/npamp_vectors.py" 2>/dev/null)" python || echo "SKIP  python"
command -v node  >/dev/null && chk "$(node "$HERE/../typescript/bin/npamp-vectors.ts" 2>/dev/null)" typescript || echo "SKIP  typescript"

# java: compile (javac) to a temp dir, then run the generator. No build tool needed.
if command -v javac >/dev/null && command -v java >/dev/null; then
  JOUT="$(mktemp -d)"
  if javac -d "$JOUT" "$HERE"/../java/src/main/java/sh/bubblefish/npamp/*.java 2>/dev/null; then
    chk "$(java -cp "$JOUT" sh.bubblefish.npamp.Vectors 2>/dev/null)" java
  else echo "FAIL  java (compile)"; fail=1; fi
  rm -rf "$JOUT"
else echo "SKIP  java"; fi

# csharp: needs the .NET SDK. Build a throwaway copy in a temp dir so no bin/obj
# is tracked in the repository, then run the produced dll. Hosts with only the .NET runtime
# (no SDK) build instead via csharp/build-local.ps1 (Roslyn csc).
if command -v dotnet >/dev/null && dotnet --list-sdks 2>/dev/null | grep -q .; then
  CSO="$(mktemp -d)"
  cp "$HERE/../csharp/Npamp.cs" "$HERE/../csharp/Vectors.cs" "$HERE/../csharp/Npamp.csproj" "$CSO/"
  ( cd "$CSO" && dotnet build -c Release -v q --nologo >/dev/null 2>&1 )
  chk "$(dotnet "$CSO/bin/Release/net8.0/npamp-vectors.dll" 2>/dev/null)" csharp
  rm -rf "$CSO"
else echo "SKIP  csharp (no .NET SDK; build via csharp/build-local.ps1)"; fi

# ruby: pure-Ruby reference (stdlib OpenSSL; CRC32C hand-rolled). require_relative is
# script-relative, so cwd does not matter.
command -v ruby >/dev/null && chk "$(ruby "$HERE/../ruby/bin/npamp_vectors.rb" 2>/dev/null)" ruby || echo "SKIP  ruby"

# php: pure-PHP reference (ext-openssl; CRC32C hand-rolled). On this host php.ini next
# to the binary enables openssl; CI Linux PHP has it built in.
command -v php >/dev/null && chk "$(php "$HERE/../php/bin/npamp-vectors.php" 2>/dev/null)" php || echo "SKIP  php"

# kotlin: compile the main sources to a temp dir, run on the JVM. The classpath
# separator + path form differ on MSYS/Cygwin (java.exe wants ';' and Windows paths).
if command -v kotlinc >/dev/null && command -v java >/dev/null; then
  case "$OSTYPE" in msys*|cygwin*) KSEP=';'; kpath() { cygpath -m "$1"; } ;; *) KSEP=':'; kpath() { printf '%s' "$1"; } ;; esac
  KT="$(mktemp -d)"
  if kotlinc "$HERE"/../kotlin/src/main/kotlin/sh/bubblefish/npamp/Npamp.kt \
      "$HERE"/../kotlin/src/main/kotlin/sh/bubblefish/npamp/Vectors.kt -d "$KT/out" 2>/dev/null; then
    STDLIB="$(dirname "$(command -v kotlinc)")/../lib/kotlin-stdlib.jar"
    chk "$(java -cp "$(kpath "$KT/out")$KSEP$(kpath "$STDLIB")" sh.bubblefish.npamp.Vectors 2>/dev/null)" kotlin
  else echo "FAIL  kotlin (compile)"; fail=1; fi
  rm -rf "$KT"
else echo "SKIP  kotlin"; fi

# swift: native `swift` on Linux/macOS; otherwise via WSL Ubuntu on a Windows host
# (swift/run.sh builds + runs; args passed positionally to avoid MSYS->WSL quoting issues).
if command -v swift >/dev/null 2>&1; then
  chk "$(bash "$HERE/../swift/run.sh" vectors 2>/dev/null)" swift
elif command -v wsl >/dev/null 2>&1; then
  W="$(echo "$HERE/../swift/run.sh" | sed -E 's|^/([a-zA-Z])/|/mnt/\1/|')"
  chk "$(MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$W" vectors 2>/dev/null)" swift
else echo "SKIP  swift"; fi

exit $fail
