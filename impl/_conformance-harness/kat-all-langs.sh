#!/usr/bin/env bash
# Independent crypto KAT gate. Every language's AES-256-GCM seal/open must reproduce
# the Google/C2SP Project Wycheproof verdicts on _shared/wycheproof/aesgcm_kat.tsv
# (66 vectors = 39 valid + 27 known-attack invalid). Unlike the golden vectors, these
# come from an authority that never saw our code, so a shared crypto bug cannot pass.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
IMPL="$HERE/.."
TSV="$IMPL/../../_shared/wycheproof/aesgcm_kat.tsv"
fail=0
chk() { # $1=label $2=output $3=exit
  if printf '%s' "$2" | grep -q "66/66 passed" && [ "$3" -eq 0 ]; then
    echo "PASS  $1"
  else
    echo "FAIL  $1 (exit $3) :: $2"; fail=1
  fi
}
export GOWORK=off

if command -v python >/dev/null; then
  o="$(python "$IMPL/python/test/kat_aesgcm_wycheproof.py" "$TSV" 2>/dev/null)"; chk python "$o" $?
else echo "SKIP  python"; fi

if command -v go >/dev/null; then
  o="$(go -C "$IMPL/go" run ./cmd/npamp-kat "$TSV" 2>/dev/null)"; chk go "$o" $?
else echo "SKIP  go"; fi

if command -v cargo >/dev/null; then
  o="$(cargo run --quiet --manifest-path "$IMPL/rust/Cargo.toml" --bin npamp-kat -- "$TSV" 2>/dev/null)"; chk rust "$o" $?
else echo "SKIP  rust"; fi

if command -v node >/dev/null; then
  o="$(node "$IMPL/typescript/bin/npamp-kat.ts" "$TSV" 2>/dev/null)"; chk typescript "$o" $?
else echo "SKIP  typescript"; fi

if command -v javac >/dev/null && command -v java >/dev/null; then
  JT="$(mktemp -d)"
  if javac -d "$JT" "$IMPL/java/src/main/java/sh/bubblefish/npamp/Npamp.java" \
      "$IMPL/java/src/test/java/sh/bubblefish/npamp/KatAesGcmWycheproof.java" 2>/dev/null; then
    o="$(java -cp "$JT" sh.bubblefish.npamp.KatAesGcmWycheproof "$TSV" 2>/dev/null)"; chk java "$o" $?
  else echo "FAIL  java (compile)"; fail=1; fi
  rm -rf "$JT"
else echo "SKIP  java"; fi

if command -v dotnet >/dev/null && dotnet --list-sdks 2>/dev/null | grep -q .; then
  CT="$(mktemp -d)"
  cp "$IMPL/csharp/Npamp.cs" "$IMPL/csharp/test/KatAesGcm.cs" "$CT/"
  cat > "$CT/kat.csproj" <<'CSPROJ'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>npamp-kat</AssemblyName>
    <StartupObject>Sh.Bubblefish.Npamp.KatAesGcm</StartupObject>
  </PropertyGroup>
</Project>
CSPROJ
  ( cd "$CT" && dotnet build -c Release -v q --nologo >/dev/null 2>&1 )
  o="$(dotnet "$CT/bin/Release/net8.0/npamp-kat.dll" "$TSV" 2>/dev/null)"; chk csharp "$o" $?
  rm -rf "$CT"
else echo "SKIP  csharp (no .NET SDK; build via csharp/build-local.ps1)"; fi

if command -v ruby >/dev/null; then
  o="$(ruby "$IMPL/ruby/test/kat_aesgcm.rb" "$TSV" 2>/dev/null)"; chk ruby "$o" $?
else echo "SKIP  ruby"; fi

if command -v php >/dev/null; then
  o="$(php "$IMPL/php/test/kat_aesgcm.php" "$TSV" 2>/dev/null)"; chk php "$o" $?
else echo "SKIP  php"; fi

if command -v kotlinc >/dev/null && command -v java >/dev/null; then
  case "$OSTYPE" in msys*|cygwin*) KSEP=';'; kpath() { cygpath -m "$1"; } ;; *) KSEP=':'; kpath() { printf '%s' "$1"; } ;; esac
  KT="$(mktemp -d)"
  if kotlinc "$IMPL"/kotlin/src/main/kotlin/sh/bubblefish/npamp/Npamp.kt \
      "$IMPL"/kotlin/src/test/kotlin/sh/bubblefish/npamp/KatAesGcm.kt -d "$KT/out" 2>/dev/null; then
    STDLIB="$(dirname "$(command -v kotlinc)")/../lib/kotlin-stdlib.jar"
    o="$(java -cp "$(kpath "$KT/out")$KSEP$(kpath "$STDLIB")" sh.bubblefish.npamp.KatAesGcm "$(kpath "$TSV")" 2>/dev/null)"; chk kotlin "$o" $?
  else echo "FAIL  kotlin (compile)"; fail=1; fi
  rm -rf "$KT"
else echo "SKIP  kotlin"; fi

# swift: native on Linux/macOS, else via WSL Ubuntu (Windows host). Args positional.
if command -v swift >/dev/null 2>&1; then
  o="$(bash "$IMPL/swift/run.sh" kat "$TSV" 2>/dev/null)"; chk swift "$o" $?
elif command -v wsl >/dev/null 2>&1; then
  W="$(echo "$IMPL/swift/run.sh" | sed -E 's|^/([a-zA-Z])/|/mnt/\1/|')"
  T="$(echo "$TSV" | sed -E 's|^/([a-zA-Z])/|/mnt/\1/|')"
  o="$(MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$W" kat "$T" 2>/dev/null)"; chk swift "$o" $?
else echo "SKIP  swift"; fi

echo "----"
[ "$fail" -eq 0 ] && echo "KAT GATE: ALL PASS" || echo "KAT GATE: FAILURES"
exit $fail
