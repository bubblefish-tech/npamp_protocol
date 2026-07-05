# build-local.ps1 — build + verify the N-PAMP C# reference on a host that has the
# .NET runtime but no SDK (so `dotnet build` is unavailable). Uses the Roslyn
# csc.exe shipped with Visual Studio / VS Build Tools to compile against the
# installed Microsoft.NETCore.App shared runtime, then runs via `dotnet <dll>`.
#
# Produces the same result the CI `dotnet run` / `dotnet test` path produces:
#   - the generator output is byte-compared against _shared/conformance-vectors/vectors.json
#   - the conformance test is executed (exit 0 = all pass)
#
# Exit code 0 only if the generator is byte-identical AND the test passes.

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$cs   = $PSScriptRoot
$vec  = Join-Path $root '_shared\conformance-vectors\vectors.json'
$work = Join-Path $env:TEMP 'npamp_csharp_build'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# --- locate Roslyn csc.exe (any VS edition) ---
$vsRoots = @(
  (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio'),
  (Join-Path $env:ProgramFiles 'Microsoft Visual Studio')
) | Where-Object { $_ -and (Test-Path $_) }
$csc = $vsRoots |
  ForEach-Object { Get-ChildItem -Path $_ -Recurse -Filter 'csc.exe' -File -ErrorAction SilentlyContinue } |
  Where-Object { $_.FullName -match 'Roslyn' } |
  Select-Object -First 1 -ExpandProperty FullName
if (-not $csc) { Write-Error 'Roslyn csc.exe not found (install VS Build Tools).'; exit 2 }

# --- locate the newest Microsoft.NETCore.App 8.0.x shared runtime ---
$shared = Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.NETCore.App'
$rt = Get-ChildItem -Path $shared -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like '8.0.*' } |
  Sort-Object { [version]$_.Name } -Descending |
  Select-Object -First 1 -ExpandProperty FullName
if (-not $rt) { Write-Error 'Microsoft.NETCore.App 8.0.x runtime not found.'; exit 2 }
$rtVer = Split-Path $rt -Leaf

$refs  = 'System.Private.CoreLib','System.Runtime','System.Console','System.Security.Cryptography',
         'System.Text.Encoding.Extensions','System.Runtime.Extensions','System.Memory','System.Collections'
$rargs = $refs | ForEach-Object { "-r:" + (Join-Path $rt ($_ + '.dll')) }
$rcfg  = '{ "runtimeOptions": { "tfm": "net8.0", "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }'

Write-Host "csc:     $csc"
Write-Host "runtime: $rtVer"

# --- compile generator + test ---
& $csc -nologo -noconfig -nostdlib -t:exe -main:Sh.Bubblefish.Npamp.Vectors `
  -out:"$work\npamp-vectors.dll" @rargs "$cs\Npamp.cs" "$cs\Vectors.cs"
if ($LASTEXITCODE -ne 0) { Write-Error 'csc failed (generator)'; exit 1 }
Set-Content "$work\npamp-vectors.runtimeconfig.json" -Value $rcfg -Encoding UTF8

& $csc -nologo -noconfig -nostdlib -t:exe -main:Sh.Bubblefish.Npamp.ConformanceTest `
  -out:"$work\npamp-test.dll" @rargs "$cs\Npamp.cs" "$cs\test\ConformanceTest.cs"
if ($LASTEXITCODE -ne 0) { Write-Error 'csc failed (test)'; exit 1 }
Set-Content "$work\npamp-test.runtimeconfig.json" -Value $rcfg -Encoding UTF8

function Norm($s) { if ($null -eq $s) { return '' }; ($s -replace "`r", "").TrimEnd("`n") }
$want = Norm (Get-Content -Raw -LiteralPath $vec)

# --- run generator, byte-compare ---
& dotnet "$work\npamp-vectors.dll" 1>"$work\out.txt" 2>$null
$got = Norm (Get-Content -Raw "$work\out.txt")
$vectorsOk = $got -eq $want
Write-Host ($vectorsOk ? "PASS  csharp vectors (byte-identical)" : "FAIL  csharp vectors")

# --- run conformance test ---
& dotnet "$work\npamp-test.dll"
$testOk = $LASTEXITCODE -eq 0

if ($vectorsOk -and $testOk) { Write-Host 'CSHARP OK'; exit 0 } else { exit 1 }
