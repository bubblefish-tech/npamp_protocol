# build-handshake-kat.ps1 — build + run the four draft-00 handshake KATs for the C# reference:
#   TranscriptKat, FinishedKat, CertVerifyKat, KeyScheduleKat
#   (binding spec/10 sections 3, 6.2, 6.1, 5; key schedule per draft-00 sections 7.4 + 7.5).
#
# These KATs need Ed25519 (RFC 8032), which the .NET BCL does NOT provide, so the handshake
# layer (Handshake.cs) depends on BouncyCastle.Cryptography 2.6.2 (MIT). SHA-256 + HMAC still
# come from System.Security.Cryptography. The dependency is pinned to that exact version.
#
# Two build paths, same net8.0 runtime + same BouncyCastle 2.6.2 binary:
#   SDK path  (CI):       a temp csproj with <PackageReference Include="BouncyCastle.Cryptography"
#                         Version="2.6.2" />, built with `dotnet build -c Release`, run as a dll.
#                         Mirrors the csharp block of _conformance-harness/kat-all-langs.sh.
#   csc fallback (no SDK): Roslyn csc.exe (VS Build Tools) against the installed shared runtime +
#                         the BouncyCastle 2.6.2 lib/net6.0 assembly (from the NuGet cache, else
#                         downloaded from nuget.org), then run as a dll. Mirrors build-local.ps1.
#
# Each test builds in its OWN temp dir from exactly Npamp.cs + Handshake.cs + that one test file,
# so the BCL-only AES-GCM KAT build (Npamp.cs alone, no BouncyCastle) is unaffected.
#
# Exit 0 iff all four KATs exit 0.

$ErrorActionPreference = 'Stop'
$cs   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path        # impl/csharp
$root = (Resolve-Path (Join-Path $cs '..\..')).Path              # repo root (has test-vectors)
$vec  = Join-Path $root 'test-vectors\v1'
$bcId = 'BouncyCastle.Cryptography'
$bcVer = '2.6.2'

$tests = @(
  @{ Class = 'Sh.Bubblefish.Npamp.TranscriptKat'; File = 'TranscriptKat.cs'; Name = 'transcript-kat' },
  @{ Class = 'Sh.Bubblefish.Npamp.FinishedKat';   File = 'FinishedKat.cs';   Name = 'finished-kat'   },
  @{ Class = 'Sh.Bubblefish.Npamp.CertVerifyKat'; File = 'CertVerifyKat.cs'; Name = 'certverify-kat' },
  @{ Class = 'Sh.Bubblefish.Npamp.KeyScheduleKat'; File = 'KeyScheduleKat.cs'; Name = 'key-schedule-kat' }
)

$haveSdk = $false
try { if ((& dotnet --list-sdks 2>$null) -match '\S') { $haveSdk = $true } } catch { }

# ---------------------------------------------------------------------------
# Resolve the BouncyCastle 2.6.2 lib/net6.0 assembly for the csc fallback path.
# ---------------------------------------------------------------------------
function Resolve-BouncyCastleDll {
  $cache = Join-Path $env:USERPROFILE ".nuget\packages\$($bcId.ToLowerInvariant())\$bcVer\lib\net6.0\$bcId.dll"
  if (Test-Path $cache) { return $cache }
  $work = Join-Path $env:TEMP 'npamp_bc_cache'
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $dll = Join-Path $work "$bcId.dll"
  if (Test-Path $dll) { return $dll }
  $nupkg = Join-Path $work 'bc.nupkg'
  $url = "https://api.nuget.org/v3-flatcontainer/$($bcId.ToLowerInvariant())/$bcVer/$($bcId.ToLowerInvariant()).$bcVer.nupkg"
  Write-Host "downloading $bcId $bcVer from nuget.org ..."
  Invoke-WebRequest -Uri $url -OutFile $nupkg -UseBasicParsing
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg)
  try {
    $entry = $zip.Entries | Where-Object { $_.FullName -eq "lib/net6.0/$bcId.dll" } | Select-Object -First 1
    if (-not $entry) { throw "lib/net6.0/$bcId.dll not found in $bcId $bcVer nupkg" }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dll, $true)
  } finally { $zip.Dispose() }
  return $dll
}

# ---------------------------------------------------------------------------
# SDK path: temp csproj with the pinned PackageReference, dotnet build, run.
# ---------------------------------------------------------------------------
function Invoke-KatSdk($t) {
  $w = Join-Path ([System.IO.Path]::GetTempPath()) ("npamp_hs_" + $t.Name + "_" + [System.Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $w | Out-Null
  try {
    Copy-Item -LiteralPath (Join-Path $cs 'Npamp.cs')               -Destination $w
    Copy-Item -LiteralPath (Join-Path $cs 'Handshake.cs')           -Destination $w
    Copy-Item -LiteralPath (Join-Path $cs (Join-Path 'test' $t.File)) -Destination $w
    @"
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>$($t.Name)</AssemblyName>
    <RootNamespace>Sh.Bubblefish.Npamp</RootNamespace>
    <StartupObject>$($t.Class)</StartupObject>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="$bcId" Version="$bcVer" />
  </ItemGroup>
</Project>
"@ | Set-Content -LiteralPath (Join-Path $w 'kat.csproj') -Encoding UTF8
    & dotnet build -c Release -v q --nologo (Join-Path $w 'kat.csproj') | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "FAIL  $($t.Name) (dotnet build)"; $script:katExit = 1; return }
    & dotnet (Join-Path $w "bin\Release\net8.0\$($t.Name).dll") $vec   # streams test output to host
    $script:katExit = $LASTEXITCODE
  } finally { Remove-Item -Recurse -Force $w -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------------------
# csc fallback: Roslyn csc + shared runtime + BouncyCastle dll, run as a dll.
# ---------------------------------------------------------------------------
function Invoke-KatCsc($t, $csc, $rt, $bc) {
  $w = Join-Path $env:TEMP ("npamp_hs_" + $t.Name)
  Remove-Item -Recurse -Force $w -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $w | Out-Null
  $refs = @()
  Get-ChildItem -Path $rt -Filter '*.dll' |
    Where-Object { ($_.Name -like 'System.*' -or $_.Name -like 'Microsoft.*' -or $_.Name -eq 'netstandard.dll' -or $_.Name -eq 'mscorlib.dll') -and ($_.Name -notlike '*.Native.*') } |
    ForEach-Object { $refs += "-r:$($_.FullName)" }
  $refs += "-r:$bc"
  $lines = @('-nologo','-noconfig','-nostdlib','-t:exe',"-main:$($t.Class)","-out:$w\$($t.Name).dll") + $refs
  $lines += (Join-Path $cs 'Npamp.cs'); $lines += (Join-Path $cs 'Handshake.cs'); $lines += (Join-Path $cs (Join-Path 'test' $t.File))
  $rsp = Join-Path $w 'csc.rsp'
  ($lines | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) | Set-Content -LiteralPath $rsp -Encoding UTF8
  & $csc "@$rsp" | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Host "FAIL  $($t.Name) (csc)"; $script:katExit = 1; return }
  '{ "runtimeOptions": { "tfm": "net8.0", "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }' |
    Set-Content -LiteralPath (Join-Path $w "$($t.Name).runtimeconfig.json") -Encoding UTF8
  Copy-Item -LiteralPath $bc -Destination (Join-Path $w "$bcId.dll") -Force
  & dotnet (Join-Path $w "$($t.Name).dll") $vec   # streams test output to host
  $script:katExit = $LASTEXITCODE
}

$fail = 0
if ($haveSdk) {
  Write-Host "build path: .NET SDK (dotnet build, PackageReference $bcId $bcVer)`n"
  foreach ($t in $tests) {
    Write-Host "=== $($t.Name) ==="
    $script:katExit = 0; Invoke-KatSdk $t; if ($script:katExit -ne 0) { $fail = 1 }
    Write-Host ''
  }
} else {
  $csc = Get-ChildItem -Path @(
            (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio'),
            (Join-Path $env:ProgramFiles 'Microsoft Visual Studio')
          ) -Recurse -Filter 'csc.exe' -File -ErrorAction SilentlyContinue |
          Where-Object { $_.FullName -match 'Roslyn' } | Select-Object -First 1 -ExpandProperty FullName
  if (-not $csc) { Write-Error 'No .NET SDK and no Roslyn csc.exe (install VS Build Tools or the .NET SDK).'; exit 2 }
  $rt = Get-ChildItem -Path (Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.NETCore.App') -Directory -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -like '8.0.*' } | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1 -ExpandProperty FullName
  if (-not $rt) { Write-Error 'Microsoft.NETCore.App 8.0.x runtime not found.'; exit 2 }
  $bc = Resolve-BouncyCastleDll
  Write-Host "build path: Roslyn csc fallback (no .NET SDK)"
  Write-Host "  csc:     $csc"
  Write-Host "  runtime: $(Split-Path $rt -Leaf)"
  Write-Host "  $bcId : $bc`n"
  foreach ($t in $tests) {
    Write-Host "=== $($t.Name) ==="
    $script:katExit = 0; Invoke-KatCsc $t $csc $rt $bc; if ($script:katExit -ne 0) { $fail = 1 }
    Write-Host ''
  }
}

if ($fail -eq 0) { Write-Host 'CSHARP HANDSHAKE KAT: ALL PASS'; exit 0 } else { Write-Host 'CSHARP HANDSHAKE KAT: FAILURES'; exit 1 }
