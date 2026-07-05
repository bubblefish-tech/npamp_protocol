# build-example.ps1 — build + run the secure-record-layer example (SecureRecordLayer.cs) for the
# N-PAMP C# reference. BCL-only (Npamp.cs, no BouncyCastle).
#
# Two build paths, same net8.0 runtime — the same convention as build-local.ps1 and
# test/build-handshake-kat.ps1: everything is built in a TEMP dir from an explicit file list, so
# no bin/obj ever lands in the source tree.
#   SDK path  (CI / dev hosts): a temp csproj built with `dotnet build -c Release`, run as a dll.
#   csc fallback (no SDK):      Roslyn csc.exe (VS Build Tools) against the installed
#                               Microsoft.NETCore.App 8.0.x shared runtime, run via `dotnet <dll>`.
#
# Exit code = the example's exit code (0 = round-trip recovered the plaintext).

$ErrorActionPreference = 'Stop'
$cs   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path   # impl/csharp
$work = Join-Path $env:TEMP 'npamp_csharp_example'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$haveSdk = $false
try { if ((& dotnet --list-sdks 2>$null) -match '\S') { $haveSdk = $true } } catch { }

if ($haveSdk) {
  # --- SDK path: throwaway csproj in a temp dir, exactly Npamp.cs + SecureRecordLayer.cs ---
  Copy-Item (Join-Path $cs 'Npamp.cs'), (Join-Path $PSScriptRoot 'SecureRecordLayer.cs') $work
  Set-Content (Join-Path $work 'example.csproj') -Encoding UTF8 -Value @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>secure-record-layer</AssemblyName>
    <StartupObject>Sh.Bubblefish.Npamp.Examples.SecureRecordLayer</StartupObject>
  </PropertyGroup>
</Project>
'@
  Push-Location $work
  try { dotnet build -c Release -v q --nologo | Out-Null } finally { Pop-Location }
  & dotnet (Join-Path $work 'bin\Release\net8.0\secure-record-layer.dll')
  exit $LASTEXITCODE
}

# --- csc fallback (mirrors build-local.ps1): Roslyn csc.exe + the 8.0.x shared runtime ---
$vsRoots = @(
  (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio'),
  (Join-Path $env:ProgramFiles 'Microsoft Visual Studio')
) | Where-Object { $_ -and (Test-Path $_) }
$csc = $vsRoots |
  ForEach-Object { Get-ChildItem -Path $_ -Recurse -Filter 'csc.exe' -File -ErrorAction SilentlyContinue } |
  Where-Object { $_.FullName -match 'Roslyn' } |
  Select-Object -First 1 -ExpandProperty FullName
if (-not $csc) { Write-Error 'No .NET SDK and no Roslyn csc.exe (install the .NET SDK or VS Build Tools).'; exit 2 }

$shared = Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.NETCore.App'
$rt = Get-ChildItem -Path $shared -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -like '8.0.*' } |
  Sort-Object { [version]$_.Name } -Descending |
  Select-Object -First 1 -ExpandProperty FullName
if (-not $rt) { Write-Error 'Microsoft.NETCore.App 8.0.x runtime not found.'; exit 2 }

$refs  = 'System.Private.CoreLib','System.Runtime','System.Console','System.Security.Cryptography',
         'System.Text.Encoding.Extensions','System.Runtime.Extensions','System.Memory','System.Collections'
$rargs = $refs | ForEach-Object { "-r:" + (Join-Path $rt ($_ + '.dll')) }
$rcfg  = '{ "runtimeOptions": { "tfm": "net8.0", "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" } } }'

& $csc -nologo -noconfig -nostdlib -t:exe -main:Sh.Bubblefish.Npamp.Examples.SecureRecordLayer `
  -out:"$work\secure-record-layer.dll" @rargs "$cs\Npamp.cs" "$PSScriptRoot\SecureRecordLayer.cs"
if ($LASTEXITCODE -ne 0) { Write-Error 'csc failed (example)'; exit 1 }
Set-Content "$work\secure-record-layer.runtimeconfig.json" -Value $rcfg -Encoding UTF8

& dotnet "$work\secure-record-layer.dll"
exit $LASTEXITCODE
