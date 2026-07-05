#!/usr/bin/env pwsh
# verify-pins.ps1  (in-slice copy)
#
# Recompute and compare every pinned hash for the N-PAMP open-bytes set, then fail loud on drift.
# Covers: the canonical draft + conformance corpus named in PIN.json, and every entry listed in
# MANIFEST.sha256 (draft, registries, spec, conformance corpus + KAT vectors + schemas).
#
# This is the gate PIN.json's note refers to. It recomputes SHA-256 over the actual bytes on disk and
# compares to the frozen expected values. Exit 0 only if every pinned file exists and matches; exit 1
# on ANY missing/mismatched/unparseable entry.
#
# This copy lives INSIDE the publishable slice (scripts/verify-pins.ps1) so the slice is
# self-contained when staged to the public repo. -Root is the directory that holds PIN.json +
# MANIFEST.sha256; by default it resolves to the repo root (this script's parent).
[CmdletBinding()]
param([string]$Root)

$ErrorActionPreference = 'Stop'

if (-not $Root) {
  if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIN.json')) {
    $Root = $PSScriptRoot                                              # script sits beside PIN.json
  } elseif (Test-Path -LiteralPath (Join-Path $PSScriptRoot '..\PIN.json')) {
    $Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path   # scripts/ -> repo root
  } else {
    $Root = $PSScriptRoot
  }
}

$fail = 0

function Test-PinnedHash([string]$relPath, [string]$expected) {
  $full = Join-Path $Root $relPath
  if (-not (Test-Path -LiteralPath $full)) {
    Write-Host "MISSING : $relPath"
    return $false
  }
  $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected.ToLower()) {
    Write-Host "MISMATCH: $relPath"
    Write-Host "    expected $($expected.ToLower())"
    Write-Host "    actual   $actual"
    return $false
  }
  Write-Host "ok      : $relPath"
  return $true
}

$pinPath = Join-Path $Root 'PIN.json'
if (-not (Test-Path -LiteralPath $pinPath)) { Write-Host "PIN.json not found under $Root"; exit 1 }
$pin = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json

Write-Host "== PIN.json pins (root: $Root) =="
if (-not (Test-PinnedHash $pin.canonical_draft $pin.canonical_draft_sha256)) { $fail++ }
if ($pin.PSObject.Properties.Name -contains 'conformance_corpus' -and $pin.conformance_corpus) {
  if (-not (Test-PinnedHash $pin.conformance_corpus $pin.conformance_corpus_sha256)) { $fail++ }
}

$manRel = if ($pin.manifest) { $pin.manifest } else { 'MANIFEST.sha256' }
$manPath = Join-Path $Root $manRel
if (-not (Test-Path -LiteralPath $manPath)) { Write-Host "manifest $manRel not found under $Root"; exit 1 }

Write-Host "== $manRel entries =="
$entries = 0
foreach ($line in Get-Content -LiteralPath $manPath) {
  $t = $line.Trim()
  if ($t -eq '' -or $t.StartsWith('#')) { continue }
  # sha256sum format: <64-hex hash><whitespace>[*]<path> ; path may contain spaces
  $m = [regex]::Match($t, '^([0-9a-fA-F]{64})\s+\*?(.+)$')
  if (-not $m.Success) { Write-Host "UNPARSEABLE: $t"; $fail++; continue }
  $entries++
  if (-not (Test-PinnedHash ($m.Groups[2].Value.Trim()) ($m.Groups[1].Value))) { $fail++ }
}

Write-Host ""
if ($fail -gt 0) { Write-Host "PINS DRIFT: $fail pinned file(s) failed verification under $Root"; exit 1 }
Write-Host "PINS OK: canonical draft + corpus + $entries manifest entries all match under $Root."
exit 0
