# spec-parity-audit.ps1 -- repo-side Section F auditor (runs in CI and via esb-gate.ps1).
# Sweeps the WHOLE tree + WHOLE ledger, so it also catches specs authored before the
# discipline existed or by other tools (Section E7). STRUCTURAL, not marker-keyed: coverage is
# keyed on the structural fact (a companion operation-spec file exists) rather than on an
# author-controlled self-label, so a companion that omits the "Class B" phrase cannot slip past.
#
# Modes:
#   -Coverage     : EVERY operation spec under spec/companion/ (minus the named-exempt
#                   vocabulary/index/example docs) MUST have a matching ledger entry with an
#                   owner and a gate. An untracked companion => FAIL (the spec-without-
#                   implementation gap made visible). A tracked gap (impl_status planned /
#                   conformance_status spec-audited, owner+gate present) => PASS: the gate
#                   enforces TRACKING, not completion. Channel INTERFACE pages under
#                   spec/channels/ are declarative (id/purpose/direction), not implementable
#                   operation specs, and are out of scope for impl-parity.
#   -VerifyClaims : honesty in BOTH directions.
#                   Over-claim  -> an impl_status=wired entry whose impl_anchors do not resolve,
#                                  or a conformance_status=graded entry whose vector_anchors do
#                                  not resolve => FAIL (false-green).
#                   Under-claim -> (F6 forward-drift) a 'planned' entry whose impl evidence now
#                                  RESOLVES (its impl_anchors all exist+match, or its
#                                  `test -f <path>` gate path exists) => FAIL: an implementation
#                                  landed but the entry was never promoted planned->wired.
#   (default: run both.)
#
# Exit 0 = clean. Exit 1 = one or more parity violations (printed).
param(
    [string]$RepoRoot = (Get-Location).Path,
    [switch]$Coverage,
    [switch]$VerifyClaims
)
$ErrorActionPreference = 'Continue'
if (-not $Coverage -and -not $VerifyClaims) { $Coverage = $true; $VerifyClaims = $true }

$ledgerPath = Join-Path $RepoRoot '.shippable/spec-parity.json'
if (-not (Test-Path $ledgerPath)) {
    Write-Error "[spec-parity-audit] .shippable/spec-parity.json not found; ledger is required for Section F."
    exit 1
}
try { $ledger = Get-Content $ledgerPath -Raw | ConvertFrom-Json }
catch { Write-Error "[spec-parity-audit] ledger unreadable: $($_.Exception.Message)"; exit 1 }

$violations = @()

# Docs under spec/companion that DEFINE vocabulary / are informative, not gradable operation
# specs. Everything else under spec/companion is a companion that MUST be tracked.
$exemptLeaf = '^(00_companion_index|55_conformance_requirements|56_worked_example|README|TEMPLATE|NEP-\d+)'
# The honest self-label a Class-B / un-graded doc SHOULD carry. Used ONLY as an additional
# honesty assertion now (never as the coverage trigger).
$ungradedPattern = '(?i)(specification[- ]audited|class\s*b\b|no\s+(machine[- ]gradable|bridge)\s+(vector|conformance[- ]vector)|absent\s+a\s+machine[- ]gradable)'

# Index the ledger by spec_anchor basename for O(1) lookup.
$byLeaf = @{}
foreach ($cap in $ledger.capabilities) {
    $a = [string]$cap.spec_anchor
    if ($a) { $byLeaf[[System.IO.Path]::GetFileName(($a -replace '\\','/'))] = $cap }
}

if ($Coverage) {
    $dir = Join-Path $RepoRoot 'spec/companion'
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Filter '*.md' -File -ErrorAction SilentlyContinue | ForEach-Object {
            $leaf = $_.Name
            if ($leaf -imatch $exemptLeaf) { return }
            # STRUCTURAL: this is a companion operation spec; it MUST be tracked -- regardless of
            # whether its text happens to contain the 'Class B' self-label.
            $entry = $byLeaf[$leaf]
            if (-not $entry) {
                $violations += "COVERAGE: companion spec '$leaf' has NO entry in spec-parity.json. Every companion under spec/companion/ must be tracked with an owner and a gate (impl_status may be honestly 'planned' -- the point is an OWNED, GATED gap, not a silent terminal state). Add an entry or do not ship it."
                return
            }
            if (-not $entry.owner) { $violations += "COVERAGE: ledger entry '$($entry.name)' (for $leaf) has no owner. A gap without an owner is a lie of omission." }
            if (-not $entry.gate)  { $violations += "COVERAGE: ledger entry '$($entry.name)' (for $leaf) has no gate. A gap must carry a runnable gate." }
            # ADDITIONAL honesty assertion: a doc that self-labels un-graded must not be recorded graded.
            $text = ''
            try { $text = Get-Content $_.FullName -Raw -ErrorAction Stop } catch {}
            if ($text -imatch $ungradedPattern -and ([string]$entry.conformance_status -imatch '(?i)^(graded|final|corpus[- ]verified)$')) {
                $violations += "HONESTY: '$($entry.name)' claims conformance_status='$($entry.conformance_status)' but $leaf self-labels un-graded/specification-audited. Downgrade to spec-audited/planned-vectors (no false-green)."
            }
        }
    }
}

if ($VerifyClaims) {
    foreach ($cap in $ledger.capabilities) {
        # -- Over-claim: a wired/graded entry's spec_anchor MUST resolve. A conformance_status=graded
        #    or impl_status=wired claim on a spec document that does not exist is an F4 false-green
        #    (the HANDSHAKE-anchor-typo class). A planned/spec-audited entry is a TRACKED gap whose
        #    document MAY still be in authoring, so it is exempt here -- coverage, not honesty, tracks
        #    a companion's existence.
        if (([string]$cap.impl_status -ieq 'wired' -or [string]$cap.conformance_status -ieq 'graded') -and $cap.spec_anchor) {
            $sf = Join-Path $RepoRoot ([string]$cap.spec_anchor)
            if (-not (Test-Path $sf)) {
                $violations += "HONESTY: '$($cap.name)' is impl_status=$($cap.impl_status)/conformance_status=$($cap.conformance_status) but its spec_anchor does not resolve: $($cap.spec_anchor) (false-green -- a graded/wired claim on a missing document)."
            }
        }
        # -- Over-claim: wired must have resolving impl anchors.
        if ([string]$cap.impl_status -ieq 'wired') {
            if (-not $cap.impl_anchors -or @($cap.impl_anchors).Count -eq 0) {
                $violations += "HONESTY: '$($cap.name)' claims impl_status=wired but lists no impl_anchors (false-green)."
            }
            foreach ($an in $cap.impl_anchors) {
                $f = Join-Path $RepoRoot ([string]$an.file)
                if (-not (Test-Path $f)) { $violations += "HONESTY: '$($cap.name)' wired anchor missing: $($an.file)"; continue }
                $c = ''
                try { $c = Get-Content $f -Raw -ErrorAction Stop } catch {}
                if ($c.IndexOf([string]$an.must_contain, [System.StringComparison]::Ordinal) -lt 0) {
                    $violations += "HONESTY: '$($cap.name)' wired anchor $($an.file) no longer contains '$($an.must_contain)' -- downgrade impl_status to planned or restore the wiring."
                }
            }
        }
        # -- Over-claim: graded must have resolving vector anchors.
        if ([string]$cap.conformance_status -ieq 'graded') {
            if (-not $cap.vector_anchors -or @($cap.vector_anchors).Count -eq 0) {
                $violations += "HONESTY: '$($cap.name)' claims conformance_status=graded but lists no vector_anchors (false-green)."
            }
            foreach ($an in $cap.vector_anchors) {
                $f = Join-Path $RepoRoot ([string]$an.file)
                if (-not (Test-Path $f)) { $violations += "HONESTY: '$($cap.name)' graded vector anchor missing: $($an.file)" }
            }
        }
        # -- Under-claim (F6 forward-drift): a planned entry whose impl evidence now resolves was
        #    never promoted. Cheap, no command execution: resolve impl_anchors, and parse a
        #    `test -f/-e <path>` gate path.
        if ([string]$cap.impl_status -ieq 'planned') {
            $implPresent = $false
            if ($cap.impl_anchors -and @($cap.impl_anchors).Count -gt 0) {
                $allResolve = $true
                foreach ($an in $cap.impl_anchors) {
                    $f = Join-Path $RepoRoot ([string]$an.file)
                    $ok = $false
                    if (Test-Path $f) {
                        $c = ''
                        try { $c = Get-Content $f -Raw -ErrorAction Stop } catch {}
                        if ($c.IndexOf([string]$an.must_contain, [System.StringComparison]::Ordinal) -ge 0) { $ok = $true }
                    }
                    if (-not $ok) { $allResolve = $false; break }
                }
                if ($allResolve) { $implPresent = $true }
            }
            if (-not $implPresent -and ([string]$cap.gate -match 'test\s+-[fe]\s+(\S+)')) {
                $gp = Join-Path $RepoRoot ($matches[1])
                if (Test-Path $gp) { $implPresent = $true }
            }
            if ($implPresent) {
                $violations += "FORWARD-DRIFT (F6): '$($cap.name)' is impl_status='planned' but its impl evidence now resolves (an implementation landed). Promote it to 'wired' and record the merge -- an un-promoted entry silently under-claims (still dishonest, in the safe direction)."
            }
        }
    }
}

if ($violations.Count -eq 0) {
    Write-Output "[spec-parity-audit] clean: coverage=$Coverage verifyClaims=$VerifyClaims; $(@($ledger.capabilities).Count) capabilities."
    exit 0
}
Write-Error ("[spec-parity-audit] $($violations.Count) parity violation(s):`n" + (($violations | Select-Object -First 40) -join "`n"))
exit 1
