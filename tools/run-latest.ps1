<#
.SYNOPSIS
    Update SandwormCheck from its public repository, then scan this host.

.DESCRIPTION
    Intended to be pasted into a fleet tool (JumpCloud, Intune, Task Scheduler)
    so a single command always runs the current signatures. Re-running it picks
    up whatever has been added to the repository since last time.

    Exit codes are the scanner's, passed through unchanged:
      0 clean | 10 suspect | 20 CONFIRMED compromise | 1 scanner error | 2 usage

    NOTE: this executes whatever is currently on the tracked branch. For a
    production fleet, set -Ref to a reviewed tag or mirror the repository
    internally. Auto-running a moving branch means trusting every future commit,
    which is the same class of risk this tool exists to detect.

.PARAMETER Repo
    Git URL to pull from.

.PARAMETER Dest
    Checkout location.

.PARAMETER Ref
    Branch or tag to check out. Defaults to main.

.PARAMETER ScannerArgs
    Extra arguments forwarded to SandwormCheck.ps1.

.EXAMPLE
    .\run-latest.ps1
    Update and scan with defaults.

.EXAMPLE
    .\run-latest.ps1 -Ref v1.0.0 -ScannerArgs '-Json'
    Pin to a reviewed tag and emit JSON.
#>

[CmdletBinding()]
param(
    [string] $Repo = 'https://github.com/RealDougEubanks/SandwormCheck.git',
    [string] $Dest = (Join-Path $env:ProgramData 'SandwormCheck'),
    [string] $Ref = 'main',
    # Anything not matched above is forwarded to the scanner. An explicit
    # [string[]] parameter does not survive `pwsh -File`, which flattens arrays
    # into a single string, and splatting one binds positionally.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ScannerArgs = @()
)

Set-StrictMode -Version 2.0
# Do not stop on native command stderr; git writes progress there.
$ErrorActionPreference = 'Continue'

function Write-RunLog {
    param([string] $Message)
    [Console]::Error.WriteLine("run-latest: $Message")
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-RunLog "git not found; install git or pre-stage the repository at $Dest"
    exit 1
}

$updated = $false
$gitOut = $null
if (Test-Path -LiteralPath (Join-Path $Dest '.git')) {
    # Discard local drift so a half-applied earlier run cannot pin old signatures.
    # Keep git's own diagnostics: "could not update" without the reason leaves an
    # operator with nothing to act on.
    $gitOut = git -C $Dest fetch --quiet --depth 1 origin $Ref 2>&1
    if ($LASTEXITCODE -eq 0) {
        $gitOut = git -C $Dest reset --hard --quiet FETCH_HEAD 2>&1
        if ($LASTEXITCODE -eq 0) { $updated = $true }
    }
} else {
    if (Test-Path -LiteralPath $Dest) { Remove-Item -Recurse -Force $Dest -ErrorAction SilentlyContinue }
    $parent = Split-Path -Parent $Dest
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $gitOut = git clone --quiet --depth 1 --branch $Ref $Repo $Dest 2>&1
    if ($LASTEXITCODE -eq 0) { $updated = $true }
}

$scanner = Join-Path $Dest 'SandwormCheck.ps1'

if (-not $updated) {
    if ($gitOut) { Write-RunLog "git said: $($gitOut -join ' ')" }
    if (Test-Path -LiteralPath $scanner) {
        # Scanning with a known-older copy beats not scanning, but the operator
        # must know the signatures may be stale.
        Write-RunLog "WARNING: could not update from $Repo; scanning with the EXISTING copy at $Dest"
        Write-RunLog "WARNING: signatures may be out of date - this result is weaker than a fresh run"
    } else {
        Write-RunLog "could not fetch $Repo and no usable copy exists at $Dest"
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $scanner)) {
    Write-RunLog "scanner not found at $scanner"
    exit 1
}

$rev = (git -C $Dest rev-parse --short HEAD 2>$null)
if (-not $rev) { $rev = 'unknown' }
Write-RunLog "revision $rev"

# Invoking the script directly keeps this working on Windows PowerShell 5.1 and
# PowerShell 7 alike; hardcoding powershell.exe breaks the latter.
#
# The exit code must reflect the SCAN, never this script's success at starting
# it. An earlier revision returned 0 when the scanner failed to bind its
# parameters, because $LASTEXITCODE still held the previous git command's status
# - reporting a host as clean that was never scanned.
# Splatting a flat ARRAY binds positionally: PowerShell does not read "-Name"
# elements as parameter names that way, so forwarded arguments land in the wrong
# parameters (-Path ended up in -SignaturePath, and -SignaturePath in -MaxDepth,
# which then failed to convert to an int). Build a hashtable, which binds by name.
$params = @{}
$i = 0
while ($i -lt $ScannerArgs.Count) {
    $tok = $ScannerArgs[$i]
    if ($tok -notlike '-*') { $i++; continue }   # stray positional
    $name = $tok.TrimStart('-')
    if (($i + 1) -lt $ScannerArgs.Count -and $ScannerArgs[$i + 1] -notlike '-*') {
        # Comma-splitting matches how PowerShell itself accepts array arguments,
        # so -Path C:\a,C:\b reaches the scanner as two roots.
        $val = $ScannerArgs[$i + 1]
        $params[$name] = if ($val -like '*,*') { $val -split ',' } else { $val }
        $i += 2
    } else {
        $params[$name] = $true                    # switch
        $i++
    }
}

$global:LASTEXITCODE = $null
try {
    $ErrorActionPreference = 'Stop'
    & $scanner @params
} catch {
    Write-RunLog "scanner failed to run: $($_.Exception.Message)"
    exit 1
}
if ($null -eq $LASTEXITCODE) {
    Write-RunLog 'scanner produced no exit code; treating as a scanner error, not as clean'
    exit 1
}
exit $LASTEXITCODE
