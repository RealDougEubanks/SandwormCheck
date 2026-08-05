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

# Zip fallback for hosts without git. GitHub serves a snapshot of any ref at
# codeload, so a machine with no git can still stay current. Downloading a zip
# gives no history and no signature verification, which is the same trust level as
# a shallow clone over HTTPS, so nothing is lost by preferring it as a fallback.
function Update-FromZip {
    param([string] $Repo, [string] $Ref, [string] $Dest)

    # https://github.com/OWNER/REPO(.git) -> OWNER/REPO
    $slug = $Repo -replace '^https://github\.com/', '' -replace '\.git$', ''
    if ($slug -notmatch '^[^/]+/[^/]+$') {
        Write-RunLog "cannot derive an archive URL from $Repo; use git or pre-stage $Dest"
        return $false
    }

    # A tag and a branch live under different prefixes; try tag first so a pinned
    # release wins, which is what a production fleet should be using.
    $urls = @(
        "https://codeload.github.com/$slug/zip/refs/tags/$Ref",
        "https://codeload.github.com/$slug/zip/refs/heads/$Ref"
    )

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("swc-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $zip = Join-Path $tmp 'src.zip'
    try {
        $got = $false
        foreach ($u in $urls) {
            try {
                # TLS 1.2 is not the default on Windows PowerShell 5.1.
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $u -OutFile $zip -UseBasicParsing -ErrorAction Stop
                $got = $true
                Write-RunLog "downloaded $u"
                break
            } catch {
                continue
            }
        }
        if (-not $got) { Write-RunLog "could not download an archive for ref '$Ref'"; return $false }

        Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force -ErrorAction Stop
        # The archive contains a single REPO-REF directory.
        $inner = Get-ChildItem -LiteralPath $tmp -Directory | Select-Object -First 1
        if (-not $inner) { Write-RunLog 'archive contained no directory'; return $false }
        if (-not (Test-Path (Join-Path $inner.FullName 'SandwormCheck.ps1'))) {
            Write-RunLog 'archive does not look like SandwormCheck; refusing to install it'
            return $false
        }

        # Replace only after the download has been validated, so a failed update
        # leaves the previous working copy intact.
        if (Test-Path -LiteralPath $Dest) { Remove-Item -Recurse -Force $Dest -ErrorAction SilentlyContinue }
        $parent = Split-Path -Parent $Dest
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Move-Item -LiteralPath $inner.FullName -Destination $Dest -Force
        return $true
    } catch {
        Write-RunLog "zip update failed: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

$hasGit = [bool] (Get-Command git -ErrorAction SilentlyContinue)
if (-not $hasGit) {
    Write-RunLog 'git not found; falling back to a zip download'
}

$updated = $false
$gitOut = $null
if (-not $hasGit) {
    $updated = Update-FromZip -Repo $Repo -Ref $Ref -Dest $Dest
} elseif (Test-Path -LiteralPath (Join-Path $Dest '.git')) {
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

# A git host that failed to update can still fall back to the archive rather than
# scanning with a stale copy.
if (-not $updated -and $hasGit) {
    Write-RunLog 'git update failed; trying the zip fallback'
    $updated = Update-FromZip -Repo $Repo -Ref $Ref -Dest $Dest
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

$rev = 'unknown'
if ($hasGit -and (Test-Path -LiteralPath (Join-Path $Dest '.git'))) {
    $r = (git -C $Dest rev-parse --short HEAD 2>$null)
    if ($r) { $rev = $r }
} elseif ($updated) {
    $rev = "archive of $Ref"
}
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
