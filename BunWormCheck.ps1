<#
.SYNOPSIS
    Host-local IOC scanner for npm supply chain compromise (Windows port).

.DESCRIPTION
    Read-only. Makes no network connections. Reports to the local console and
    communicates its verdict through the exit code:

        0   no indicators found
        10  SUSPECT indicators only
        20  at least one CONFIRMED indicator
        1   scanner error (an incomplete scan is NOT a clean scan)
        2   usage error

    Reads the same signature/*.conf files as bunwormcheck.sh and implements the
    same check types with the same semantics. See docs/spec.md.

    Requires PowerShell 5.1 (shipped with Windows 10/11) or PowerShell 7+.
    No external modules.

.PARAMETER SignaturePath
    Signature file or directory. Defaults to .\signatures next to this script.

.PARAMETER Path
    One or more scan roots. Defaults to auto-detected user profile directories
    and common deployment paths.

.PARAMETER MaxDepth
    Directory recursion depth limit (1-64, default 12).

.PARAMETER MaxFileSize
    Skip files larger than this many bytes for hash and content checks
    (1024-1073741824, default 8388608).

.PARAMETER TimeoutSeconds
    Wall-clock scan limit (10-86400, default 900).

.PARAMETER Json
    Emit a single JSON object instead of the text report.

.PARAMETER Quiet
    Print only the verdict line.

.EXAMPLE
    .\BunWormCheck.ps1
    Scan with defaults and let $LASTEXITCODE carry the verdict.

.EXAMPLE
    .\BunWormCheck.ps1 -Json | Out-File scan.json
    Machine-readable output for a log pipeline.
#>

[CmdletBinding()]
param(
    [Alias('s')]
    [string] $SignaturePath,

    [Alias('p')]
    [string[]] $Path,

    # Bounds are validated in Invoke-Main rather than with [ValidateRange], which
    # fails at parameter binding and would exit 1 instead of the documented
    # usage code 2 — the sh and PowerShell scanners must agree on exit codes.
    [int] $MaxDepth = 12,

    [long] $MaxFileSize = 8388608,

    [int] $TimeoutSeconds = 900,

    [switch] $Json,

    [switch] $Quiet,

    [switch] $NoColor,

    [switch] $Version
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.0.0'
$EXIT_CLEAN = 0
$EXIT_ERROR = 1
$EXIT_USAGE = 2
$EXIT_SUSPECT = 10
$EXIT_CONFIRMED = 20

# Findings accumulate here as PSCustomObjects with Severity/Id/TargetPath/Detail/Description.
$script:Findings = New-Object System.Collections.ArrayList
$script:Campaigns = New-Object System.Collections.ArrayList
$script:SkippedPaths = New-Object System.Collections.ArrayList
$script:Truncated = $false
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$script:FilesWalked = 0

# ---------------------------------------------------------------------------
# Diagnostics. Non-report output goes to stderr/verbose so stdout stays parseable.
# ---------------------------------------------------------------------------
function Write-Diag {
    param([string] $Message)
    Write-Verbose $Message
}

function Write-Warn {
    param([string] $Message)
    [Console]::Error.WriteLine("bunwormcheck: warning: $Message")
}

function Stop-WithError {
    param([int] $Code, [string] $Message)
    [Console]::Error.WriteLine("bunwormcheck: $Message")
    exit $Code
}

# ---------------------------------------------------------------------------
# Signature loading
# ---------------------------------------------------------------------------
function Resolve-SignatureFiles {
    param([string] $Requested)

    if ([string]::IsNullOrWhiteSpace($Requested)) {
        $scriptDir = Split-Path -Parent $PSCommandPath
        $Requested = Join-Path $scriptDir 'signatures'
        if (-not (Test-Path -LiteralPath $Requested)) {
            Stop-WithError $EXIT_ERROR "no signatures found at $Requested (use -SignaturePath)"
        }
    }

    if (-not (Test-Path -LiteralPath $Requested)) {
        Stop-WithError $EXIT_ERROR "signature path does not exist: $Requested"
    }

    $item = Get-Item -LiteralPath $Requested
    if ($item.PSIsContainer) {
        $files = @(Get-ChildItem -LiteralPath $Requested -Filter '*.conf' -File |
            Sort-Object Name | Select-Object -ExpandProperty FullName)
        if ($files.Count -eq 0) {
            Stop-WithError $EXIT_ERROR "no *.conf signature files in directory: $Requested"
        }
        return $files
    }
    return @($item.FullName)
}

function Import-Signatures {
    param([string[]] $Files)

    $records = New-Object System.Collections.ArrayList
    $validTypes = @('PATHEXISTS', 'PATHGLOB', 'FILENAME', 'SHA256', 'SHA1', 'PKGVER', 'CONTENT')

    foreach ($file in $Files) {
        try {
            $lines = Get-Content -LiteralPath $file -ErrorAction Stop
        } catch {
            Stop-WithError $EXIT_ERROR "cannot read signature file ${file}: $($_.Exception.Message)"
        }

        $campaign = ''
        $sigVersion = ''
        $lineNo = 0

        foreach ($rawLine in $lines) {
            $lineNo++
            $line = $rawLine -replace "`r", ''

            if ($line -match '^#!\s*campaign\s+(.+)$' -and -not $campaign) {
                $campaign = $Matches[1].Trim()
                continue
            }
            if ($line -match '^#!\s*version\s+(.+)$' -and -not $sigVersion) {
                $sigVersion = $Matches[1].Trim()
                continue
            }
            if ($line.Trim() -eq '' -or $line.TrimStart().StartsWith('#')) { continue }

            $parts = $line.Split('|')
            if ($parts.Count -lt 5) {
                Stop-WithError $EXIT_ERROR "${file}:${lineNo}: expected 5 pipe-delimited fields, got $($parts.Count)"
            }

            $type = $parts[0].Trim().ToUpperInvariant()
            $sev = $parts[1].Trim().ToUpperInvariant()
            $id = $parts[2].Trim()
            $pattern = $parts[3].Trim()
            # Description is the last field and may itself contain pipes.
            $desc = ($parts[4..($parts.Count - 1)] -join '|').Trim()

            # A malformed record is a hard error. Skipping it would silently
            # shrink coverage and could report a clean host.
            if ($validTypes -notcontains $type) {
                Stop-WithError $EXIT_ERROR "${file}:${lineNo}: unknown check type '$type'"
            }
            if ($sev -ne 'CONFIRMED' -and $sev -ne 'SUSPECT') {
                Stop-WithError $EXIT_ERROR "${file}:${lineNo}: severity must be CONFIRMED or SUSPECT, got '$sev'"
            }
            if (-not $id) { Stop-WithError $EXIT_ERROR "${file}:${lineNo}: empty signature ID" }
            if (-not $pattern) { Stop-WithError $EXIT_ERROR "${file}:${lineNo}: empty pattern for $id" }
            if (-not $desc) { Stop-WithError $EXIT_ERROR "${file}:${lineNo}: empty description for $id" }

            switch ($type) {
                'SHA256' {
                    if ($pattern -notmatch '^[0-9a-fA-F]{64}$') {
                        Stop-WithError $EXIT_ERROR "${file}:${lineNo}: ${id}: SHA256 must be 64 hex characters, got $($pattern.Length)"
                    }
                    $pattern = $pattern.ToLowerInvariant()
                }
                'SHA1' {
                    if ($pattern -notmatch '^[0-9a-fA-F]{40}$') {
                        Stop-WithError $EXIT_ERROR "${file}:${lineNo}: ${id}: SHA1 must be 40 hex characters, got $($pattern.Length)"
                    }
                    $pattern = $pattern.ToLowerInvariant()
                }
                'PKGVER' {
                    if ($pattern -notmatch '@') {
                        Stop-WithError $EXIT_ERROR "${file}:${lineNo}: ${id}: PKGVER must be name@version"
                    }
                }
            }

            [void] $records.Add([PSCustomObject]@{
                Type        = $type
                Severity    = $sev
                Id          = $id
                Pattern     = $pattern
                Description = $desc
            })
        }

        if (-not $campaign) { $campaign = Split-Path -Leaf $file }
        if (-not $sigVersion) { $sigVersion = 'unversioned' }
        [void] $script:Campaigns.Add("$campaign ($sigVersion)")
    }

    if ($records.Count -eq 0) {
        Stop-WithError $EXIT_ERROR 'no valid signature records loaded'
    }
    Write-Diag "loaded $($records.Count) signature records"
    return $records
}

function Add-Finding {
    param(
        [string] $Severity,
        [string] $Id,
        [string] $TargetPath,
        [string] $Detail,
        [string] $Description
    )
    [void] $script:Findings.Add([PSCustomObject]@{
        Severity    = $Severity
        Id          = $Id
        TargetPath  = $TargetPath
        Detail      = $Detail
        Description = $Description
    })
}

# ---------------------------------------------------------------------------
# Scan roots
# ---------------------------------------------------------------------------
function Get-UserProfileRoot {
    # The directory holding per-user profiles. $env:SystemDrive is absent when
    # PowerShell 7 runs on macOS or Linux, so fall back rather than throw.
    if ($env:SystemDrive) {
        $p = Join-Path $env:SystemDrive 'Users'
        if (Test-Path -LiteralPath $p) { return $p }
    }
    foreach ($p in @('/Users', '/home')) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

function Get-DefaultScanPaths {
    $roots = New-Object System.Collections.ArrayList

    $usersDir = Get-UserProfileRoot
    if ($usersDir) {
        foreach ($d in Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue) {
            # Skip the Windows service and template profiles.
            if ($d.Name -in @('Public', 'Default', 'Default User', 'All Users', 'Shared', 'Guest')) { continue }
            [void] $roots.Add($d.FullName)
        }
    }

    $extra = New-Object System.Collections.ArrayList
    foreach ($v in @($env:USERPROFILE, $env:HOME, $env:APPDATA, $env:LOCALAPPDATA)) {
        if ($v) { [void] $extra.Add($v) }
    }
    if ($env:SystemDrive) {
        foreach ($leaf in @('inetpub', 'projects', 'src')) {
            [void] $extra.Add((Join-Path $env:SystemDrive $leaf))
        }
    }
    foreach ($candidate in $extra) {
        if (Test-Path -LiteralPath $candidate -ErrorAction SilentlyContinue) { [void] $roots.Add($candidate) }
    }

    return @($roots | Select-Object -Unique)
}

# Directories never descended into: keeps a fleet scan finishing in minutes and
# avoids reparse points that can loop.
$script:PruneNames = @(
    '.git', '$Recycle.Bin', 'Windows', 'WinSxS', 'Temp',
    'INetCache', 'WebCache', 'Microsoft', 'OneDrive', 'Recent'
)

function Get-WalkedFiles {
    param([string] $Root, [int] $Depth)

    $results = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue([PSCustomObject]@{ Dir = $Root; Level = 0 })

    while ($queue.Count -gt 0) {
        if ($script:Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $script:Truncated = $true
            break
        }
        $node = $queue.Dequeue()

        try {
            $entries = Get-ChildItem -LiteralPath $node.Dir -Force -ErrorAction Stop
        } catch {
            # Unreadable directories are recorded, never silently swallowed: a
            # path we could not read must not be implied to be clean.
            [void] $script:SkippedPaths.Add($node.Dir)
            continue
        }

        foreach ($entry in $entries) {
            if ($entry.PSIsContainer) {
                if ($node.Level -ge $Depth) { continue }
                if ($script:PruneNames -contains $entry.Name) { continue }
                # Do not follow reparse points (junctions, symlinks): they can
                # create cycles and escape the scan root.
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                $queue.Enqueue([PSCustomObject]@{ Dir = $entry.FullName; Level = $node.Level + 1 })
            } else {
                [void] $results.Add($entry.FullName)
            }
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
function Invoke-PathExistsCheck {
    param([object[]] $Signatures, [string[]] $HomeDirs)

    foreach ($sig in ($Signatures | Where-Object { $_.Type -eq 'PATHEXISTS' })) {
        $targets = New-Object System.Collections.ArrayList

        $sep = [IO.Path]::DirectorySeparatorChar

        if ($sig.Pattern.StartsWith('~/')) {
            # Expand against every profile we know about, not just the current
            # user: a fleet agent runs as SYSTEM and the artifacts live in
            # individual profiles.
            $rest = $sig.Pattern.Substring(2).Replace('/', $sep)
            foreach ($h in $HomeDirs) { [void] $targets.Add((Join-Path $h $rest)) }
        } else {
            # Translate the Unix-style paths in shared signature files onto
            # their Windows equivalents where one exists.
            $p = $sig.Pattern
            if ($p.StartsWith('/tmp/')) {
                $rest = $p.Substring(5).Replace('/', $sep)
                if ($env:TEMP) { [void] $targets.Add((Join-Path $env:TEMP $rest)) }
                if ($env:TMPDIR) { [void] $targets.Add((Join-Path $env:TMPDIR $rest)) }
                foreach ($h in $HomeDirs) {
                    [void] $targets.Add((Join-Path (Join-Path $h 'AppData/Local/Temp'.Replace('/', $sep)) $rest))
                }
            } elseif ($p.StartsWith('/')) {
                # Unix-only absolute path. Applicable when this port runs on
                # macOS or Linux; on Windows there is no equivalent to check.
                if ($sep -eq '/') { [void] $targets.Add($p) }
            } else {
                [void] $targets.Add($p)
            }
        }

        foreach ($t in $targets) {
            try {
                # -Path (not -LiteralPath) so wildcards in the signature expand.
                $hits = @(Resolve-Path -Path $t -ErrorAction SilentlyContinue)
            } catch {
                continue
            }
            foreach ($hit in $hits) {
                Add-Finding $sig.Severity $sig.Id $hit.Path 'path exists' $sig.Description
            }
        }
    }
}

function Invoke-FilenameCheck {
    param([object[]] $Signatures, [string[]] $Candidates)

    $byName = @{}
    foreach ($sig in ($Signatures | Where-Object { $_.Type -eq 'FILENAME' })) {
        $key = $sig.Pattern.ToLowerInvariant()
        if (-not $byName.ContainsKey($key)) { $byName[$key] = New-Object System.Collections.ArrayList }
        [void] $byName[$key].Add($sig)
    }
    if ($byName.Count -eq 0) { return }

    foreach ($file in $Candidates) {
        $leaf = [IO.Path]::GetFileName($file).ToLowerInvariant()
        if ($byName.ContainsKey($leaf)) {
            foreach ($sig in $byName[$leaf]) {
                Add-Finding $sig.Severity $sig.Id $file 'filename match' $sig.Description
            }
        }
    }
}

function Invoke-PathGlobCheck {
    param([object[]] $Signatures, [string[]] $Candidates)

    $globs = @($Signatures | Where-Object { $_.Type -eq 'PATHGLOB' })
    if ($globs.Count -eq 0) { return }

    foreach ($file in $Candidates) {
        # Signature globs are written with forward slashes; compare on a
        # normalized copy so one pattern works on both platforms.
        $norm = $file -replace '\\', '/'
        foreach ($sig in $globs) {
            if ($norm -like $sig.Pattern) {
                Add-Finding $sig.Severity $sig.Id $file 'path glob match' $sig.Description
            }
        }
    }
}

function Invoke-HashCheck {
    param([object[]] $Signatures, [string[]] $Candidates, [string] $Algorithm)

    $sigs = @($Signatures | Where-Object { $_.Type -eq $Algorithm })
    if ($sigs.Count -eq 0) { return }

    $lookup = @{}
    foreach ($sig in $sigs) {
        if (-not $lookup.ContainsKey($sig.Pattern)) { $lookup[$sig.Pattern] = New-Object System.Collections.ArrayList }
        [void] $lookup[$sig.Pattern].Add($sig)
    }

    foreach ($file in $Candidates) {
        try {
            $info = Get-Item -LiteralPath $file -Force -ErrorAction Stop
            if ($info.Length -gt $MaxFileSize) { continue }
            $digest = (Get-FileHash -LiteralPath $file -Algorithm $Algorithm -ErrorAction Stop).Hash.ToLowerInvariant()
        } catch {
            # An unreadable or vanished file is not a detection; note and move on.
            Write-Diag "hash skipped for ${file}: $($_.Exception.Message)"
            continue
        }
        if ($lookup.ContainsKey($digest)) {
            foreach ($sig in $lookup[$digest]) {
                Add-Finding $sig.Severity $sig.Id $file "$Algorithm match" $sig.Description
            }
        }
    }
}

function Invoke-ContentCheck {
    param([object[]] $Signatures, [string[]] $Candidates)

    $sigs = @($Signatures | Where-Object { $_.Type -eq 'CONTENT' })
    if ($sigs.Count -eq 0) { return }

    foreach ($file in $Candidates) {
        try {
            $info = Get-Item -LiteralPath $file -Force -ErrorAction Stop
            if ($info.Length -gt $MaxFileSize) { continue }
            $text = [IO.File]::ReadAllText($file)
        } catch {
            Write-Diag "content skipped for ${file}: $($_.Exception.Message)"
            continue
        }
        foreach ($sig in $sigs) {
            # Ordinal literal comparison: no regex dialect surprises, and it
            # matches the -F semantics of the sh implementation.
            if ($text.IndexOf($sig.Pattern, [StringComparison]::Ordinal) -ge 0) {
                Add-Finding $sig.Severity $sig.Id $file 'content match' $sig.Description
            }
        }
    }
}

function Invoke-PkgVerCheck {
    param([object[]] $Signatures, [string[]] $AllFiles)

    $sigs = @($Signatures | Where-Object { $_.Type -eq 'PKGVER' })
    if ($sigs.Count -eq 0) { return }

    $wanted = @{}
    foreach ($sig in $sigs) {
        $key = $sig.Pattern.ToLowerInvariant()
        if (-not $wanted.ContainsKey($key)) { $wanted[$key] = New-Object System.Collections.ArrayList }
        [void] $wanted[$key].Add($sig)
    }

    foreach ($file in $AllFiles) {
        if ([IO.Path]::GetFileName($file) -ne 'package.json') { continue }
        try {
            $info = Get-Item -LiteralPath $file -Force -ErrorAction Stop
            if ($info.Length -gt $MaxFileSize) { continue }
            $text = [IO.File]::ReadAllText($file)
        } catch {
            Write-Diag "package.json skipped for ${file}: $($_.Exception.Message)"
            continue
        }

        # Take the first "name" and "version" keys, which in an npm-generated
        # manifest are the package's own. Avoids a full JSON parse so a manifest
        # with trailing garbage still yields a usable answer.
        $nameMatch = [regex]::Match($text, '"name"\s*:\s*"([^"]*)"')
        $verMatch = [regex]::Match($text, '"version"\s*:\s*"([^"]*)"')
        if (-not $nameMatch.Success -or -not $verMatch.Success) { continue }

        $nv = ($nameMatch.Groups[1].Value + '@' + $verMatch.Groups[1].Value).ToLowerInvariant()
        if ($wanted.ContainsKey($nv)) {
            foreach ($sig in $wanted[$nv]) {
                Add-Finding $sig.Severity $sig.Id $file "installed $nv" $sig.Description
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Candidate selection (spec section 6)
# ---------------------------------------------------------------------------
function Select-Candidates {
    param([string[]] $AllFiles, [object[]] $Signatures)

    $names = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($sig in ($Signatures | Where-Object { $_.Type -eq 'FILENAME' })) {
        [void] $names.Add($sig.Pattern)
    }
    foreach ($n in @('settings.json', 'tasks.json', 'package.json', 'setup.mjs')) {
        [void] $names.Add($n)
    }

    $out = New-Object System.Collections.ArrayList
    foreach ($file in $AllFiles) {
        $leaf = [IO.Path]::GetFileName($file)
        if ($names.Contains($leaf)) { [void] $out.Add($file); continue }
        if ($file -match '(?i)[\\/](node_modules|\.claude|\.vscode)[\\/]') { [void] $out.Add($file) }
    }
    return @($out | Select-Object -Unique)
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
function Get-HostIdentifier {
    $hostName = try { [Net.Dns]::GetHostName() } catch { 'unknown' }
    $machine = ''
    try {
        $machine = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
                -Name MachineGuid -ErrorAction Stop).MachineGuid
    } catch {
        $machine = ''
    }
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        $bytes = [Text.Encoding]::UTF8.GetBytes("$hostName|$machine")
        $hex = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
        $sha.Dispose()
        return "$hostName/" + $hex.Substring(0, 12)
    } catch {
        return $hostName
    }
}

function Get-Verdict {
    if (@($script:Findings | Where-Object { $_.Severity -eq 'CONFIRMED' }).Count -gt 0) { return 'CONFIRMED' }
    if ($script:Findings.Count -gt 0) { return 'SUSPECT' }
    return 'CLEAN'
}

function Get-ExitCode {
    switch (Get-Verdict) {
        'CONFIRMED' { return $EXIT_CONFIRMED }
        'SUSPECT' { return $EXIT_SUSPECT }
        default {
            # An incomplete scan that found nothing is not a clean result.
            if ($script:Truncated) { return $EXIT_ERROR }
            return $EXIT_CLEAN
        }
    }
}

function Write-TextReport {
    param([string[]] $Roots)

    $useColor = -not $NoColor -and -not $env:NO_COLOR
    $verdict = Get-Verdict
    $confirmed = @($script:Findings | Where-Object { $_.Severity -eq 'CONFIRMED' }).Count
    $suspect = @($script:Findings | Where-Object { $_.Severity -eq 'SUSPECT' }).Count

    if (-not $Quiet) {
        Write-Output "BunWormCheck $($script:ToolVersion)"
        Write-Output ("  host      : " + (Get-HostIdentifier))
        Write-Output ("  scanned   : {0} roots, {1} files, {2}s" -f `
                $Roots.Count, $script:FilesWalked, [int]$script:Stopwatch.Elapsed.TotalSeconds)
        Write-Output "  campaigns :"
        foreach ($c in $script:Campaigns) { Write-Output "              $c" }
        Write-Output ''

        if ($script:Findings.Count -gt 0) {
            Write-Output 'Findings:'
            foreach ($f in ($script:Findings | Sort-Object Severity, Id, TargetPath)) {
                $line = "  {0,-9} {1,-12} {2}" -f $f.Severity, $f.Id, $f.TargetPath
                if ($useColor) {
                    $c = if ($f.Severity -eq 'CONFIRMED') { 'Red' } else { 'Yellow' }
                    Write-Host $line -ForegroundColor $c
                    Write-Host ("            ({0}) {1}" -f $f.Detail, $f.Description) -ForegroundColor DarkGray
                } else {
                    Write-Output $line
                    Write-Output ("            ({0}) {1}" -f $f.Detail, $f.Description)
                }
            }
            Write-Output ''
        } else {
            Write-Output 'No indicators found.'
            Write-Output ''
        }

        if ($script:SkippedPaths.Count -gt 0) {
            Write-Output "$($script:SkippedPaths.Count) path(s) unreadable and skipped - coverage is incomplete:"
            foreach ($p in ($script:SkippedPaths | Select-Object -First 25)) { Write-Output "  $p" }
            if ($script:SkippedPaths.Count -gt 25) {
                Write-Output "  ... and $($script:SkippedPaths.Count - 25) more"
            }
            Write-Output ''
        }

        if ($script:Truncated) {
            Write-Output "SCAN TRUNCATED: the ${TimeoutSeconds}s timeout expired before all roots were walked."
            Write-Output 'This result is NOT a clean bill of health. Re-run with a longer -TimeoutSeconds.'
            Write-Output ''
        }
    }

    switch ($verdict) {
        'CONFIRMED' {
            $msg = "VERDICT: CONFIRMED COMPROMISE - $confirmed confirmed, $suspect suspect indicator(s). Isolate this host and rotate its credentials. See docs/remediation.md"
            if ($useColor) { Write-Host $msg -ForegroundColor Red } else { Write-Output $msg }
        }
        'SUSPECT' {
            $msg = "VERDICT: SUSPECT - $suspect suspect indicator(s), no confirmed payload. Remediate the affected dependencies."
            if ($useColor) { Write-Host $msg -ForegroundColor Yellow } else { Write-Output $msg }
        }
        default {
            if ($script:Truncated) {
                Write-Output 'VERDICT: INCOMPLETE - no indicators found, but the scan did not finish.'
            } else {
                $msg = 'VERDICT: CLEAN - no indicators found.'
                if ($useColor) { Write-Host $msg -ForegroundColor Green } else { Write-Output $msg }
            }
        }
    }
}

function Write-JsonReport {
    param([string[]] $Roots)

    $report = [ordered]@{
        schema           = 'bunwormcheck/v1'
        tool_version     = $script:ToolVersion
        host             = Get-HostIdentifier
        scanned_at       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        duration_seconds = [int] $script:Stopwatch.Elapsed.TotalSeconds
        files_walked     = $script:FilesWalked
        truncated        = $script:Truncated
        paths_skipped    = $script:SkippedPaths.Count
        scan_roots       = @($Roots)
        campaigns        = @($script:Campaigns)
        counts           = [ordered]@{
            confirmed = @($script:Findings | Where-Object { $_.Severity -eq 'CONFIRMED' }).Count
            suspect   = @($script:Findings | Where-Object { $_.Severity -eq 'SUSPECT' }).Count
        }
        findings         = @(
            $script:Findings | Sort-Object Severity, Id, TargetPath | ForEach-Object {
                [ordered]@{
                    severity    = $_.Severity
                    id          = $_.Id
                    path        = $_.TargetPath
                    detail      = $_.Detail
                    description = $_.Description
                }
            }
        )
        verdict          = Get-Verdict
        exit_code        = Get-ExitCode
    }

    # -Compress keeps the record on one line so log shippers treat it as one event.
    Write-Output ($report | ConvertTo-Json -Depth 6 -Compress)
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Invoke-Main {
    if ($Version) {
        Write-Output "bunwormcheck $($script:ToolVersion)"
        exit $EXIT_CLEAN
    }

    if ($MaxDepth -lt 1 -or $MaxDepth -gt 64) {
        Stop-WithError $EXIT_USAGE "-MaxDepth must be between 1 and 64, got: $MaxDepth"
    }
    if ($MaxFileSize -lt 1024 -or $MaxFileSize -gt 1073741824) {
        Stop-WithError $EXIT_USAGE "-MaxFileSize must be between 1024 and 1073741824, got: $MaxFileSize"
    }
    if ($TimeoutSeconds -lt 10 -or $TimeoutSeconds -gt 86400) {
        Stop-WithError $EXIT_USAGE "-TimeoutSeconds must be between 10 and 86400, got: $TimeoutSeconds"
    }

    $sigFiles = Resolve-SignatureFiles -Requested $SignaturePath
    $signatures = Import-Signatures -Files $sigFiles

    if ($Path) {
        foreach ($p in $Path) {
            if (-not (Test-Path -LiteralPath $p -PathType Container)) {
                Stop-WithError $EXIT_USAGE "-Path is not a directory: $p"
            }
        }
        $roots = @($Path | ForEach-Object { (Get-Item -LiteralPath $_).FullName } | Select-Object -Unique)
    } else {
        $roots = Get-DefaultScanPaths
    }
    if ($roots.Count -eq 0) {
        Stop-WithError $EXIT_ERROR 'no scannable roots found; pass -Path explicitly'
    }

    # Profile directories used to expand ~ in PATHEXISTS patterns.
    $homeDirs = New-Object System.Collections.ArrayList
    $usersDir = Get-UserProfileRoot
    if ($usersDir) {
        foreach ($d in Get-ChildItem -LiteralPath $usersDir -Directory -ErrorAction SilentlyContinue) {
            [void] $homeDirs.Add($d.FullName)
        }
    }
    foreach ($v in @($env:USERPROFILE, $env:HOME)) {
        if ($v) { [void] $homeDirs.Add($v) }
    }
    $homeDirs = @($homeDirs | Select-Object -Unique)

    $allFiles = New-Object System.Collections.ArrayList
    foreach ($root in $roots) {
        if ($script:Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $script:Truncated = $true
            break
        }
        Write-Diag "walking $root"
        foreach ($f in (Get-WalkedFiles -Root $root -Depth $MaxDepth)) { [void] $allFiles.Add($f) }
    }
    $allFilesArr = @($allFiles)
    $script:FilesWalked = $allFilesArr.Count

    $candidates = Select-Candidates -AllFiles $allFilesArr -Signatures $signatures
    Write-Diag "$($script:FilesWalked) files walked, $($candidates.Count) candidates"

    Invoke-PathExistsCheck -Signatures $signatures -HomeDirs $homeDirs
    Invoke-FilenameCheck -Signatures $signatures -Candidates $candidates
    Invoke-PathGlobCheck -Signatures $signatures -Candidates $candidates
    Invoke-PkgVerCheck -Signatures $signatures -AllFiles $allFilesArr
    Invoke-ContentCheck -Signatures $signatures -Candidates $candidates
    Invoke-HashCheck -Signatures $signatures -Candidates $candidates -Algorithm 'SHA256'
    Invoke-HashCheck -Signatures $signatures -Candidates $candidates -Algorithm 'SHA1'

    # De-duplicate: the same artifact can trip several signatures via different
    # check types, and one line per (severity, id, path) is enough.
    $unique = @($script:Findings | Sort-Object Severity, Id, TargetPath -Unique)
    $script:Findings = New-Object System.Collections.ArrayList
    foreach ($f in $unique) { [void] $script:Findings.Add($f) }

    if ($Json) { Write-JsonReport -Roots $roots } else { Write-TextReport -Roots $roots }

    exit (Get-ExitCode)
}

try {
    Invoke-Main
} catch {
    # No unhandled exception may escape: an uncaught throw would surface a
    # PowerShell exit code that the fleet console would misread.
    [Console]::Error.WriteLine("bunwormcheck: unhandled error: $($_.Exception.Message)")
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit $EXIT_ERROR
}
