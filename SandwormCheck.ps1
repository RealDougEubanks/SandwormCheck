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

    Reads the same signature/*.conf files as sandwormcheck.sh and implements the
    same check types with the same semantics. See docs/spec.md.

    Indicator content is not original research: it is assembled from public work
    by Wiz, Socket, JFrog, CyberKendra, and Aikido. Credits and per-indicator
    provenance are in docs/references.md.

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
    Wall-clock scan limit for the whole scan (10-86400, default 1800). Must match
    the sh scanner's default; tools/checks.sh asserts that they agree.

.PARAMETER Fast
    Skip the content and hash sweeps. Keeps every cheap high-signal check and
    finishes in seconds even on a machine with hundreds of repositories.

.PARAMETER Json
    Emit a single JSON object instead of the text report.

.PARAMETER Quiet
    Print only the verdict line.

.EXAMPLE
    .\SandwormCheck.ps1
    Scan with defaults and let $LASTEXITCODE carry the verdict.

.EXAMPLE
    .\SandwormCheck.ps1 -Json | Out-File scan.json
    Machine-readable output for a log pipeline.
#>

[CmdletBinding()]
param(
    [Alias('s')]
    [string] $SignaturePath,

    [Alias('p')]
    [string[]] $Path,

    [Alias('x')]
    [string[]] $Exclude = @(),

    # Bounds are validated in Invoke-Main rather than with [ValidateRange], which
    # fails at parameter binding and would exit 1 instead of the documented
    # usage code 2: the sh and PowerShell scanners must agree on exit codes.
    [int] $MaxDepth = 12,

    [long] $MaxFileSize = 8388608,

    [int] $TimeoutSeconds = 7200,

    # Skips the content and hash sweeps: the two stages whose cost is proportional
    # to BYTES rather than to file count. Deliberate coverage choice, not a
    # truncation, so the verdict is reported normally.
    [switch] $Fast,

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
function Set-Truncated {
    $script:Truncated = $true
}

function Test-BudgetLeft {
    # True while time budget remains; marks the scan truncated when it is gone.
    #
    # The port previously checked the budget only inside the directory walk, so the
    # content and hash sweeps ran unbounded. A fleet host given -TimeoutSeconds 1500
    # was killed by its agent at 1800s with exit 124 and produced no verdict at all:
    # the walk stopped on time and the sweeps then ran past the agent's limit. The sh
    # engine had five budget checks to this port's two, and the parity tests never
    # caught it because they run on fixtures that finish instantly.
    if ($script:Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
        Set-Truncated
        return $false
    }
    return $true
}

function Write-Diag {
    param([string] $Message)
    Write-Verbose $Message
}

function Write-Warn {
    param([string] $Message)
    [Console]::Error.WriteLine("sandwormcheck: warning: $Message")
}

function Stop-WithError {
    param([int] $Code, [string] $Message)
    [Console]::Error.WriteLine("sandwormcheck: $Message")
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
    $validTypes = @('PATHEXISTS', 'PATHGLOB', 'FILENAME', 'SHA256', 'SHA1', 'PKGVER', 'CONTENT', 'PROCESS')

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
    # A campaign split across several files (hand-maintained indicators in one,
    # generated package versions in another) declares the same name in each.
    $uniqueCampaigns = @($script:Campaigns | Select-Object -Unique)
    $script:Campaigns = New-Object System.Collections.ArrayList
    foreach ($c in $uniqueCampaigns) { [void] $script:Campaigns.Add($c) }
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
    'INetCache', 'WebCache', 'Microsoft', 'OneDrive', 'Recent',
    # Tool-managed snapshot stores mirror scanned content, so they reproduce every
    # marker string the scanner looks for and generate pure noise.
    'file-history', '.history', 'projects'
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
    $mins = @{}
    foreach ($sig in ($Signatures | Where-Object { $_.Type -eq 'FILENAME' })) {
        $sf = Split-SizeFloor $sig.Pattern
        $key = $sf.Pattern.ToLowerInvariant()
        if (-not $byName.ContainsKey($key)) { $byName[$key] = New-Object System.Collections.ArrayList }
        [void] $byName[$key].Add($sig)
        $mins["$($sig.Id)|$key"] = $sf.Min
    }
    if ($byName.Count -eq 0) { return }

    $fnN = 0
    foreach ($file in $Candidates) {
        if ((++$fnN % 50000) -eq 0 -and -not (Test-BudgetLeft)) { break }
        $leaf = [IO.Path]::GetFileName($file).ToLowerInvariant()
        if ($byName.ContainsKey($leaf)) {
            foreach ($sig in $byName[$leaf]) {
                $m = $mins["$($sig.Id)|$leaf"]
                if (-not (Test-SizeFloor $file $m)) { continue }
                Add-Finding $sig.Severity $sig.Id $file 'filename match' $sig.Description
            }
        }
    }
}

function Convert-GlobToRegex {
    param([string] $Glob)
    # * matches within ONE path segment, ** crosses segments, **/ also matches zero
    # segments. PowerShell's -like cannot express that, and treating * as "any
    # characters" made it impossible to say "directly inside a package directory" --
    # the discriminator that separates the payload from the legitimate
    # regenerate-unicode-properties/General_Category/Math_Symbol.js.
    $out = '^'
    $i = 0
    while ($i -lt $Glob.Length) {
        $c = $Glob[$i]
        if ($c -eq '*') {
            if ($i + 1 -lt $Glob.Length -and $Glob[$i + 1] -eq '*') {
                if ($i + 2 -lt $Glob.Length -and $Glob[$i + 2] -eq '/') {
                    $out += '(.*/)?'; $i += 3; continue
                }
                $out += '.*'; $i += 2; continue
            }
            $out += '[^/]*'; $i++; continue
        }
        if ($c -eq '?') { $out += '[^/]'; $i++; continue }
        if ('.[]()+^$\{}|' -contains [string]$c) { $out += '\' + $c } else { $out += [regex]::Escape([string]$c) }
        $i++
    }
    return $out + '$'
}

function Split-SizeFloor {
    param([string] $Pattern)
    # ">=N " prefix: the payload is a ~728 KB bundle while the legitimate Unicode
    # file of the same name is about 1 KB, so size alone separates them.
    if ($Pattern -match '^>=([0-9]+) (.+)$') {
        return @{ Min = [long] $Matches[1]; Pattern = $Matches[2] }
    }
    return @{ Min = [long] 0; Pattern = $Pattern }
}

function Test-SizeFloor {
    param([string] $FilePath, [long] $Min)
    if ($Min -le 0) { return $true }
    try {
        $len = (Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop).Length
    } catch { return $false }
    if ($len -lt $Min) {
        Write-Diag "size floor: $FilePath is ${len}B, under ${Min}B"
        return $false
    }
    return $true
}

function Invoke-PathGlobCheck {
    param([object[]] $Signatures, [string[]] $Candidates)

    $globs = @($Signatures | Where-Object { $_.Type -eq 'PATHGLOB' })
    if ($globs.Count -eq 0) { return }

    $compiled = foreach ($sig in $globs) {
        $sf = Split-SizeFloor $sig.Pattern
        [PSCustomObject]@{
            Sig = $sig
            Rx  = [regex]::new((Convert-GlobToRegex $sf.Pattern), 'IgnoreCase')
            Min = $sf.Min
        }
    }

    $pgN = 0
    foreach ($file in $Candidates) {
        if ((++$pgN % 50000) -eq 0 -and -not (Test-BudgetLeft)) { break }
        # Signature globs use forward slashes; compare on a normalized copy so one
        # pattern works on both platforms.
        $norm = $file -replace '\\', '/'
        foreach ($c in $compiled) {
            if (-not $c.Rx.IsMatch($norm)) { continue }
            if (-not (Test-SizeFloor $file $c.Min)) { continue }
            Add-Finding $c.Sig.Severity $c.Sig.Id $file 'path glob match' $c.Sig.Description
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

    $hashed = 0
    foreach ($file in $Candidates) {
        # Hashing reads every byte, so this stage must be bounded too.
        if ((++$hashed % 1000) -eq 0 -and -not (Test-BudgetLeft)) {
            Write-Warn "$Algorithm hashing stopped after $hashed of $($Candidates.Count) files (-TimeoutSeconds $TimeoutSeconds)"
            break
        }
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

function Split-ContentScope {
    param([string] $Pattern)
    # "[glob,glob] pattern" restricts a CONTENT match to matching paths.
    #
    # A bare string match cannot tell an infection from a description of one.
    # Investigating the campaign produces artifacts holding every marker string:
    # assistant transcripts, shell history, incident notes, a saved advisory, and
    # this scanner's own --json report. All were reported as CONFIRMED COMPROMISE
    # before scoping.
    if ($Pattern.StartsWith('[')) {
        $close = $Pattern.IndexOf('] ')
        if ($close -gt 1) {
            $globs = $Pattern.Substring(1, $close - 1)
            $rest = $Pattern.Substring($close + 2)
            $rx = @()
            foreach ($g in ($globs -split ',')) {
                $g = $g.Trim()
                if ($g) { $rx += (Convert-GlobToRegex $g) }
            }
            return @{ Pattern = $rest; Scopes = $rx }
        }
    }
    return @{ Pattern = $Pattern; Scopes = @() }
}

function Invoke-ContentCheck {
    param([object[]] $Signatures, [string[]] $Candidates)

    $sigs = @($Signatures | Where-Object { $_.Type -eq 'CONTENT' })
    if ($sigs.Count -eq 0) { return }

    $compiled = foreach ($sig in $sigs) {
        $sc = Split-ContentScope $sig.Pattern
        [PSCustomObject]@{
            Sig     = $sig
            Needle  = $sc.Pattern
            Scopes  = @(foreach ($r in $sc.Scopes) { [regex]::new($r, 'IgnoreCase') })
        }
    }

    foreach ($file in $Candidates) {
        try {
            $info = Get-Item -LiteralPath $file -Force -ErrorAction Stop
            if ($info.Length -gt $MaxFileSize) { continue }
            $text = [IO.File]::ReadAllText($file)
        } catch {
            Write-Diag "content skipped for ${file}: $($_.Exception.Message)"
            continue
        }
        $norm = $file -replace '\\', '/'
        foreach ($c in $compiled) {
            # Ordinal literal comparison: no regex dialect surprises, and it matches
            # the -F semantics of the sh implementation.
            if ($text.IndexOf($c.Needle, [StringComparison]::Ordinal) -lt 0) { continue }
            if ($c.Scopes.Count -gt 0) {
                $inScope = $false
                foreach ($r in $c.Scopes) { if ($r.IsMatch($norm)) { $inScope = $true; break } }
                if (-not $inScope) {
                    Write-Diag "out of scope: $file for $($c.Sig.Id)"
                    continue
                }
            }
            Add-Finding $c.Sig.Severity $c.Sig.Id $file 'content match' $c.Sig.Description
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

    $pvN = 0
    foreach ($file in $AllFiles) {
        if ((++$pvN % 20000) -eq 0 -and -not (Test-BudgetLeft)) { break }
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
# Exclusions
#
# The scanner's own directory and signature directory are ALWAYS excluded. The
# repository's tests/fixtures are built to trip every signature, and
# tools/run-latest.ps1 installs under ProgramData, so without this a fleet-wide
# run reported CONFIRMED COMPROMISE on every host from the tool's own test data.
#
# Accepted blind spot: anything able to write into the tool's install directory
# could equally rewrite the scanner, so excluding it concedes nothing defensible.
# Other copies of the repository are NOT auto-excluded, because matching "looks
# like a checkout" anywhere would be a spoofable blind spot. Use -Exclude.
# ---------------------------------------------------------------------------
function Get-CanonicalPath {
    param([string] $P)
    try {
        $item = Get-Item -LiteralPath $P -Force -ErrorAction Stop
        if ($item.PSIsContainer) { return $item.FullName }
        return $item.FullName
    } catch { return $P }
}

function Get-NormalizedPath {
    param([string] $P)
    # Slashes unified and runs collapsed, so a trailing separator or a doubled one
    # cannot defeat a prefix comparison.
    $n = $P -replace '\\', '/'
    while ($n -match '//') { $n = $n -replace '//', '/' }
    return $n.TrimEnd('/')
}

function Build-Exclusions {
    $out = New-Object System.Collections.ArrayList
    $add = {
        param($p)
        if ([string]::IsNullOrWhiteSpace($p)) { return }
        foreach ($v in @($p, (Get-CanonicalPath $p))) {
            $nv = Get-NormalizedPath $v
            if ($nv -and -not $out.Contains($nv)) { [void] $out.Add($nv) }
        }
    }

    $selfDir = Split-Path -Parent $PSCommandPath
    & $add $selfDir

    if (-not [string]::IsNullOrWhiteSpace($SignaturePath)) {
        if (Test-Path -LiteralPath $SignaturePath -PathType Container) {
            & $add $SignaturePath
        } else {
            & $add (Split-Path -Parent $SignaturePath)
        }
    }
    foreach ($e in $Exclude) { & $add $e }

    Write-Diag "excluding $($out.Count) path prefix(es)"
    return $out
}

function Test-Excluded {
    param([string] $FilePath, [object[]] $Prefixes)
    if (-not $Prefixes -or $Prefixes.Count -eq 0) { return $false }
    $n = Get-NormalizedPath $FilePath
    foreach ($p in $Prefixes) {
        if ($n -eq $p -or $n.StartsWith($p + '/', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Live implant processes
#
# Without this the scanner is blind to a running implant whose files have been
# removed: the dead-man's switch polls GitHub every 60 seconds, so the process can
# outlive its artifacts. Reporting that host as clean would be a false clean.
#
# Read-only: reads the process table and never signals or modifies anything.
# ---------------------------------------------------------------------------

# Tools whose normal job is to name a file they are inspecting, so an implant
# filename in their arguments means nothing. Interpreters are deliberately NOT
# listed: the real gh-token-monitor.sh is a shell script, so it appears as
# "/bin/sh /path/gh-token-monitor.sh" and skipping shells would miss it.
$script:ProcSkipTools = @(
    'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'find', 'locate', 'mdfind',
    'awk', 'sed', 'cat', 'less', 'more', 'head', 'tail', 'vi', 'vim', 'nvim',
    'emacs', 'nano', 'code', 'subl', 'open', 'strings', 'xxd', 'od', 'file',
    'ps', 'pgrep', 'wc', 'sort', 'uniq', 'diff', 'cmp', 'md5', 'shasum',
    'sha256sum', 'findstr', 'select-string', 'notepad', 'notepad++'
)

function Get-ProcessTable {
    # Returns objects with Pid, ParentPid, Exe, and Args.
    $rows = New-Object System.Collections.ArrayList
    $onWindows = $true
    $v = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
    if ($v) { $onWindows = [bool] $v.Value }   # PowerShell 7 defines this
    # Windows PowerShell 5.1 does not define $IsWindows, and only runs on Windows.

    if ($onWindows) {
        try {
            foreach ($p in Get-CimInstance Win32_Process -ErrorAction Stop) {
                $cmd = if ($p.CommandLine) { $p.CommandLine } else { $p.Name }
                [void] $rows.Add([PSCustomObject]@{
                    Pid = [int] $p.ProcessId
                    ParentPid = [int] $p.ParentProcessId
                    Exe = $p.Name
                    Args = $cmd
                })
            }
        } catch {
            Write-Warn "could not read the process table; PROCESS checks were SKIPPED"
            return $null
        }
    } else {
        try {
            # Invoked through a variable, and by absolute path where available:
            # on Windows "ps" is an alias for Get-Process, so a bare call trips
            # PSAvoidUsingCmdletAliases even though this branch is Unix-only.
            $psBin = if (Test-Path '/bin/ps') { '/bin/ps' } else { 'ps' }
            $out = & $psBin -Ao 'pid=,ppid=,args=' 2>$null
            if (-not $out) { $out = & $psBin ax -o 'pid=,ppid=,args=' 2>$null }
            if (-not $out) { throw 'ps produced no output' }
            foreach ($line in $out) {
                $t = $line.Trim() -split '\s+', 3
                if ($t.Count -lt 3) { continue }
                $exe = ($t[2] -split '\s+')[0]
                [void] $rows.Add([PSCustomObject]@{
                    Pid = [int] $t[0]
                    ParentPid = [int] $t[1]
                    Exe = $exe
                    Args = $t[2]
                })
            }
        } catch {
            Write-Warn "could not read the process table; PROCESS checks were SKIPPED"
            return $null
        }
    }
    return $rows
}

function Invoke-ProcessCheck {
    param([object[]] $Signatures)

    $sigs = @($Signatures | Where-Object { $_.Type -eq 'PROCESS' })
    if ($sigs.Count -eq 0) { return }

    $table = Get-ProcessTable
    if ($null -eq $table) { return }

    $byPid = @{}
    foreach ($r in $table) { $byPid[$r.Pid] = $r }

    # Every ancestor of this scan: an operator's own investigation command
    # frequently names the artifacts, and our argv mentions the signature path.
    $mine = New-Object System.Collections.Generic.HashSet[int]
    $cur = $PID
    $guard = 0
    while ($cur -and $cur -ne 0 -and $cur -ne 1 -and $guard -lt 40) {
        [void] $mine.Add($cur)
        if (-not $byPid.ContainsKey($cur)) { break }
        $cur = $byPid[$cur].ParentPid
        $guard++
    }

    foreach ($r in $table) {
        if ($mine.Contains($r.Pid)) { continue }
        $base = $r.Exe
        $slash = [Math]::Max($base.LastIndexOf('/'), $base.LastIndexOf('\'))
        if ($slash -ge 0) { $base = $base.Substring($slash + 1) }
        $base = $base -replace '\.exe$', ''
        if ($script:ProcSkipTools -contains $base.ToLowerInvariant()) { continue }

        foreach ($sig in $sigs) {
            if ($r.Args.IndexOf($sig.Pattern, [StringComparison]::Ordinal) -ge 0) {
                # PID only, never the command line: command lines can carry
                # credentials as arguments, and findings reach fleet console logs.
                Add-Finding $sig.Severity $sig.Id "pid $($r.Pid)" 'process match' $sig.Description
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Lockfile pins
#
# Invoke-PkgVerCheck only sees installed packages. A project that pins a
# compromised version in its lockfile but has never had `npm install` run on
# this host still needs remediation, and will reintroduce the bad version on the
# next install.
# ---------------------------------------------------------------------------

# bun.lockb is binary but not opaque: it embeds registry tarball URLs as
# contiguous ASCII, so the resolved-URL patterns work against a Latin-1 decode.
# A miss in a .lockb is less conclusive than a miss in a text lockfile.
$script:LockfileNames = @(
    'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock',
    'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'
)

function Get-PkgVerLookup {
    param([object[]] $Signatures)
    $want = @{}
    foreach ($sig in ($Signatures | Where-Object { $_.Type -eq 'PKGVER' })) {
        if (-not $want.ContainsKey($sig.Pattern)) { $want[$sig.Pattern] = $sig }
    }
    return $want
}

function Invoke-LockfileCheck {
    param([object[]] $Signatures, [string[]] $AllFiles)

    # Extract every (name, version) pair the lockfile actually declares, then look
    # each one up in the PKGVER table. One pass per lockfile, independent of how
    # many signatures are loaded.
    #
    # The earlier approach built a literal pattern per signature per format
    # (~16,000 for this campaign) and substring-searched each lockfile, which
    # measured 30-60s on a single 175 KB pnpm lockfile. Parsing structurally is
    # both faster and more precise: name and version are recovered as fields, so
    # an unscoped signature cannot match a scoped package sharing its basename.
    $want = Get-PkgVerLookup -Signatures $Signatures
    if ($want.Count -eq 0) { return }

    $lfseen = 0
    foreach ($file in $AllFiles) {
        if ((++$lfseen % 20000) -eq 0 -and -not (Test-BudgetLeft)) { break }
        $leaf = [IO.Path]::GetFileName($file)
        if ($script:LockfileNames -notcontains $leaf) { continue }

        # A lockfile nested inside node_modules is a dependency's own dev
        # lockfile; npm, yarn, and pnpm all ignore those when resolving, so a hit
        # there would mislead as well as waste work. npm-shrinkwrap.json is the
        # exception: npm does honor a shipped one.
        if ($file -match '(?i)[\\/]node_modules[\\/]' -and $leaf -ne 'npm-shrinkwrap.json') { continue }

        try {
            $info = Get-Item -LiteralPath $file -Force -ErrorAction Stop
            if ($info.Length -gt $MaxFileSize) {
                Write-Diag "lockfile skipped (over -MaxFileSize): $file"
                continue
            }
            # Latin-1 so bun.lockb's embedded ASCII survives; a UTF-8 decode
            # mangles the surrounding binary and can drop the URLs.
            $text = [IO.File]::ReadAllText($file, [Text.Encoding]::GetEncoding(28591))
        } catch {
            Write-Diag "lockfile skipped for ${file}: $($_.Exception.Message)"
            continue
        }

        $seen = New-Object System.Collections.Generic.HashSet[string]

        $report = {
            param($nv)
            if (-not $want.ContainsKey($nv)) { return }
            if (-not $seen.Add($nv)) { return }
            $sig = $want[$nv]
            Add-Finding $sig.Severity $sig.Id $file "pinned $nv in $leaf" $sig.Description
        }

        # "name@version" -> split at the LAST @ so scoped names survive.
        $atForm = {
            param($t)
            $p = $t.LastIndexOf('@')
            if ($p -gt 0) { & $report ($t.Substring(0, $p) + '@' + $t.Substring($p + 1)) }
        }
        # "name/version" (pnpm 5.x keys) -> split at the LAST slash.
        $slashForm = {
            param($t)
            $p = $t.LastIndexOf('/')
            if ($p -gt 0) { & $report ($t.Substring(0, $p) + '@' + $t.Substring($p + 1)) }
        }
        $token = {
            param($t)
            if ([string]::IsNullOrEmpty($t)) { return }
            if ($t.StartsWith('/')) { $t = $t.Substring(1) }
            if ($t.EndsWith(':')) { $t = $t.Substring(0, $t.Length - 1) }
            if ($t -eq '') { return }
            $t = $t.Replace('@npm:', '@')
            # Both forms are tried; each self-guards. A scoped name starts with
            # "@", so requiring the @ past index 0 would wrongly reject
            # "@cacheable/memory@2.2.1".
            & $atForm $t
            & $slashForm $t
        }

        foreach ($rawLine in ($text -split "`n")) {
            $line = $rawLine.TrimEnd("`r")

            # 1. Resolved registry tarball URL: .../<name>/-/<base>-<ver>.tgz
            #    Covers npm v1/v2/v3, npm-shrinkwrap, yarn v1, and bun.lockb.
            $i = $line.IndexOf('/-/')
            if ($i -gt 3) {
                $rest = $line.Substring($i + 3)
                $j = $rest.IndexOf('.tgz')
                if ($j -gt 1) {
                    $basever = $rest.Substring(0, $j)
                    $pre = $line.Substring(0, $i)
                    $k = $pre.LastIndexOf('/')
                    if ($k -ge 0) {
                        $last = $pre.Substring($k + 1)
                        $pre2 = $pre.Substring(0, $k)
                        $k2 = $pre2.LastIndexOf('/')
                        $prev = if ($k2 -ge 0) { $pre2.Substring($k2 + 1) } else { $pre2 }
                        # A scope only counts if the preceding segment starts with @.
                        $nm = if ($prev.StartsWith('@')) { "$prev/$last" } else { $last }
                        if ($basever.StartsWith("$last-")) {
                            & $report ($nm + '@' + $basever.Substring($last.Length + 1))
                        }
                    }
                }
            }

            # 2. Every quoted token: yarn berry resolutions, bun.lock entries, and
            #    quoted pnpm mapping keys.
            $parts = $line.Split('"')
            for ($m = 1; $m -lt $parts.Count; $m += 2) { & $token $parts[$m] }
            $parts = $line.Split("'")
            for ($m = 1; $m -lt $parts.Count; $m += 2) { & $token $parts[$m] }

            # 3. Bare pnpm mapping key: indented, ends in a colon.
            if ($line -match '^[ \t]+[^ \t"'']+:[ \t]*$') { & $token $line.Trim() }
        }
    }
}

# ---------------------------------------------------------------------------
# Candidate selection (spec section 6)
# ---------------------------------------------------------------------------
function Select-Candidates {
    param([string[]] $AllFiles, [object[]] $Signatures)

    $names = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($sig in ($Signatures | Where-Object { $_.Type -eq 'FILENAME' -or $_.Type -eq 'PATHGLOB' })) {
        # Strip any ">=N " size floor, then take the trailing path component so the
        # basename still enters the hash candidate set.
        $pv = (Split-SizeFloor $sig.Pattern).Pattern
        $leaf = ($pv -split '/')[-1]
        if ($leaf -and $leaf -notmatch '[*?]') { [void] $names.Add($leaf) }
    }
    foreach ($n in @('settings.json', 'tasks.json', 'package.json', 'setup.mjs')) {
        [void] $names.Add($n)
    }

    $out = New-Object System.Collections.ArrayList
    $rx = [regex]::new('[\\/](node_modules|\.claude|\.vscode)[\\/]', 'IgnoreCase')
    $n = 0
    foreach ($file in $AllFiles) {
        if ((++$n % 20000) -eq 0 -and -not (Test-BudgetLeft)) {
            Write-Warn "candidate selection stopped after $n files (-TimeoutSeconds $TimeoutSeconds)"
            break
        }
        $leaf = [IO.Path]::GetFileName($file)
        if ($names.Contains($leaf)) { [void] $out.Add($file); continue }
        # A compiled regex reused across files, rather than -match recompiling per
        # file, which is measurable over hundreds of thousands of paths.
        if ($rx.IsMatch($file)) { [void] $out.Add($file) }
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

    # Suppress colour when stdout is not a console, matching the sh scanner's
    # [ -t 1 ] guard, so redirected or piped output stays plain.
    $useColor = -not $NoColor -and -not $env:NO_COLOR -and -not [Console]::IsOutputRedirected
    $verdict = Get-Verdict
    $confirmed = @($script:Findings | Where-Object { $_.Severity -eq 'CONFIRMED' }).Count
    $suspect = @($script:Findings | Where-Object { $_.Severity -eq 'SUSPECT' }).Count

    if (-not $Quiet) {
        Write-Output "SandwormCheck $($script:ToolVersion)"
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
            Write-Output "SCAN TRUNCATED: the ${TimeoutSeconds}s -TimeoutSeconds was exhausted before the scan finished."
            Write-Output 'Some checks did not run. See the warnings on stderr for which.'
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
            } elseif ($Fast) {
                $msg = 'VERDICT: CLEAN (fast) - no indicators found. Content and hash sweeps were skipped by -Fast.'
                if ($useColor) { Write-Host $msg -ForegroundColor Green } else { Write-Output $msg }
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
        schema           = 'sandwormcheck/v1'
        tool_version     = $script:ToolVersion
        host             = Get-HostIdentifier
        scanned_at       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        duration_seconds = [int] $script:Stopwatch.Elapsed.TotalSeconds
        files_walked     = $script:FilesWalked
        truncated        = $script:Truncated
        fast_mode        = [bool] $Fast
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
        Write-Output "sandwormcheck $($script:ToolVersion)"
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

    $sigFiles = @(Resolve-SignatureFiles -Requested $SignaturePath)
    $signatures = @(Import-Signatures -Files $sigFiles)

    if ($Path) {
        foreach ($p in $Path) {
            if (-not (Test-Path -LiteralPath $p -PathType Container)) {
                Stop-WithError $EXIT_USAGE "-Path is not a directory: $p"
            }
        }
        $roots = @($Path | ForEach-Object { (Get-Item -LiteralPath $_).FullName } | Select-Object -Unique)
    } else {
        $roots = @(Get-DefaultScanPaths)
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
    $exclusions = @(Build-Exclusions)
    if ($exclusions.Count -gt 0) {
        # Inlined rather than piping through Where-Object with a function call per
        # path. A PowerShell function invocation per file over hundreds of thousands
        # of paths dominated the run: with a 20s budget the scan took 97s, almost all
        # of it here, after the walk had already stopped on time.
        $kept = New-Object System.Collections.ArrayList
        $exArr = @($exclusions)
        $n = 0
        foreach ($f in $allFiles) {
            if ((++$n % 20000) -eq 0 -and -not (Test-BudgetLeft)) {
                Write-Warn "exclusion filtering stopped after $n files (-TimeoutSeconds $TimeoutSeconds)"
                break
            }
            $nf = $f.Replace('\', '/')
            $skip = $false
            foreach ($p in $exArr) {
                if ($nf.Length -ge $p.Length -and
                    $nf.StartsWith($p, [StringComparison]::OrdinalIgnoreCase) -and
                    ($nf.Length -eq $p.Length -or $nf[$p.Length] -eq '/')) {
                    $skip = $true; break
                }
            }
            if (-not $skip) { [void] $kept.Add($f) }
        }
        $allFilesArr = @($kept)
    } else {
        $allFilesArr = @($allFiles)
    }
    $script:FilesWalked = $allFilesArr.Count

    # Wrap in @(): a PowerShell function returning an empty array yields $null,
    # and under Set-StrictMode reading .Count on $null throws. A scan whose
    # candidate set is legitimately empty must not crash.
    if ($Fast) {
        # The sweeps that consume this list do not run, so building it is pure cost.
        $candidates = @()
        Write-Diag '-Fast: candidate list not built'
    } else {
        $candidates = @(Select-Candidates -AllFiles $allFilesArr -Signatures $signatures)
    }
    Write-Diag "$($script:FilesWalked) files walked, $($candidates.Count) candidates"

    Invoke-PathExistsCheck -Signatures $signatures -HomeDirs $homeDirs
    Invoke-FilenameCheck -Signatures $signatures -Candidates $candidates
    Invoke-PathGlobCheck -Signatures $signatures -Candidates $candidates
    Invoke-ProcessCheck -Signatures $signatures
    Invoke-PkgVerCheck -Signatures $signatures -AllFiles $allFilesArr
    Invoke-LockfileCheck -Signatures $signatures -AllFiles $allFilesArr
    if ($Fast) {
        Write-Diag '-Fast: skipping content and hash sweeps by request'
    } else {
        if (Test-BudgetLeft) {
            Invoke-ContentCheck -Signatures $signatures -Candidates $candidates
        } else {
            Write-Warn "skipped content markers: -TimeoutSeconds $TimeoutSeconds exhausted"
        }
        if (Test-BudgetLeft) {
            Invoke-HashCheck -Signatures $signatures -Candidates $candidates -Algorithm 'SHA256'
            Invoke-HashCheck -Signatures $signatures -Candidates $candidates -Algorithm 'SHA1'
        } else {
            Write-Warn "skipped hash checks: -TimeoutSeconds $TimeoutSeconds exhausted"
        }
    }

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
    [Console]::Error.WriteLine("sandwormcheck: unhandled error: $($_.Exception.Message)")
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit $EXIT_ERROR
}
