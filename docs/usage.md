# Usage

## Requirements

| Platform | Needs | Notes |
|---|---|---|
| macOS | `/bin/sh` | Works on stock macOS. No Homebrew, no Node. |
| Linux | `/bin/sh` + coreutils | `sh`, `dash`, and `bash` all tested. |
| Windows | PowerShell 5.1+ | Ships with Windows 10/11. PowerShell 7 also works. |

Hash checks need one of `sha256sum`, `shasum`, or `openssl` on Unix; `Get-FileHash` is
built in on Windows. If no hashing tool is found, the scanner prints a warning and skips
hash checks rather than silently passing them.

## Basic invocation

Scan the default roots (all user home directories plus common deployment paths):

```sh
./sandwormcheck.sh
```

Run as root to reach every user profile:

```sh
sudo ./sandwormcheck.sh
```

Windows, from an elevated prompt:

```powershell
.\SandwormCheck.ps1
```

## Reading the result

```
$ ./sandwormcheck.sh --path ~/work
SandwormCheck 1.0.0
  host      : build-07/4e45e1ed311a
  scanned   : 1 roots, 21874 files, 38s
  campaigns :
              Shai-Hulud: Here We Go Again (keyv / cacheable npm worm) (2026.08.04.1)

Findings:
  CONFIRMED SH25-F001    /Users/dana/work/api/node_modules/keyv/Math_Symbol.js
            (filename match) Stage-two Bun payload bundle dropped by the worm loader
  SUSPECT   SH25-V001    /Users/dana/work/api/node_modules/keyv/package.json
            (installed keyv@6.0.0) Compromised release

VERDICT: CONFIRMED COMPROMISE — 1 confirmed, 1 suspect indicator(s). Isolate this host and rotate its credentials. See docs/remediation.md
$ echo $?
20
```

The `host` field is the hostname plus a truncated hash of hostname + machine ID. It lets
you correlate repeat scans of the same box without the tool transmitting anything.

## Options

### `-s`, `--signatures PATH` / `-SignaturePath PATH`

A signature file or a directory of `*.conf` files. Defaults to `signatures/` beside the
script. Pointing at a directory loads every campaign in it:

```sh
./sandwormcheck.sh --signatures /opt/ioc/campaigns
```

### `-p`, `--path PATH` / `-Path PATH`

Scan root. Repeatable. Overrides auto-detection entirely — useful for a targeted check
or a fast CI gate:

```sh
./sandwormcheck.sh --path /srv/app --path /home/deploy
```

```powershell
.\SandwormCheck.ps1 -Path C:\projects,C:\inetpub
```

### `--max-depth N` / `-MaxDepth N`

Directory recursion limit, 1–64, default 12. Deeply nested `node_modules` trees are the
reason the default is not lower. Lower it for a faster, shallower sweep.

### `--max-file-size N` / `-MaxFileSize N`

Files larger than this (bytes) are skipped for hash and content checks. Default 8 MiB;
the payload is ~728 KB. Raise it only if you have a reason to.

### `--timeout N` / `-TimeoutSeconds N`

Wall-clock ceiling, 10–86400, default 900. On expiry the scanner reports what it found
and marks the run truncated. **A truncated scan that found nothing exits `1`, not `0`** —
an incomplete scan is not a clean scan.

### `--json` / `-Json`

One JSON object on stdout. Diagnostics stay on stderr, so stdout is always parseable.

```sh
./sandwormcheck.sh --json | jq '{host, verdict, n: (.findings | length)}'
```

```json
{
  "schema": "sandwormcheck/v1",
  "tool_version": "1.0.0",
  "host": "build-07/4e45e1ed311a",
  "scanned_at": "2026-08-04T18:22:41Z",
  "duration_seconds": 38,
  "files_walked": 21874,
  "truncated": false,
  "paths_skipped": 0,
  "scan_roots": ["/Users/dana/work"],
  "campaigns": ["Shai-Hulud: Here We Go Again (keyv / cacheable npm worm) (2026.08.04.1)"],
  "counts": { "confirmed": 1, "suspect": 1 },
  "findings": [
    {
      "severity": "CONFIRMED",
      "id": "SH25-F001",
      "path": "/Users/dana/work/api/node_modules/keyv/Math_Symbol.js",
      "detail": "filename match",
      "description": "Stage-two Bun payload bundle dropped by the worm loader"
    }
  ],
  "verdict": "CONFIRMED",
  "exit_code": 20
}
```

The `schema` field is versioned. Anything consuming this output should check it before
reading fields, so a future `sandwormcheck/v2` does not break your pipeline silently.

### `-q`, `--quiet` / `-Quiet`

Verdict line only. For when the exit code is what you actually want:

```sh
./sandwormcheck.sh --quiet || echo "needs attention"
```

### `-v`, `--verbose` / `-Verbose`

Progress to stderr: which root is being walked, how many files and candidates. Use it
when a scan is slower than expected.

### `--no-color` / `-NoColor`

Disable ANSI color. Color is already suppressed automatically when stdout is not a TTY
or when `NO_COLOR` is set in the environment, so you rarely need this explicitly.

## Common recipes

**Only care whether the host is compromised, not whether a dependency needs bumping:**

```sh
./sandwormcheck.sh --quiet
[ $? -eq 20 ] && echo "INCIDENT" || echo "no confirmed compromise"
```

**Gate CI on a clean tree:**

```sh
./sandwormcheck.sh --path "$CI_PROJECT_DIR" --quiet --timeout 120
case $? in
  0)  echo "clean" ;;
  10) echo "compromised dependency version present"; exit 1 ;;
  20) echo "PAYLOAD PRESENT — failing hard"; exit 1 ;;
  *)  echo "scanner error — treating as a failure"; exit 1 ;;
esac
```

Note the `*)` branch. Treating a scanner error as a pass is how a broken check becomes a
silent gap.

**Archive results for later correlation:**

```sh
./sandwormcheck.sh --json > "/var/log/sandwormcheck-$(date -u +%Y%m%dT%H%M%SZ).json"
```

**Scan a single project quickly:**

```sh
./sandwormcheck.sh --path . --max-depth 8 --timeout 60
```

## Performance

Measured on a developer machine with 414,000 files and 14 GB across roughly 4,000
installed packages, a full scan takes about **6.5 minutes**, well inside the 900s default
timeout. Smaller trees finish in seconds. `--verbose` reports elapsed seconds per stage,
so if a scan is slow you can see which stage owns the time — content matching is normally
the largest share, since it is the only stage that reads every candidate file.

Three things keep it bounded:

1. Heavy directories are never descended into — caches, `.git/objects`, trash, cloud
   storage mounts, `/System`, `/proc`, and friends.
2. Content checks run on *candidate* files only: those whose name matches a signature, or
   that sit inside `node_modules`, `.claude`, or `.vscode`. The broad sweep uses a single
   batched `grep -l`, and only files that matched are re-read to identify which pattern
   hit.
3. Hash checks are narrower still — only files whose basename a signature actually names.
   Hashing reads every byte, and hashing the full candidate set would mean reading the
   whole 14 GB. If a signature set has hash records with no matching basename, the scanner
   warns rather than silently checking nothing.

If a scan is slow, run with `--verbose` to see which root is responsible, then narrow
with `--path` or lower `--max-depth`.

## Troubleshooting

**Exit 1 with "unknown check type" or "SHA256 must be 64 hex characters"**
A signature file has a malformed record; the message names the file and line. Malformed
records are a hard error on purpose — skipping them would quietly shrink coverage and
could report a host as clean when it was not scanned properly.

**"N path(s) unreadable and skipped"**
The scanner could not read those paths, so it cannot vouch for them. Re-run with `sudo`
or as Administrator.

**"SCAN TRUNCATED"**
The timeout expired mid-walk. Raise `--timeout` or narrow the scope with `--path`. The
exit code will be `1` rather than `0` if nothing was found, because the scan is
incomplete.

**"no SHA-256 tool found"**
Install coreutils or openssl. Hash checks are skipped until then, and the warning says
so — the scanner will not pretend those checks passed.

**"refusing to run under zsh"**
zsh does not field-split unquoted expansions, which would make the scanner under-report.
Invoke it as `./sandwormcheck.sh` or `sh sandwormcheck.sh`. If a POSIX `/bin/sh` exists the
script re-execs itself automatically.
