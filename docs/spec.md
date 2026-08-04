# BunWormCheck — Specification

Version: 1.0.0
Status: accepted
Last updated: 2026-08-04

## 1. Purpose

BunWormCheck is a host-local indicator-of-compromise scanner for the npm supply chain
worm that hit the `keyv` and `cacheable` namespaces on 2026-08-04 (self-identified in
its exfiltration artifacts as `Shai-Hulud: Here We Go Again`).

It answers one question per host: **does this machine show signs of this compromise?**
It reports to the local console and communicates its verdict through the process exit
code so a fleet management tool can triage thousands of results without parsing output.

### Non-goals

BunWormCheck does not:

- Remediate, quarantine, delete, or modify anything. It is strictly read-only.
- Contact any network service. No C2, no telemetry, no signature auto-update, no
  package registry lookups. See §7.
- Replace an EDR product or a registry-side dependency audit. It inspects the host
  filesystem only.
- Prove a host is clean. A `0` exit means "none of the encoded indicators were found."

## 2. Threat model of the thing being detected

Understanding the malware's behavior drives the check design. From the Wiz, Socket, and
CyberKendra write-ups (see `docs/references.md`):

| Stage | Behavior | On-disk artifact |
|---|---|---|
| Delivery | Malicious package versions published to npm; `preinstall` hook | `setup.mjs` in the package tarball |
| Loader | Downloads Bun 1.3.13 from GitHub releases into a temp dir | `/tmp/bun-dl-*` |
| Payload | ~728 KB Bun bundle, basE91-obfuscated | `Math_Symbol.js`, `math_init.js` |
| Credential theft | Cloud metadata (169.254.169.254), npm/GitHub tokens, Vault, K8s SA tokens, AI tool configs, crypto wallets, `/etc/shadow` | none reliably |
| C2 discovery | Resolves domains from an Ethereum contract via `eth_call` | domain strings in payload |
| Exfiltration | Pushes to attacker-created GitHub repos | repo description `Shai-Hulud: Here We Go Again` |
| Persistence (repo) | IDE autostart hooks that run without `npm install` | `.claude/settings.json` SessionStart hook, `.vscode/tasks.json` folderOpen task |
| Persistence (host) | Dead-man's-switch token watcher polling GitHub every 60s | `~/.config/gh-token-monitor/`, `~/.local/bin/gh-token-monitor.sh`, macOS LaunchAgent, Linux systemd user unit |
| Propagation | Stolen npm token + OIDC trusted publishing republishes the maintainer's whole portfolio | new malicious versions |

Two consequences shape the design:

1. **A Node-based scanner is disqualified.** The compromise lives in the npm
   ecosystem. A scanner that needs `npm install` to run could pull a malicious
   transitive dependency onto the host it is auditing, and may not run at all on a
   server without a Node toolchain. The scanner must have zero runtime dependencies
   beyond the OS shell.
2. **Repo-level IDE hooks execute without an install step.** Scanning only
   `node_modules` misses a live persistence vector. Project working trees must be
   scanned for `.claude/` and `.vscode/` hook injection independently of packages.

## 3. Architecture

```
signatures/*.conf      ← campaign IOC data (pipe-delimited, no code)
        │
        ├──────────────┬───────────────────┐
        ▼              ▼                   ▼
 bunwormcheck.sh   BunWormCheck.ps1    tests/run-tests.sh
 (macOS, Linux)      (Windows)          (fixtures)
        │              │
        └──────┬───────┘
               ▼
      console report (text or JSON)
      + tiered exit code
```

Two scanner implementations, one signature format. Both engines implement the same
check types with the same semantics, read the same `.conf` files, and produce the same
exit codes. Adding a new campaign — this worm's next wave, or an unrelated one — means
adding a `.conf` file. It must not require touching either scanner.

### 3.1 Why data-driven

The user requirement is that this be reusable "to scan for new things as they come
out." Encoding IOCs as data rather than shell conditionals means:

- A responder who is not a shell programmer can add indicators.
- Signature files can be reviewed as a diff of facts, not logic.
- The engines stay under test while the data churns.
- Multiple campaigns can be scanned in one pass (`--signatures` accepts a directory).

## 4. Signature file format

Plain text, one record per line, pipe-delimited. Chosen over JSON/YAML because both
POSIX `sh` and PowerShell 5.1 parse it without a third-party library or `jq`.

```
CHECK_TYPE|SEVERITY|ID|PATTERN|DESCRIPTION
```

- `#` at the start of a line is a comment. Blank lines are ignored.
- Leading/trailing whitespace around each field is stripped.
- `PATTERN` must not contain a literal `|`. `DESCRIPTION` is the last field and may.
- A file must declare metadata via comment directives:
  `#!campaign`, `#!version`, `#!updated`, `#!reference`.

### 4.1 Check types

| Type | `PATTERN` semantics | Notes |
|---|---|---|
| `PATHEXISTS` | Absolute path, `~` expanded, shell glob allowed | Persistence artifacts |
| `FILENAME` | Exact basename, matched anywhere under a scan root | Dropped payloads |
| `PATHGLOB` | Glob matched against the full discovered path | Filenames too common to match on basename alone |
| `SHA256` | 64 hex chars, compared against candidate files | Highest confidence |
| `SHA1` | 40 hex chars | Some vendors published SHA-1 only |
| `PKGVER` | `name@version`, exact match against `package.json` | Vulnerable-version detection |
| `CONTENT` | Literal substring, searched in bounded candidate files | Strings, domains, markers |

Rejected as out of scope for v1: regex content matching (portability of regex dialects
between `grep` and .NET is a correctness trap), and version *ranges* for `PKGVER`
(semver comparison in POSIX `sh` is not worth the bug surface — the campaign publishes
discrete bad versions, so enumerate them).

### 4.2 Severity

- `CONFIRMED` — the artifact has no benign explanation. Payload files, matching
  hashes, host persistence units, exfil markers.
- `SUSPECT` — consistent with compromise but has plausible benign causes. A vulnerable
  package version present on disk (may never have executed), or a domain string that a
  legitimate web3 project might reference.

Severity is a property of the indicator, declared in the signature file. The engine
does not infer it.

## 5. Exit codes

| Code | Meaning | Fleet action |
|---|---|---|
| `0` | No indicators found | none |
| `10` | Only `SUSPECT` indicators found | schedule a dependency bump; review |
| `20` | At least one `CONFIRMED` indicator found | treat host as compromised; rotate credentials, isolate |
| `1` | Scanner error (unreadable signatures, malformed record, internal failure) | fix and re-run; **not** a clean result |
| `2` | Usage error (bad flag, bad argument) | fix invocation |

Highest severity wins: a host with both a `SUSPECT` and a `CONFIRMED` finding exits
`20`. Codes are contiguous with room to insert future tiers, and deliberately avoid
the 126–165 range reserved by shells for "command not found" and signal deaths.

`1` must never be conflated with clean. A JumpCloud policy that alerts on non-zero
handles this correctly by default.

## 6. Scan scope and bounding

Scanning an entire disk for `node_modules` is slow enough that fleet operators will
disable it. Default scope:

**Package/project roots** (recursive, depth-bounded):
- Every real user home directory (`/Users/*` on macOS, `/home/*` on Linux, plus
  `$HOME` and root's home)
- `/opt`, `/srv`, `/var/www`, `/usr/local/lib/node_modules`

**Pruned unconditionally** — never descended into:
`.git/objects`, `.Trash`, `Library/Caches`, `Library/CloudStorage`, `/System`,
`/private/var/vm`, `/proc`, `/sys`, `/dev`, `/Volumes`, `/net`, snap/flatpak mounts.

**Explicit host paths**: the `PATHEXISTS` records are checked directly, independent of
scan roots, so persistence units are found even with a narrow `--path`.

Bounds, all overridable:
- `--max-depth` (default 12) — passed to the directory walk.
- `--max-file-size` (default 8 MiB) — files above this are not hashed or content-searched.
  The payload is ~728 KB; the cap keeps a stray VM image from stalling the scan.
- `--timeout` (default 900s) — wall-clock ceiling. On expiry the scanner reports what
  it found, prints an explicit truncation warning, and exits `1` if nothing was found
  (an incomplete scan is not a clean scan) or the severity code if something was.

Content and hash checks only consider *candidate* files: those whose basename matches a
`FILENAME` signature, or that live in a path segment named `node_modules`, `.claude`,
or `.vscode`. Hashing every file on the disk is not viable; hashing the files the
malware is known to write is.

## 7. No network egress

The scanner makes no outbound connections. This is a hard requirement, not a default:

- A possibly-compromised host should not be told to fetch and execute anything.
- Fleet scanning must work on air-gapped and egress-filtered machines.
- The user explicitly required no C2.

Signature updates arrive through `git pull` or by copying a `.conf` file — an operator
action, never an automatic runtime fetch. Tests assert the scanner sources contain no
network invocation (`curl`, `wget`, `nc`, `Invoke-WebRequest`, ...).

## 8. Output

Default is human-readable text on stdout: a per-finding line with severity, ID, path,
and description, then a summary block with host identity, counts, and the verdict.

`--json` emits a single JSON object for log pipelines: schema version, host, scan
metadata (roots, duration, truncation flag), a `findings` array, and the verdict plus
exit code. Diagnostics go to stderr in both modes so stdout stays parseable.

`--quiet` suppresses per-finding output, printing only the verdict line. Useful when
only the exit code matters.

The report includes a stable host identifier (hostname plus a truncated hash of
hostname + machine ID) so findings can be correlated across runs without transmitting
anything. No file contents, secrets, or matched credential material are ever printed —
only paths and signature IDs. Printing a matched secret into a JumpCloud command log
would move the secret somewhere new.

## 9. Privileges

Runs unprivileged, scanning what the invoking user can read. Under JumpCloud (root),
coverage extends to all user home directories and root-owned persistence paths.
Unreadable paths are counted and reported as `skipped`, never silently swallowed —
a scan that could not read `/Users/alice` must say so rather than imply alice is clean.

## 10. Testing requirements

- Fixture trees under `tests/fixtures/`: `clean/`, `suspect/` (vulnerable
  `package.json` only), `confirmed/` (payload filename, known-hash file, injected IDE
  hooks, exfil marker string).
- One test per check type asserting both a true positive and a true negative.
- Exit-code assertions for all five codes.
- Malformed signature records must exit `1` with a message naming file and line — not
  be skipped silently, which would produce a false clean.
- Argument validation: unknown flags, non-numeric bounds, out-of-range bounds,
  nonexistent `--path`.
- A guard test asserting no network primitives in either scanner.
- Fixture payload files contain inert text, never real malware. Hash-match fixtures
  use a file whose hash is added to a test-only signature file.

## 11. Compatibility

- `bunwormcheck.sh`: POSIX `sh`. Tested against `bash` 3.2 (macOS system shell),
  `dash`, and `zsh`. No bashisms, no `mapfile`, no `[[`, no arrays.
- `BunWormCheck.ps1`: PowerShell 5.1 (shipped with Windows 10/11) and PowerShell 7+.
  No external modules.
- External commands used, all in POSIX or base OS: `find`, `grep`, `sed`, `awk`, `od`,
  plus one of `shasum`/`sha256sum`/`openssl` for hashing (probed at startup; absence
  disables hash checks with a loud warning rather than a silent pass).
