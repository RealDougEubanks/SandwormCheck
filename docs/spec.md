# SandwormCheck — Specification

Version: 1.0.0
Status: accepted
Last updated: 2026-08-04

## 1. Purpose

SandwormCheck is a host-local indicator-of-compromise scanner for the npm supply chain
worm that hit the `keyv` and `cacheable` namespaces on 2026-08-04 (self-identified in
its exfiltration artifacts as `Shai-Hulud: Here We Go Again`).

It answers one question per host: **does this machine show signs of this compromise?**
It reports to the local console and communicates its verdict through the process exit
code so a fleet management tool can triage thousands of results without parsing output.

### Non-goals

SandwormCheck does not:

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
 sandwormcheck.sh   SandwormCheck.ps1    tests/run-tests.sh
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
| `FILENAME` | Exact basename, matched anywhere under a scan root. Optional `>=<bytes> ` size floor | Dropped payloads |
| `PATHGLOB` | Glob against the full path; `*` stays within one segment, `**` crosses. Optional `>=<bytes> ` size floor | Filenames too common to match on basename alone |
| `SHA256` | 64 hex chars, compared against candidate files | Highest confidence |
| `SHA1` | 40 hex chars | Some vendors published SHA-1 only |
| `PKGVER` | `name@version`, exact match against `package.json` **and lockfiles** | Vulnerable-version detection |
| `CONTENT` | Literal substring in bounded candidate files, with an optional `[glob,glob] ` path scope | Strings, domains, markers |
| `PROCESS` | Literal substring, searched in running process command lines | Live implant whose files are gone |

Rejected as out of scope for v1: regex content matching (portability of regex dialects
between `grep` and .NET is a correctness trap), and version *ranges* for `PKGVER`
(semver comparison in POSIX `sh` is not worth the bug surface — the campaign publishes
discrete bad versions, so enumerate them). Note this means a lockfile *range spec*
such as `"keyv": "^6.0.0"` is not matched; only the resolved version is.

### 4.2 Investigating the campaign must not look like the campaign

A string match cannot distinguish an infection from a description of one. Everything that
records an investigation ends up holding every marker string the scanner looks for:

| Artifact | Why it matches |
|---|---|
| `~/.claude/projects/*.jsonl` | a user asked an assistant whether they were infected |
| shell history, terminal logs | the investigator grepped for the filenames |
| incident notes, tickets, saved advisories | they quote the IOCs |
| **this scanner's own `--json` report** | findings embed the descriptions and domains |

All of these were reported as `CONFIRMED COMPROMISE` on real hosts. The last is the sharpest:
the documentation tells operators to save `--json` output, and the next scan then flags that
file — the tool manufacturing evidence of its own compromise.

`CONTENT` signatures therefore take an optional path scope, `[glob,glob] pattern`, and every
shipped one uses it. The scopes match where the artifact actually lives: IDE configs,
package manifests, launchd/systemd units, shell rc files, and code. A `.jsonl` transcript, a
`.log`, a `.md`, or a stray `.json` report is not where a payload lives.

The signature *descriptions* already said this — "in a config or unit file", "inside an IDE
config or package manifest". The implementation ignored it. Where a description states a
scope, the pattern must now encode it.

Residual: a code file deliberately containing a marker string still matches. That is a much
narrower surface than every file on disk, and it is documented rather than hidden.

### 4.3 Filename collisions with legitimate packages

A payload filename is not automatically distinctive. The worm's ~728 KB Bun bundle is named
`Math_Symbol.js`, and `regenerate-unicode-properties` ships a legitimate 1 KB Unicode
codepoint list at `General_Category/Math_Symbol.js`. `Math_Symbol` is the real Unicode
category `Sm`, and that package is a transitive dependency of `@babel/plugin-transform-*`,
so it appears in a large share of all JavaScript projects. Matching the basename at
`CONFIRMED` produced five findings on an untouched host and instructed the operator to
isolate it and rotate every credential.

Two independent discriminators are used, and either alone would have prevented it:

1. **Position.** The loader writes the payload at a package *root*
   (`node_modules/keyv/Math_Symbol.js`); the Unicode file sits one level deeper under
   `General_Category/`. Expressing that requires `*` not to cross a separator, which is why
   `PATHGLOB` has real glob semantics rather than treating `*` as "any characters".
2. **Size.** A `>=<bytes> ` prefix on the pattern requires a minimum file size. 728 KB
   versus 1 KB is not a close call.

The general rule for signature authoring: before adding a filename signature, check whether
the name exists in the registry. A name that looks distinctive may have been chosen
*because* it blends into common dependency trees.

### 4.4 Process coverage

Filesystem checks alone leave a false-clean hole: this campaign's dead-man's switch
polls GitHub every 60 seconds, and the payload has a 24-hour TTL self-destruct, so
the process can outlive its own artifacts. A host whose files were partially
cleaned but whose watcher is still resident would otherwise report `CLEAN`.

`PROCESS` matches a literal substring against the full argument list of every
running process, with two restrictions:

1. **The scanner's own ancestry is skipped.** Our argv names the signature
   directory, and the shell that launched us often names the artifacts too.
2. **Processes whose executable is an inspection tool are skipped** — `grep`,
   `find`, `vim`, `strings`, `cat`, and similar. Naming a suspicious file is their
   job. Interpreters are deliberately *not* excluded: the real
   `gh-token-monitor.sh` is a shell script and appears as
   `/bin/sh /path/gh-token-monitor.sh`, so skipping shells would miss the exact
   implant the check exists to find.

Both restrictions were added in response to failures found while testing. Matching
every command line with no exclusions reported an operator's own
`grep -r Math_Symbol.js /` as a **confirmed compromise** — an incident responder
would have implicated themselves. Narrowing to `argv[0]`/`argv[1]` fixed that but
missed `bun run <payload>`, where the payload sits at `argv[2]`.

Shells running an **inline** script (`-c`, `-Command`) are skipped: the whole script text
sits in their arguments, so any mention of an artifact name matched. An operator running
`sh -c "...Math_Symbol.js..."` was reported as a confirmed compromise. A real script implant
runs as `/bin/sh /path/implant.sh`, with no `-c`.

**Findings name the PID only, never the command line.** Command lines can carry
credentials passed as arguments, and findings are written to fleet console logs;
printing one would relocate a secret. Asserted by a test.

If the process table cannot be read, the check is skipped with a warning rather
than silently passing.

Not covered, and recorded in `docs/ToDo.md`: whether a LaunchAgent or systemd unit
is *loaded* (as opposed to its file existing), the `loginctl enable-linger` marker,
and the npm cache. A `launchctl`/`systemctl` query would catch a unit that is
registered while its plist has been deleted.

### 4.5 Lockfile coverage

`PKGVER` matches two independent sources:

1. **Installed manifests** — the first `name` and `version` in each
   `package.json`. Reported as `installed <name@version>`.
2. **Lockfile pins** — `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
   `pnpm-lock.yaml`, `bun.lock`, and `bun.lockb`. Reported as
   `pinned <name@version> in <lockfile>`.

Lockfiles matter because a project can pin a compromised version without it ever
being installed on the scanned host — a fresh `npm install` would then reintroduce
it. Deliberately **not** a separate `LOCKFILE` check type: that would require two
signature records per package version, doubling a file that already holds a few
thousand records and creating a second place for the two to drift apart.

Matching **parses the lockfile structurally** rather than substring-searching it.
For each line the scanner recovers candidate `(name, version)` pairs and looks
each one up in a hash table built from the `PKGVER` records:

1. **Resolved registry tarball URL** — `.../<name>/-/<basename>-<version>.tgz`,
   covering `package-lock.json` v1/v2/v3, `npm-shrinkwrap.json`, `yarn.lock` v1,
   and `bun.lockb`. The scope is recovered by checking whether the path segment
   before the name begins with `@`.
2. **Quoted tokens** — yarn berry `resolution: "name@npm:version"`, `bun.lock`
   entries, and quoted pnpm mapping keys. Split at the *last* `@` so scoped names
   survive.
3. **Bare pnpm mapping keys** — `name@version:` (v6/v9) and `/name/version:`
   (v5). The latter splits at the last `/`.

Two properties follow from parsing rather than pattern matching:

- **Cost is independent of signature count.** One pass per lockfile. The earlier
  design generated a literal pattern per signature per format — about 16,000
  patterns for this campaign — and ran `grep -Ff` over each lockfile. That
  measured 30–60 seconds on a single 175 KB pnpm lockfile, because BSD `grep`
  degrades sharply with a large `-f` pattern file. Structural parsing brought the
  same stage from 90s to under 1s on a real repository.
- **No basename false positive is possible.** Name and version are recovered as
  fields, so an unscoped signature such as `utils@2.5.1` cannot match
  `@cacheable/utils@2.5.1`. The pattern-based design needed a secondary confirm
  regex to suppress exactly this; parsing removes the class of bug rather than
  patching it. A regression fixture covers it.

**Nested lockfiles.** A lockfile inside `node_modules/` is a dependency's own dev
lockfile. npm, yarn, and pnpm all ignore those when resolving, so reporting one
would be a misleading claim about the scanned project — they are skipped.
`npm-shrinkwrap.json` is the deliberate exception: npm honors a shipped
shrinkwrap, so a nested one does affect what gets installed and is still read.

`bun.lockb` is binary but not opaque — it stores registry URLs as contiguous
ASCII. NUL bytes are translated to newlines before parsing (and it is read as
Latin-1, never UTF-8, which mangles the surrounding bytes). A *hit* there is as
reliable as in a text lockfile; a *miss* is less conclusive, because its
non-registry entries are not recoverable this way.

Not detected, all failing closed as false negatives rather than false positives:
git, `file:`, `link:`, and `workspace:` dependencies; yarn berry `patch:`
resolutions, which are percent-encoded; pnpm and bun alias forms; and npm entries
that carry no `resolved` field.

### 4.6 Severity

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
- Every home directory in a conventional user-home location, taken from the OS user
  database (`dscl` on macOS, `getent`/`/etc/passwd` elsewhere) rather than by globbing:
  `/Users/*`, `/home/*`, `/export/home/*`, plus `/root` and `/var/root`. Globbing missed
  macOS's root account (home `/var/root`, not `/root`) and any directory-service account
  with a home elsewhere.
- `/opt`, `/srv`, `/var/www`, `/usr/local/lib/node_modules`

**Per-user checks cover EVERY account**, not just the walked ones. `PATHEXISTS` patterns
beginning `~/` are expanded against every home in the user database, including service
accounts whose homes live under `/var/db` or `/var/lib`. Those homes are not *walked* --
there are hundreds and some are large -- but a path lookup is cheap, so per-user
persistence (`~/.config/gh-token-monitor`, `~/Library/LaunchAgents/...`) is still detected
on a service account. Walk roots are selected by location rather than by UID: a UID
threshold silently dropped accounts that had previously been covered.

A scan root that is a **symlink is followed** (`find -H`); symlinks *inside* the tree are
not. Following inner links would let one pull the scan outside its root and permit cycles.
Without following the root, a symlinked path such as macOS's `/tmp` walks zero files and the
scan reports clean.

**Always excluded** — the scanner's own directory, its loaded signature files, and anything
passed to `--exclude`. This is load-bearing rather than tidy: `tests/fixtures/` is built to
trip every signature and the tool installs into a default scan root, so without it a fresh
install reports itself as a confirmed compromise. Signature files match their own `CONTENT`
patterns for the same reason. Other copies of the repository are not auto-excluded, because
detecting "a checkout" anywhere would be a spoofable blind spot — use `--exclude`.

**Pruned unconditionally** — never descended into:
`.git/objects`, `.Trash`, `Library/Caches`, `Library/CloudStorage`, `/System`,
`/private/var/vm`, `/proc`, `/sys`, `/dev`, `/Volumes`, `/net`, snap/flatpak mounts, and the
tool-managed snapshot stores `file-history` and `.history`. Snapshot stores mirror whatever
was edited, so they reproduce every marker string the scanner looks for: 142 of 156 findings
on the development machine were an agent's `file-history` copies of the signature files.

**Explicit host paths**: the `PATHEXISTS` records are checked directly, independent of
scan roots, so persistence units are found even with a narrow `--path`.

Bounds, all overridable:
- `--max-depth` (default 12) — passed to the directory walk.
- `--max-file-size` (default 8 MiB) — files above this are not hashed or content-searched.
  The payload is ~728 KB; the cap keeps a stray VM image from stalling the scan.
- `--timeout` (default 1800s) — wall-clock ceiling for the **whole** scan. On expiry the
  scanner reports what it found, prints an explicit truncation warning naming the stages
  that were skipped, and exits `1` if nothing was found (an incomplete scan is not a clean
  scan) or the severity code if something was.

  The budget is checked between stages and between work chunks (4,000 files for the content
  sweep, 2,000 for hashing), and once per root during the walk. It is therefore a **soft**
  ceiling: a scan can overshoot by up to one chunk or one root. A 60s budget measured 92s
  on a large home directory. When sizing this against a fleet tool's own command timeout,
  leave headroom — the point is for the scanner to self-report a truncated scan rather than
  be killed mid-run, which yields no verdict at all.

  Cheap checks (persistence paths, filenames, path globs, processes, package versions,
  lockfiles) always run. Only the expensive content and hash sweeps are skipped when the
  budget is gone, so a truncated scan still covers the highest-signal indicators.

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

## 11. Performance with large signature sets

The shipped signature set holds a few thousand `PKGVER` records. Three separate
scaling traps showed up while measuring against a real developer machine
(414,000 files, 14 GB across ~4,000 installed packages), each of which made a
fleet scan unusable:

| Stage | Naive form | Cost | Fix |
|---|---|---|---|
| Signature parsing | ~15 processes per record | 51s before reading a file | single `awk` pass |
| `PKGVER` matching | rescan every signature per manifest | O(sigs x files) | `name@version` hash lookup |
| Lockfile matching | ~16,000 `grep -F` patterns per file | 30-60s per lockfile | structural parse, O(file) |
| Hashing | hash every candidate | reads all 14 GB | narrow to signature basenames |
| Content matching | one `grep` per pattern per file | ~10 processes per file | batched `grep -Ff` via `xargs` |

The governing rule for any future check: **cost must scale with the number of
files scanned, not with signatures times files.** A scanner nobody runs because
it takes an hour detects nothing.

`--verbose` prints elapsed seconds against each stage so a regression here is
visible in the output rather than needing a profiler.

## 12. Compatibility

- `sandwormcheck.sh`: POSIX `sh`. Tested against `bash` 3.2 (macOS system shell),
  `dash`, and `zsh`. No bashisms, no `mapfile`, no `[[`, no arrays.
- `SandwormCheck.ps1`: PowerShell 5.1 (shipped with Windows 10/11) and PowerShell 7+.
  No external modules.
- External commands used, all in POSIX or base OS: `find`, `grep`, `sed`, `awk`, `od`,
  plus one of `shasum`/`sha256sum`/`openssl` for hashing (probed at startup; absence
  disables hash checks with a loud warning rather than a silent pass).
