# SandwormCheck

A host-local scanner that answers one question: **does this machine show signs of the
npm supply chain worm that hit the `keyv` and `cacheable` namespaces on 2026-08-04?**

It prints what it found to the console and puts its verdict in the exit code, so you can
run it across a fleet with JumpCloud (or Ansible, Intune, SSH, or by hand) and triage by
result code.

- **Read-only.** It never modifies, quarantines, or deletes anything.
- **No network.** No C2, no telemetry, no phone-home, no signature auto-download. It
  works on air-gapped hosts.
- **No dependencies.** POSIX shell on macOS/Linux, PowerShell 5.1+ on Windows. Notably
  it does not need Node or npm — running an npm-based tool to investigate an npm
  compromise is a bad idea.
- **Extensible.** Indicators live in plain-text signature files. New campaign, new file;
  no code change.

## Quick start

```sh
git clone https://github.com/RealDougEubanks/SandwormCheck.git
cd SandwormCheck
./sandwormcheck.sh
echo "exit code: $?"
```

Windows:

```powershell
git clone https://github.com/RealDougEubanks/SandwormCheck.git
cd SandwormCheck
.\SandwormCheck.ps1
"exit code: $LASTEXITCODE"
```

With no arguments it scans user home directories and common deployment paths. Run it as
root or Administrator to cover every user profile on the machine.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| `0` | No indicators found | Nothing |
| `10` | **Suspect** — a compromised package version is present, but no payload or persistence | Bump the dependency; review the project |
| `20` | **Confirmed** — payload, persistence, or exfiltration artifact found | Treat the host as compromised: isolate it and rotate its credentials |
| `1` | Scanner error — bad signature file, or the scan did not finish | Fix and re-run. **This is not a clean result.** |
| `2` | Usage error — bad flag or argument | Fix the invocation |

The distinction between `10` and `20` is the useful part at fleet scale. A `10` is a
Monday-morning dependency bump. A `20` means someone's npm and cloud credentials are
already gone and you have an incident. See [docs/remediation.md](docs/remediation.md).

## What it looks for

The worm's on-disk footprint. **Every indicator in this repository comes from public
research published by others** — Wiz, Socket, JFrog, CyberKendra, and Aikido. This project
contributes the scanner, not the threat intelligence. See [Credits](#credits) for who found
what, and [docs/references.md](docs/references.md) for per-indicator provenance.

- **Payload files** — `Math_Symbol.js` and `math_init.js`, the ~728 KB Bun bundle.
- **Loader hashes** — known SHA-256 and SHA-1 digests of the payload and both
  `setup.mjs` loader variants.
- **IDE autostart hooks** — injected `.claude/settings.json` SessionStart hooks and
  `.vscode/tasks.json` folderOpen tasks. These run *without* `npm install`, so a working
  tree stays dangerous even after you delete `node_modules`.
- **Host persistence** — the `gh-token-monitor` dead-man's switch: its state directory,
  watcher script, macOS LaunchAgent, and Linux systemd user unit.
- **Exfiltration markers** — the `Shai-Hulud: Here We Go Again` string and the embedded
  threat string unique to this payload.
- **C2 and staging domains** — `npm-cache.com`, `pypi-get.com`, `js-mirror.com`.
- **Compromised package versions** — 2,255 `name@version` pairs across 463 package
  names, matched both against installed packages and against **lockfile pins**, so a
  project that pins a bad version without having installed it is still caught. Covers
  `package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`, `yarn.lock` (v1 and berry),
  `pnpm-lock.yaml` (v5/v6/v9), `bun.lock`, and `bun.lockb`.

### What it does not do

It reads the filesystem. It cannot see what your registry saw, and it cannot tell you
whether stolen credentials have been used. Pair it with a registry audit — see
[docs/references.md](docs/references.md#cross-checks-worth-running-alongside-this-scanner).

The package list is a point-in-time snapshot taken while the campaign was still
republishing. No public source found so far enumerates more than the 463 names / 2,255
versions encoded here: Socket's CSV feed (2,236 pairs) is a strict subset, and Aikido, the
vendor claiming the widest impact, reports 434 names across 1,381 versions with every
package it names covered. Notably both the Wiz and Socket feeds omit the entire `@keyv/*`
scope, so the list is a union of three vendors rather than a copy of one — see
[docs/references.md](docs/references.md). That is a good sign, not a completeness proof:
the worm was active when the lists were collected. **A clean result is not proof of
safety** — it means none of the encoded indicators were found.

Refresh the list with `tools/merge-package-list.sh`; see
[docs/signatures.md](docs/signatures.md#updating-this-campaign).

## Performance

Measured on a developer machine with 414,000 files and 14 GB across ~4,000 installed
packages: **about 6.5 minutes**, inside the 900s default timeout. Small trees finish in
seconds. Cost scales with files scanned, not with the number of signatures — see
[docs/spec.md](docs/spec.md) §11. Run with `--verbose` to get elapsed seconds per stage.

## Usage

```
./sandwormcheck.sh [options]

  -s, --signatures PATH   Signature file or directory (default: ./signatures)
  -p, --path PATH         Scan root; repeatable (default: auto-detected)
      --max-depth N       Directory depth limit (1-64, default 12)
      --max-file-size N   Skip larger files for hash/content checks (default 8 MiB)
      --timeout N         Wall-clock limit in seconds (10-86400, default 900)
      --json              Emit one JSON object instead of text
  -q, --quiet             Print only the verdict line
  -v, --verbose           Progress to stderr
      --no-color          Disable ANSI color
  -h, --help              Full help
```

More examples, including JSON output and CI use, are in [docs/usage.md](docs/usage.md).

## Fleet deployment

[docs/jumpcloud.md](docs/jumpcloud.md) has copy-paste JumpCloud commands for macOS,
Linux, and Windows, plus how to read the result codes across a fleet and equivalents for
Ansible, Intune, and plain SSH.

## Adding new indicators

Signature files are pipe-delimited text:

```
CHECK_TYPE|SEVERITY|ID|PATTERN|DESCRIPTION
```

For the next campaign, drop a new `.conf` into `signatures/` and both scanners pick it
up on the next run. Seven check types are supported: `PATHEXISTS`, `PATHGLOB`, `FILENAME`,
`SHA256`, `SHA1`, `PKGVER`, and `CONTENT`. The format contract, the false-positive rules, and
a worked example are in [docs/signatures.md](docs/signatures.md).

## Testing

```sh
./tests/run-tests.sh                              # against /bin/sh
SHELLS="sh bash dash zsh" ./tests/run-tests.sh    # every shell you care about
```

153 assertions covering every check type (true positive and true negative), all five exit
codes, every lockfile format, signature and argument validation, secret non-disclosure,
read-only behavior, and parity between the shell and PowerShell implementations. Several
fixtures are regressions from false positives found by scanning a real machine — a
legitimate package shipping `dist/.../setup.mjs`, a scoped package sharing an unscoped
signature's basename, and a dependency's own nested `yarn.lock`. Test fixtures contain
inert placeholder text — no live malware is in this repo.

## Documentation

| Document | Contents |
|---|---|
| [docs/spec.md](docs/spec.md) | Design contract: architecture, check semantics, scan bounding, exit codes |
| [docs/usage.md](docs/usage.md) | Command-line reference and examples |
| [docs/jumpcloud.md](docs/jumpcloud.md) | Fleet deployment and result triage |
| [docs/signatures.md](docs/signatures.md) | Signature format and how to add a campaign |
| [docs/remediation.md](docs/remediation.md) | What to do when a host comes back `20` |
| [docs/references.md](docs/references.md) | Source advisories and IOC provenance |
| [docs/assumptions.md](docs/assumptions.md) | Recorded design decisions and accepted risks |
| [docs/ToDo.md](docs/ToDo.md) | Known gaps and planned work |

## Credits

The detection content here is not original research. It is assembled from work published
by the following teams, each of whom investigated and disclosed this campaign — thanks to
all of them:

| Source | What this project uses from it |
|---|---|
| **[Wiz](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack)** | Payload filenames, SHA-1 hashes, C2 and staging domains, the embedded threat string, the `Shai-Hulud: Here We Go Again` exfil marker, the `Bun/1.3.13` user agent, and the Ethereum-contract C2 discovery mechanism. Their [IOC CSV](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv) supplied the bulk of the package list. |
| **[Socket](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain)** | SHA-256 hashes for the payload and both `setup.mjs` loader variants, the full `gh-token-monitor` persistence chain, the targeted credential inventory, and the OIDC trusted-publishing propagation path. Their [CSV feed](https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv) is the most convenient machine-readable package list. |
| **[JFrog](https://research.jfrog.com/post/shai-hulud-is-back-august/)** | The only published source carrying all 19 `@keyv/*` packages — the campaign's namesake scope, which both the Wiz and Socket feeds omit. Also corrected `file-entry-cache` to `11.1.6`. |
| **[CyberKendra](https://www.cyberkendra.com/2026/08/npm-worm-hits-keyv-and-cacheable.html)** | Publication timeline, the `file-entry-cache` / `flat-cache` transitive vector, `loginctl enable-linger` on Linux, the 24-hour TTL self-destruct, and the Defender detection name `Trojan:npm/MalBun.A`. |
| **[Aikido](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack)** | Independent impact figures used to cross-check package-list coverage, and the community-spread packages outside the keyv/cacheable namespaces. |

The package list is a **union** of these feeds precisely because none of them is complete
on its own. Where they disagree, `docs/references.md` records the discrepancy and how it
was resolved — including two cases where a published version number was wrong.

Vendor names and links are attribution only; none of these organisations endorse or are
affiliated with this tool.

## Security

The scanner reports paths and signature IDs only. It never prints file contents, so a
matched credential is not copied into your fleet console's command log. It requires no
elevated privileges beyond read access to the paths you want covered.

Report issues with the tool itself through this repository. If you find a machine that
comes back `20`, treat it as an incident first and file the bug second.

## License

MIT. See [LICENSE](LICENSE).
