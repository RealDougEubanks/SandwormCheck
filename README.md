# BunWormCheck

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
git clone https://github.com/your-org/BunWormCheck.git
cd BunWormCheck
./bunwormcheck.sh
echo "exit code: $?"
```

Windows:

```powershell
git clone https://github.com/your-org/BunWormCheck.git
cd BunWormCheck
.\BunWormCheck.ps1
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

The worm's on-disk footprint, drawn from the Wiz, Socket, and CyberKendra write-ups
(full provenance in [docs/references.md](docs/references.md)):

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
- **Compromised package versions** — `keyv@6.0.0`, `cacheable@2.5.1`,
  `flat-cache@6.1.24`, `file-entry-cache@11.1.7`, and the rest of the known set.

### What it does not do

It reads the filesystem. It cannot see what your registry saw, so it will not catch a
project that pinned a bad version but never installed it on a scanned host, and it
cannot tell you whether stolen credentials have been used. Pair it with a lockfile sweep
and a registry audit — see [docs/references.md](docs/references.md#cross-checks-worth-running-alongside-this-scanner).

Vendors reported 400+ affected packages and the campaign was republishing in real time.
The package-version list here is a point-in-time snapshot and is certainly incomplete.
**A clean result is not proof of safety** — it means none of the encoded indicators were
found.

## Usage

```
./bunwormcheck.sh [options]

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

The suite covers every check type (true positive and true negative), all five exit
codes, signature and argument validation, secret non-disclosure, read-only behavior, and
parity between the shell and PowerShell implementations. Test fixtures contain inert
placeholder text — no live malware is in this repo.

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

## Security

The scanner reports paths and signature IDs only. It never prints file contents, so a
matched credential is not copied into your fleet console's command log. It requires no
elevated privileges beyond read access to the paths you want covered.

Report issues with the tool itself through this repository. If you find a machine that
comes back `20`, treat it as an incident first and file the bug second.

## License

MIT. See [LICENSE](LICENSE).
