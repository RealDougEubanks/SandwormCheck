# To do

## Known gaps

- **The package version list is incomplete.** Vendors reported 400+ affected packages;
  `signatures/shai-hulud-2026-08.conf` encodes 14 confirmed name@version pairs. Pull the
  current list from the Socket campaign page and extend the `PKGVER` block. See
  `docs/signatures.md#updating-this-campaign`.
- **No lockfile scanning.** The scanner reads installed `package.json` files, so it misses
  a project that pins a compromised version but has not installed it on any scanned host.
  A `LOCKFILE` check type reading `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`
  would close this.
- **No npm cache tarball inspection.** A malicious tarball sitting in `~/.npm/_cacache`
  is not detected unless it has been extracted. Worth adding as a `SUSPECT` check.
- **PSScriptAnalyzer has not been run** against `BunWormCheck.ps1` — it was not available
  in the development environment. `shellcheck -s sh` is clean for the shell scanner.
- **The Windows port has only been exercised via PowerShell 7 on macOS.** The logic is
  path-agnostic and the parity tests pass, but it has not run on Windows PowerShell 5.1 on
  a real Windows host. Validate before relying on it for a Windows fleet.

## Planned

- `LOCKFILE` check type (see above) — the largest single coverage gain available.
- Optional `--exclude PATH` flag for known-noisy directories on specific fleets.
- A `--list-signatures` flag to print the loaded signature set without scanning, for
  verifying a signature update landed before rolling it out.
- CI job running the suite across `sh`/`bash`/`dash` plus a Windows runner for the
  PowerShell port.
- A helper that converts a vendor CSV of affected packages into `PKGVER` records, since
  hand-transcribing 400 versions invites typos and a mangled record fails the scan closed.

## Deliberately not planned

- Automatic signature updates over the network. The scanner must never fetch and execute
  anything on a possibly-compromised host. Updates are `git pull`, an operator action.
- Remediation or quarantine actions. Read-only is a design constraint, not an omission —
  see `docs/spec.md`.
- Regex `CONTENT` matching. See `docs/assumptions.md` for why literal matching is used.
