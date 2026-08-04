# To do

## Known gaps

- **The package version list is still incomplete.**
  `signatures/shai-hulud-2026-08-packages.conf` encodes **2,255 name@version pairs across
  463 package names**, from the union of the Wiz IOC CSV and JFrog's published table, with
  a 25-pair random sample independently corroborated against the npm registry
  (all 25 published 2026-08-04 then unpublished).
  **Aikido reports 868 package names** — roughly 1.9x ours — and publishes no export.
  Their version count (1,381) is *lower* than ours (2,255), so the lists differ in shape
  rather than one containing the other; there is plausibly a tail of a few hundred names
  missing. Getting that list is the highest-value remaining action, followed by Socket's
  real-time campaign page (HTTP 403 to scripted fetches; needs a browser session).
  Both source lists were labelled "Ongoing" at collection, so a re-pull is warranted.
- **No npm cache tarball inspection.** A malicious tarball sitting in `~/.npm/_cacache`
  is not detected unless it has been extracted. Worth adding as a `SUSPECT` check.
- **The Windows port has only been exercised via PowerShell 7 on macOS.** The logic is
  path-agnostic and the parity tests pass, but it has not run on Windows PowerShell 5.1 on
  a real Windows host. Validate before relying on it for a Windows fleet.

## Planned

- **A nested `npm-shrinkwrap.json` hit is reported like a project-level pin.** Nested
  lockfiles are skipped except shrinkwraps (npm honors those), but when one does fire the
  wording does not say the pin belongs to a dependency rather than to this project.
- **`bun.lockb` misses are inconclusive** and are currently reported the same as a text
  lockfile miss. Surfacing that distinction would avoid overstating coverage.
- **Content matching still reads every candidate file.** It is the dominant remaining
  cost on a large tree. Restricting the broad sweep by extension, or dropping it to
  signature basenames the way hashing does, would cut it — at some loss of breadth.
- **8 packages are reportedly still live on npm** with the `preinstall` hook intact
  (7 `@ornikar/*` plus `@onereach/postcss-scoped-selector@1.2.1`) rather than
  unpublished. They are in the signature set, but flagging them as *still installable*
  would help operators prioritize.
- Optional `--exclude PATH` flag for known-noisy directories on specific fleets.
- A `--list-signatures` flag to print the loaded signature set without scanning, for
  verifying a signature update landed before rolling it out.
- CI job running the suite across `sh`/`bash`/`dash` plus a Windows runner for the
  PowerShell port.

## Done since first draft

- Lockfile scanning, as an extension to `PKGVER` rather than a separate check type.
  Covers npm v1/v2/v3, shrinkwrap, yarn v1 and berry, pnpm v5/v6/v9, `bun.lock`, and
  `bun.lockb`, by parsing each lockfile structurally rather than pattern-matching it.
- Package list expanded from 14 to **2,255** name@version pairs across 463 names, with
  `tools/make-package-signatures.sh` to regenerate it from a `name@version` list with
  validation and stable hash-derived IDs.
- Corrected `file-entry-cache@11.1.7` (does not exist) to `11.1.6`.
- PSScriptAnalyzer run and clean at Error+Warning, with every exclusion justified in
  `PSScriptAnalyzerSettings.psd1`. `shellcheck -s sh` is clean for the shell scanner and
  the test suite.
- Removed `SH25-R004` (`CONTENT|setup.mjs`), which produced 28 false positives when
  scanning a real machine. Regression fixture added.
- Performance work to make a fleet scan viable: signature parsing, `PKGVER` matching,
  lockfile matching, hashing, and content matching were each O(signatures x files) or
  worse. See the table in `docs/spec.md` section 11. `--verbose` now reports elapsed
  seconds per stage so regressions are visible.

## Deliberately not planned

- Automatic signature updates over the network. The scanner must never fetch and execute
  anything on a possibly-compromised host. Updates are `git pull`, an operator action.
- Remediation or quarantine actions. Read-only is a design constraint, not an omission —
  see `docs/spec.md`.
- Regex `CONTENT` matching. See `docs/assumptions.md` for why literal matching is used.
