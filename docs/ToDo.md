# To do

## Known gaps

- **The package version list is still incomplete.**
  `signatures/shai-hulud-2026-08-packages.conf` encodes **2,255 name@version pairs across
  463 package names**, from the union of the Wiz IOC CSV and JFrog's published table, with
  a 25-pair random sample independently corroborated against the npm registry
  (all 25 published 2026-08-04 then unpublished).
  No public source found so far lists more. Aikido, the vendor claiming the widest
  impact, reports **434 names across 1,381 versions** — fewer than ours in both
  dimensions — and all 16 packages it names are covered, including the five
  community-spread ones outside the keyv/cacheable namespaces (`@deliveroo/reevent`,
  `@or-sdk/invitations`, `@picsart/ai-sdk`, `@qlik/embed-runtime`, `picasso.js`).
  Socket's machine-readable feed has since been located and cross-checked
  (`https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv`)
  — 2,236 pairs, a strict subset of ours, contributing nothing new. Refresh with
  `tools/merge-package-list.sh`; see `docs/signatures.md`. Remaining avenue: re-query
  OSV.dev, which held no advisories for this campaign at all when checked. All source
  lists were labelled "Ongoing" at collection, so a periodic re-pull is warranted.
- **Loaded-but-fileless persistence is not detected.** The `PROCESS` check finds a
  running watcher, and `PATHEXISTS` finds the LaunchAgent plist or systemd unit file, but
  nothing queries `launchctl list` or `systemctl --user list-units`. A unit that is
  registered while its file has been deleted would be missed until it next spawns. Same
  for the `loginctl enable-linger` marker under `/var/lib/systemd/linger/`, which was
  left out because linger is legitimately enabled on many hosts and would false-positive.
- **No npm cache tarball inspection.** A malicious tarball sitting in `~/.npm/_cacache`
  is not detected unless it has been extracted. Worth adding as a `SUSPECT` check.
- **The Windows port now passes on real `windows-latest`**, across all ten fixture trees
  with correct exit codes, plus the malformed-signature, JSON-schema, and
  no-secret-disclosure assertions. Remaining caveat: CI runs **PowerShell 7**. Windows
  PowerShell **5.1** is still unverified, which is why the sources are kept pure ASCII (5.1
  reads a BOM-less file as ANSI) and bounds are validated manually rather than with
  `[ValidateRange]`. Worth one manual 5.1 run before trusting it on an older fleet.

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

## Go ecosystem support

The campaign crossed into Go on 2026-08-05: Socket's feed lists 21 golang entries across 8
modules, including the maintainer's own `github.com/jaredwray/{keyv,cacheable,ecto}`. See
`docs/references.md`.

Dependency detection here is npm-only. Adding Go would mean:

- a `GOMODVER` check type parsing `go.mod` and `go.sum`, whose version syntax
  (`v0.0.0-20260805040439-27421527967b`, `+incompatible` suffixes) does not fit `PKGVER`;
- module paths as identifiers (`github.com/owner/repo`) rather than package names, so the
  scoped-basename reasoning that governs the lockfile matcher does not transfer;
- lifting the npm-only filter in `tools/merge-package-list.sh`, which currently skips and
  reports non-npm rows.

Worth doing only if Go services in the fleet consume those modules. Until then the artifact
signatures still catch a Go-delivered infection by its payload, persistence, or process --
just not by its manifest. Stated in the README rather than left implicit.

## Known false-positive sources

- **Documentation about the campaign matches the campaign.** `CONTENT` signatures look for
  distinctive strings, and those appear in vendor advisories, IOC feeds, incident tickets,
  and this repository. A host storing any of that produces content matches. The tool's own
  directory and signature files are excluded automatically, and snapshot stores
  (`file-history`, `.history`) are pruned, but a saved advisory in `~/Documents` will still
  match. Corroborate content-only hits before paging anyone; `--exclude` covers known
  locations. A deeper fix would be to require corroboration before a content-only match is
  reported as `CONFIRMED`.
- **A second checkout of this repository is not auto-excluded.** Only the running install
  is. Detecting "a SandwormCheck checkout" anywhere on disk would be trivially spoofable
  into an arbitrary blind spot, so it is deliberately left to `--exclude`.
- **`tests/fixtures/` is inherently IOC-shaped.** A cleaner design would generate fixtures
  at test time so the repository never contains files matching its own shipped signatures.

## Repository hygiene

- Branch protection is applied with `tools/setup-repo-protection.sh`. It currently
  exempts admins from the review requirement, because requiring an approving review with
  one maintainer would block every merge. When a second maintainer joins, re-run it with
  `REQUIRE_APPROVALS=1 ENFORCE_ADMINS=true`.
- Required status check names in that script must match the rendered job names in
  `.github/workflows/test.yml`. The script verifies this, because a renamed job would
  otherwise silently stop being required.
- GitHub Actions are pinned to commit SHAs rather than tags; Dependabot proposes bumps
  weekly. A tag is a mutable reference, which is the attack class this tool detects.
- Not yet done: no CodeQL (little value for shell and PowerShell), no signed commits or
  signed tags, and no release process — `main` is the supported version.

## Deliberately not planned

- Automatic signature updates over the network. The scanner must never fetch and execute
  anything on a possibly-compromised host. Updates are `git pull`, an operator action.
- Remediation or quarantine actions. Read-only is a design constraint, not an omission —
  see `docs/spec.md`.
- Regex `CONTENT` matching. See `docs/assumptions.md` for why literal matching is used.
