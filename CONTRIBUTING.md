# Contributing to SandwormCheck

This is a security tool that people run on machines they are worried about. Two
consequences shape everything below:

1. **A false clean is the worst possible bug.** Reporting a compromised host as
   clean is worse than crashing, worse than a false positive, and worse than being
   slow. Any change that could cause a check to silently not run must fail loudly
   instead.
2. **A signature that fires on clean machines is also a bug.** It trains operators
   to ignore the tool, which produces false cleans by a slower route. One
   signature was removed after it produced 28 false positives on a single laptop.

## Quick start

```sh
git clone https://github.com/RealDougEubanks/SandwormCheck.git
cd SandwormCheck
./tools/install-hooks.sh          # pre-commit, pre-push, commit-msg
./tools/checks.sh                 # everything CI runs
```

Install the optional linters so the hooks do real work locally:

```sh
brew install shellcheck                                   # or: apt install shellcheck
pwsh -c 'Install-Module PSScriptAnalyzer -Scope CurrentUser'
```

Hooks **skip** checks whose tool is missing rather than blocking you, and say so.
CI installs everything and is the real gate.

## Workflow

`main` is protected: no direct pushes, no force pushes, CI must pass. Work on a
branch and open a pull request, even as the sole maintainer — the PR is where CI
runs and where the diff gets read.

```sh
git switch -c fix/short-description
# ... work ...
./tools/checks.sh
git push -u origin fix/short-description
gh pr create --fill
```

Branch names: `feature/`, `fix/`, `hotfix/`, `docs/`, or `claude/`.

Commit subjects go under 72 characters and say what changed — the `commit-msg`
hook rejects `wip`, `Update`, and similar. Bodies are free-form; explaining *why*
is more useful than restating the diff.

Self-merge is fine here. CI passing and reading your own diff are not optional.

## What every change needs

**Tests.** The suite is `tests/run-tests.sh`, plain POSIX sh with no framework.
Run it across every shell claimed in `docs/spec.md`:

```sh
SHELLS="sh bash dash zsh" ./tests/run-tests.sh
```

New behaviour needs a true positive *and* a true negative. Bug fixes need a test
that fails before the fix. Several existing fixtures came from real false
positives — `tests/fixtures/legit-setup/` and `lockfile/fp-basename/` exist
because scanning a real machine found them.

**Parity.** `sandwormcheck.sh` and `SandwormCheck.ps1` must agree on findings and
exit codes. The suite asserts this. A change to one almost always needs the other.

**No new dependencies.** POSIX sh plus coreutils, or PowerShell 5.1 with no
modules. The scanner deliberately cannot require Node — running an npm-based tool
to investigate an npm compromise is self-defeating, and the tool must work on a
server with no toolchain.

**No network calls in the scanners.** Enforced by a check. Signature updates are
an operator action (`git pull`), never a runtime fetch: a possibly-compromised
host should not be told to fetch and execute anything.

**Performance must scale with files, not signatures.** The shipped set holds a few
thousand records. Five stages were once O(signatures x files) and a full scan did
not finish; see the table in `docs/spec.md` section 11. Any new check must keep
cost proportional to files scanned. `--verbose` reports elapsed seconds per stage.

**Never print file contents.** Findings carry paths and signature IDs only. A
matched file may hold a live credential, and echoing it into a fleet console's
command log relocates the secret. Asserted by a test.

## Adding or changing signatures

Read [docs/signatures.md](docs/signatures.md) first. In short:

- Prefer the narrowest check type that works: `SHA256` over `FILENAME`,
  `PATHGLOB` over `FILENAME`.
- Before adding one, ask whether a legitimate developer could produce the
  artifact. Test against `tests/fixtures/clean/` **and** a real project tree.
- `CONFIRMED` means a host gets isolated and someone gets paged. When in doubt use
  `SUSPECT` and explain the ambiguity in the description — an operator reading a
  finding at 2am has only that sentence.
- The package list is generated. Edit `signatures/compromised-packages.txt` via
  `tools/merge-package-list.sh`, then regenerate with
  `tools/make-package-signatures.sh`. `tools/checks.sh` fails if the generated
  file is stale.
- Cite your source in `docs/references.md`. Every indicator in this repository
  came from published research by someone else; keep it that way and keep the
  credit accurate.

Merging package feeds **unions**, never replaces. Two of the three vendor feeds
omit the entire `@keyv/*` scope, so overwriting from one would silently delete 19
confirmed packages.

## Documentation

- `docs/spec.md` — the design contract. Change it in the same commit as behaviour.
- `docs/assumptions.md` — record any non-obvious decision, with the reason. This
  file is the project's memory; several entries exist because a "clean" refactor
  reintroduced a bug that had already been reasoned about once.
- `docs/ToDo.md` — known gaps. Adding a limitation here is not an admission of
  failure; an undocumented limitation is.

If a change makes the tool *less* certain about something, say so in the docs. The
README states plainly that a clean result is not proof of safety, and that the
package list is incomplete. Do not quietly upgrade those claims.

## Reporting a false positive

The most useful bug report for this project. Include the signature ID, the path
that matched, and why the file is legitimate. A confirmed false positive usually
becomes a fixture plus either a narrower signature or a removed one.

## Security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for a vulnerability in
the scanner itself.

## Licence

Contributions are accepted under the [BSD 3-Clause Licence](LICENSE). By opening a
pull request you confirm you have the right to contribute the code and agree to
license it under those terms.
