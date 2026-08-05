# Assumptions

Non-obvious decisions, per the project Golden Rules. Newest last.

---

**Assumption:** The scanner is written in POSIX `sh` and PowerShell, not Node/TypeScript,
despite the project Golden Rules defaulting to strict typing and Zod validation.
**Why:** The compromise being detected lives in the npm ecosystem. A Node-based scanner
would need `npm install` to run, which risks pulling a malicious transitive dependency
onto the host it is auditing, and would not run at all on servers without a Node
toolchain. JumpCloud executes shell on macOS/Linux and PowerShell on Windows, both
present by default. The Golden Rules' intent — validated, typed, bounded input — is met
through explicit runtime validation of every signature record and CLI argument, with a
hard error on anything malformed.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Signature severity is declared as data in the signature file rather than
inferred by the engine.
**Why:** Whether an indicator has a benign explanation is a property of the indicator, and
the person encoding it from a vendor advisory is the one who knows. Inference in the
engine would need updating for every new campaign, defeating the data-driven design.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** A malformed signature record is a fatal error (exit `1`), not a skipped
line.
**Why:** Skipping it would silently shrink coverage. A scan that quietly stopped checking
half its indicators and then reported "clean" is the worst possible failure mode for this
tool. Failing closed forces the operator to fix the file.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** A truncated scan that found nothing exits `1`, not `0`.
**Why:** "I did not finish looking" and "I looked everywhere and found nothing" are
different answers. Collapsing them would let a timeout on a slow host be recorded as a
clean bill of health.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** No version-range matching for `PKGVER`; exact versions are enumerated.
**Why:** Semver range comparison in POSIX `sh` is a large bug surface for little gain —
the campaign publishes discrete malicious versions, so enumeration is both simpler and
more precise. Accepted cost: the version list needs updating as new versions surface,
which is a signature-file edit.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** `CONTENT` checks use literal substring matching, not regex.
**Why:** Regex dialects differ between `grep` and .NET. A pattern that matched on macOS
but not Windows would produce inconsistent fleet results that are very hard to debug.
Every indicator in the current campaign is expressible as a literal string.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Hash and content checks run only against a candidate file set (files
matching a `FILENAME` signature, plus anything inside `node_modules`, `.claude`, or
`.vscode`), not every file walked.
**Why:** Hashing every file on a developer disk takes hours, and a scanner nobody runs
detects nothing. Accepted risk: an indicator whose file is outside the candidate set will
not fire. Documented in `docs/signatures.md` with the workaround (add a `FILENAME` record
to bring the file into the set).
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Public Ethereum RPC providers used by the payload for C2 discovery
(`eth.llamarpc.com`, `eth-mainnet.nodereal.io`, `go.getblock.io`) are deliberately **not**
encoded as signatures.
**Why:** They are legitimate public services. On any web3 developer's machine they appear
in normal project code, and a signature that fires on clean hosts trains operators to
ignore the tool. The campaign-specific domains (`npm-cache.com`, `pypi-get.com`,
`js-mirror.com`) are encoded instead. Accepted risk: a host that contacted only the RPC
providers and left no other artifact will not be flagged by content matching.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** `setup.mjs` is matched ONLY by `PATHGLOB` scoped to `.claude/` and
`.vscode/`, and by the loader hashes. There is no `FILENAME` or `CONTENT` record for it.
**Why:** `setup.mjs` is a common legitimate filename, so a basename match would flag a
large share of clean projects — that is why the `PATHGLOB` check type exists. A
lower-severity `CONTENT|SUSPECT|setup.mjs` record was kept initially as defence in depth,
then removed: scanning one real developer machine produced **28 false positives** from it.
`emdash` ships `dist/astro/middleware/setup.mjs`, `motion-dom` ships
`gestures/utils/setup.mjs`, and source maps and `package.json` files reference the name in
passing. The `PATHGLOB` records already cover the directories the worm actually writes to.
A signature that fires on clean machines trains operators to ignore the tool, which is
worse than not having the signature. Regression fixture: `tests/fixtures/legit-setup/`.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Wiz's three 40-hex-character values, labelled SHA256 in their advisory,
are encoded as `SHA1`.
**Why:** 40 hex characters is a SHA-1 digest; 64 is SHA-256. The label appears to be an
error. Both algorithms are supported by the engines, so encoding them correctly costs
nothing and a mislabeled entry would simply never match.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Findings report file paths and signature IDs only — never file contents or
matched text.
**Why:** The payload harvests credentials, so a matched file may contain live secrets.
Echoing content into a JumpCloud command log would copy a secret into a new system with
different access controls and retention. Enforced by a test that scans a fixture
containing a fake token and asserts it does not appear in either output mode.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** The host identifier is `hostname` plus the first 12 hex characters of
SHA-256(hostname + machine ID).
**Why:** Lets an operator correlate repeat scans of the same machine without the tool
transmitting anything. Truncation to 48 bits is adequate for de-duplicating a fleet and
is not relied on for security.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** The scanner re-execs itself under `/bin/sh` when invoked as
`zsh sandwormcheck.sh`, and refuses to run if no POSIX `sh` exists.
**Why:** zsh does not field-split unquoted parameter expansions, which caused eleven
checks to silently under-report during testing. Under-reporting produces a false clean —
the failure mode this tool must never have. A hard re-exec is preferable to either a
degraded scan or a rewrite in the intersection of both shells' semantics.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** The PowerShell port validates numeric bounds manually instead of using
`[ValidateRange]`.
**Why:** `[ValidateRange]` fails at parameter binding, which exits `1` — the scanner-error
code — where the documented usage-error code is `2`. Both scanners must agree on exit
codes or fleet triage becomes platform-dependent.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** The Golden Rules sections on caching/CDN, health check endpoints, API
versioning, and pagination are not applicable and are not implemented.
**Why:** SandwormCheck is a single-shot local CLI. It exposes no HTTP surface, serves no
requests, and has no deployable service to health-check. The `--json` output is
schema-versioned (`sandwormcheck/v1`), which is the applicable form of the API-versioning
rule.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Lockfile scanning extends the existing `PKGVER` check type rather than
adding a separate `LOCKFILE` type.
**Why:** A separate type would need two signature records per compromised version —
4,510 records instead of 2,255 for this campaign — and create a second place for the
pair to drift out of sync. One record covering both sources, with the `detail` field
distinguishing `installed X` from `pinned X in <lockfile>`, gives the operator the same
information with half the data and no possibility of disagreement.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Lockfiles are parsed structurally to recover `(name, version)` pairs,
rather than searched for per-signature literal patterns.
**Why:** The pattern approach needed ~16,000 literals to cover 2,255 versions across six
formats, and measured 30-60 seconds on a single 175 KB pnpm lockfile — BSD `grep`
degrades sharply with a large `-f` file. It also required a secondary confirm regex to
stop an unscoped signature matching a scoped package that shares its basename. Parsing
is O(file) regardless of signature count, and recovers name and version as fields, which
removes that false-positive class entirely instead of patching it. Measured 90s to under
1s on a real repository.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Lockfiles nested inside `node_modules/` are skipped, except
`npm-shrinkwrap.json`.
**Why:** A `yarn.lock` or `package-lock.json` shipped inside a published package is that
package's own dev lockfile; npm, yarn, and pnpm all ignore them when resolving, so
reporting one would be a false claim about the scanned project. npm *does* honor a
shipped `npm-shrinkwrap.json`, so those still affect what gets installed and are read.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Hash checks run only against files whose basename a `FILENAME` or
`PATHGLOB` signature names; content checks keep full breadth but are size-bounded; and
neither bound applies to `FILENAME`/`PATHGLOB` matching.
**Why:** Hashing reads every byte, and the candidate set on a real machine measured
260,000 files totalling 14 GB. Narrowing by basename loses nothing real, because every
published hash for this campaign belongs to a file the malware writes under a known
name — and if a signature set has hash records with no matching basename, that gap is
warned about rather than passing silently. Size bounds must NOT gate
`FILENAME`/`PATHGLOB`, since a path match needs no file read and an oversized payload is
still detectable by name; an earlier revision filtered the shared candidate list by size
and would have missed exactly that.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** `bun.lockb` is scanned despite being a binary format, using `grep -a`
and a Latin-1 decode on Windows.
**Why:** It stores registry tarball URLs as contiguous ASCII, so the resolved-URL
patterns work against it. A UTF-8 decode mangles the surrounding binary and can drop
those URLs, hence the explicit Latin-1. Accepted limitation: a *hit* is as reliable as
in a text lockfile, but a *miss* is less conclusive, because non-registry entries are
not readable this way. Documented in `docs/spec.md` §4.2.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** Signature IDs in the generated package file are derived from a hash of
`name@version` rather than assigned sequentially.
**Why:** IDs end up in incident tickets and need to stay stable. The package list is
known to be incomplete and will be regenerated from longer inputs; sequential numbering
would renumber every entry after each insertion. Hash-derived IDs only ever add. The
generator checks for collisions and fails rather than silently merging two packages
under one ID.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** `file-entry-cache@11.1.6` is the compromised version, not `11.1.7` as
Socket's advisory states.
**Why:** `11.1.7` has never existed on npm. The registry's `time` map records `11.1.6`
published 2026-08-04T10:13:02Z with no corresponding entry in `versions`, which is the
signature of a version that was published and then unpublished in a takedown. Wiz and
JFrog both say `11.1.6`. Socket's `11.1.7` looks like a typo, and it was carried into an
earlier revision of this repo's signature file before being caught.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** PowerShell function returns are wrapped in `@()` at the call site
wherever `.Count` is read.
**Why:** A PowerShell function returning an empty array yields `$null`, and under
`Set-StrictMode -Version 2.0` reading `.Count` on `$null` throws. This surfaced as a
crash on the first scan whose candidate set was legitimately empty (a directory holding
only a lockfile). Guarding at the call site is more robust than relying on every
function to return a non-empty collection.
**Recorded by:** Claude
**Date:** 2026-08-04

---

**Assumption:** The git hooks and CI both invoke `tools/checks.sh` rather than each
defining their own checks.
**Why:** Two definitions drift, and then "it passed locally" and "it passed in CI" stop
meaning the same thing — which is how a check quietly stops running. One entry point with
`--staged` and `--quick` flags keeps them identical by construction.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** Hooks skip a check whose tool is missing, and warn, rather than failing
the commit.
**Why:** A contributor without shellcheck should still be able to clone and commit. The
alternative makes the toolchain a barrier to entry for a tool whose whole premise is
having no dependencies. CI installs everything and is the enforcing gate, so nothing
reaches `main` unchecked either way. This is a deliberate trade of local strictness for
approachability, not an oversight.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `tools/make-package-signatures.sh` takes the `#!updated` date as an
argument instead of using today's date.
**Why:** Embedding the clock made the generated file differ every day, so the drift check
in `tools/checks.sh` failed for a reason unrelated to content. A generator whose output
depends only on its inputs can be verified byte-for-byte; one that reads the clock cannot.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** Branch protection requires a pull request and passing CI, but exempts
admins from the review requirement (`enforce_admins: false`,
`required_approving_review_count: 0`).
**Why:** With a single maintainer, requiring an approving review would make every merge
impossible, and requiring admin enforcement would lock the owner out of their own
repository. This enforces the parts that catch real mistakes — a PR to read the diff on,
and green CI — without a rule that can only be satisfied by disabling it. Documented in
`tools/setup-repo-protection.sh` with the exact settings to change when a second
maintainer joins.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** GitHub Actions are pinned to commit SHAs, not version tags.
**Why:** A tag is a mutable reference. Moving a tag under a consumer is the same attack
class this repository exists to detect, so pinning by tag in a supply chain scanner would
be self-undermining. Dependabot is configured to propose SHA bumps weekly so pinning does
not mean going stale.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** The secret scan in `tools/checks.sh` excludes `tests/fixtures/` and
`*.md`, and uses conservative provider-prefixed patterns.
**Why:** Fixtures deliberately contain inert fake tokens to prove the scanner does not
echo file contents, and the docs quote credential formats. Scanning them would produce
permanent false failures and train contributors to bypass the hook with `--no-verify`,
which is worse than a narrower scan. Patterns require a provider prefix
(`ghp_`, `AKIA`, `npm_`, ...) rather than entropy heuristics, for the same
false-positive-cost reason that governs the detection signatures themselves.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `PROCESS` findings report the PID only, never the matched command line.
**Why:** Command lines routinely carry credentials as arguments, and findings are written
to fleet console logs. Printing one would move a secret into a new system with different
access controls, which is the same reasoning that keeps file contents out of every other
finding. Asserted by a test.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `PROCESS` matching searches the full argument list but skips processes
whose executable is an inspection tool, and does not skip interpreters.
**Why:** Three revisions were needed. Matching all command lines with no exclusions
reported an operator's own `grep -r Math_Symbol.js /` as a CONFIRMED compromise, so an
incident responder investigating a host would implicate themselves. Restricting to
`argv[0]`/`argv[1]` removed that but missed `bun run <payload>`, where the payload is at
`argv[2]`. Excluding by executable restores full argument coverage without the
self-report. Interpreters must stay in scope because the real `gh-token-monitor.sh` runs
as `/bin/sh /path/gh-token-monitor.sh`; an intermediate revision skipped shells and
missed it entirely.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** npm, pnpm, and yarn debug logs are included in the content candidate set.
**Why:** Those logs record the `preinstall` hook that ran, which survives deleting
`node_modules` and is often the only remaining trace on a host that was partially cleaned.
Cheap to add, since the logs are few and small.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `file_size()` selects the stat flavour from the mode probed at startup and
falls back to `wc -c`, rather than chaining `stat -f || stat -c`.
**Why:** The chained form is correct on BSD and silently wrong on GNU, where `-f` means
`--file-system` and a BSD format string is therefore taken as a *filename*. GNU printed
filesystem details for the real file and failed on the bogus one, so the fallback appended
the real size to that output. The caller received a multi-line string, the numeric
comparison errored, and `--max-file-size` stopped being enforced on every Linux host.
Developed and tested only on macOS, this was invisible until CI ran on Linux.
`probe_stat` now probes GNU first, because a BSD-first probe is ambiguous on GNU rather
than cleanly failing. A total failure reports size 0, which makes a file look small and so
gets it scanned rather than skipped — for a detection tool, erring toward doing the work is
the safe direction. `tests/shims/gnu-stat/` replays the GNU path from a BSD host so this
cannot regress.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `tools/checks.sh` runs `shellcheck --severity=warning`, not the default.
**Why:** shellcheck exits non-zero on *any* finding, including info-level advisories, and
distros ship different releases with different info checks enabled. Ubuntu's shellcheck
failed CI on notes that the locally installed 0.11.0 does not emit at all — SC2317
("unreachable") fired on a trap handler, which is a false positive by construction. CI
breaking because a distro bumped a package is noise, not signal. Warnings and errors still
fail the gate. The genuinely avoidable notes were rewritten rather than silenced, so the
codebase is clean at default severity too.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** The PowerShell port invokes `ps` through a variable, by absolute path where
one exists.
**Why:** On Windows `ps` is an alias for `Get-Process`, so PSScriptAnalyzer flags a bare
call under `PSAvoidUsingCmdletAliases` even though that branch is unreachable on Windows —
the CIM path is used there. Static analysis cannot see the platform guard. Invoking through
a variable is also more explicit about calling the Unix binary rather than a cmdlet.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** The missing-hash-coverage warning keys off the SIGNATURE SET, not off an
empty candidate list.
**Why:** The first version warned whenever the hash candidate list came out empty, which is
the normal state of a clean host with no matching files. It therefore fired on healthy
machines, telling operators "hash checks will find nothing" — which reads as a broken tool
and trains them to ignore its output, the same dynamic that makes a noisy signature worse
than no signature. Coverage is a property of the signature set (hash records with no
FILENAME/PATHGLOB to bring a file into scope), not of the host being scanned. Found by
running the real deployment path against the public repository rather than a fixture.
**Recorded by:** Claude
**Date:** 2026-08-05

**Assumption:** The directory walk uses `find -H`, following a symlink given as a scan root
but not symlinks encountered inside the tree.
**Why:** `find <symlink>` returns zero files. Without `-H` a symlinked root was walked as
nothing and the scan reported CLEAN — a false clean, the worst failure mode this tool has.
It was not hypothetical: `/tmp` is a symlink to `private/tmp` on macOS, so `--path /tmp`
scanned nothing, and a relocated or symlinked home directory would have silently gone
uncovered across a fleet. Symlinks *within* the tree remain unfollowed on purpose: following
them would let a link pull the scan outside its root and would allow cycles. Both halves are
covered by tests.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** The scanner always excludes its own directory and its loaded signature
files, and prunes tool-managed snapshot stores (`file-history`, `.history`).
**Why:** `tests/fixtures/` is built to trip every signature, and `tools/run-latest.*`
installs to `/opt/sandwormcheck` or `%ProgramData%` — both inside default scan roots. A
fresh install scanned by itself returned exit 20, "isolate this host and rotate all
credentials", so a fleet-wide run would have reported **100% false positives on the first
sweep** and permanently destroyed trust in the tool. Signature files also match their own
`CONTENT` patterns, and editor/agent snapshot stores mirror any scanned content, which is
how 142 of 156 findings on the development machine turned out to be Claude Code's
`file-history` copies of the signature files.
**Accepted blind spot:** anything able to write into the tool's own install directory could
equally rewrite the scanner itself, so excluding it concedes nothing that was defensible.
Other copies of the repository are deliberately NOT auto-excluded, because matching "looks
like a SandwormCheck checkout" anywhere on disk would be trivially spoofable into an
arbitrary blind spot; `--exclude` covers those explicitly.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** A signature *directory* is excluded wholesale, but a signature *file* only
by its own exact path.
**Why:** Excluding a signature file's parent directory silently excludes everything beside
it. Pointing `--signatures` at a file in a directory that also holds scan targets would
then cover nothing while still reporting a verdict. Caught when seven tests began passing
signature files from the same temporary directory as their fixtures.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** Exclusion prefixes are compared with runs of slashes collapsed, and are
recorded in both the `/private/...` and `/...` spellings on macOS.
**Why:** `$TMPDIR` commonly ends in a slash, so walked paths can contain `T//name` while
the prefix holds `T/name`; a trailing slash on `--exclude` produces the same mismatch; and
macOS reaches the same directory as both `/tmp` and `/private/tmp`. Each of these made an
exclusion silently miss, and a missed exclusion means the tool reports its own fixtures.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `PROCESS` skips shells running an inline script (`-c`, `-Command`).
**Why:** A shell invoked with `-c` carries the entire script text in its arguments, so any
mention of an artifact name looks like a match. An incident responder running
`sh -c "...Math_Symbol.js..."` was reported as a CONFIRMED compromise — the tool
implicating the person investigating with it. A genuine script implant is executed as
`/bin/sh /path/implant.sh`, with no `-c`, so skipping this form costs no real detection.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** The test suite scans a COPY of `tests/fixtures/` placed outside the
repository.
**Why:** Self-exclusion covers the install directory, which contains the fixtures, so
scanning them in place tested nothing — 127 assertions failed the moment self-exclusion
landed. Copying them out lets the suite exercise the real shipped default rather than
needing a `--no-self-exclude` escape hatch that production would never use, and keeps the
run hermetic.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** Home directories are enumerated from the OS user database, and per-user
`PATHEXISTS` checks run against *every* account while only conventionally-located homes are
walked.
**Why:** Globbing `/Users/*` and `/home/*` missed macOS's root account, whose home is
`/var/root` rather than `/root`, and any directory-service or network account with a home
elsewhere. Since this campaign's persistence is per-user, a missed home is a missed
compromise on that account — and the scanner is run as root precisely to cover them all.
Service-account homes are excluded from the *walk* because there are hundreds and some are
large, which would push a fleet scan past any sane timeout; they remain covered by the
cheap path-existence checks. Walk roots are chosen by location, not by a UID threshold: the
UID heuristic looked more principled but silently dropped accounts such as
`/Users/HDHomeRun` that the previous globbing had always covered.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** The deployment runners fall back to a GitHub zip archive when git is
absent, and also when a git update fails.
**Why:** A Windows host in the fleet reported "git not found", and a scanner that cannot
install is a scanner that detects nothing. An archive carries no history and no signature,
but that is the same trust level as a shallow clone over HTTPS, so the fallback gives up
nothing that the primary path provided. The archive is validated — it must contain the
scanner — before the existing copy is replaced, so a failed or hijacked download leaves a
working install in place rather than destroying it. TLS 1.2 is forced explicitly because
Windows PowerShell 5.1 does not negotiate it by default.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `PATHGLOB` implements real glob semantics (`*` within one segment, `**`
across) and both `PATHGLOB` and `FILENAME` accept an optional `>=<bytes> ` size floor.
**Why:** A live fleet scan returned five `CONFIRMED` findings on a host nobody had touched in
months, all on `node_modules/regenerate-unicode-properties/General_Category/Math_Symbol.js`
— a legitimate 1 KB Unicode codepoint list. `Math_Symbol` is the real Unicode category `Sm`,
and the package is a transitive dependency of `@babel/plugin-transform-*`, so it is present
in a large share of all JavaScript projects. The report told the operator to isolate the host
and rotate every credential.

Expanding `*` to `.*` meant a glob could not express "directly inside a package directory",
which is the discriminator that separates the payload's drop location from the Unicode
file's. Real glob semantics plus a size floor give two independent discriminators, either
sufficient alone: the payload is ~728 KB, the data file ~1 KB.

This is the same mistake as the removed `SH25-R004` (`CONTENT|setup.mjs`) — a name too
common to be evidence — repeated at `CONFIRMED` severity on a filename that looked
distinctive. The worm most likely chose `Math_Symbol.js` *because* it blends into Babel
dependency trees. Signature authoring now requires checking whether a filename exists in the
registry before trusting it.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** `.claude/projects` is pruned alongside `file-history` and `.history`.
**Why:** Claude Code session transcripts are JSONL files containing whatever was discussed,
so a session about this campaign reproduces every marker string the scanner looks for. Two
of the seven findings in the same fleet report were transcripts. Pruning `file-history`
alone was not enough.
**Recorded by:** Claude
**Date:** 2026-08-05

---

**Assumption:** Committed payload fixtures are small placeholders, padded past the size
floor by the test harness.
**Why:** Keeping a real-sized payload fixture in the repository would add megabytes and
place something resembling a payload under version control. But the previous fixtures were a
single line, which the size floor correctly rejected — meaning they had never represented
something the scanner would detect on a real host. Padding in the copy keeps the repository
small while exercising the real threshold.
**Recorded by:** Claude
**Date:** 2026-08-05
