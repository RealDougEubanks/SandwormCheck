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
