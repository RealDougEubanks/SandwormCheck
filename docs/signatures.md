# Writing signatures

Indicators are data, not code. To cover a new campaign, add a `.conf` file to
`signatures/`. Both scanners pick it up on the next run with no code change.

## File format

```
CHECK_TYPE|SEVERITY|ID|PATTERN|DESCRIPTION
```

Rules:

- One record per line, five pipe-delimited fields.
- Lines starting with `#` are comments. Blank lines are ignored.
- Whitespace around each field is stripped.
- `PATTERN` must not contain a literal `|`.
- `DESCRIPTION` is the last field and may contain `|`.
- Both LF and CRLF line endings work.

Every field is required. A malformed record is a **hard error** that exits `1` — it does
not get skipped. Silently ignoring a bad record would shrink coverage invisibly and could
report a host as clean when the check never ran.

### Header directives

```
#!campaign  Human-readable campaign name
#!version   2026.08.04.1
#!updated   2026-08-04
#!reference https://vendor.example/advisory
```

`campaign` and `version` appear in the report so an operator can tell which signature set
produced a finding. `reference` is for humans reading the file; repeat it as needed.

## Check types

### `PATHEXISTS` — a specific path exists

For persistence artifacts at known locations. Checked directly, independent of scan
roots, so it fires even with a narrow `--path`.

```
PATHEXISTS|CONFIRMED|EX-001|~/.config/evil-agent/token|Stolen token staged by the implant
PATHEXISTS|SUSPECT|EX-002|/tmp/loader-dl-*|Loader staging directory
```

`~/` expands against *every* user home on the machine, not just the invoking user's — a
fleet agent runs as root and the artifacts live in individual profiles. Shell globs are
allowed. Absolute Unix paths are skipped on Windows; `/tmp/...` is mapped to the Windows
temp directories.

### `FILENAME` — a basename anywhere under a scan root

For dropped payloads with distinctive names.

```
FILENAME|CONFIRMED|EX-003|Math_Symbol.js|Stage-two payload bundle
```

Only use this when the name is genuinely distinctive. `index.js` would match tens of
thousands of legitimate files.

### `PATHGLOB` — a glob matched against the full path

For filenames too common to match on basename alone. Write patterns with forward slashes;
the Windows port normalizes separators before comparing.

```
PATHGLOB|CONFIRMED|EX-004|*/.claude/setup.mjs|Loader injected into the Claude Code config dir
```

This is the type that exists specifically because `setup.mjs` is a perfectly normal
filename. `FILENAME|setup.mjs` would flag half the ecosystem; `PATHGLOB` flags only the
directory the malware actually writes to.

### `SHA256` / `SHA1` — file digest

The highest-confidence check. Use it whenever a vendor publishes a hash.

```
SHA256|CONFIRMED|EX-005|9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc|Payload bundle
SHA1|CONFIRMED|EX-006|35a672cf34b996b91f3e1c28cbf3a05a37e036e4|Payload bundle (vendor published SHA-1 only)
```

Must be exactly 64 or 40 hex characters. Case-insensitive. If a vendor publishes a digest
without saying which algorithm it is, count the characters — 40 is SHA-1, 64 is SHA-256.
When two vendors publish different digests for the same logical file, encode both; the
loader probably had variants.

### `PKGVER` — an installed package version

Matched against the first `name` and `version` in each `package.json`.

```
PKGVER|SUSPECT|EX-007|keyv@6.0.0|Compromised release
```

Exact match only. There is deliberately no version-range support: semver comparison in
POSIX `sh` is a bug farm, and campaigns publish discrete bad versions, so enumerate them.
Scoped packages work as written (`@scope/name@1.2.3`).

### `CONTENT` — a literal substring in a candidate file

For embedded strings, C2 domains, and markers.

```
CONTENT|CONFIRMED|EX-008|Shai-Hulud: Here We Go Again|Campaign self-identifier
CONTENT|CONFIRMED|EX-009|evil-c2.example|C2 domain
```

Literal substring, not regex — `grep -F` on Unix, ordinal `IndexOf` on Windows. Keeping
regex out avoids the dialect differences between `grep` and .NET that would make one
engine match where the other does not.

Only *candidate* files are searched (see below), and only files under `--max-file-size`.

## What gets searched

Hashing and grepping an entire disk is not viable, so `SHA256`, `SHA1`, and `CONTENT`
checks run against a candidate set:

- Files whose basename matches any `FILENAME` signature
- `settings.json`, `tasks.json`, `package.json`, `setup.mjs`
- Anything inside a `node_modules`, `.claude`, or `.vscode` directory

**If your indicator lives outside that set, add a `FILENAME` record for its basename**
so the file becomes a candidate, then add the hash or content record. A `CONTENT`
signature for a file nobody visits will never fire.

`PATHEXISTS` and `PKGVER` are not subject to candidate selection.

## Severity

- **`CONFIRMED`** — no benign explanation exists. Payload files, matching hashes, host
  persistence units, exfiltration markers. Produces exit `20`: this host is compromised.
- **`SUSPECT`** — consistent with compromise but plausibly benign. A vulnerable package
  version that may never have executed; a domain string a legitimate project might
  reference. Produces exit `10`: remediate, but do not page anyone.

Choose carefully. `CONFIRMED` means someone gets woken up and a machine gets isolated.
When in doubt, use `SUSPECT` and explain the ambiguity in the description — an operator
reading a finding at 2am has only that sentence to go on.

### False positives are a real cost

A signature that fires on clean machines trains operators to ignore the tool, which is
worse than not having the signature. Before adding one:

1. Run it against `tests/fixtures/clean/` and a real project tree.
2. Ask whether a legitimate developer could produce this artifact. Public Ethereum RPC
   endpoints (`eth.llamarpc.com`, `nodereal.io`, `getblock.io`) are deliberately *not*
   signatures in the shipped set for this reason — the worm used them, but so does every
   web3 project.
3. Prefer the narrowest type that works: `SHA256` over `FILENAME`, `PATHGLOB` over
   `FILENAME`.

## Adding a campaign

1. Create `signatures/<campaign-slug>.conf` with header directives.
2. Pick an ID prefix nobody else uses (`SH25-` is taken by the 2026-08 keyv/cacheable
   campaign). Keep IDs stable — they end up in incident tickets.
3. Add records, narrowest check type first.
4. Add fixtures under `tests/fixtures/` and assertions in `tests/run-tests.sh`: one true
   positive and one true negative per new signature.
5. Run the suite:
   ```sh
   SHELLS="sh bash dash" ./tests/run-tests.sh
   ```
6. Record anything non-obvious about your choices in `docs/assumptions.md`, and cite your
   sources in `docs/references.md`.

Both scanners load every `*.conf` in the signature directory, so multiple campaigns scan
in one pass and each finding is attributed to its own campaign in the report.

## Updating this campaign

The keyv/cacheable campaign was actively republishing when these indicators were
collected, and vendors reported 400+ affected packages against the 14 versions encoded
here. To extend the list:

1. Pull the current package list from the Socket campaign page or the vendor CSV linked
   in `docs/references.md`.
2. Append `PKGVER|SUSPECT|SH25-Vnnn|name@version|Compromised release` records, continuing
   the existing numbering.
3. Bump `#!version` and `#!updated` in the header.
4. Re-run the suite and commit.

Bulk-generating those records from a vendor CSV is fine — just eyeball the diff before
committing, because a mangled record fails the whole scan closed with exit `1`.
