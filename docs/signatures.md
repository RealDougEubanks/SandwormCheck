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

A single `PKGVER` record covers **both** an installed package and a lockfile pin — you
do not write two records. The finding's `detail` field tells them apart:

- `installed keyv@6.0.0` — found in an installed `package.json`
- `pinned keyv@6.0.0 in package-lock.json` — pinned but possibly never installed

Lockfile formats covered: `package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`,
`yarn.lock` (v1 and berry), `pnpm-lock.yaml` (v5/v6/v9), `bun.lock`, and `bun.lockb`.
Range specs are not matched — only resolved versions — so `"keyv": "^6.0.0"` in a
`dependencies` block does not fire, but the resolved `6.0.0` entry does.

Lockfiles nested inside `node_modules/` are skipped (a dependency's own dev lockfile
does not affect resolution), except `npm-shrinkwrap.json`, which npm honors. See
`docs/spec.md` section 4.2 for the parsing strategy and its known gaps.

Note that adding a hash record also needs a `FILENAME` record for that basename, since
hash checks are narrowed by basename for performance. The scanner warns if you forget.

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

The package list is generated, not hand-edited. To refresh it from a vendor feed:

```sh
curl -sSf 'https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv' \
  -o /tmp/socket.csv

./tools/merge-package-list.sh /tmp/socket.csv > /tmp/merged.txt
mv /tmp/merged.txt signatures/compromised-packages.txt

./tools/make-package-signatures.sh signatures/compromised-packages.txt \
  > signatures/shai-hulud-2026-08-packages.conf

./tests/run-tests.sh
```

`merge-package-list.sh` filters a Socket-style CSV to **npm rows only**, reporting how many
non-npm rows it skipped and from which ecosystem. The feed gained golang entries on
2026-08-05; a Go pseudo-version is not something `PKGVER` can match, so ingesting them would
add records that can never fire. It accepts a plain `name@version` list too, and it
**unions** rather than replaces. That is not politeness — as of 2026-08-04 both the Wiz
CSV and Socket's CSV omit the entire `@keyv/*` scope, which only JFrog published, so
overwriting from a single feed would silently delete 19 confirmed packages. The tool
reports how many already-known pairs a feed lacks so you can see this happening.

`make-package-signatures.sh` validates every record and rejects the file rather than
emitting a malformed one, because a bad record fails every scan closed with exit `1`. IDs
are derived from a hash of `name@version`, so a longer input never renumbers existing
entries — they end up in incident tickets.

Neither tool makes network calls; fetch the feed separately so the repository stays usable
on an air-gapped host.
