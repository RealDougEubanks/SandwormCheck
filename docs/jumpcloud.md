# Fleet deployment

The scanner is built for this: it takes no input, writes nothing, contacts nothing, and
puts its verdict in the exit code.

## Triage table

Point your alerting at the code, not the text output.

| Exit code | Verdict | Priority | Action |
|---|---|---|---|
| `0` | Clean | — | None |
| `10` | Suspect | Normal | A compromised package version is on disk but no payload ran. Bump the dependency, rebuild, re-scan. |
| `20` | **Confirmed** | **Urgent** | Payload, persistence, or exfil artifact present. Isolate the host and rotate every credential it touched. See [remediation.md](remediation.md). |
| `1` | Scanner error | Normal | The scan did not complete, or a signature file is malformed. **Do not read this as clean.** Check stderr. |
| `2` | Usage error | Low | The command is wrong. Fix the policy. |
| `124` | **Killed by the agent's command timeout** — not a SandwormCheck code | Normal | You have no verdict for this host. Lower `--timeout` below the agent's limit, or narrow the scan with `--path`. |
| `137`, `143` | Killed (`SIGKILL` / `SIGTERM`) | Normal | Same: no verdict. Check for an agent limit or a memory/policy kill. |

A JumpCloud policy that alerts on any non-zero result is correct by default: `1` and `2`
both mean "you don't have an answer for this host yet," which is exactly what you want
surfaced.

## JumpCloud Commands

### Where the command bodies live

**Use the self-contained snippets in the [README](../README.md#self-updating-runner-recommended).**
They are deliberately the single copy: this document previously carried its own
git-only versions, they drifted from the ones that gained a zip fallback, and hosts
without git kept failing with `git not found` while the fallback existed elsewhere
in the repository. One copy, kept correct, beats two that disagree.

Those snippets need no prerequisites beyond a shell. They use git when it is
present and download an archive when it is not, so a Windows box without git works
without any preparation.

### JumpCloud specifics to add on top

**macOS / Linux** — command type **Mac** or **Linux**, run as `root`. Paste the
README's shell snippet, and set the timeout below JumpCloud's own command timeout:

```sh
sh "$DEST/sandwormcheck.sh" --timeout 1800
```

Root matters. Home directories come from the OS user database, so every account is
covered — including macOS's root account at `/var/root` — but only if the scan can
read them.

**Windows** — command type **Windows**, which runs as SYSTEM in PowerShell. Paste
the README's PowerShell snippet. Two details in it are load-bearing for a service
account:

- `exit $LASTEXITCODE` on the last line. Without it the policy reports the
  wrapper's status and every host looks clean.
- `[IO.Path]::GetTempPath()` rather than `$env:TEMP`, which is not guaranteed to be
  set for the account a fleet agent runs under.

JumpCloud's Windows runner uses **Windows PowerShell 5.1**, not PowerShell 7. The
port is written for 5.1 — sources are pure ASCII so a BOM-less file is not read as
ANSI, and numeric bounds are validated in code rather than with `[ValidateRange]` —
but CI exercises PowerShell 7. Run it manually on one host before trusting it
fleet-wide.

### If the fleet has no outbound access

Drop the repository into your golden image, or push it with a JumpCloud file
distribution policy, and reduce the command to the final scan line. `tools/run-latest.sh`
and `tools/run-latest.ps1` are the same update logic with more diagnostics, useful
once the repo is already on the host.

### Capturing structured results

To keep JSON for later correlation while still returning the verdict through the exit
code:

```sh
#!/bin/sh
set -u
# /var/log is outside the default scan roots. Do not write reports inside a scanned
# path: findings embed the marker strings, so an earlier report used to be flagged as
# a compromise by the next scan. CONTENT signatures are scoped now, but keeping
# output out of scanned trees removes the question.
OUT="/var/log/sandwormcheck/$(date -u +%Y%m%dT%H%M%SZ).json"
mkdir -p "$(dirname "$OUT")"

sh /opt/sandwormcheck/sandwormcheck.sh --json --timeout 600 > "$OUT"
CODE=$?

# Echo it so it also lands in the JumpCloud command result.
cat "$OUT"
exit $CODE
```

## Scheduling

Run it on a recurring schedule, not just once. The campaign was republishing packages in
real time, so a host that scanned clean on Tuesday can be compromised by Wednesday's
`npm install`.

A reasonable cadence:

- **Daily** on developer machines and build agents — they run `npm install` constantly.
- **Weekly** on servers with pinned, reviewed dependencies.
- **On demand** after every signature update.

Signature updates are a `git pull`, which the commands above already do on each run. The
scanner itself never fetches anything.

## Other tooling

**Ansible**

```yaml
- name: Scan for npm worm indicators
  ansible.builtin.command:
    cmd: sh /opt/sandwormcheck/sandwormcheck.sh --json --timeout 600
  register: bwc
  changed_when: false
  failed_when: bwc.rc not in [0, 10, 20]

- name: Flag confirmed compromise
  ansible.builtin.fail:
    msg: "CONFIRMED COMPROMISE on {{ inventory_hostname }} — isolate and rotate credentials"
  when: bwc.rc == 20
```

`failed_when` lists the codes that mean "the scanner ran successfully and has an answer."
`1` and `2` are genuine task failures and should surface as such.

**Microsoft Intune** — deploy as a Win32 app or a remediation script. Intune treats a
non-zero exit as failure, which gives you the alerting for free; use `-Json` and write to
a known path if you want the detail.

**Plain SSH across a host list**

```sh
while read -r host; do
    ssh "$host" 'sh /opt/sandwormcheck/sandwormcheck.sh --quiet --timeout 600'
    printf '%s\t%s\n' "$host" "$?"
done < hosts.txt | tee results.tsv

echo "--- confirmed compromise ---"
awk -F'\t' '$2 == 20 {print $1}' results.tsv
echo "--- needs a dependency bump ---"
awk -F'\t' '$2 == 10 {print $1}' results.tsv
echo "--- no answer yet (scanner error) ---"
awk -F'\t' '$2 == 1 || $2 == 2 {print $1}' results.tsv
```

**cron**

```cron
17 4 * * * /bin/sh /opt/sandwormcheck/sandwormcheck.sh --quiet --timeout 1800 || logger -t sandwormcheck -p auth.warning "scan returned $?"
```

## Operational notes

- **Run as root / SYSTEM.** Unprivileged runs only cover what the invoking user can read.
  The scanner reports how many paths it had to skip, so an under-privileged run is
  visible rather than silently narrow — but you still want full coverage.
- **A 124 means the agent killed the scan.** SandwormCheck only ever exits 0, 1, 2, 10, or
20. Anything else came from outside it. `124` is the conventional "timed out" status, so it
means the agent's command timeout fired before the scanner finished — and you get **no
verdict**, which is strictly worse than a truncated one.

Fix it by making the scanner stop first:

1. Find the agent's command timeout for that policy.
2. Set `--timeout` / `-TimeoutSeconds` comfortably below it (leave 10-20% headroom, since
   the budget is a soft ceiling checked between work chunks).
3. If even that is too short for a full scan, narrow the scope instead of raising the
   budget: `--path C:\Users --path C:\projects` on Windows, or scan developer machines on
   a longer schedule than servers.

A self-truncated scan reports exit `1` and still covers the cheap high-signal checks --
persistence paths, payload filenames, running processes, package versions and lockfile pins.
Only the content and hash sweeps are dropped.

**Budget the timeout.** 600s suits most laptops. Build agents with large caches may
  need more. The default is 1800s, because a full scan of a developer machine measured
  960s and a 900s budget truncated it.

  **Keep the scanner's `--timeout` below JumpCloud's own command timeout.** If the agent
  kills the process you get no verdict at all; if the scanner stops itself you get exit
  `1`, which means "no answer yet" and is triageable. Check the agent's limit and leave
  headroom.
- **Nothing is written to the scanned host** except what you redirect yourself. The
  scanner's own temp directory is removed on exit, including on error paths.
- **No credentials appear in command logs.** Findings are paths and signature IDs only —
  never file contents. This matters because a fleet console's command output is one more
  place a leaked token could come to rest.
- **Deploy the repo, not just the script.** The scanner needs its `signatures/` directory.
  Pass `--signatures` explicitly if you keep signatures somewhere else.
