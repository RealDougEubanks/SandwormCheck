# Remediation

What to do about a scan result. This is incident guidance, not a substitute for your own
IR process.

> SandwormCheck is read-only and will not clean anything up. Every step below is yours to
> perform deliberately.

---

## Exit `20` — confirmed compromise

Assume every credential reachable from this host is already stolen. The payload harvested
cloud metadata, npm and GitHub tokens, Vault and Kubernetes tokens, AI tool configs, and
crypto wallets, then exfiltrated to attacker-controlled GitHub repositories. The stolen
npm token republishes the maintainer's entire package portfolio, so one developer laptop
can become a supply chain incident for your customers.

### 1. Contain

- Isolate the host from the network. Do not shut it down if you intend to collect
  volatile evidence.
- If it is a CI runner or build agent, take it out of the pool immediately — it likely
  held the most valuable tokens on your estate.
- Preserve the scanner's JSON output and the artifact paths it named before touching
  anything.

### 2. Kill persistence

The dead-man's switch polls GitHub every 60 seconds and evaluates a remote-supplied
command when it detects that the stolen token was revoked. **Remove persistence before
revoking tokens**, or you hand the attacker a trigger.

macOS:

```sh
launchctl bootout gui/"$(id -u)"/com.user.gh-token-monitor 2>/dev/null
rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
rm -rf ~/.config/gh-token-monitor ~/.local/bin/gh-token-monitor.sh
```

Linux:

```sh
systemctl --user disable --now gh-token-monitor.service 2>/dev/null
rm -f ~/.config/systemd/user/gh-token-monitor.service
rm -rf ~/.config/gh-token-monitor ~/.local/bin/gh-token-monitor.sh
loginctl disable-linger "$USER"
```

Repeat for **every** user profile on the machine — the scanner reports the path of each
artifact it found, so work from its output rather than assuming one user.

Then remove the repository-level autostart hooks, which run without any `npm install`:

- `.claude/settings.json` — delete the injected `SessionStart` hook
- `.vscode/tasks.json` — delete the injected `folderOpen` task
- `.claude/setup.mjs`, `.vscode/setup.mjs`, `math_init.js`, `Math_Symbol.js` — delete

Do not open an affected project in VS Code or Claude Code until those files are gone.
Opening the folder is the trigger.

### 3. Rotate everything

In rough order of blast radius:

1. **npm tokens** — revoke all, including CI tokens and granular access tokens. Check
   your npm account's publish history for versions you did not publish. Disable OIDC
   trusted publishing for affected packages until you have reviewed it; that is the
   mechanism the worm used to republish.
2. **GitHub** — revoke personal access tokens, OAuth grants, and SSH keys. Review the
   org audit log for repositories created around the compromise window, especially any
   with the description `Shai-Hulud: Here We Go Again`. Rotate Actions secrets and
   organization secrets.
3. **Cloud** — rotate AWS keys and any role reachable via instance metadata, GCP service
   account keys, Azure client secrets. Review CloudTrail / Cloud Audit Logs for use of
   those credentials since the compromise.
4. **Vault and Kubernetes** — revoke Vault tokens and Kubernetes service account tokens.
5. **AI tool credentials** — Claude, OpenAI, Codex, Cursor, Gemini API keys.
6. **Crypto wallets** — Foundry, Solana, and Monero keys were targeted. If a wallet key
   was on this host, move the funds. Rotation is not possible.
7. **Local accounts** — `/etc/shadow` was in scope on Linux. Force a password reset for
   local accounts on affected hosts.

Rotate based on what the host could reach, not on what you can prove was taken. Absence
of evidence of use is not evidence the credential is safe.

### 4. Clean the dependencies

```sh
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
npm ls keyv cacheable cache-manager flat-cache file-entry-cache
```

Then re-scan. Pin known-good versions and check the result against your registry's audit
log — `flat-cache` and `file-entry-cache` arrive transitively through the eslint
toolchain, so they show up in projects that never depended on them directly.

### 5. Decide about rebuilding

A confirmed compromise means arbitrary code ran as the user. Persistence removal
addresses the mechanisms that were publicly documented; it does not prove nothing else
was installed. For build agents and anything holding production credentials, reimage
rather than clean. For a developer laptop, weigh the cost against the fact that the
payload had a 24-hour TTL self-destruct — which means the absence of artifacts today does
not prove the absence of activity yesterday.

### 6. Notify

If your own packages were republished, you are now upstream of someone else's incident.
Notify your consumers, yank the malicious versions, and publish an advisory. Check
whether your org requires regulatory disclosure for the credential classes involved.

---

## Exit `10` — suspect

A compromised package version is on disk, but no payload, persistence, or exfiltration
artifact was found. Most commonly the tarball was fetched but install scripts did not run,
or it is sitting in a package cache.

This is a dependency problem, not an incident — but confirm rather than assume:

```sh
npm ls keyv cacheable cache-manager flat-cache file-entry-cache
rm -rf node_modules package-lock.json && npm cache clean --force && npm install
./sandwormcheck.sh --path . --verbose
```

Check whether install scripts could have run:

- `npm config get ignore-scripts` — if `true`, the `preinstall` hook never fired.
- Your CI logs for the install step around the compromise window.

If install scripts were enabled and the package was installed during the window, treat it
as exit `20` and rotate credentials. Escalating a `10` you are unsure about is cheap;
under-reacting is not.

---

## Exit `1` — scanner error

**This is not a clean result.** You do not have an answer for this host. Common causes:

- A malformed signature record — the message names the file and line.
- The scan timed out mid-walk. Raise `--timeout` or narrow with `--path`.
- Unreadable paths. Re-run with `sudo` or as Administrator.

Fix and re-run before recording the host as scanned.

---

## Verifying remediation

```sh
sudo ./sandwormcheck.sh --verbose
echo "exit: $?"
```

You want exit `0` with zero skipped paths. Then:

- Re-scan on a schedule for at least a week — a fresh `npm install` can reintroduce a bad
  version if a lockfile still pins one.
- Sweep lockfiles across **all** repositories, not just the ones on this host. The scanner
  reads the filesystem; it cannot see a bad version pinned in a repo nobody has installed
  locally.
- Confirm no unexpected package versions were published under your npm account.
- Watch for authentication attempts using the rotated credentials.

A clean scan means none of the encoded indicators were found. Given that the campaign was
republishing in real time and the encoded package list is a point-in-time snapshot, it is
evidence of health, not proof of it.
