# Security policy

SandwormCheck is a detection tool. A flaw in it can mean a compromised machine is
reported as clean, so vulnerability reports are welcome and taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting:

1. Go to the [Security tab](https://github.com/RealDougEubanks/SandwormCheck/security/advisories)
2. Choose **Report a vulnerability**

That opens a private advisory visible only to the maintainers.

If private reporting is unavailable, email the address on the maintainer's GitHub
profile with `SandwormCheck` in the subject.

Expect an acknowledgement within a few days. This is a small project with one
maintainer; there is no paid support and no bounty programme.

## What counts as a vulnerability here

Ranked by how much they matter:

- **A false clean.** Any input or condition that makes the scanner exit `0` when an
  encoded indicator is present on the host. This is the most serious class of bug
  in this project, more serious than a crash.
- **Silent check skipping.** A path where a check does not run but the scan still
  reports a verdict. Missing tools, unreadable files, and truncated scans are all
  meant to be loud; a quiet one is a bug.
- **Secret disclosure.** The scanner printing file contents, matched credential
  material, or anything beyond paths and signature IDs. Findings land in fleet
  console logs, so this relocates a secret into a new system.
- **Code execution or privilege escalation.** The scanner is read-only and makes no
  network calls. Anything that writes outside its temp directory, executes scanned
  content, or is exploitable by a crafted file on a scanned host qualifies.
- **Signature or supply chain integrity.** A way to make the scanner load
  attacker-controlled signatures, or a compromise of this repository's own release
  path.

## What does not count

- **False positives.** Real bugs, but not security issues — open a normal issue.
  See CONTRIBUTING.md; they are the most useful ordinary report this project gets.
- **Incomplete signature coverage.** The package list is a documented,
  acknowledged snapshot of an ongoing campaign. Missing packages are a data gap,
  not a vulnerability. New indicators are very welcome as pull requests.
- **The tool not detecting a different campaign.** By design it detects what its
  signature files describe.

## Scope note on running the tool

The scanner is read-only, makes no network connections, and requires no privileges
beyond read access to the paths being scanned. It is normally run as root or
SYSTEM to cover every user profile, which means a bug in it runs privileged —
hence the emphasis above.

The self-updating runners in `tools/run-latest.*` pull from this repository and
execute what they find. Auto-running a moving branch means trusting every future
commit here, which is the same class of risk this tool detects. For production
fleets, pin a reviewed tag or mirror the repository internally. This is documented
in the README rather than hidden.

## Supported versions

`main` is the supported version. There are no long-term support branches; fixes
land on `main` and are picked up by the next run of the self-updating runners.
