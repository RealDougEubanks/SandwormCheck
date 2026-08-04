# Test fixtures

Fake project trees used by `tests/run-tests.sh`.

**These contain no malware.** Files that stand in for the worm's payload hold inert
placeholder text; they are named like the real artifacts so the `FILENAME` and `PATHGLOB`
checks have something to match. Hash-check fixtures are generated at test time and their
digests written into a temporary signature file, so no real malicious hash needs to be
paired with real malicious content.

| Tree | Expected verdict | Contents |
|---|---|---|
| `clean/` | `CLEAN` (exit 0) | `keyv@5.5.1`, a normal `.vscode/tasks.json` |
| `suspect/` | `SUSPECT` (exit 10) | `keyv@6.0.0` and `flat-cache@6.1.24`, no payload |
| `confirmed/` | `CONFIRMED` (exit 20) | Payload filename, injected IDE hooks, exfil marker string |

Additional fixtures for hash checks, odd path names, binary files, permission-denied
roots, and secret non-disclosure are created in a temp directory during the run and torn
down afterwards.
