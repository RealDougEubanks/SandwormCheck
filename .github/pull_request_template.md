## What changed and why

<!-- The "why" is the part that is hard to recover from the diff later. -->

## Checks

- [ ] `./tools/checks.sh` passes locally
- [ ] `SHELLS="sh bash dash" ./tests/run-tests.sh` passes
- [ ] Both scanners updated, or the change genuinely affects only one
- [ ] No new runtime dependency, and no network call added to a scanner

## If this touches signatures

- [ ] Tested against `tests/fixtures/clean/` and a real project tree for false positives
- [ ] Narrowest workable check type used (`SHA256` / `PATHGLOB` over `FILENAME`)
- [ ] `CONFIRMED` only where the artifact has no benign explanation
- [ ] Source cited in `docs/references.md`
- [ ] Generated package file regenerated if its input list changed

## If this changes behaviour

- [ ] `docs/spec.md` updated in this commit
- [ ] Non-obvious decisions recorded in `docs/assumptions.md`
- [ ] Cost still scales with files scanned, not with signature count

## False-clean review

<!-- Required. A false clean is this project's worst failure mode. -->
Could this change cause a check to not run while the scan still reports a verdict?
If so, how does it fail loudly instead?
