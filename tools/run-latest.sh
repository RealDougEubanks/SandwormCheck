#!/bin/sh
# Update SandwormCheck from its public repository, then scan this host.
#
# Intended to be pasted into a fleet tool (JumpCloud, Ansible, cron, ssh) so a
# single command always runs the current signatures. Re-running it picks up
# whatever has been added to the repository since last time.
#
# Exit codes are the scanner's, passed through unchanged:
#   0 clean | 10 suspect | 20 CONFIRMED compromise | 1 scanner error | 2 usage
#
# Environment overrides:
#   SWC_REPO     git URL to pull from
#   SWC_DEST     checkout location
#   SWC_REF      branch or tag to check out (default: main)
#   SWC_ARGS     extra arguments passed to the scanner
#
# NOTE: this executes whatever is currently on the tracked branch. For a
# production fleet, set SWC_REF to a reviewed tag or mirror the repository
# internally — auto-running a moving branch means trusting every future commit,
# which is the same class of risk this tool exists to detect.

set -u

REPO=${SWC_REPO:-https://github.com/RealDougEubanks/SandwormCheck.git}
DEST=${SWC_DEST:-/opt/sandwormcheck}
REF=${SWC_REF:-main}

log() { printf 'run-latest: %s\n' "$*" >&2; }

command -v git >/dev/null 2>&1 || {
	log "git not found; install git or pre-stage the repository at $DEST"
	exit 1
}

# Keep git's own diagnostics: "could not update" without the reason leaves an
# operator with nothing to act on.
GITLOG=$(mktemp "${TMPDIR:-/tmp}/swc-git.XXXXXX") || GITLOG=/dev/null
trap 'rm -f "$GITLOG"' EXIT

updated=0
if [ -d "$DEST/.git" ]; then
	# Discard local drift so a half-applied earlier run cannot pin old signatures.
	if git -C "$DEST" fetch --quiet --depth 1 origin "$REF" >"$GITLOG" 2>&1 &&
		git -C "$DEST" reset --hard --quiet FETCH_HEAD >>"$GITLOG" 2>&1; then
		updated=1
	fi
else
	rm -rf "$DEST" 2>/dev/null || :
	if mkdir -p "$(dirname "$DEST")" 2>/dev/null &&
		git clone --quiet --depth 1 --branch "$REF" "$REPO" "$DEST" >"$GITLOG" 2>&1; then
		updated=1
	fi
fi

if [ "$updated" -eq 0 ] && [ -s "$GITLOG" ]; then
	log "git said: $(head -2 "$GITLOG" | tr '\n' ' ')"
fi

if [ "$updated" -eq 0 ]; then
	if [ -x "$DEST/sandwormcheck.sh" ] || [ -f "$DEST/sandwormcheck.sh" ]; then
		# Scanning with a known-older copy beats not scanning, but the operator
		# must know the signatures may be stale.
		log "WARNING: could not update from $REPO; scanning with the EXISTING copy at $DEST"
		log "WARNING: signatures may be out of date — this result is weaker than a fresh run"
	else
		log "could not fetch $REPO and no usable copy exists at $DEST"
		exit 1
	fi
fi

[ -f "$DEST/sandwormcheck.sh" ] || {
	log "scanner not found at $DEST/sandwormcheck.sh"
	exit 1
}

log "revision $(git -C "$DEST" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

# shellcheck disable=SC2086  # SWC_ARGS is intentionally word-split
sh "$DEST/sandwormcheck.sh" ${SWC_ARGS:-}
