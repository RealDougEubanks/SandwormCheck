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

# Zip fallback for hosts without git. GitHub serves a snapshot of any ref at
# codeload, so a machine with no git can still stay current. An archive carries no
# history and no signature, which is the same trust level as a shallow clone over
# HTTPS, so nothing is given up by using it as a fallback.
update_from_zip() {
	_slug=$(printf '%s' "$REPO" | sed -e 's#^https://github\.com/##' -e 's#\.git$##')
	case $_slug in
	*/*) ;;
	*)
		log "cannot derive an archive URL from $REPO; use git or pre-stage $DEST"
		return 1
		;;
	esac

	_fetch=""
	if command -v curl >/dev/null 2>&1; then
		_fetch=curl
	elif command -v wget >/dev/null 2>&1; then
		_fetch=wget
	else
		log "neither git, curl, nor wget is available; cannot update"
		return 1
	fi
	command -v unzip >/dev/null 2>&1 || {
		log "unzip not available; cannot expand the archive"
		return 1
	}

	_tmp=$(mktemp -d "${TMPDIR:-/tmp}/swc-zip.XXXXXX") || return 1
	# A tag and a branch live under different prefixes; try the tag first so a
	# pinned release wins, which is what a production fleet should be using.
	for _u in "https://codeload.github.com/$_slug/zip/refs/tags/$REF" \
		"https://codeload.github.com/$_slug/zip/refs/heads/$REF"; do
		if [ "$_fetch" = curl ]; then
			curl -fsSL "$_u" -o "$_tmp/src.zip" 2>/dev/null && break
		else
			wget -q "$_u" -O "$_tmp/src.zip" 2>/dev/null && break
		fi
		rm -f "$_tmp/src.zip"
	done
	[ -s "$_tmp/src.zip" ] || {
		log "could not download an archive for ref '$REF'"
		rm -rf "$_tmp"
		return 1
	}

	unzip -q "$_tmp/src.zip" -d "$_tmp/x" 2>/dev/null || {
		log "could not expand the archive"
		rm -rf "$_tmp"
		return 1
	}
	_inner=$(find "$_tmp/x" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -1)
	if [ -z "$_inner" ] || [ ! -f "$_inner/sandwormcheck.sh" ]; then
		log "archive does not look like SandwormCheck; refusing to install it"
		rm -rf "$_tmp"
		return 1
	fi

	# Replace only after the download has been validated, so a failed update leaves
	# the previous working copy intact.
	rm -rf "$DEST" 2>/dev/null || :
	mkdir -p "$(dirname "$DEST")" 2>/dev/null || :
	mv "$_inner" "$DEST" || {
		log "could not install to $DEST"
		rm -rf "$_tmp"
		return 1
	}
	chmod +x "$DEST/sandwormcheck.sh" 2>/dev/null || :
	rm -rf "$_tmp"
	log "installed archive of $REF"
	return 0
}

HAS_GIT=0
command -v git >/dev/null 2>&1 && HAS_GIT=1
[ "$HAS_GIT" -eq 1 ] || log "git not found; falling back to a zip download"

# Keep git's own diagnostics: "could not update" without the reason leaves an
# operator with nothing to act on.
GITLOG=$(mktemp "${TMPDIR:-/tmp}/swc-git.XXXXXX") || GITLOG=/dev/null
trap 'rm -f "$GITLOG"' EXIT

updated=0
if [ "$HAS_GIT" -eq 0 ]; then
	update_from_zip && updated=1
elif [ -d "$DEST/.git" ]; then
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

# A git host whose update failed can still fall back to the archive rather than
# scanning with a stale copy.
if [ "$updated" -eq 0 ] && [ "$HAS_GIT" -eq 1 ]; then
	log "git update failed; trying the zip fallback"
	update_from_zip && updated=1
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

if [ "$HAS_GIT" -eq 1 ] && [ -d "$DEST/.git" ]; then
	log "revision $(git -C "$DEST" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
else
	log "revision archive of $REF"
fi

# shellcheck disable=SC2086  # SWC_ARGS is intentionally word-split
sh "$DEST/sandwormcheck.sh" ${SWC_ARGS:-}
