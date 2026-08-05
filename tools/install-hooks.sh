#!/bin/sh
# Install the repository's git hooks.
#
#   ./tools/install-hooks.sh            install
#   ./tools/install-hooks.sh --uninstall
#
# Points core.hooksPath at .githooks/ rather than copying files into .git/hooks,
# so the hooks are version-controlled and an update arrives with a normal pull.
# Requires git 2.9 or newer.
#
# No third-party framework is used on purpose. This repository's whole premise is
# that a security tool should not need a dependency tree to run.

set -eu

PROGNAME="install-hooks"
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
	printf '%s: not inside a git repository\n' "$PROGNAME" >&2
	exit 1
}
cd "$ROOT"

UNINSTALL=0
case "${1:-}" in
--uninstall) UNINSTALL=1 ;;
"") ;;
-h | --help)
	sed -n '2,12p' "$0"
	exit 0
	;;
*)
	printf '%s: unknown option: %s\n' "$PROGNAME" "$1" >&2
	exit 2
	;;
esac

if [ "$UNINSTALL" -eq 1 ]; then
	git config --unset core.hooksPath 2>/dev/null || :
	printf '%s: hooks uninstalled (core.hooksPath cleared)\n' "$PROGNAME"
	exit 0
fi

# core.hooksPath landed in git 2.9. Fail with an actionable message rather than
# appearing to succeed while installing nothing.
GITVER=$(git --version | awk '{print $3}')
GITMAJ=${GITVER%%.*}
GITREST=${GITVER#*.}
GITMIN=${GITREST%%.*}
case $GITMAJ$GITMIN in
*[!0-9]*)
	printf '%s: warning: could not parse git version %s; attempting anyway\n' "$PROGNAME" "$GITVER" >&2
	;;
*)
	if [ "$GITMAJ" -lt 2 ] || { [ "$GITMAJ" -eq 2 ] && [ "$GITMIN" -lt 9 ]; }; then
		printf '%s: git %s is too old for core.hooksPath (need 2.9+)\n' "$PROGNAME" "$GITVER" >&2
		printf '%s: copy .githooks/* into .git/hooks/ manually instead\n' "$PROGNAME" >&2
		exit 1
	fi
	;;
esac

[ -d .githooks ] || {
	printf '%s: .githooks/ not found\n' "$PROGNAME" >&2
	exit 1
}

chmod +x .githooks/* 2>/dev/null || :
git config core.hooksPath .githooks

printf '%s: installed. core.hooksPath = %s\n' "$PROGNAME" "$(git config core.hooksPath)"
printf '%s: active hooks:\n' "$PROGNAME"
for h in .githooks/*; do
	[ -f "$h" ] || continue
	printf '  %s\n' "$(basename "$h")"
done
cat <<'MSG'

  pre-commit  fast checks on staged files (lint, secrets, signature load)
  pre-push    full checks including the test suite
  commit-msg  subject line is present, under 72 chars, and not a placeholder

Bypass any hook with --no-verify. CI runs the same checks via tools/checks.sh,
so nothing reaches main unchecked either way.
MSG
