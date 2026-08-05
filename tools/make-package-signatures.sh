#!/bin/sh
# Generate a PKGVER signature file from a list of compromised name@version pairs.
#
#   ./tools/make-package-signatures.sh INPUT [CAMPAIGN] [SIGVERSION] [UPDATED] > out.conf
#
# INPUT is a text file with one `name@version` per line. Blank lines and lines
# starting with `#` are ignored. Anything that is not a well-formed name@version
# is reported on stderr and the script exits non-zero without emitting a file —
# a mangled record would fail every scan closed with exit 1, so it is caught
# here instead.
#
# Signature IDs are derived from a hash of name@version rather than a sequence,
# so regenerating from a longer list does not renumber existing IDs. IDs end up
# in incident tickets and need to stay stable.
#
# See docs/signatures.md for the output format.

set -eu

PROGNAME="make-package-signatures"

usage() {
	printf 'usage: %s INPUT [CAMPAIGN] [SIGVERSION] [UPDATED]\n' "$PROGNAME" >&2
	exit 2
}

[ $# -ge 1 ] || usage
INPUT=$1
CAMPAIGN=${2:-"Shai-Hulud: Here We Go Again (keyv / cacheable npm worm)"}
SIGVERSION=${3:-"$(date -u '+%Y.%m.%d').1"}
# Taken as an argument so output depends only on inputs. Embedding "today" would
# make the file differ every day and defeat the drift check in tools/checks.sh.
UPDATED=${4:-"$(date -u '+%Y-%m-%d')"}

[ -f "$INPUT" ] || {
	printf '%s: input not found: %s\n' "$PROGNAME" "$INPUT" >&2
	exit 1
}

hash_of() {
	# Short stable digest of stdin. Any of these tools is fine; they all agree
	# with themselves, which is all stability requires.
	if command -v sha1sum >/dev/null 2>&1; then
		sha1sum | cut -c1-8
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 1 | cut -c1-8
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha1 | awk '{print $NF}' | cut -c1-8
	else
		printf '%s: no SHA-1 tool available for ID generation\n' "$PROGNAME" >&2
		exit 1
	fi
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/mkpkgsig.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- Validate and normalize -------------------------------------------------
# A package name is lowercase, may be scoped, and may contain . _ -
# A version is anything non-empty without a pipe (prerelease tags are allowed).
awk '
	{ sub(/\r$/, "") }
	/^[[:space:]]*($|#)/ { next }
	{
		gsub(/^[[:space:]]+|[[:space:]]+$/, "")
		if ($0 == "") next
		if (index($0, "|") > 0) { print "pipe in record: " $0 > "/dev/stderr"; bad++; next }
		# Split at the last @, so scoped names survive.
		p = 0
		for (i = length($0); i > 1; i--) if (substr($0, i, 1) == "@") { p = i; break }
		if (p == 0) { print "no version: " $0 > "/dev/stderr"; bad++; next }
		name = substr($0, 1, p-1)
		ver  = substr($0, p+1)
		if (name !~ /^(@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/) { print "bad name: " $0 > "/dev/stderr"; bad++; next }
		if (ver  !~ /^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$/) { print "bad version: " $0 > "/dev/stderr"; bad++; next }
		print name "@" ver
	}
	END { if (bad) { print "rejected " bad " malformed record(s)" > "/dev/stderr"; exit 1 } }
' "$INPUT" | sort -u >"$WORK/pairs"

TOTAL=$(wc -l <"$WORK/pairs" | tr -d ' ')
[ "$TOTAL" -gt 0 ] || {
	printf '%s: no valid records in %s\n' "$PROGNAME" "$INPUT" >&2
	exit 1
}
NAMES=$(sed 's/@[^@]*$//' "$WORK/pairs" | sort -u | wc -l | tr -d ' ')

# --- Assign stable IDs ------------------------------------------------------
: >"$WORK/ids"
while IFS= read -r nv; do
	[ -n "$nv" ] || continue
	printf '%s\t%s\n' "SH25-V$(printf '%s' "$nv" | hash_of)" "$nv" >>"$WORK/ids"
done <"$WORK/pairs"

# A collision would silently merge two packages under one ID.
DUPES=$(cut -f1 "$WORK/ids" | sort | uniq -d)
if [ -n "$DUPES" ]; then
	printf '%s: signature ID collision, widen the hash:\n%s\n' "$PROGNAME" "$DUPES" >&2
	exit 1
fi

# --- Emit -------------------------------------------------------------------
cat <<EOF
# SandwormCheck signature file — compromised package versions
#
# GENERATED FILE. Do not hand-edit; regenerate instead:
#   ./tools/make-package-signatures.sh signatures/compromised-packages.txt \\
#     > signatures/shai-hulud-2026-08-packages.conf
# See docs/signatures.md#updating-this-campaign
#
#!campaign  $CAMPAIGN
#!version   $SIGVERSION
#!updated   $UPDATED
# Indicator sources. This list is a UNION of these feeds -- no single one is
# complete. Credit and per-source detail: docs/references.md
#!reference https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv
#!reference https://research.jfrog.com/post/shai-hulud-is-back-august/
#!reference https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv
#!reference https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack
#!reference https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack
#
# $TOTAL name@version pairs across $NAMES distinct package names.
#
# Severity is SUSPECT, not CONFIRMED: the presence of a compromised version on
# disk or pinned in a lockfile means the bad version was resolved, but not that
# the payload executed. Install scripts may be disabled, or the tarball may be
# sitting in a cache. Escalate only if a CONFIRMED indicator also fires.
#
# IDs are derived from a hash of name@version so that regenerating from a longer
# list does not renumber existing entries.

EOF

awk -F'\t' '{ printf "PKGVER|SUSPECT|%s|%s|Compromised release published 2026-08-04\n", $1, $2 }' \
	"$WORK/ids" | sort -t'|' -k4,4

printf '%s: emitted %s records (%s package names)\n' "$PROGNAME" "$TOTAL" "$NAMES" >&2
