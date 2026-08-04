#!/bin/sh
# Merge a vendor package feed into signatures/compromised-packages.txt.
#
#   ./tools/merge-package-list.sh FEED [FEED...]
#
# FEED is either:
#   - a Socket-style CSV with an "Ecosystem,Namespace,Name,Version,..." header, or
#   - a plain text file with one `name@version` per line.
#
# The result is the UNION of the existing list and every feed. This is a merge,
# never a replace, because no single vendor feed is complete: as of 2026-08-04
# both the Wiz CSV and Socket's CSV omit the entire `@keyv/*` scope -- the
# campaign's namesake -- which only JFrog published. Overwriting from one feed
# would silently drop 19 confirmed packages.
#
# Prints a summary to stderr and the merged list to stdout, so a refresh is:
#
#   curl -sSf 'https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv' \
#     -o /tmp/socket.csv
#   ./tools/merge-package-list.sh /tmp/socket.csv > /tmp/merged.txt
#   mv /tmp/merged.txt signatures/compromised-packages.txt
#   ./tools/make-package-signatures.sh signatures/compromised-packages.txt \
#     > signatures/shai-hulud-2026-08-packages.conf
#
# This tool makes no network calls of its own: fetch the feed separately so the
# repository stays usable on an air-gapped host. See docs/signatures.md.

set -eu

PROGNAME="merge-package-list"
BASE="signatures/compromised-packages.txt"

[ $# -ge 1 ] || {
	printf 'usage: %s FEED [FEED...]\n' "$PROGNAME" >&2
	exit 2
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/mergepkg.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# Normalize one feed to name@version, one per line.
normalize() {
	# A Socket-style CSV is detected by its header rather than by file extension.
	if head -1 "$1" | grep -qi '^ecosystem,namespace,name,version'; then
		awk -F',' '
			NR == 1 { next }
			{
				ns = $2; nm = $3; ver = $4
				gsub(/^[ \t"]+|[ \t"\r]+$/, "", ns)
				gsub(/^[ \t"]+|[ \t"\r]+$/, "", nm)
				gsub(/^[ \t"]+|[ \t"\r]+$/, "", ver)
				if (nm == "" || ver == "") next
				print (ns == "" ? nm : ns "/" nm) "@" ver
			}
		' "$1"
	else
		awk '{ sub(/\r$/, ""); gsub(/^[ \t]+|[ \t]+$/, "") } NF && $0 !~ /^#/ { print }' "$1"
	fi
}

[ -f "$BASE" ] || {
	printf '%s: base list not found: %s (run from the repository root)\n' "$PROGNAME" "$BASE" >&2
	exit 1
}

normalize "$BASE" | sort -u >"$WORK/base"
cp "$WORK/base" "$WORK/all"

for feed in "$@"; do
	[ -f "$feed" ] || {
		printf '%s: feed not found: %s\n' "$PROGNAME" "$feed" >&2
		exit 1
	}
	normalize "$feed" | sort -u >"$WORK/feed"
	_n=$(wc -l <"$WORK/feed" | tr -d ' ')
	_new=$(comm -13 "$WORK/all" "$WORK/feed" | wc -l | tr -d ' ')
	_absent=$(comm -23 "$WORK/all" "$WORK/feed" | wc -l | tr -d ' ')
	printf '%s: %s -> %s pair(s); %s new, %s already-known pair(s) absent from this feed\n' \
		"$PROGNAME" "$feed" "$_n" "$_new" "$_absent" >&2
	if [ "$_absent" -gt 0 ]; then
		printf '%s:   (kept -- no feed is authoritative on its own)\n' "$PROGNAME" >&2
	fi
	sort -u "$WORK/all" "$WORK/feed" >"$WORK/next"
	mv "$WORK/next" "$WORK/all"
done

_before=$(wc -l <"$WORK/base" | tr -d ' ')
_after=$(wc -l <"$WORK/all" | tr -d ' ')
printf '%s: %s -> %s pair(s), %s name(s)\n' "$PROGNAME" "$_before" "$_after" \
	"$(sed 's/@[^@]*$//' "$WORK/all" | sort -u | wc -l | tr -d ' ')" >&2

cat "$WORK/all"
