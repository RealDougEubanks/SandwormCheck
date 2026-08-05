#!/bin/sh
# SandwormCheck — host-local IOC scanner for npm supply chain compromise.
#
# Read-only. Makes no network connections. Reports to the local console and
# communicates its verdict through the exit code:
#
#   0   no indicators found
#   10  SUSPECT indicators only
#   20  at least one CONFIRMED indicator
#   1   scanner error (an incomplete scan is NOT a clean scan)
#   2   usage error
#
# See docs/spec.md for the design contract and docs/usage.md for examples.
#
# Indicator content is not original research: it is assembled from public work by
# Wiz, Socket, JFrog, CyberKendra, and Aikido. Credits and per-indicator
# provenance are in docs/references.md.
#
# POSIX sh only: no arrays, no [[ ]], no local, no process substitution.

# zsh does not field-split unquoted parameter expansions, which silently breaks
# several checks and would under-report indicators — a false clean, the worst
# failure mode this tool has. If someone invokes us as `zsh sandwormcheck.sh`,
# re-exec under a real POSIX shell rather than run degraded.
# shellcheck disable=SC2296  # ZSH_VERSION is only read when zsh is the interpreter
if [ -n "${ZSH_VERSION:-}" ]; then
	if [ -x /bin/sh ]; then
		BWC_REEXEC=1 exec /bin/sh "$0" "$@"
	fi
	printf 'sandwormcheck: refusing to run under zsh (no POSIX /bin/sh found)\n' >&2
	exit 1
fi

set -eu

VERSION="1.0.0"
PROGNAME="sandwormcheck"

EXIT_CLEAN=0
EXIT_ERROR=1
EXIT_USAGE=2
EXIT_SUSPECT=10
EXIT_CONFIRMED=20

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SIG_ARG=""
SCAN_PATHS=""
MAX_DEPTH=12
MAX_FILE_SIZE=8388608   # 8 MiB
TIMEOUT_SECS=900
OUTPUT_MODE="text"
QUIET=0
VERBOSE=0
NO_COLOR=0

# Runtime state
WORKDIR=""
FINDINGS_FILE=""
CANDIDATES_FILE=""
HASHCAND_FILE=""
CONTENTCAND_FILE=""
STAT_MODE=""
SIGFILES=""
HASH_SHA256=""
HASH_SHA1=""
COUNT_CONFIRMED=0
COUNT_SUSPECT=0
COUNT_SKIPPED=0
TRUNCATED=0
SCAN_START=0
CAMPAIGNS=""

# ---------------------------------------------------------------------------
# Diagnostics. Everything non-report goes to stderr so stdout stays parseable.
# ---------------------------------------------------------------------------
err() { printf '%s: %s\n' "$PROGNAME" "$*" >&2; }
warn() { printf '%s: warning: %s\n' "$PROGNAME" "$*" >&2; }
# Progress lines carry elapsed seconds so a slow stage is identifiable from the
# output rather than by guesswork.
info() {
	if [ "$VERBOSE" -eq 1 ]; then
		printf '%s: [%4ss] %s\n' "$PROGNAME" "$(elapsed)" "$*" >&2
	fi
}

die() {
	code=$1
	shift
	err "$*"
	exit "$code"
}

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
	# Preserve the caller's exit status across cleanup.
	_status=$?
	if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
		rm -rf "$WORKDIR" 2>/dev/null || :
	fi
	exit "$_status"
}
trap cleanup EXIT
trap 'die $EXIT_ERROR "interrupted"' INT TERM HUP

usage() {
	cat <<EOF
$PROGNAME $VERSION — npm supply chain compromise scanner

Usage: $PROGNAME [options]

Options:
  -s, --signatures PATH   Signature file or directory (default: ./signatures)
  -p, --path PATH         Scan root; repeatable. Default: auto-detected user
                          home directories and common deployment paths.
      --max-depth N       Directory walk depth limit (1-64, default 12)
      --max-file-size N   Skip files larger than N bytes for hash/content
                          checks (1024-1073741824, default 8388608)
      --timeout N         Wall-clock scan limit in seconds (10-86400, default 900)
      --json              Emit a single JSON object instead of text
  -q, --quiet             Print only the verdict line
  -v, --verbose           Print progress to stderr
      --no-color          Disable ANSI color
  -h, --help              This message
      --version           Print version and exit

Exit codes:
  0  clean        10  suspect        20  confirmed compromise
  1  scanner error (NOT clean)       2  usage error

This tool is read-only and makes no network connections.
EOF
}

# ---------------------------------------------------------------------------
# Argument validation. Bounded and typed per docs/spec.md §6.
# ---------------------------------------------------------------------------
require_int() {
	# require_int <value> <min> <max> <flagname>
	case "$1" in
	'' | *[!0-9]*) die "$EXIT_USAGE" "$4 requires a non-negative integer, got: '$1'" ;;
	esac
	# Strip leading zeros so 007 compares numerically and doesn't look octal.
	_v=$(printf '%s' "$1" | sed 's/^0*\([0-9]\)/\1/')
	if [ "$_v" -lt "$2" ] || [ "$_v" -gt "$3" ]; then
		die "$EXIT_USAGE" "$4 must be between $2 and $3, got: $_v"
	fi
	printf '%s' "$_v"
}

parse_args() {
	while [ $# -gt 0 ]; do
		case $1 in
		-s | --signatures)
			[ $# -ge 2 ] || die "$EXIT_USAGE" "$1 requires an argument"
			SIG_ARG=$2
			shift 2
			;;
		-p | --path)
			[ $# -ge 2 ] || die "$EXIT_USAGE" "$1 requires an argument"
			[ -d "$2" ] || die "$EXIT_USAGE" "--path is not a directory: $2"
			SCAN_PATHS="$SCAN_PATHS$2
"
			shift 2
			;;
		--max-depth)
			[ $# -ge 2 ] || die "$EXIT_USAGE" "$1 requires an argument"
			MAX_DEPTH=$(require_int "$2" 1 64 "--max-depth")
			shift 2
			;;
		--max-file-size)
			[ $# -ge 2 ] || die "$EXIT_USAGE" "$1 requires an argument"
			MAX_FILE_SIZE=$(require_int "$2" 1024 1073741824 "--max-file-size")
			shift 2
			;;
		--timeout)
			[ $# -ge 2 ] || die "$EXIT_USAGE" "$1 requires an argument"
			TIMEOUT_SECS=$(require_int "$2" 10 86400 "--timeout")
			shift 2
			;;
		--json)
			OUTPUT_MODE="json"
			shift
			;;
		-q | --quiet)
			QUIET=1
			shift
			;;
		-v | --verbose)
			VERBOSE=1
			shift
			;;
		--no-color)
			NO_COLOR=1
			shift
			;;
		-h | --help)
			usage
			exit "$EXIT_CLEAN"
			;;
		--version)
			printf '%s %s\n' "$PROGNAME" "$VERSION"
			exit "$EXIT_CLEAN"
			;;
		--)
			shift
			break
			;;
		-*) die "$EXIT_USAGE" "unknown option: $1 (try --help)" ;;
		*) die "$EXIT_USAGE" "unexpected argument: $1 (paths go via --path)" ;;
		esac
	done
	[ $# -eq 0 ] || die "$EXIT_USAGE" "unexpected trailing arguments: $*"
}

# ---------------------------------------------------------------------------
# Environment probing
# ---------------------------------------------------------------------------
script_dir() {
	# Resolve the directory holding this script, following one symlink level.
	_s=$0
	if [ -L "$_s" ]; then
		_link=$(readlink "$_s" 2>/dev/null || printf '%s' "$_s")
		case $_link in
		/*) _s=$_link ;;
		*) _s=$(dirname "$_s")/$_link ;;
		esac
	fi
	(cd "$(dirname "$_s")" 2>/dev/null && pwd) || printf '.'
}

probe_hashers() {
	if command -v sha256sum >/dev/null 2>&1; then
		HASH_SHA256="sha256sum"
	elif command -v shasum >/dev/null 2>&1; then
		HASH_SHA256="shasum -a 256"
	elif command -v openssl >/dev/null 2>&1; then
		HASH_SHA256="openssl_256"
	fi

	if command -v sha1sum >/dev/null 2>&1; then
		HASH_SHA1="sha1sum"
	elif command -v shasum >/dev/null 2>&1; then
		HASH_SHA1="shasum -a 1"
	elif command -v openssl >/dev/null 2>&1; then
		HASH_SHA1="openssl_1"
	fi

	# Absence disables hash checks loudly. Silently skipping them would turn a
	# missing tool into a false clean result.
	[ -n "$HASH_SHA256" ] || warn "no SHA-256 tool found (sha256sum/shasum/openssl); SHA256 checks will be SKIPPED"
	[ -n "$HASH_SHA1" ] || warn "no SHA-1 tool found; SHA1 checks will be SKIPPED"
}

hash_file() {
	# hash_file <algo> <path> -> lowercase hex digest, or empty on failure
	_algo=$1
	_path=$2
	if [ "$_algo" = "sha256" ]; then
		case $HASH_SHA256 in
		"") return 0 ;;
		openssl_256) openssl dgst -sha256 "$_path" 2>/dev/null | awk '{print $NF}' ;;
		*) $HASH_SHA256 "$_path" 2>/dev/null | awk '{print $1}' ;;
		esac
	else
		case $HASH_SHA1 in
		"") return 0 ;;
		openssl_1) openssl dgst -sha1 "$_path" 2>/dev/null | awk '{print $NF}' ;;
		*) $HASH_SHA1 "$_path" 2>/dev/null | awk '{print $1}' ;;
		esac
	fi
}

file_size() {
	# Size in bytes. Always yields a non-negative integer.
	#
	# The previous form chained `stat -f '%z' || stat -c '%s'`, which is wrong on
	# GNU: there -f means --file-system, so '%z' was taken as a FILENAME. GNU stat
	# printed filesystem details for the real file AND failed on the bogus one, so
	# the fallback appended the real size to that output. The caller received a
	# multi-line string, the numeric comparison errored, and --max-file-size
	# silently stopped being enforced on Linux. Caught by CI, not by review.
	_fs=""
	if [ "$STAT_MODE" = "gnu" ]; then
		_fs=$(stat -c '%s' "$1" 2>/dev/null)
	elif [ "$STAT_MODE" = "bsd" ]; then
		_fs=$(stat -f '%z' "$1" 2>/dev/null)
	fi
	# POSIX fallback whenever stat gave nothing usable. wc -c on a redirect uses
	# fstat for regular files, so it does not read the contents.
	case ${_fs:-} in
	'' | *[!0-9]*) _fs=$(wc -c <"$1" 2>/dev/null | tr -d ' \t') ;;
	esac
	# If even that failed, report 0. That makes the file look small, so it is
	# scanned rather than skipped: for a detection tool, erring toward doing the
	# work is the safe direction.
	case ${_fs:-} in
	'' | *[!0-9]*) _fs=0 ;;
	esac
	printf '%s' "$_fs"
}

probe_stat() {
	# Pick the batched stat form once. BSD and GNU stat take different flags but
	# both accept many paths per invocation, which is what makes size filtering
	# affordable on a large tree.
	# GNU is probed FIRST because its -f flag means --file-system and would
	# misinterpret a BSD-style format string as a filename, making a
	# BSD-first probe ambiguous rather than cleanly failing.
	if stat -c '%s' . >/dev/null 2>&1; then
		STAT_MODE="gnu"
	elif stat -f '%z' . >/dev/null 2>&1; then
		STAT_MODE="bsd"
	else
		STAT_MODE=""
		warn "no usable stat(1); --max-file-size will be enforced one file at a time"
	fi
}

size_filter() {
	# stdin: newline-separated paths. stdout: those at or under --max-file-size.
	#
	# Note: a path containing a literal tab is dropped here. Such a path also
	# cannot be represented in the pipe-delimited findings format, so it is out of
	# scope rather than silently mishandled.
	if [ "$STAT_MODE" = "bsd" ]; then
		tr '\n' '\0' | xargs -0 -n 200 stat -f '%z	%N' 2>/dev/null || :
	elif [ "$STAT_MODE" = "gnu" ]; then
		tr '\n' '\0' | xargs -0 -n 200 stat -c '%s	%n' 2>/dev/null || :
	else
		# No batched stat: fall back to one call per file. Correct, just slower.
		while IFS= read -r f; do
			[ -n "$f" ] || continue
			printf '%s\t%s\n' "$(file_size "$f")" "$f"
		done
	fi | awk -F'\t' -v m="$MAX_FILE_SIZE" 'NF>=2 && $1+0 <= m { sub(/^[^\t]*\t/, ""); print }'
}

host_id() {
	_hn=$(hostname 2>/dev/null || printf 'unknown')
	_machine=""
	if [ -r /etc/machine-id ]; then
		_machine=$(cat /etc/machine-id 2>/dev/null || :)
	elif command -v ioreg >/dev/null 2>&1; then
		_machine=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null |
			awk -F'"' '/IOPlatformUUID/{print $4; exit}' || :)
	fi
	if [ -n "$HASH_SHA256" ]; then
		_h=$(printf '%s|%s' "$_hn" "$_machine" | hash_stdin_256 | cut -c1-12)
		printf '%s/%s' "$_hn" "$_h"
	else
		printf '%s' "$_hn"
	fi
}

hash_stdin_256() {
	# SHA-256 of stdin. Kept as its own function because a `case` nested inside
	# a command substitution does not parse on bash 3.2 (the macOS system shell).
	if [ "$HASH_SHA256" = "openssl_256" ]; then
		openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
	else
		$HASH_SHA256 2>/dev/null | awk '{print $1}'
	fi
}

elapsed() {
	_now=$(date +%s 2>/dev/null || printf '0')
	printf '%s' $((_now - SCAN_START))
}

timed_out() {
	[ "$(elapsed)" -ge "$TIMEOUT_SECS" ]
}

# ---------------------------------------------------------------------------
# Signature loading
# ---------------------------------------------------------------------------
resolve_signatures() {
	if [ -z "$SIG_ARG" ]; then
		SIG_ARG="$(script_dir)/signatures"
		[ -e "$SIG_ARG" ] || die "$EXIT_ERROR" "no signatures found at $SIG_ARG (use --signatures)"
	fi
	[ -e "$SIG_ARG" ] || die "$EXIT_ERROR" "signature path does not exist: $SIG_ARG"

	if [ -d "$SIG_ARG" ]; then
		SIGFILES=$(find "$SIG_ARG" -maxdepth 1 -type f -name '*.conf' 2>/dev/null | sort || :)
		[ -n "$SIGFILES" ] || die "$EXIT_ERROR" "no *.conf signature files in directory: $SIG_ARG"
	elif [ -f "$SIG_ARG" ]; then
		SIGFILES=$SIG_ARG
	else
		die "$EXIT_ERROR" "signature path is neither a file nor a directory: $SIG_ARG"
	fi

	printf '%s\n' "$SIGFILES" | while IFS= read -r f; do
		[ -n "$f" ] || continue
		[ -r "$f" ] || die "$EXIT_ERROR" "signature file is not readable: $f"
	done || exit "$EXIT_ERROR"
}

load_signatures() {
	# Normalize every signature file into WORKDIR/sigs: TYPE|SEV|ID|PATTERN|DESC
	: >"$WORKDIR/sigs"
	_total=0
	for f in $SIGFILES; do
		[ -n "$f" ] || continue
		_campaign=$(sed -n 's/^#![[:space:]]*campaign[[:space:]]\{1,\}//p' "$f" | head -1)
		[ -n "$_campaign" ] || _campaign=$(basename "$f")
		_sigver=$(sed -n 's/^#![[:space:]]*version[[:space:]]\{1,\}//p' "$f" | head -1)
		CAMPAIGNS="$CAMPAIGNS$_campaign (${_sigver:-unversioned})
"
		# Parse and validate in one awk pass. The equivalent shell loop spawns
		# roughly fifteen processes per record, which takes about a minute on a
		# few thousand signatures — slow enough that operators would skip runs.
		#
		# A malformed record is a hard error, not a skipped line: silently
		# dropping it would shrink coverage invisibly and could report a host as
		# clean when the check never ran.
		awk -v file="$f" '
			function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
			function fail(lineno, msg) {
				printf "%s:%d: %s\n", file, lineno, msg > "/dev/stderr"
				bad = 1
				exit 1
			}
			{ sub(/\r$/, "") }                       # tolerate CRLF-edited files
			/^[ \t]*$/ { next }
			/^[ \t]*#/ { next }
			{
				n = split($0, f, "|")
				if (n < 5) fail(FNR, "expected 5 pipe-delimited fields, got " n)
				type = trim(f[1]); sev = trim(f[2]); id = trim(f[3]); pat = trim(f[4])
				desc = f[5]
				for (i = 6; i <= n; i++) desc = desc "|" f[i]
				desc = trim(desc)

				if (type !~ /^(PATHEXISTS|PATHGLOB|FILENAME|SHA256|SHA1|PKGVER|CONTENT|PROCESS)$/)
					fail(FNR, "unknown check type \x27" type "\x27")
				if (sev != "CONFIRMED" && sev != "SUSPECT")
					fail(FNR, "severity must be CONFIRMED or SUSPECT, got \x27" sev "\x27")
				if (id == "")   fail(FNR, "empty signature ID")
				if (pat == "")  fail(FNR, "empty pattern for " id)
				if (desc == "") fail(FNR, "empty description for " id)

				if (type == "SHA256") {
					if (pat !~ /^[0-9a-fA-F]{64}$/)
						fail(FNR, id ": SHA256 must be 64 hex characters, got " length(pat))
					pat = tolower(pat)
				} else if (type == "SHA1") {
					if (pat !~ /^[0-9a-fA-F]{40}$/)
						fail(FNR, id ": SHA1 must be 40 hex characters, got " length(pat))
					pat = tolower(pat)
				} else if (type == "PKGVER") {
					if (index(pat, "@") == 0)
						fail(FNR, id ": PKGVER must be name@version")
				}

				printf "%s|%s|%s|%s|%s\n", type, sev, id, pat, desc
				kept++
			}
			END { if (!bad) printf "%d records\n", kept > "/dev/stderr" }
		' "$f" >>"$WORKDIR/sigs" 2>"$WORKDIR/sigerr" ||
			die "$EXIT_ERROR" "$(head -1 "$WORKDIR/sigerr")"
	done

	# A campaign split across several files (indicators in one, generated package
	# versions in another) declares the same name in each; list it once.
	CAMPAIGNS=$(printf '%s' "$CAMPAIGNS" | awk 'NF && !seen[$0]++')

	_total=$(grep -c '|' "$WORKDIR/sigs" 2>/dev/null || printf '0')
	[ "$_total" -gt 0 ] || die "$EXIT_ERROR" "no valid signature records loaded"
	info "loaded $_total signature records"
}

sigs_of_type() {
	# Print signature records of a given type. Empty output is normal.
	awk -F'|' -v t="$1" '$1==t' "$WORKDIR/sigs" 2>/dev/null || :
}

# ---------------------------------------------------------------------------
# Scan roots
# ---------------------------------------------------------------------------
default_scan_paths() {
	_out=""
	for d in /Users /home; do
		[ -d "$d" ] || continue
		for h in "$d"/*; do
			# Skip macOS pseudo-users and non-directories.
			[ -d "$h" ] || continue
			case $(basename "$h") in
			Shared | Guest | .*) continue ;;
			esac
			_out="$_out$h
"
		done
	done
	[ -n "${HOME:-}" ] && [ -d "${HOME:-}" ] && _out="$_out$HOME
"
	[ -d /root ] && _out="$_out/root
"
	for d in /opt /srv /var/www /usr/local/lib/node_modules; do
		[ -d "$d" ] && _out="$_out$d
"
	done
	# De-duplicate while preserving order.
	printf '%s' "$_out" | awk 'NF && !seen[$0]++'
}

walk() {
	# walk <root> -> newline-separated file list, pruned and depth-bounded.
	# Pruning keeps a fleet-wide scan finishing in minutes rather than hours and
	# avoids pseudo-filesystems and network mounts that can hang find. Every
	# check writes findings straight to $FINDINGS_FILE rather than incrementing
	# counters, because the check loops run inside pipeline subshells where
	# variable assignments would be discarded; tally() derives the counts.
	_root=$1
	case $_root in
	/proc* | /sys* | /dev* | /Volumes* | /net* | /System*) return 0 ;;
	esac
	# -H follows a symlink given ON THE COMMAND LINE but not symlinks found inside
	# the tree. Without it a symlinked root yields zero files and the scan reports
	# CLEAN: /tmp is a symlink to private/tmp on macOS, and a relocated home
	# directory is often a symlink too, so whole roots silently went unscanned.
	# Symlinks *within* the tree stay unfollowed, which avoids cycles and stops a
	# link from pulling the scan outside its root.
	find -H "$_root" -maxdepth "$MAX_DEPTH" \
		\( -name .git -o -name .Trash -o -name Caches \
		-o -name CloudStorage -o -name .npm-cache \) -prune -o \
		-type f -print 2>/dev/null || :
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
check_pathexists() {
	sigs_of_type PATHEXISTS | while IFS='|' read -r _t _sev _id _pat _desc; do
		[ -n "$_id" ] || continue
		# Expand ~ against every home directory we know about, not just $HOME,
		# because JumpCloud runs as root and the artifacts live in user homes.
		# The '~/' branch matches a literal tilde prefix in the signature text;
		# expansion happens per-home inside the branch, not here.
		# shellcheck disable=SC2088
		case $_pat in
		'~/'*)
			_rest=${_pat#'~/'}
			printf '%s\n' "$HOMES" | while IFS= read -r h; do
				[ -n "$h" ] || continue
				glob_report "$h/$_rest" "$_sev" "$_id" "$_desc"
			done
			;;
		*) glob_report "$_pat" "$_sev" "$_id" "$_desc" ;;
		esac
	done
}

glob_report() {
	# glob_report <glob> <sev> <id> <desc> — emit a finding line per match.
	# Runs in a subshell pipeline, so findings are appended to the file
	# directly and counted later by tally().
	for m in $1; do
		[ -e "$m" ] || continue
		printf '%s|%s|%s|%s|%s\n' "$2" "$3" "$m" "path exists" "$4" >>"$FINDINGS_FILE"
	done
}

check_filenames_and_globs() {
	# One awk pass over the candidate list for both types. The previous form ran
	# a shell `while read` loop per signature over the whole list, which on a real
	# tree of a few hundred thousand candidates costs seconds per signature.
	[ -s "$CANDIDATES_FILE" ] || return 0

	awk -F'|' '
		function globToRe(g,   out, i, c) {
			# Signature globs use only * and ?, so a small translation is enough.
			out = "^"
			for (i = 1; i <= length(g); i++) {
				c = substr(g, i, 1)
				if (c == "*") out = out ".*"
				else if (c == "?") out = out "."
				else if (c ~ /[.\[\]()+^$\\{}|\/]/) out = out "\\" c
				else out = out c
			}
			return out "$"
		}
		$1=="FILENAME" || $1=="PATHGLOB" {
			desc=$5
			for (i=6; i<=NF; i++) desc = desc "|" $i
			n++
			type[n]=$1; sev[n]=$2; id[n]=$3; pat[n]=$4; d[n]=desc
			if ($1=="PATHGLOB") re[n] = globToRe($4)
		}
		END { for (i=1; i<=n; i++) printf "%s\t%s\t%s\t%s\t%s\t%s\n", type[i], sev[i], id[i], pat[i], d[i], re[i] }
	' "$WORKDIR/sigs" >"$WORKDIR/fnsigs" 2>/dev/null || :
	[ -s "$WORKDIR/fnsigs" ] || return 0

	awk -v sigfile="$WORKDIR/fnsigs" '
		BEGIN {
			FS = "\t"
			while ((getline line < sigfile) > 0) {
				split(line, f, "\t")
				n++
				type[n]=f[1]; sev[n]=f[2]; id[n]=f[3]; pat[n]=f[4]; d[n]=f[5]; re[n]=f[6]
				if (f[1] == "FILENAME") byname[f[4]] = byname[f[4]] n ","
			}
			close(sigfile)
			FS = "\n"
		}
		{
			path = $0
			slash = 0
			for (i = length(path); i > 0; i--) if (substr(path, i, 1) == "/") { slash = i; break }
			leaf = slash ? substr(path, slash+1) : path

			if (leaf in byname) {
				cnt = split(byname[leaf], idx, ",")
				for (j = 1; j <= cnt; j++) {
					k = idx[j] + 0
					if (k) printf "%s|%s|%s|filename match|%s\n", sev[k], id[k], path, d[k]
				}
			}
			for (k = 1; k <= n; k++) {
				if (type[k] == "PATHGLOB" && path ~ re[k])
					printf "%s|%s|%s|path glob match|%s\n", sev[k], id[k], path, d[k]
			}
		}
	' "$CANDIDATES_FILE" >>"$FINDINGS_FILE" 2>/dev/null || :
}

check_hashes() {
	# check_hashes <lowercase_algo> <uppercase_check_type>
	#
	# Hashes are computed in batches: sha256sum/shasum accept many paths per
	# invocation and print "digest  path". Spawning one hasher per file costs tens
	# of thousands of processes on a real dependency tree and takes minutes.
	# Digests are then matched against a lookup table in one awk pass, so cost
	# scales with files rather than files times signatures.
	_algo=$1
	_type=$2
	_sigs=$(sigs_of_type "$_type")
	[ -n "$_sigs" ] || return 0
	[ -s "$HASHCAND_FILE" ] || return 0

	_hasher=""
	if [ "$_algo" = "sha256" ]; then _hasher=$HASH_SHA256; else _hasher=$HASH_SHA1; fi
	[ -n "$_hasher" ] || return 0

	# digest -> SEV|ID|DESC
	awk -F'|' -v t="$_type" '
		$1==t {
			desc=$5
			for (i=6; i<=NF; i++) desc = desc "|" $i
			printf "%s\t%s|%s|%s\n", $4, $2, $3, desc
		}
	' "$WORKDIR/sigs" >"$WORKDIR/hmap.$_algo" 2>/dev/null || :
	[ -s "$WORKDIR/hmap.$_algo" ] || return 0

	if [ "$_hasher" = "openssl_256" ] || [ "$_hasher" = "openssl_1" ]; then
		# openssl prints "SHA256(path)= digest" and has no batch-friendly form
		# worth parsing; it is the last-resort fallback, so keep it simple.
		while IFS= read -r f; do
			[ -n "$f" ] || continue
			_d=$(hash_file "$_algo" "$f")
			[ -n "$_d" ] || continue
			printf '%s\t%s\n' "$_d" "$f"
		done <"$HASHCAND_FILE" >"$WORKDIR/digests.$_algo"
	else
		# shellcheck disable=SC2086  # $_hasher is a command plus its flags
		tr '\n' '\0' <"$HASHCAND_FILE" |
			xargs -0 -n 200 $_hasher 2>/dev/null |
			awk '{ d=$1; $1=""; sub(/^[ \t]+/, ""); printf "%s\t%s\n", tolower(d), $0 }' \
				>"$WORKDIR/digests.$_algo" || :
	fi

	awk -F'\t' -v mapfile="$WORKDIR/hmap.$_algo" -v t="$_type" '
		BEGIN {
			while ((getline line < mapfile) > 0) {
				p = index(line, "\t")
				if (p) want[substr(line, 1, p-1)] = substr(line, p+1)
			}
			close(mapfile)
		}
		$1 in want {
			split(want[$1], f, "|")
			desc = f[3]
			for (i = 4; i in f; i++) desc = desc "|" f[i]
			printf "%s|%s|%s|%s match|%s\n", f[1], f[2], $2, t, desc
		}
	' "$WORKDIR/digests.$_algo" >>"$FINDINGS_FILE" 2>/dev/null || :
}

check_content() {
	# One batched grep over many files at a time rather than a grep per pattern
	# per file. The per-file form costs (patterns + 1) processes for every
	# candidate, which on a real dependency tree is hundreds of thousands of
	# processes and takes minutes.
	_sigs=$(sigs_of_type CONTENT)
	[ -n "$_sigs" ] || return 0
	[ -s "$CONTENTCAND_FILE" ] || return 0

	# Literal patterns for the batched pass, plus a pattern -> signature map.
	: >"$WORKDIR/cpat"
	: >"$WORKDIR/cmap"
	printf '%s\n' "$_sigs" | while IFS='|' read -r _t _sev _id _pat _desc; do
		[ -n "$_id" ] || continue
		printf '%s\n' "$_pat" >>"$WORKDIR/cpat"
		printf '%s\t%s|%s|%s\n' "$_pat" "$_sev" "$_id" "$_desc" >>"$WORKDIR/cmap"
	done
	[ -s "$WORKDIR/cpat" ] || return 0

	# -o with -H gives path:pattern per hit. -a so a binary payload does not
	# suppress output. xargs batches the file list; -n keeps the argument list
	# under the platform limit.
	# Two stages. `grep -l` stops at the first match per file and keeps grep on its
	# fast fixed-string path, so the broad sweep over every candidate is as cheap
	# as possible. Only the few files that matched are then re-read with `-o` to
	# learn which pattern hit, which is the expensive mode.
	#
	# NUL-delimited so paths containing spaces survive xargs. -a because a binary
	# payload must not suppress output.
	: >"$WORKDIR/chits"
	tr '\n' '\0' <"$CONTENTCAND_FILE" |
		xargs -0 -n 200 grep -laFf "$WORKDIR/cpat" 2>/dev/null |
		sort -u >"$WORKDIR/chits" || :
	[ -s "$WORKDIR/chits" ] || return 0

	tr '\n' '\0' <"$WORKDIR/chits" |
		xargs -0 -n 50 grep -oaHFf "$WORKDIR/cpat" 2>/dev/null |
		sort -u |
		while IFS= read -r line; do
			[ -n "$line" ] || continue
			# grep -H output is path:matched-text. A path may itself contain ':',
			# so split on the LAST occurrence of a known pattern instead: look up
			# each candidate pattern as a suffix.
			_hitpat=""
			_path=""
			while IFS= read -r p; do
				[ -n "$p" ] || continue
				case $line in
				*":$p")
					_hitpat=$p
					_path=${line%":$p"}
					break
					;;
				esac
			done <"$WORKDIR/cpat"
			[ -n "$_hitpat" ] || continue
			_rec=$(awk -F'\t' -v h="$_hitpat" '$1==h {print $2; exit}' "$WORKDIR/cmap")
			[ -n "$_rec" ] || continue
			_sev=$(printf '%s' "$_rec" | cut -d'|' -f1)
			_id=$(printf '%s' "$_rec" | cut -d'|' -f2)
			_desc=$(printf '%s' "$_rec" | cut -d'|' -f3-)
			printf '%s|%s|%s|%s|%s\n' "$_sev" "$_id" "$_path" "content match" "$_desc" >>"$FINDINGS_FILE"
		done
}

build_pkgver_lookup() {
	# name@version -> SEV|ID|DESC, one record per line. Built once so the checks
	# below are a hash lookup rather than a scan of every signature per file:
	# with a few thousand PKGVER records the nested-loop form is unusably slow.
	awk -F'|' '
		$1=="PKGVER" {
			desc=$5
			for (i=6; i<=NF; i++) desc = desc "|" $i
			printf "%s\t%s|%s|%s\n", $4, $2, $3, desc
		}
	' "$WORKDIR/sigs" >"$WORKDIR/pkgmap" 2>/dev/null || :
	[ -s "$WORKDIR/pkgmap" ]
}

check_pkgver() {
	build_pkgver_lookup || return 0

	# Only package.json files directly inside a package directory matter.
	grep -F '/package.json' "$WORKDIR/allfiles" 2>/dev/null |
		awk -v mapfile="$WORKDIR/pkgmap" -v maxsize="$MAX_FILE_SIZE" '
		BEGIN {
			FS = "\t"
			while ((getline line < mapfile) > 0) {
				t = index(line, "\t")
				if (t) want[substr(line, 1, t-1)] = substr(line, t+1)
			}
			close(mapfile)
		}
		{
			pj = $0
			if (pj !~ /\/package\.json$/) next

			# Extract the first "name" and "version", which in an npm-generated
			# manifest are the package own. Avoids a full JSON parse so a
			# manifest with trailing garbage still yields a usable answer.
			name = ""; ver = ""; n = 0
			while ((getline l < pj) > 0) {
				if (++n > 400) break        # own metadata is at the top
				if (name == "" && match(l, /"name"[ \t]*:[ \t]*"[^"]*"/)) {
					s = substr(l, RSTART, RLENGTH)
					sub(/^"name"[ \t]*:[ \t]*"/, "", s); sub(/"$/, "", s)
					name = s
				}
				if (ver == "" && match(l, /"version"[ \t]*:[ \t]*"[^"]*"/)) {
					s = substr(l, RSTART, RLENGTH)
					sub(/^"version"[ \t]*:[ \t]*"/, "", s); sub(/"$/, "", s)
					ver = s
				}
				if (name != "" && ver != "") break
			}
			close(pj)
			if (name == "" || ver == "") next

			nv = name "@" ver
			if (nv in want) {
				split(want[nv], f, "|")
				desc = f[3]
				for (i = 4; i in f; i++) desc = desc "|" f[i]
				printf "%s|%s|%s|installed %s|%s\n", f[1], f[2], pj, nv, desc
			}
		}
	' >>"$FINDINGS_FILE" 2>/dev/null || :
}

check_process() {
	# Match signature patterns against the command lines of running processes.
	#
	# Without this the scanner is blind to a live implant whose files have been
	# removed: this campaign's dead-man's switch polls GitHub every 60 seconds, so
	# the process can outlive the artifacts on disk. Reporting that host as clean
	# would be a false clean, the worst failure mode this tool has.
	#
	# Read-only: it reads the process table and never signals or modifies anything.
	_sigs=$(sigs_of_type PROCESS)
	[ -n "$_sigs" ] || return 0

	# BSD and GNU ps disagree on flags; try each before giving up.
	if ps -Ao pid=,ppid=,args= >"$WORKDIR/ps" 2>/dev/null && [ -s "$WORKDIR/ps" ]; then
		:
	elif ps ax -o pid=,ppid=,args= >"$WORKDIR/ps" 2>/dev/null && [ -s "$WORKDIR/ps" ]; then
		:
	elif ps -eo pid=,ppid=,args= >"$WORKDIR/ps" 2>/dev/null && [ -s "$WORKDIR/ps" ]; then
		:
	else
		# Loud, not silent: a skipped check must never look like a passed one.
		warn "could not read the process table; PROCESS checks were SKIPPED"
		return 0
	fi

	# Every ancestor of this scan, so the shell that launched us cannot be reported.
	# An operator's own investigation command frequently names the artifacts.
	: >"$WORKDIR/psskip"
	_p=$$
	_guard=0
	while [ -n "$_p" ] && [ "$_p" != "0" ] && [ "$_p" != "1" ] && [ "$_guard" -lt 40 ]; do
		printf '%s\n' "$_p" >>"$WORKDIR/psskip"
		_p=$(awk -v t="$_p" '$1==t {print $2; exit}' "$WORKDIR/ps" 2>/dev/null)
		_guard=$((_guard + 1))
	done

	sigs_of_type PROCESS >"$WORKDIR/pssigs"

	# Matching searches the whole argument list, but skips processes whose
	# executable is an inspection tool.
	#
	# An earlier revision searched every command line with no exclusions and
	# flagged the operator's own `grep -r Math_Symbol.js /` as a CONFIRMED
	# compromise -- an incident responder investigating the host would have
	# implicated themselves. The next revision searched only argv[0] and argv[1],
	# which fixed that but missed `bun run <payload>` and any invocation carrying a
	# flag, because the payload then sits at argv[2] or later. Excluding by
	# executable keeps full argument coverage without the self-report.
	awk -v skipfile="$WORKDIR/psskip" -v sigfile="$WORKDIR/pssigs" '
		BEGIN {
			while ((getline p < skipfile) > 0) if (p != "") mine[p] = 1
			close(skipfile)
			while ((getline l < sigfile) > 0) {
				n = split(l, f, "|")
				if (n < 5) continue
				d = f[5]
				for (i = 6; i <= n; i++) d = d "|" f[i]
				k++; sev[k] = f[2]; id[k] = f[3]; pat[k] = f[4]; desc[k] = d
			}
			close(sigfile)
			# Tools whose normal job is to name a file they are inspecting, so
			# seeing an implant filename in their arguments means nothing.
			#
			# Interpreters are deliberately NOT in this list. The real
			# gh-token-monitor.sh is a shell script, so ps shows it as
			# "/bin/sh /path/gh-token-monitor.sh"; skipping shells here made the
			# check miss the exact implant it exists to find.
			split("grep egrep fgrep rg ag ack find locate mdfind awk sed cat less more " \
			      "head tail vi vim nvim emacs nano code subl open strings xxd od file " \
			      "ps pgrep wc sort uniq diff cmp md5 shasum sha256sum", t, " ")
			for (i in t) tool[t[i]] = 1
		}
		{
			pid = $1
			if (pid in mine) next
			exe = $3
			# Basename of the executable.
			b = exe
			if (match(b, /\/[^\/]+$/)) b = substr(b, RSTART + 1)
			if (b in tool) next
			# Full argument list, fields 3..NF.
			hay = ""
			for (j = 3; j <= NF; j++) hay = hay " " $j
			for (i = 1; i <= k; i++) {
				if (index(hay, pat[i]) > 0) {
					# PID only, never the command line: command lines can carry
					# credentials as arguments, and findings reach fleet console
					# logs. See docs/spec.md section 8.
					printf "%s|%s|pid %s|process match|%s\n", sev[i], id[i], pid, desc[i]
				}
			}
		}
	' "$WORKDIR/ps" >>"$FINDINGS_FILE" 2>/dev/null || :
}

# ---------------------------------------------------------------------------
# Lockfile pins (spec §4.2)
#
# check_pkgver only sees packages that are actually installed. A project that
# pins a compromised version in its lockfile but has never had `npm install`
# run on this host is equally in need of remediation, and will reintroduce the
# bad version on the next install. These checks read the lockfile directly.
# ---------------------------------------------------------------------------
# bun.lockb is binary but not opaque: it embeds registry tarball URLs as
# contiguous ASCII, so the resolved-URL patterns work on it with grep -a. A miss
# in a .lockb is less conclusive than a miss in a text lockfile, because its
# non-registry entries are not readable this way.
LOCKFILE_NAMES="package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock bun.lockb"

check_lockfiles() {
	# Extract every (name, version) pair the lockfile actually declares, then look
	# each one up in the PKGVER table. One awk pass per lockfile, independent of
	# how many signatures are loaded.
	#
	# The earlier approach generated a literal pattern per signature per format
	# (~16,000 patterns for this campaign) and ran `grep -Ff` over each lockfile.
	# That measured 30-60s on a single 175 KB pnpm lockfile — BSD grep degrades
	# badly with a large -f pattern file — which made a fleet scan unusable.
	#
	# Parsing structurally is also more precise than substring matching: the name
	# and version are recovered as fields, so an unscoped signature cannot match a
	# scoped package that merely shares its basename.
	build_pkgver_lookup || return 0

	: >"$WORKDIR/locknames"
	for n in $LOCKFILE_NAMES; do
		printf '/%s\n' "$n" >>"$WORKDIR/locknames"
	done

	grep -Fs -f "$WORKDIR/locknames" "$WORKDIR/allfiles" 2>/dev/null |
		while IFS= read -r lf; do
			[ -n "$lf" ] || continue
			_leaf=${lf##*/}
			case " $LOCKFILE_NAMES " in
			*" $_leaf "*) ;;
			*) continue ;;
			esac
			# A lockfile nested inside node_modules is a dependency's own dev
			# lockfile. npm, yarn, and pnpm all ignore those when resolving, so a
			# hit there would be a misleading finding as well as wasted work.
			# npm-shrinkwrap.json is the exception: npm does honor a shipped one.
			case $lf in
			*/node_modules/*)
				[ "$_leaf" = "npm-shrinkwrap.json" ] || continue
				;;
			esac
			if [ ! -f "$lf" ] || [ ! -r "$lf" ]; then continue; fi
			_sz=$(file_size "$lf")
			if [ "$_sz" -gt "$MAX_FILE_SIZE" ]; then
				info "lockfile skipped (over --max-file-size): $lf"
				continue
			fi

			# tr NUL -> newline so bun.lockb, which is binary but stores registry
			# URLs as contiguous ASCII, can be parsed by the same program.
			tr '\0' '\n' <"$lf" 2>/dev/null |
				awk -v mapfile="$WORKDIR/pkgmap" -v lf="$lf" -v leaf="$_leaf" '
				BEGIN {
					while ((getline line < mapfile) > 0) {
						t = index(line, "\t")
						if (t) want[substr(line, 1, t-1)] = substr(line, t+1)
					}
					close(mapfile)
				}
				function report(nv) {
					if (!(nv in want)) return
					if (seen[nv]++) return
					split(want[nv], f, "|")
					desc = f[3]
					for (i = 4; i in f; i++) desc = desc "|" f[i]
					printf "%s|%s|%s|pinned %s in %s|%s\n", f[1], f[2], lf, nv, leaf, desc
				}
				# "name@version" -> split at the LAST @ so scoped names survive.
				function atForm(t,   p, i) {
					p = 0
					for (i = length(t); i > 1; i--) if (substr(t, i, 1) == "@") { p = i; break }
					if (p > 1) report(substr(t, 1, p-1) "@" substr(t, p+1))
				}
				# "name/version" (pnpm 5.x keys) -> split at the LAST slash.
				function slashForm(t,   p, i) {
					p = 0
					for (i = length(t); i > 1; i--) if (substr(t, i, 1) == "/") { p = i; break }
					if (p > 1) report(substr(t, 1, p-1) "@" substr(t, p+1))
				}
				function token(t) {
					sub(/^\//, "", t)
					sub(/:$/, "", t)
					if (t == "") return
					gsub(/@npm:/, "@", t)
					# Both forms are tried; each self-guards on finding its
					# separator past position 1. A scoped name starts with "@", so
					# testing index(t,"@")>1 would wrongly reject
					# "@cacheable/memory@2.2.1".
					atForm(t)
					slashForm(t)
				}
				{
					line = $0
					sub(/\r$/, "", line)

					# 1. Resolved registry tarball URL: .../<name>/-/<base>-<ver>.tgz
					#    Covers npm v1/v2/v3, npm-shrinkwrap, yarn v1, and bun.lockb.
					i = index(line, "/-/")
					if (i > 3) {
						rest = substr(line, i + 3)
						j = index(rest, ".tgz")
						if (j > 1) {
							basever = substr(rest, 1, j - 1)
							pre = substr(line, 1, i - 1)
							k = 0
							for (x = length(pre); x > 0; x--) if (substr(pre, x, 1) == "/") { k = x; break }
							if (k > 0) {
								last = substr(pre, k + 1)
								pre2 = substr(pre, 1, k - 1)
								k2 = 0
								for (x = length(pre2); x > 0; x--) if (substr(pre2, x, 1) == "/") { k2 = x; break }
								prev = substr(pre2, k2 + 1)
								# A scope is only a scope if the preceding segment starts with @.
								nm = (substr(prev, 1, 1) == "@") ? prev "/" last : last
								if (substr(basever, 1, length(last) + 1) == last "-") {
									report(nm "@" substr(basever, length(last) + 2))
								}
							}
						}
					}

					# 2. Every quoted token: yarn berry resolutions, bun.lock entries,
					#    and quoted pnpm mapping keys.
					n = split(line, q, "\"")
					for (m = 2; m <= n; m += 2) token(q[m])
					n = split(line, q2, "\x27")
					for (m = 2; m <= n; m += 2) token(q2[m])

					# 3. Bare pnpm mapping key: two-space indent, ends in a colon.
					if (line ~ /^[ \t]+[^ \t"\x27]+:[ \t]*$/) {
						t = line
						gsub(/^[ \t]+|[ \t]+$/, "", t)
						token(t)
					}
				}
			' >>"$FINDINGS_FILE" 2>/dev/null || :
		done
}

# ---------------------------------------------------------------------------
# Candidate selection (spec §6)
# ---------------------------------------------------------------------------
build_file_lists() {
	: >"$WORKDIR/allfiles"
	printf '%s\n' "$SCAN_PATHS" | while IFS= read -r root; do
		[ -n "$root" ] || continue
		if [ ! -r "$root" ]; then
			printf '%s\n' "$root" >>"$WORKDIR/skipped"
			continue
		fi
		if timed_out; then
			printf '1' >"$WORKDIR/truncated"
			break
		fi
		info "walking $root"
		walk "$root" >>"$WORKDIR/allfiles"
	done

	# Candidates: files the malware is known to write, or files inside the
	# directories it writes into. Hashing/grepping the whole disk is not viable.
	# Basenames worth looking at: those a FILENAME signature names outright, plus
	# the trailing component of each PATHGLOB, plus the config and manifest files
	# the checks always need.
	: >"$WORKDIR/namepat"
	{
		sigs_of_type FILENAME | cut -d'|' -f4
		sigs_of_type PATHGLOB | cut -d'|' -f4 | sed 's|.*/||'
	} | sort -u | while IFS= read -r n; do
		[ -n "$n" ] || continue
		case $n in
		*'*'* | *'?'*) continue ;; # a glob basename is not a usable literal
		esac
		printf '/%s\n' "$n" >>"$WORKDIR/namepat"
	done
	printf '/settings.json\n/tasks.json\n/package.json\n/setup.mjs\n' >>"$WORKDIR/namepat"
	sort -u "$WORKDIR/namepat" -o "$WORKDIR/namepat" 2>/dev/null ||
		{ sort -u "$WORKDIR/namepat" >"$WORKDIR/np.tmp" && mv "$WORKDIR/np.tmp" "$WORKDIR/namepat"; }

	{
		grep -Fs -f "$WORKDIR/namepat" "$WORKDIR/allfiles" 2>/dev/null || :
		grep -Es '/(node_modules|\.claude|\.vscode)/' "$WORKDIR/allfiles" 2>/dev/null || :
		# npm/yarn/pnpm debug logs record the preinstall hook that ran, which
		# survives deleting node_modules and is often the only remaining trace.
		grep -Es '/(_logs|\.npm/_logs|\.pnpm-debug|\.yarn/cache)/' "$WORKDIR/allfiles" 2>/dev/null || :
	} | sort -u >"$CANDIDATES_FILE"

	# Hash candidates are deliberately NARROW: only files whose basename a
	# FILENAME or PATHGLOB signature actually names.
	#
	# Hashing reads every byte. A developer machine's node_modules trees measured
	# 14 GB across 260,000 candidate files here, and hashing that per host is not
	# something a fleet operator will tolerate — an unrun scan detects nothing.
	# Every published hash for this campaign belongs to a file the malware writes
	# under a known name, so narrowing by basename loses no real coverage. If a
	# signature set has hash records with no matching basename, that IS a coverage
	# gap and is reported loudly below rather than passing silently.
	grep -Fs -f "$WORKDIR/namepat" "$CANDIDATES_FILE" 2>/dev/null |
		size_filter | sort -u >"$HASHCAND_FILE" || :

	# Warn only about a SIGNATURE AUTHORING gap: hash records with no
	# FILENAME/PATHGLOB signature to bring any file into the hash candidate set.
	#
	# The earlier condition tested whether the candidate list came out empty, which
	# is the normal state of a clean host with no matching files. That fired on
	# healthy machines and told operators "hash checks will find nothing", which
	# reads as a broken tool. Coverage is a property of the signature set, not of
	# the host being scanned.
	if [ -n "$(sigs_of_type SHA256)$(sigs_of_type SHA1)" ] &&
		[ -z "$(sigs_of_type FILENAME)$(sigs_of_type PATHGLOB)" ]; then
		warn "hash signatures are loaded but the signature set has no FILENAME or PATHGLOB record, so no file will ever be hashed. Add a FILENAME record for the basename you are hashing (see docs/signatures.md)."
	fi

	# Content candidates keep full breadth but are size-bounded, so one oversized
	# artifact cannot dominate the scan.
	#
	# CANDIDATES_FILE itself stays UNFILTERED. FILENAME and PATHGLOB match on the
	# path alone and must not depend on file size — an oversized payload is still
	# detectable by name, and size-filtering before those checks would silently
	# miss it.
	size_filter <"$CANDIDATES_FILE" | sort -u >"$CONTENTCAND_FILE" || :

	info "$(wc -l <"$WORKDIR/allfiles" | tr -d ' ') files walked, $(wc -l <"$CANDIDATES_FILE" | tr -d ' ') candidates, $(wc -l <"$CONTENTCAND_FILE" | tr -d ' ') content, $(wc -l <"$HASHCAND_FILE" | tr -d ' ') hash"
}

tally() {
	COUNT_CONFIRMED=$(awk -F'|' '$1=="CONFIRMED"' "$FINDINGS_FILE" 2>/dev/null | wc -l | tr -d ' ')
	COUNT_SUSPECT=$(awk -F'|' '$1=="SUSPECT"' "$FINDINGS_FILE" 2>/dev/null | wc -l | tr -d ' ')
	COUNT_SKIPPED=$(wc -l <"$WORKDIR/skipped" 2>/dev/null | tr -d ' ' || printf '0')
	if [ -f "$WORKDIR/truncated" ]; then TRUNCATED=1; fi
	: "${COUNT_CONFIRMED:=0}" "${COUNT_SUSPECT:=0}" "${COUNT_SKIPPED:=0}"
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
setup_color() {
	C_RED="" C_YEL="" C_GRN="" C_DIM="" C_OFF=""
	[ "$NO_COLOR" -eq 1 ] && return 0
	[ -n "${NO_COLOR_ENV:-}" ] && return 0
	[ -t 1 ] || return 0
	C_RED=$(printf '\033[31m')
	C_YEL=$(printf '\033[33m')
	C_GRN=$(printf '\033[32m')
	C_DIM=$(printf '\033[2m')
	C_OFF=$(printf '\033[0m')
}

verdict_of() {
	if [ "$COUNT_CONFIRMED" -gt 0 ]; then
		printf 'CONFIRMED'
	elif [ "$COUNT_SUSPECT" -gt 0 ]; then
		printf 'SUSPECT'
	else
		printf 'CLEAN'
	fi
}

exit_code_of() {
	case $(verdict_of) in
	CONFIRMED) printf '%s' "$EXIT_CONFIRMED" ;;
	SUSPECT) printf '%s' "$EXIT_SUSPECT" ;;
	*)
		# An incomplete scan that found nothing is not a clean result.
		if [ "$TRUNCATED" -eq 1 ]; then printf '%s' "$EXIT_ERROR"; else printf '%s' "$EXIT_CLEAN"; fi
		;;
	esac
}

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

report_text() {
	_v=$(verdict_of)
	if [ "$QUIET" -eq 0 ]; then
		printf '%s\n' "SandwormCheck $VERSION"
		printf '  host      : %s\n' "$HOSTID"
		printf '  scanned   : %s roots, %s files, %ss\n' \
			"$(printf '%s' "$SCAN_PATHS" | awk 'NF' | wc -l | tr -d ' ')" \
			"$(wc -l <"$WORKDIR/allfiles" | tr -d ' ')" "$(elapsed)"
		printf '  campaigns :\n'
		printf '%s' "$CAMPAIGNS" | awk 'NF{print "              " $0}'
		printf '\n'

		if [ -s "$FINDINGS_FILE" ]; then
			printf 'Findings:\n'
			sort -t'|' -k1,1 "$FINDINGS_FILE" | while IFS='|' read -r sev id path detail desc; do
				[ -n "$id" ] || continue
				if [ "$sev" = "CONFIRMED" ]; then _c=$C_RED; else _c=$C_YEL; fi
				printf '  %s%-9s%s %-12s %s\n' "$_c" "$sev" "$C_OFF" "$id" "$path"
				printf '  %s%s(%s) %s%s\n' "          " "$C_DIM" "$detail" "$desc" "$C_OFF"
			done
			printf '\n'
		else
			printf '%sNo indicators found.%s\n\n' "$C_GRN" "$C_OFF"
		fi

		if [ "$COUNT_SKIPPED" -gt 0 ]; then
			printf '%s%s path(s) unreadable and skipped — coverage is incomplete:%s\n' \
				"$C_YEL" "$COUNT_SKIPPED" "$C_OFF"
			awk 'NF{print "  " $0}' "$WORKDIR/skipped"
			printf '\n'
		fi
		if [ "$TRUNCATED" -eq 1 ]; then
			printf '%sSCAN TRUNCATED: the %ss timeout expired before all roots were walked.%s\n' \
				"$C_RED" "$TIMEOUT_SECS" "$C_OFF"
			printf 'This result is NOT a clean bill of health. Re-run with a longer --timeout.\n\n'
		fi
	fi

	case $_v in
	CONFIRMED) printf '%sVERDICT: CONFIRMED COMPROMISE%s — %s confirmed, %s suspect indicator(s). Isolate this host and rotate its credentials. See docs/remediation.md\n' "$C_RED" "$C_OFF" "$COUNT_CONFIRMED" "$COUNT_SUSPECT" ;;
	SUSPECT) printf '%sVERDICT: SUSPECT%s — %s suspect indicator(s), no confirmed payload. Remediate the affected dependencies.\n' "$C_YEL" "$C_OFF" "$COUNT_SUSPECT" ;;
	*)
		if [ "$TRUNCATED" -eq 1 ]; then
			printf 'VERDICT: INCOMPLETE — no indicators found, but the scan did not finish.\n'
		else
			printf '%sVERDICT: CLEAN%s — no indicators found.\n' "$C_GRN" "$C_OFF"
		fi
		;;
	esac
}

report_json() {
	_code=$(exit_code_of)
	printf '{'
	printf '"schema":"sandwormcheck/v1",'
	printf '"tool_version":"%s",' "$VERSION"
	printf '"host":"%s",' "$(json_escape "$HOSTID")"
	printf '"scanned_at":"%s",' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf 'unknown')"
	printf '"duration_seconds":%s,' "$(elapsed)"
	printf '"files_walked":%s,' "$(wc -l <"$WORKDIR/allfiles" | tr -d ' ')"
	printf '"truncated":%s,' "$([ "$TRUNCATED" -eq 1 ] && printf 'true' || printf 'false')"
	printf '"paths_skipped":%s,' "$COUNT_SKIPPED"

	printf '"scan_roots":['
	_first=1
	printf '%s\n' "$SCAN_PATHS" | awk 'NF' | while IFS= read -r r; do
		[ "$_first" -eq 1 ] || printf ','
		_first=0
		printf '"%s"' "$(json_escape "$r")"
	done
	printf '],'

	printf '"campaigns":['
	printf '%s' "$CAMPAIGNS" | awk 'NF' | awk '{
		gsub(/\\/,"\\\\"); gsub(/"/,"\\\"");
		printf "%s\"%s\"", (NR>1 ? "," : ""), $0
	}'
	printf '],'

	printf '"counts":{"confirmed":%s,"suspect":%s},' "$COUNT_CONFIRMED" "$COUNT_SUSPECT"

	printf '"findings":['
	if [ -s "$FINDINGS_FILE" ]; then
		sort -t'|' -k1,1 "$FINDINGS_FILE" | awk -F'|' '
			function esc(s) { gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\t/,"\\t",s); return s }
			NF>=5 {
				printf "%s{\"severity\":\"%s\",\"id\":\"%s\",\"path\":\"%s\",\"detail\":\"%s\",\"description\":\"%s\"}",
					(n++ ? "," : ""), esc($1), esc($2), esc($3), esc($4), esc($5)
			}'
	fi
	printf '],'

	printf '"verdict":"%s",' "$(verdict_of)"
	printf '"exit_code":%s' "$_code"
	printf '}\n'
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
	parse_args "$@"
	setup_color

	SCAN_START=$(date +%s 2>/dev/null || printf '0')

	WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/sandwormcheck.XXXXXX") ||
		die "$EXIT_ERROR" "cannot create temporary directory"
	FINDINGS_FILE="$WORKDIR/findings"
	CANDIDATES_FILE="$WORKDIR/candidates"
	HASHCAND_FILE="$WORKDIR/hashcand"
	CONTENTCAND_FILE="$WORKDIR/contentcand"
	: >"$FINDINGS_FILE"
	: >"$CANDIDATES_FILE"
	: >"$HASHCAND_FILE"
	: >"$CONTENTCAND_FILE"
	: >"$WORKDIR/skipped"

	probe_hashers
	probe_stat
	HOSTID=$(host_id)

	resolve_signatures
	load_signatures

	if [ -z "$SCAN_PATHS" ]; then
		SCAN_PATHS=$(default_scan_paths)
		SCAN_PATHS="$SCAN_PATHS
"
	fi
	[ -n "$(printf '%s' "$SCAN_PATHS" | awk 'NF')" ] ||
		die "$EXIT_ERROR" "no scannable roots found; pass --path explicitly"

	# Home directories used to expand ~ in PATHEXISTS patterns.
	HOMES=$(
		for d in /Users /home; do
			[ -d "$d" ] && find "$d" -maxdepth 1 -mindepth 1 -type d 2>/dev/null
		done
		[ -d /root ] && printf '/root\n'
		[ -n "${HOME:-}" ] && printf '%s\n' "$HOME"
	)
	HOMES=$(printf '%s\n' "$HOMES" | awk 'NF && !seen[$0]++')

	build_file_lists

	info "checking explicit persistence paths"
	check_pathexists
	info "checking filenames and path globs"
	check_filenames_and_globs
	info "checking package versions"
	check_pkgver
	info "checking lockfile pins"
	check_lockfiles
	info "checking running processes"
	check_process
	info "checking content markers"
	check_content
	info "checking hashes"
	check_hashes sha256 SHA256
	check_hashes sha1 SHA1

	# De-duplicate: the same artifact can trip several signatures via different
	# check types, and one line per (severity,id,path) is enough.
	sort -u "$FINDINGS_FILE" -o "$FINDINGS_FILE" 2>/dev/null ||
		{ sort -u "$FINDINGS_FILE" >"$FINDINGS_FILE.tmp" && mv "$FINDINGS_FILE.tmp" "$FINDINGS_FILE"; }

	tally

	if [ "$OUTPUT_MODE" = "json" ]; then
		report_json
	else
		report_text
	fi

	exit "$(exit_code_of)"
}

main "$@"
