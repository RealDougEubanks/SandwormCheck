#!/bin/sh
# BunWormCheck — host-local IOC scanner for npm supply chain compromise.
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
# POSIX sh only: no arrays, no [[ ]], no local, no process substitution.

# zsh does not field-split unquoted parameter expansions, which silently breaks
# several checks and would under-report indicators — a false clean, the worst
# failure mode this tool has. If someone invokes us as `zsh bunwormcheck.sh`,
# re-exec under a real POSIX shell rather than run degraded.
# shellcheck disable=SC2296  # ZSH_VERSION is only read when zsh is the interpreter
if [ -n "${ZSH_VERSION:-}" ]; then
	if [ -x /bin/sh ]; then
		BWC_REEXEC=1 exec /bin/sh "$0" "$@"
	fi
	printf 'bunwormcheck: refusing to run under zsh (no POSIX /bin/sh found)\n' >&2
	exit 1
fi

set -eu

VERSION="1.0.0"
PROGNAME="bunwormcheck"

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
info() { [ "$VERBOSE" -eq 1 ] && printf '%s: %s\n' "$PROGNAME" "$*" >&2 || :; }

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
	# Portable size in bytes; BSD stat and GNU stat differ.
	stat -f '%z' "$1" 2>/dev/null || stat -c '%s' "$1" 2>/dev/null || printf '0'
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
		_lineno=0
		while IFS= read -r line || [ -n "$line" ]; do
			_lineno=$((_lineno + 1))
			# Strip CR so CRLF-edited signature files still parse.
			line=$(printf '%s' "$line" | tr -d '\r')
			case $line in
			'' | '#'*) continue ;;
			esac

			_type=$(printf '%s' "$line" | cut -d'|' -f1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
			_sev=$(printf '%s' "$line" | cut -d'|' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
			_id=$(printf '%s' "$line" | cut -d'|' -f3 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
			_pat=$(printf '%s' "$line" | cut -d'|' -f4 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
			_desc=$(printf '%s' "$line" | cut -d'|' -f5- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

			# A malformed record must be a hard error. Skipping it would
			# silently shrink coverage and could report a clean host.
			case $_type in
			PATHEXISTS | PATHGLOB | FILENAME | SHA256 | SHA1 | PKGVER | CONTENT) ;;
			*) die "$EXIT_ERROR" "$f:$_lineno: unknown check type '$_type'" ;;
			esac
			case $_sev in
			CONFIRMED | SUSPECT) ;;
			*) die "$EXIT_ERROR" "$f:$_lineno: severity must be CONFIRMED or SUSPECT, got '$_sev'" ;;
			esac
			[ -n "$_id" ] || die "$EXIT_ERROR" "$f:$_lineno: empty signature ID"
			[ -n "$_pat" ] || die "$EXIT_ERROR" "$f:$_lineno: empty pattern for $_id"
			[ -n "$_desc" ] || die "$EXIT_ERROR" "$f:$_lineno: empty description for $_id"

			case $_type in
			SHA256)
				validate_hex "$_pat" 64 ||
					die "$EXIT_ERROR" "$f:$_lineno: $_id: SHA256 must be 64 hex characters, got ${#_pat}"
				_pat=$(printf '%s' "$_pat" | tr 'A-F' 'a-f')
				;;
			SHA1)
				validate_hex "$_pat" 40 ||
					die "$EXIT_ERROR" "$f:$_lineno: $_id: SHA1 must be 40 hex characters, got ${#_pat}"
				_pat=$(printf '%s' "$_pat" | tr 'A-F' 'a-f')
				;;
			PKGVER)
				case $_pat in
				*@*) ;;
				*) die "$EXIT_ERROR" "$f:$_lineno: $_id: PKGVER must be name@version" ;;
				esac
				;;
			esac

			printf '%s|%s|%s|%s|%s\n' "$_type" "$_sev" "$_id" "$_pat" "$_desc" >>"$WORKDIR/sigs"
			_total=$((_total + 1))
		done <"$f"
	done
	[ "$_total" -gt 0 ] || die "$EXIT_ERROR" "no valid signature records loaded"
	info "loaded $_total signature records"
}

validate_hex() {
	# validate_hex <string> <expected_length>
	[ "${#1}" -eq "$2" ] || return 1
	case $1 in
	*[!0-9a-fA-F]*) return 1 ;;
	esac
	return 0
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
	find "$_root" -maxdepth "$MAX_DEPTH" \
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
	# Single pass over the candidate file list for FILENAME and PATHGLOB.
	sigs_of_type FILENAME | while IFS='|' read -r _t _sev _id _pat _desc; do
		[ -n "$_id" ] || continue
		awk -v pat="$_pat" -F/ '$NF==pat' "$CANDIDATES_FILE" |
			while IFS= read -r hit; do
				[ -n "$hit" ] || continue
				printf '%s|%s|%s|%s|%s\n' "$_sev" "$_id" "$hit" "filename match" "$_desc" >>"$FINDINGS_FILE"
			done
	done

	sigs_of_type PATHGLOB | while IFS='|' read -r _t _sev _id _pat _desc; do
		[ -n "$_id" ] || continue
		while IFS= read -r hit; do
			[ -n "$hit" ] || continue
			# shellcheck disable=SC2254  # glob match is intentional
			case $hit in
			$_pat)
				printf '%s|%s|%s|%s|%s\n' "$_sev" "$_id" "$hit" "path glob match" "$_desc" >>"$FINDINGS_FILE"
				;;
			esac
		done <"$CANDIDATES_FILE"
	done
}

check_hashes() {
	# check_hashes <lowercase_algo> <uppercase_check_type>
	_algo=$1
	_type=$2
	_sigs=$(sigs_of_type "$_type")
	[ -n "$_sigs" ] || return 0
	if [ "$_algo" = "sha256" ] && [ -z "$HASH_SHA256" ]; then return 0; fi
	if [ "$_algo" = "sha1" ] && [ -z "$HASH_SHA1" ]; then return 0; fi

	while IFS= read -r f; do
		[ -n "$f" ] || continue
		[ -f "$f" ] && [ -r "$f" ] || continue
		_sz=$(file_size "$f")
		[ "$_sz" -le "$MAX_FILE_SIZE" ] || continue
		_d=$(hash_file "$_algo" "$f")
		[ -n "$_d" ] || continue
		printf '%s\n' "$_sigs" | while IFS='|' read -r _t _sev _id _pat _desc; do
			[ -n "$_id" ] || continue
			if [ "$_d" = "$_pat" ]; then
				printf '%s|%s|%s|%s|%s\n' "$_sev" "$_id" "$f" "$_type match" "$_desc" >>"$FINDINGS_FILE"
			fi
		done
	done <"$CANDIDATES_FILE"
}

check_content() {
	_sigs=$(sigs_of_type CONTENT)
	[ -n "$_sigs" ] || return 0
	while IFS= read -r f; do
		[ -n "$f" ] || continue
		[ -f "$f" ] && [ -r "$f" ] || continue
		_sz=$(file_size "$f")
		[ "$_sz" -le "$MAX_FILE_SIZE" ] || continue
		printf '%s\n' "$_sigs" | while IFS='|' read -r _t _sev _id _pat _desc; do
			[ -n "$_id" ] || continue
			# -F: literal substring, no regex dialect surprises.
			# -q: stop at first match. -s: suppress unreadable-file noise.
			if grep -qFs -- "$_pat" "$f" 2>/dev/null; then
				printf '%s|%s|%s|%s|%s\n' "$_sev" "$_id" "$f" "content match" "$_desc" >>"$FINDINGS_FILE"
			fi
		done
	done <"$CANDIDATES_FILE"
}

check_pkgver() {
	_sigs=$(sigs_of_type PKGVER)
	[ -n "$_sigs" ] || return 0
	# Only package.json files directly inside a package directory matter.
	grep -F 'package.json' "$WORKDIR/allfiles" 2>/dev/null |
		while IFS= read -r pj; do
			case $pj in
			*/package.json) ;;
			*) continue ;;
			esac
			[ -r "$pj" ] || continue
			_sz=$(file_size "$pj")
			[ "$_sz" -le "$MAX_FILE_SIZE" ] || continue

			# Extract the top-level "name" and "version" without a JSON parser.
			# Nested deps declare their own name/version inside objects, so take
			# the first occurrence of each, which in npm-generated manifests is
			# the package's own.
			_name=$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pj" 2>/dev/null | head -1)
			_ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$pj" 2>/dev/null | head -1)
			[ -n "$_name" ] && [ -n "$_ver" ] || continue
			_nv="$_name@$_ver"

			printf '%s\n' "$_sigs" | while IFS='|' read -r _t _sev _id _pat _desc; do
				[ -n "$_id" ] || continue
				if [ "$_nv" = "$_pat" ]; then
					printf '%s|%s|%s|%s|%s\n' "$_sev" "$_id" "$pj" "installed $_nv" "$_desc" >>"$FINDINGS_FILE"
				fi
			done
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
	_names=$(sigs_of_type FILENAME | cut -d'|' -f4 | sort -u)
	: >"$WORKDIR/namepat"
	printf '%s\n' "$_names" | while IFS= read -r n; do
		[ -n "$n" ] || continue
		printf '/%s\n' "$n" >>"$WORKDIR/namepat"
	done
	printf '/settings.json\n/tasks.json\n/package.json\n/setup.mjs\n' >>"$WORKDIR/namepat"

	{
		grep -Fs -f "$WORKDIR/namepat" "$WORKDIR/allfiles" 2>/dev/null || :
		grep -Es '/(node_modules|\.claude|\.vscode)/' "$WORKDIR/allfiles" 2>/dev/null || :
	} | sort -u >"$CANDIDATES_FILE"

	info "$(wc -l <"$WORKDIR/allfiles" | tr -d ' ') files walked, $(wc -l <"$CANDIDATES_FILE" | tr -d ' ') candidates"
}

tally() {
	COUNT_CONFIRMED=$(awk -F'|' '$1=="CONFIRMED"' "$FINDINGS_FILE" 2>/dev/null | wc -l | tr -d ' ')
	COUNT_SUSPECT=$(awk -F'|' '$1=="SUSPECT"' "$FINDINGS_FILE" 2>/dev/null | wc -l | tr -d ' ')
	COUNT_SKIPPED=$(wc -l <"$WORKDIR/skipped" 2>/dev/null | tr -d ' ' || printf '0')
	[ -f "$WORKDIR/truncated" ] && TRUNCATED=1 || :
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
		printf '%s\n' "BunWormCheck $VERSION"
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
	printf '"schema":"bunwormcheck/v1",'
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

	WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/bunwormcheck.XXXXXX") ||
		die "$EXIT_ERROR" "cannot create temporary directory"
	FINDINGS_FILE="$WORKDIR/findings"
	CANDIDATES_FILE="$WORKDIR/candidates"
	: >"$FINDINGS_FILE"
	: >"$CANDIDATES_FILE"
	: >"$WORKDIR/skipped"

	probe_hashers
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
