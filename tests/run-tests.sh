#!/bin/sh
# SandwormCheck test suite. POSIX sh, no external test framework.
#
#   ./tests/run-tests.sh              run against /bin/sh
#   SHELLS="sh bash dash zsh" ./tests/run-tests.sh   run against several shells
#
# Exits 0 if every assertion passes, 1 otherwise.

set -u

TESTDIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$TESTDIR")
SCANNER="$ROOT/sandwormcheck.sh"
SIGS="$ROOT/signatures"
FIX="$TESTDIR/fixtures"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/bwc-tests.XXXXXX")

PASS=0
FAIL=0
CURRENT_SHELL="sh"

trap 'rm -rf "$TMP"' EXIT

ok() {
	PASS=$((PASS + 1))
	printf '  ok   %s\n' "$1"
}

no() {
	FAIL=$((FAIL + 1))
	printf '  FAIL %s\n' "$1"
	[ $# -ge 2 ] && printf '       %s\n' "$2"
}

check() {
	# check <status> <label> [detail] — 0 passes, anything else fails.
	# Avoids the `cond && ok ... || no ...` idiom, which reads as if-then-else
	# but is not one.
	if [ "$1" -eq 0 ]; then ok "$2"; else no "$2" "${3:-}"; fi
}

run() {
	# run <expected_exit> <label> [args...]
	_want=$1
	_label=$2
	shift 2
	"$CURRENT_SHELL" "$SCANNER" "$@" >"$TMP/out" 2>"$TMP/err"
	_got=$?
	if [ "$_got" -eq "$_want" ]; then
		ok "$_label (exit $_got)"
	else
		no "$_label" "expected exit $_want, got $_got; stderr: $(head -2 "$TMP/err" | tr '\n' ' ')"
	fi
}

expect_out() {
	# expect_out <substring> <label>
	if grep -qF -- "$1" "$TMP/out"; then
		ok "$2"
	else
		no "$2" "stdout did not contain: $1"
	fi
}

refute_out() {
	if grep -qF -- "$1" "$TMP/out"; then
		no "$2" "stdout unexpectedly contained: $1"
	else
		ok "$2"
	fi
}

expect_err() {
	if grep -qF -- "$1" "$TMP/err"; then
		ok "$2"
	else
		no "$2" "stderr did not contain: $1"
	fi
}

# ===========================================================================
section() { printf '\n== %s ==\n' "$1"; }

test_exit_codes() {
	section "exit codes and verdict tiers [$CURRENT_SHELL]"

	run 0 "clean tree exits 0" --path "$FIX/clean" --signatures "$SIGS" --no-color
	expect_out "VERDICT: CLEAN" "clean tree reports CLEAN"

	run 10 "vulnerable-version-only tree exits 10" --path "$FIX/suspect" --signatures "$SIGS" --no-color
	expect_out "VERDICT: SUSPECT" "suspect tree reports SUSPECT"
	refute_out "CONFIRMED COMPROMISE" "suspect tree does not claim confirmed compromise"

	run 20 "payload-present tree exits 20" --path "$FIX/confirmed" --signatures "$SIGS" --no-color
	expect_out "VERDICT: CONFIRMED COMPROMISE" "confirmed tree reports CONFIRMED"

	# Highest severity wins: the confirmed tree also contains SUSPECT findings.
	expect_out "SUSPECT" "confirmed tree still lists its suspect findings"
}

test_check_types() {
	section "check types: true positives [$CURRENT_SHELL]"

	run 20 "scan confirmed tree" --path "$FIX/confirmed" --signatures "$SIGS" --no-color
	expect_out "SH25-F001" "FILENAME detects Math_Symbol.js"
	expect_out "SH25-R001" "PATHGLOB detects .claude/setup.mjs"
	expect_out "SH25-R002" "PATHGLOB detects .vscode/setup.mjs"
	expect_out "SH25-M001" "CONTENT detects the Shai-Hulud exfil marker"
	expect_out "SH25-N001" "CONTENT detects the npm-cache.com C2 domain"
	# Assert on the name@version in the detail text, not the signature ID: IDs in
	# the generated package file are hash-derived and would churn on regeneration.
	expect_out "installed keyv@6.0.0" "PKGVER detects keyv@6.0.0"

	run 10 "scan suspect tree" --path "$FIX/suspect" --signatures "$SIGS" --no-color
	expect_out "installed flat-cache@6.1.24" "PKGVER detects flat-cache@6.1.24"

	# Hash checks use a generated signature file so no real malware is needed.
	_hashfix="$TMP/hashfix/proj/node_modules/pkg"
	mkdir -p "$_hashfix"
	printf 'inert sandwormcheck hash fixture\n' >"$_hashfix/Math_Symbol.js"
	_s256=$(hash_of 256 "$_hashfix/Math_Symbol.js")
	_s1=$(hash_of 1 "$_hashfix/Math_Symbol.js")
	if [ -n "$_s256" ] && [ -n "$_s1" ]; then
		# A FILENAME record is what brings the file into the hash candidate set.
		# Hashing is narrowed by basename because hashing a whole dependency tree
		# reads gigabytes per host; see docs/spec.md section 6.
		cat >"$TMP/hash.conf" <<EOF
#!campaign  hash self-test
#!version   test
FILENAME|SUSPECT|TEST-F001|Math_Symbol.js|Inert filename fixture
SHA256|CONFIRMED|TEST-H001|$_s256|Inert SHA-256 fixture
SHA1|CONFIRMED|TEST-H002|$_s1|Inert SHA-1 fixture
EOF
		run 20 "SHA256/SHA1 match exits 20" --path "$TMP/hashfix" --signatures "$TMP/hash.conf" --no-color
		expect_out "TEST-H001" "SHA256 check matches a known digest"
		expect_out "TEST-H002" "SHA1 check matches a known digest"

		# The coverage gap must be reported, not pass silently: hash records whose
		# basename nothing names would otherwise find nothing and look clean.
		cat >"$TMP/hash-nofn.conf" <<EOF
#!campaign  hash gap self-test
SHA256|CONFIRMED|TEST-H003|$_s256|Hash with no FILENAME record
EOF
		run 0 "hash record with no covering FILENAME finds nothing" \
			--path "$TMP/hashfix" --signatures "$TMP/hash-nofn.conf" --no-color
		expect_err "hash signatures are loaded but no file matched" \
			"missing hash coverage is warned about, not silent"
	else
		printf '  skip hash checks (no hashing tool available)\n'
	fi

	# PATHEXISTS against an isolated fake home.
	mkdir -p "$TMP/fakehome/.config/gh-token-monitor"
	printf 'inert\n' >"$TMP/fakehome/.config/gh-token-monitor/token"
	HOME="$TMP/fakehome" "$CURRENT_SHELL" "$SCANNER" \
		--path "$TMP/fakehome" --signatures "$SIGS" --no-color >"$TMP/out" 2>"$TMP/err"
	_got=$?
	if [ "$_got" -eq 20 ]; then
		ok "PATHEXISTS persistence artifact exits 20"
	else
		no "PATHEXISTS persistence artifact exits 20" "got exit $_got"
	fi
	expect_out "SH25-P00" "PATHEXISTS detects gh-token-monitor under \$HOME"
}

test_true_negatives() {
	section "check types: true negatives [$CURRENT_SHELL]"

	run 0 "clean tree" --path "$FIX/clean" --signatures "$SIGS" --no-color
	refute_out "installed keyv@6.0.0" "keyv@5.5.1 does not match the keyv@6.0.0 signature"
	refute_out "SH25-F001" "no payload filename reported in a clean tree"
	refute_out "SH25-R001" "a legitimate .vscode/tasks.json is not flagged"
	refute_out "SH25-N001" "no C2 domain reported in a clean tree"

	# A legitimately-named setup.mjs outside .claude/.vscode must not be a
	# CONFIRMED path-glob hit. This is the false-positive case that made
	# PATHGLOB necessary in the first place.
	# Regression from a real-world scan: a legitimate package that ships
	# dist/.../setup.mjs, plus its source map and a package.json referencing the
	# name, must stay clean. A bare CONTENT match on "setup.mjs" produced 28 false
	# positives on one developer machine before it was removed.
	run 0 "a package legitimately shipping setup.mjs is not flagged" \
		--path "$FIX/legit-setup" --signatures "$SIGS" --no-color
	refute_out "setup.mjs" "no finding mentions a legitimate setup.mjs"

	mkdir -p "$TMP/fp/proj/scripts"
	printf 'export default {};\n' >"$TMP/fp/proj/scripts/setup.mjs"
	printf '{"name":"legit","version":"1.0.0"}\n' >"$TMP/fp/proj/package.json"
	run 0 "legitimate scripts/setup.mjs is not flagged" --path "$TMP/fp" --signatures "$SIGS" --no-color
}

test_lockfiles() {
	section "lockfile pins [$CURRENT_SHELL]"

	LFX="$FIX/lockfile"

	run 10 "npm lockfileVersion 3 pin exits 10" --path "$LFX/npm3" --signatures "$SIGS" --no-color
	expect_out "pinned keyv@6.0.0 in package-lock.json" "npm v3: unscoped pin detected via resolved URL"
	expect_out "pinned @keyv/redis@6.0.0 in package-lock.json" "npm v3: scoped pin detected via resolved URL"

	run 10 "npm lockfileVersion 1 pin exits 10" --path "$LFX/npm1" --signatures "$SIGS" --no-color
	expect_out "pinned flat-cache@6.1.24 in package-lock.json" "npm v1: pin detected"

	run 10 "yarn.lock v1 pin exits 10" --path "$LFX/yarn1" --signatures "$SIGS" --no-color
	expect_out "pinned cacheable@2.5.1 in yarn.lock" "yarn v1: unscoped pin detected"
	expect_out "pinned @cacheable/utils@2.5.1 in yarn.lock" "yarn v1: scoped pin detected"

	run 10 "pnpm-lock.yaml v9 pin exits 10" --path "$LFX/pnpm9" --signatures "$SIGS" --no-color
	expect_out "pinned cache-manager@7.2.10 in pnpm-lock.yaml" "pnpm v9: unquoted key detected"
	# pnpm quotes scoped keys, so the colon is not adjacent to the version.
	expect_out "pinned @cacheable/memory@2.2.1 in pnpm-lock.yaml" "pnpm v9: quoted scoped key detected"

	# A lockfile listing only safe versions must stay clean. This fixture also
	# holds cacheable-request@2.5.1 and @cacheable/utils@9.9.9 as prefix and
	# scope traps.
	run 0 "lockfile with only safe versions exits 0" --path "$LFX/clean-lock" --signatures "$SIGS" --no-color
	refute_out "pinned" "no pin reported for safe versions"
	refute_out "cacheable@2.5.1" "cacheable-request@2.5.1 does not match cacheable@2.5.1"

	# The false positive the confirm regex exists to prevent: a scoped package
	# whose basename and version match an unscoped signature. Its resolved URL
	# contains the unscoped signature's tarball path as a literal substring.
	run 0 "scoped package sharing an unscoped basename exits 0" \
		--path "$LFX/fp-basename" --signatures "$SIGS" --no-color
	refute_out "pinned" "basename collision does not produce a false pin"

	# Lockfile detection must not depend on the package being installed: these
	# fixtures contain no node_modules at all.
	if [ -d "$LFX/npm3/node_modules" ]; then
		no "lockfile fixtures have no node_modules" "npm3 fixture unexpectedly has node_modules"
	else
		ok "lockfile fixtures detect pins with nothing installed"
	fi

	# A lockfile nested inside node_modules is a dependency's own dev lockfile.
	# npm, yarn, and pnpm ignore those when resolving, so reporting one would be a
	# misleading finding about the scanned project.
	run 0 "nested node_modules/*/yarn.lock is ignored" \
		--path "$LFX/nested" --signatures "$SIGS" --no-color
	refute_out "pinned" "a dependency's own lockfile is not reported as a pin"

	# npm-shrinkwrap.json is the exception: npm honors a shipped one, so a nested
	# shrinkwrap does affect what gets installed and must still be read.
	run 10 "nested npm-shrinkwrap.json is still read" \
		--path "$LFX/shrinkwrap" --signatures "$SIGS" --no-color
	expect_out "pinned cache-manager@7.2.10 in npm-shrinkwrap.json" \
		"nested shrinkwrap pin is detected"

	# An oversized lockfile is skipped rather than parsed. Padded past the 1024
	# byte floor that --max-file-size accepts, since the committed fixture is
	# smaller than that.
	mkdir -p "$TMP/biglock/proj"
	{
		printf '{"lockfileVersion":3,"packages":{"node_modules/keyv":{"version":"6.0.0",'
		printf '"resolved":"https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz","integrity":"sha512-'
		i=0
		while [ "$i" -lt 40 ]; do printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; i=$((i + 1)); done
		printf '=="}}}\n'
	} >"$TMP/biglock/proj/package-lock.json"

	run 10 "oversized lockfile is detected when under the cap" \
		--path "$TMP/biglock" --signatures "$SIGS" --max-file-size 8388608 --no-color
	expect_out "pinned keyv@6.0.0" "padded lockfile still parses normally"

	run 0 "lockfile above --max-file-size is skipped" \
		--path "$TMP/biglock" --signatures "$SIGS" --max-file-size 1024 --no-color
	refute_out "pinned" "oversized lockfile produces no pin"
}

test_process_check() {
	section "PROCESS check: live implant with no files on disk [$CURRENT_SHELL]"

	mkdir -p "$TMP/procempty" "$TMP/procbin"
	printf '#!/bin/sh\nsleep 20\n' >"$TMP/procbin/gh-token-monitor.sh"
	printf '#!/bin/sh\nsleep 20\n' >"$TMP/procbin/bun"
	chmod +x "$TMP/procbin/gh-token-monitor.sh" "$TMP/procbin/bun"

	# The scan root is empty, so only the process table can produce a finding.
	# This is the false-clean case the check exists for: the dead-man's switch
	# polls every 60s and can outlive its own files.
	"$TMP/procbin/gh-token-monitor.sh" &
	_w1=$!
	"$TMP/procbin/bun" run /tmp/nowhere/Math_Symbol.js &
	_w2=$!
	sleep 1

	run 20 "a running watcher is found with nothing on disk" \
		--path "$TMP/procempty" --signatures "$SIGS" --no-color
	expect_out "SH25-X001" "PROCESS detects the gh-token-monitor watcher"
	expect_out "SH25-X002" "PROCESS detects the payload past argv[1] (bun run ...)"
	# Command lines can carry credentials as arguments, and findings reach fleet
	# console logs, so only the PID may be reported.
	refute_out "gh-token-monitor.sh" "the finding names the PID, not the command line"
	refute_out "$TMP/procbin" "no command-line path is echoed"

	kill "$_w1" "$_w2" 2>/dev/null || :
	sleep 1
	run 0 "after the processes exit, the same scan is clean" \
		--path "$TMP/procempty" --signatures "$SIGS" --no-color

	# An incident responder searching for these artifacts must not implicate
	# themselves. An earlier revision reported the operator's own grep as a
	# CONFIRMED compromise.
	grep -r "Math_Symbol.js gh-token-monitor math_init.js" "$TMP/procempty" >/dev/null 2>&1 &
	_g=$!
	sleep 1
	run 0 "an operator grepping for the artifacts is not flagged" \
		--path "$TMP/procempty" --signatures "$SIGS" --no-color
	refute_out "SH25-X" "no PROCESS finding from a search tool"
	wait "$_g" 2>/dev/null || :
}

test_signature_validation() {
	section "signature validation [$CURRENT_SHELL]"

	printf '#!campaign t\nBOGUSTYPE|CONFIRMED|X-1|foo|desc\n' >"$TMP/bad-type.conf"
	run 1 "unknown check type is a hard error" --path "$FIX/clean" --signatures "$TMP/bad-type.conf"
	expect_err "unknown check type" "error names the bad check type"
	expect_err "bad-type.conf:2" "error names file and line number"

	printf '#!campaign t\nFILENAME|MAYBE|X-1|foo|desc\n' >"$TMP/bad-sev.conf"
	run 1 "invalid severity is a hard error" --path "$FIX/clean" --signatures "$TMP/bad-sev.conf"
	expect_err "severity must be CONFIRMED or SUSPECT" "error explains valid severities"

	printf '#!campaign t\nSHA256|CONFIRMED|X-1|deadbeef|desc\n' >"$TMP/bad-hash.conf"
	run 1 "short SHA256 is a hard error" --path "$FIX/clean" --signatures "$TMP/bad-hash.conf"
	expect_err "64 hex characters" "error explains the expected digest length"

	printf '#!campaign t\nSHA1|CONFIRMED|X-1|zzzz567890123456789012345678901234567890|desc\n' >"$TMP/nonhex.conf"
	run 1 "non-hex SHA1 is a hard error" --path "$FIX/clean" --signatures "$TMP/nonhex.conf"

	printf '#!campaign t\nPKGVER|SUSPECT|X-1|noversion|desc\n' >"$TMP/bad-pkg.conf"
	run 1 "PKGVER without @version is a hard error" --path "$FIX/clean" --signatures "$TMP/bad-pkg.conf"
	expect_err "PKGVER must be name@version" "error explains the PKGVER format"

	printf '#!campaign t\nFILENAME|CONFIRMED||foo|desc\n' >"$TMP/no-id.conf"
	run 1 "empty signature ID is a hard error" --path "$FIX/clean" --signatures "$TMP/no-id.conf"

	printf '#!campaign t\nFILENAME|CONFIRMED|X-1|foo|\n' >"$TMP/no-desc.conf"
	run 1 "empty description is a hard error" --path "$FIX/clean" --signatures "$TMP/no-desc.conf"

	printf '# only comments here\n' >"$TMP/empty.conf"
	run 1 "signature file with no records is a hard error" --path "$FIX/clean" --signatures "$TMP/empty.conf"

	run 1 "nonexistent signature path is an error" --path "$FIX/clean" --signatures "$TMP/does-not-exist.conf"

	mkdir -p "$TMP/emptydir"
	run 1 "signature directory with no .conf files is an error" --path "$FIX/clean" --signatures "$TMP/emptydir"

	# CRLF-edited signature files must still parse (Windows contributors).
	printf '#!campaign t\r\nFILENAME|CONFIRMED|CRLF-1|Math_Symbol.js|crlf desc\r\n' >"$TMP/crlf.conf"
	run 20 "CRLF signature file parses" --path "$FIX/confirmed" --signatures "$TMP/crlf.conf" --no-color
	expect_out "CRLF-1" "CRLF record produced a finding"
}

test_argument_validation() {
	section "argument validation [$CURRENT_SHELL]"

	run 2 "unknown flag is a usage error" --bogus-flag
	expect_err "unknown option" "error mentions the unknown option"

	run 2 "positional argument is a usage error" /some/path
	run 2 "--path with a nonexistent directory is a usage error" --path "$TMP/nope"
	run 2 "--max-depth with a non-integer is a usage error" --max-depth abc --path "$FIX/clean"
	run 2 "--max-depth of 0 is out of range" --max-depth 0 --path "$FIX/clean"
	run 2 "--max-depth of 65 is out of range" --max-depth 65 --path "$FIX/clean"
	run 2 "--timeout below the floor is out of range" --timeout 5 --path "$FIX/clean"
	run 2 "--max-file-size below the floor is out of range" --max-file-size 10 --path "$FIX/clean"
	run 2 "--signatures without an argument is a usage error" --signatures
	run 2 "--path without an argument is a usage error" --path

	run 0 "--help exits 0" --help
	expect_out "Usage:" "--help prints usage"
	run 0 "--version exits 0" --version
	expect_out "sandwormcheck" "--version prints the program name"

	# Bounds at their documented limits must be accepted.
	run 0 "--max-depth 1 is accepted" --max-depth 1 --path "$FIX/clean" --signatures "$SIGS"
	run 0 "--max-depth 64 is accepted" --max-depth 64 --path "$FIX/clean" --signatures "$SIGS"
	run 0 "leading-zero integer is accepted" --max-depth 007 --path "$FIX/clean" --signatures "$SIGS"
}

test_output_modes() {
	section "output modes [$CURRENT_SHELL]"

	"$CURRENT_SHELL" "$SCANNER" --path "$FIX/confirmed" --signatures "$SIGS" --json >"$TMP/out" 2>"$TMP/err"
	_code=$?
	if [ "$_code" -eq 20 ]; then
		ok "--json preserves the exit code"
	else
		no "--json preserves the exit code" "got $_code"
	fi

	if command -v python3 >/dev/null 2>&1; then
		if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$TMP/out" 2>/dev/null; then
			ok "--json emits parseable JSON"
		else
			no "--json emits parseable JSON" "$(head -c 200 "$TMP/out")"
		fi
		_v=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$TMP/out" 2>/dev/null)
		if [ "$_v" = "CONFIRMED" ]; then
			ok "JSON verdict field is CONFIRMED"
		else
			no "JSON verdict field is CONFIRMED" "got '$_v'"
		fi
		_n=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["findings"]))' "$TMP/out" 2>/dev/null)
		if [ "${_n:-0}" -gt 0 ]; then
			ok "JSON findings array is populated"
		else
			no "JSON findings array is populated" "got '${_n:-}'"
		fi
		_e=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["exit_code"])' "$TMP/out" 2>/dev/null)
		if [ "$_e" = "20" ]; then
			ok "JSON exit_code matches the process exit code"
		else
			no "JSON exit_code matches the process exit code" "got '$_e'"
		fi
	else
		printf '  skip JSON parse assertions (no python3)\n'
	fi

	# A clean scan must still emit valid JSON with an empty findings array.
	"$CURRENT_SHELL" "$SCANNER" --path "$FIX/clean" --signatures "$SIGS" --json >"$TMP/out" 2>/dev/null
	if command -v python3 >/dev/null 2>&1; then
		python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["findings"]==[]; assert d["verdict"]=="CLEAN"' \
			"$TMP/out" 2>/dev/null
		check $? "clean scan emits valid JSON with no findings"
	fi

	run 20 "--quiet preserves the exit code" --path "$FIX/confirmed" --signatures "$SIGS" --quiet --no-color
	expect_out "VERDICT:" "--quiet still prints the verdict"
	refute_out "SH25-F001" "--quiet suppresses per-finding output"

	# Diagnostics must not pollute stdout, which downstream tooling parses.
	"$CURRENT_SHELL" "$SCANNER" --path "$FIX/clean" --signatures "$SIGS" --verbose --json >"$TMP/out" 2>"$TMP/err"
	if command -v python3 >/dev/null 2>&1; then
		python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$TMP/out" 2>/dev/null
		check $? "--verbose keeps stdout clean JSON"
	fi
	if [ -s "$TMP/err" ]; then
		ok "--verbose writes progress to stderr"
	else
		no "--verbose writes progress to stderr" "stderr was empty"
	fi
}

test_multi_campaign() {
	section "multi-campaign signature directory [$CURRENT_SHELL]"

	mkdir -p "$TMP/multi"
	cp "$SIGS"/*.conf "$TMP/multi/" 2>/dev/null || :
	cat >"$TMP/multi/future-campaign.conf" <<'EOF'
#!campaign  Hypothetical future npm campaign
#!version   test.1
FILENAME|CONFIRMED|FUT-001|totally_new_payload.js|A future payload
EOF
	mkdir -p "$TMP/multifix/proj/node_modules/x"
	printf 'inert\n' >"$TMP/multifix/proj/node_modules/x/totally_new_payload.js"
	printf '{"name":"x","version":"1.0.0"}\n' >"$TMP/multifix/proj/node_modules/x/package.json"

	run 20 "a new campaign file is picked up with no code change" \
		--path "$TMP/multifix" --signatures "$TMP/multi" --no-color
	expect_out "FUT-001" "the new campaign's signature fires"
	expect_out "Hypothetical future npm campaign" "both campaigns are listed in the report"
	expect_out "Shai-Hulud" "the original campaign is still listed"
}

test_gnu_stat_compat() {
	section "GNU stat compatibility"

	# The scanner once chained `stat -f '%z' || stat -c '%s'` for file sizes, which
	# is correct on BSD and silently wrong on GNU, where -f means --file-system.
	# The result was a multi-line string, an errored numeric comparison, and
	# --max-file-size not being enforced on any Linux host. macOS-only testing
	# missed it; CI on Linux caught it. This replays the GNU path from any host.
	_shim="$TESTDIR/shims/gnu-stat"
	if [ ! -x "$_shim/stat" ]; then
		printf '  skip (GNU stat shim not present)\n'
		return 0
	fi
	if [ "$(uname -s)" = "Linux" ]; then
		printf '  skip (on Linux the native GNU path is already covered)\n'
		return 0
	fi

	mkdir -p "$TMP/gnulock/proj"
	{
		printf '{"lockfileVersion":3,"packages":{"node_modules/keyv":{"version":"6.0.0",'
		printf '"resolved":"https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz","integrity":"sha512-'
		_i=0
		while [ "$_i" -lt 40 ]; do
			printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
			_i=$((_i + 1))
		done
		printf '=="}}}\n'
	} >"$TMP/gnulock/proj/package-lock.json"

	PATH="$_shim:$PATH" "$CURRENT_SHELL" "$SCANNER" --path "$TMP/gnulock" \
		--signatures "$SIGS" --max-file-size 1024 --quiet --no-color >"$TMP/out" 2>"$TMP/err"
	_got=$?
	if [ "$_got" -eq 0 ]; then
		ok "GNU stat: oversized lockfile skipped, --max-file-size honoured"
	else
		no "GNU stat: oversized lockfile skipped" "expected exit 0, got $_got"
	fi

	PATH="$_shim:$PATH" "$CURRENT_SHELL" "$SCANNER" --path "$TMP/gnulock" \
		--signatures "$SIGS" --quiet --no-color >"$TMP/out" 2>"$TMP/err"
	_got=$?
	if [ "$_got" -eq 10 ]; then
		ok "GNU stat: the same lockfile is read when under the cap"
	else
		no "GNU stat: the same lockfile is read when under the cap" "expected exit 10, got $_got"
	fi

	# A silently empty candidate list would make content and hash checks do nothing
	# while the scan still reported a verdict.
	PATH="$_shim:$PATH" "$CURRENT_SHELL" "$SCANNER" --path "$FIX/confirmed" \
		--signatures "$SIGS" --verbose --quiet --no-color >"$TMP/out" 2>"$TMP/err"
	_counts=$(grep -oE '[0-9]+ content, [0-9]+ hash' "$TMP/err" | tail -1)
	case ${_counts:-} in
	"0 content, 0 hash" | "")
		no "GNU stat: candidate lists are populated" "got '${_counts:-<none>}'"
		;;
	*) ok "GNU stat: candidate lists are populated ($_counts)" ;;
	esac
}

test_no_network() {
	section "no network egress [$CURRENT_SHELL]"

	# The scanner must never reach the network: docs/spec.md §7. Grep the
	# sources for network primitives rather than trusting review.
	_hits=$(grep -nE '(^|[^[:alnum:]_./-])(curl|wget|nc|ncat|telnet|ftp|ssh|scp|rsync|openssl[[:space:]]+s_client)([^[:alnum:]_-]|$)' \
		"$SCANNER" 2>/dev/null | grep -v '^[0-9]*:#' || :)
	if [ -z "$_hits" ]; then
		ok "sh scanner contains no network client invocations"
	else
		no "sh scanner contains no network client invocations" "$_hits"
	fi

	_ps="$ROOT/SandwormCheck.ps1"
	if [ -f "$_ps" ]; then
		_hits=$(grep -niE '(Invoke-WebRequest|Invoke-RestMethod|System\.Net\.WebClient|DownloadString|DownloadFile|Net\.Sockets|Test-Connection|New-Object[[:space:]]+Net)' \
			"$_ps" 2>/dev/null | grep -v ':[[:space:]]*#' || :)
		if [ -z "$_hits" ]; then
			ok "PowerShell scanner contains no network client invocations"
		else
			no "PowerShell scanner contains no network client invocations" "$_hits"
		fi
	fi
}

test_readonly() {
	section "read-only behavior [$CURRENT_SHELL]"

	# A scan must not alter the tree it inspects.
	_before=$(find "$FIX/confirmed" -type f -exec ls -ld {} \; 2>/dev/null | sort)
	"$CURRENT_SHELL" "$SCANNER" --path "$FIX/confirmed" --signatures "$SIGS" >/dev/null 2>&1 || :
	_after=$(find "$FIX/confirmed" -type f -exec ls -ld {} \; 2>/dev/null | sort)
	if [ "$_before" = "$_after" ]; then
		ok "scanning does not modify the scanned tree"
	else
		no "scanning does not modify the scanned tree" "file metadata changed"
	fi

	# No temp directory should survive the run, on a clean exit or an error exit.
	# Use an isolated TMPDIR so a leak from an earlier shell's section cannot be
	# misattributed to this one.
	mkdir -p "$TMP/tmpdir-clean" "$TMP/tmpdir-err"
	TMPDIR="$TMP/tmpdir-clean" "$CURRENT_SHELL" "$SCANNER" \
		--path "$FIX/confirmed" --signatures "$SIGS" >/dev/null 2>&1 || :
	_leaked=$(find "$TMP/tmpdir-clean" -maxdepth 1 -name 'sandwormcheck.*' 2>/dev/null | wc -l | tr -d ' ')
	if [ "$_leaked" -eq 0 ]; then
		ok "no temporary directory is leaked on a normal exit"
	else
		no "no temporary directory is leaked on a normal exit" "$_leaked left behind"
	fi

	printf '#!campaign t\nBOGUS|CONFIRMED|X-1|foo|desc\n' >"$TMP/leak-bad.conf"
	TMPDIR="$TMP/tmpdir-err" "$CURRENT_SHELL" "$SCANNER" \
		--path "$FIX/clean" --signatures "$TMP/leak-bad.conf" >/dev/null 2>&1 || :
	_leaked=$(find "$TMP/tmpdir-err" -maxdepth 1 -name 'sandwormcheck.*' 2>/dev/null | wc -l | tr -d ' ')
	if [ "$_leaked" -eq 0 ]; then
		ok "no temporary directory is leaked on an error exit"
	else
		no "no temporary directory is leaked on an error exit" "$_leaked left behind"
	fi
}

test_no_secret_disclosure() {
	section "no secret disclosure [$CURRENT_SHELL]"

	# Findings report paths and signature IDs, never file contents. Printing a
	# matched secret into a fleet command log would relocate the secret.
	mkdir -p "$TMP/secret/proj/node_modules/pkg" "$TMP/secret/.config/gh-token-monitor"
	printf 'ghp_THISISAFAKETOKENVALUE000000000000\n' >"$TMP/secret/.config/gh-token-monitor/token"
	printf 'npm-cache.com ghp_THISISAFAKETOKENVALUE000000000000\n' \
		>"$TMP/secret/proj/node_modules/pkg/Math_Symbol.js"
	printf '{"name":"pkg","version":"1.0.0"}\n' >"$TMP/secret/proj/node_modules/pkg/package.json"

	HOME="$TMP/secret" "$CURRENT_SHELL" "$SCANNER" --path "$TMP/secret" \
		--signatures "$SIGS" --no-color >"$TMP/out" 2>"$TMP/err"
	refute_out "ghp_THISISAFAKETOKENVALUE" "text report does not echo matched file contents"

	HOME="$TMP/secret" "$CURRENT_SHELL" "$SCANNER" --path "$TMP/secret" \
		--signatures "$SIGS" --json >"$TMP/out" 2>"$TMP/err"
	refute_out "ghp_THISISAFAKETOKENVALUE" "JSON report does not echo matched file contents"
}

test_robustness() {
	section "robustness [$CURRENT_SHELL]"

	# Paths with spaces, quotes, and UTF-8 must not break the pipeline.
	mkdir -p "$TMP/odd/my project (v2)/node_modules/keyv"
	printf '{"name":"keyv","version":"6.0.0"}\n' \
		>"$TMP/odd/my project (v2)/node_modules/keyv/package.json"
	printf 'inert\n' >"$TMP/odd/my project (v2)/node_modules/keyv/Math_Symbol.js"
	run 20 "paths containing spaces and parentheses are handled" \
		--path "$TMP/odd" --signatures "$SIGS" --no-color
	expect_out "my project (v2)" "the odd path appears in the finding"

	# An unreadable root must be reported, not silently treated as clean.
	if [ "$(id -u)" -ne 0 ]; then
		mkdir -p "$TMP/denied/inner"
		printf 'inert\n' >"$TMP/denied/inner/Math_Symbol.js"
		chmod 000 "$TMP/denied"
		"$CURRENT_SHELL" "$SCANNER" --path "$TMP/denied" --signatures "$SIGS" --no-color \
			>"$TMP/out" 2>"$TMP/err" || :
		expect_out "unreadable" "an unreadable scan root is reported as incomplete coverage"
		chmod 755 "$TMP/denied" 2>/dev/null || :
	else
		printf '  skip unreadable-root test (running as root)\n'
	fi

	# A binary file among the candidates must not crash the content check.
	mkdir -p "$TMP/bin/proj/node_modules/pkg"
	printf '{"name":"pkg","version":"1.0.0"}\n' >"$TMP/bin/proj/node_modules/pkg/package.json"
	dd if=/dev/urandom of="$TMP/bin/proj/node_modules/pkg/blob.bin" bs=1024 count=64 2>/dev/null
	printf 'inert\n' >"$TMP/bin/proj/node_modules/pkg/Math_Symbol.js"
	run 20 "binary candidate files do not break the content check" \
		--path "$TMP/bin" --signatures "$SIGS" --no-color

	# --max-file-size must actually exclude oversized files from hash checks.
	if [ -n "$(hash_of 256 "$TMP/bin/proj/node_modules/pkg/Math_Symbol.js")" ]; then
		mkdir -p "$TMP/big/proj/node_modules/pkg"
		printf '{"name":"pkg","version":"1.0.0"}\n' >"$TMP/big/proj/node_modules/pkg/package.json"
		dd if=/dev/zero of="$TMP/big/proj/node_modules/pkg/Math_Symbol.js" bs=1024 count=200 2>/dev/null
		_h=$(hash_of 256 "$TMP/big/proj/node_modules/pkg/Math_Symbol.js")
		cat >"$TMP/big.conf" <<EOF
#!campaign  size-bound test
FILENAME|SUSPECT|SIZE-F01|Math_Symbol.js|Brings the file into the hash candidate set
SHA256|CONFIRMED|SIZE-001|$_h|Oversized fixture
EOF
		# Exit 10, not 0: the FILENAME record still matches at SUSPECT. What must
		# not appear is the CONFIRMED hash finding.
		run 10 "files above --max-file-size are excluded from hash checks" \
			--path "$TMP/big" --signatures "$TMP/big.conf" --max-file-size 2048 --no-color
		refute_out "SIZE-001" "oversized file produces no hash finding"
		run 20 "the same file matches when the size cap allows it" \
			--path "$TMP/big" --signatures "$TMP/big.conf" --max-file-size 1048576 --no-color
	fi
}

test_powershell_parity() {
	section "PowerShell port parity"

	_ps="$ROOT/SandwormCheck.ps1"
	if [ ! -f "$_ps" ]; then
		printf '  skip (SandwormCheck.ps1 not present)\n'
		return 0
	fi
	if ! command -v pwsh >/dev/null 2>&1; then
		printf '  skip (pwsh not installed; run on Windows or install PowerShell 7)\n'
		return 0
	fi

	pscan() {
		# pscan <expected_exit> <label> [args...]
		_want=$1
		_label=$2
		shift 2
		pwsh -NoProfile -File "$_ps" "$@" >"$TMP/out" 2>"$TMP/err"
		_got=$?
		if [ "$_got" -eq "$_want" ]; then
			ok "$_label (exit $_got)"
		else
			no "$_label" "expected exit $_want, got $_got; stderr: $(head -2 "$TMP/err" | tr '\n' ' ')"
		fi
	}

	pscan 0 "ps1: clean tree exits 0" -Path "$FIX/clean" -SignaturePath "$SIGS" -NoColor
	expect_out "VERDICT: CLEAN" "ps1: clean tree reports CLEAN"

	pscan 10 "ps1: suspect tree exits 10" -Path "$FIX/suspect" -SignaturePath "$SIGS" -NoColor
	expect_out "VERDICT: SUSPECT" "ps1: suspect tree reports SUSPECT"

	pscan 20 "ps1: confirmed tree exits 20" -Path "$FIX/confirmed" -SignaturePath "$SIGS" -NoColor
	expect_out "VERDICT: CONFIRMED COMPROMISE" "ps1: confirmed tree reports CONFIRMED"

	# The two engines must agree on which signatures fire, not merely on the
	# verdict. Compare the sorted set of finding IDs from each.
	for tree in clean suspect confirmed; do
		sh "$SCANNER" --path "$FIX/$tree" --signatures "$SIGS" --no-color >"$TMP/sh.out" 2>/dev/null || :
		pwsh -NoProfile -File "$_ps" -Path "$FIX/$tree" -SignaturePath "$SIGS" -NoColor >"$TMP/ps.out" 2>/dev/null || :
		grep -oE 'SH25-[A-Z][0-9]+' "$TMP/sh.out" 2>/dev/null | sort -u >"$TMP/sh.ids" || :
		grep -oE 'SH25-[A-Z][0-9]+' "$TMP/ps.out" 2>/dev/null | sort -u >"$TMP/ps.ids" || :
		if cmp -s "$TMP/sh.ids" "$TMP/ps.ids"; then
			ok "ps1: identical signature IDs fire on the $tree tree"
		else
			no "ps1: identical signature IDs fire on the $tree tree" \
				"sh=[$(tr '\n' ' ' <"$TMP/sh.ids")] ps=[$(tr '\n' ' ' <"$TMP/ps.ids")]"
		fi
	done

	pscan 20 "ps1: -Json preserves the exit code" -Path "$FIX/confirmed" -SignaturePath "$SIGS" -Json
	if command -v python3 >/dev/null 2>&1; then
		python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["verdict"]=="CONFIRMED"; assert d["exit_code"]==20; assert d["schema"]=="sandwormcheck/v1"' \
			"$TMP/out" 2>/dev/null
		check $? "ps1: -Json emits the v1 schema with a matching verdict" "$(head -c 200 "$TMP/out")"
	fi

	pscan 20 "ps1: -Quiet preserves the exit code" -Path "$FIX/confirmed" -SignaturePath "$SIGS" -Quiet -NoColor
	refute_out "SH25-F001" "ps1: -Quiet suppresses per-finding output"

	# Error and usage codes must match the sh scanner exactly.
	printf '#!campaign t\nBOGUS|CONFIRMED|X-1|foo|desc\n' >"$TMP/ps-bad.conf"
	pscan 1 "ps1: unknown check type exits 1" -Path "$FIX/clean" -SignaturePath "$TMP/ps-bad.conf"
	expect_err "unknown check type" "ps1: error names the bad check type"

	printf '#!campaign t\nSHA256|CONFIRMED|X-1|deadbeef|desc\n' >"$TMP/ps-hash.conf"
	pscan 1 "ps1: short SHA256 exits 1" -Path "$FIX/clean" -SignaturePath "$TMP/ps-hash.conf"

	pscan 1 "ps1: nonexistent signature path exits 1" -Path "$FIX/clean" -SignaturePath "$TMP/nope.conf"
	pscan 2 "ps1: nonexistent -Path exits 2" -Path "$TMP/nope-dir" -SignaturePath "$SIGS"
	pscan 2 "ps1: -MaxDepth 0 exits 2" -Path "$FIX/clean" -SignaturePath "$SIGS" -MaxDepth 0
	pscan 2 "ps1: -MaxDepth 65 exits 2" -Path "$FIX/clean" -SignaturePath "$SIGS" -MaxDepth 65
	pscan 2 "ps1: -TimeoutSeconds below the floor exits 2" -Path "$FIX/clean" -SignaturePath "$SIGS" -TimeoutSeconds 5
	pscan 2 "ps1: -MaxFileSize below the floor exits 2" -Path "$FIX/clean" -SignaturePath "$SIGS" -MaxFileSize 10

	# Lockfile pins must agree exactly between the two engines, including the
	# false-positive fixtures.
	for tree in npm3 npm1 yarn1 pnpm9 clean-lock fp-basename nested shrinkwrap; do
		sh "$SCANNER" --path "$FIX/lockfile/$tree" --signatures "$SIGS" --no-color >"$TMP/sh.out" 2>/dev/null || :
		pwsh -NoProfile -File "$_ps" -Path "$FIX/lockfile/$tree" -SignaturePath "$SIGS" -NoColor >"$TMP/ps.out" 2>/dev/null || :
		grep -oE 'pinned [^ ]+ in [^)]*' "$TMP/sh.out" 2>/dev/null | sort -u >"$TMP/sh.pins" || :
		grep -oE 'pinned [^ ]+ in [^)]*' "$TMP/ps.out" 2>/dev/null | sort -u >"$TMP/ps.pins" || :
		if cmp -s "$TMP/sh.pins" "$TMP/ps.pins"; then
			ok "ps1: identical lockfile pins on the $tree fixture"
		else
			no "ps1: identical lockfile pins on the $tree fixture" \
				"sh=[$(tr '\n' ' ' <"$TMP/sh.pins")] ps=[$(tr '\n' ' ' <"$TMP/ps.pins")]"
		fi
	done

	# Secrets must never be echoed, same guarantee as the sh scanner.
	if [ -d "$TMP/secret" ]; then
		pscan 20 "ps1: scans the secret fixture" -Path "$TMP/secret" -SignaturePath "$SIGS" -NoColor
		refute_out "ghp_THISISAFAKETOKENVALUE" "ps1: report does not echo matched file contents"
	fi
}

hash_of() {
	# hash_of <1|256> <path>
	if [ "$1" = "256" ]; then
		if command -v sha256sum >/dev/null 2>&1; then
			sha256sum "$2" 2>/dev/null | awk '{print $1}'
		elif command -v shasum >/dev/null 2>&1; then
			shasum -a 256 "$2" 2>/dev/null | awk '{print $1}'
		fi
	else
		if command -v sha1sum >/dev/null 2>&1; then
			sha1sum "$2" 2>/dev/null | awk '{print $1}'
		elif command -v shasum >/dev/null 2>&1; then
			shasum -a 1 "$2" 2>/dev/null | awk '{print $1}'
		fi
	fi
}

# ===========================================================================
[ -f "$SCANNER" ] || {
	printf 'scanner not found: %s\n' "$SCANNER" >&2
	exit 1
}

printf 'SandwormCheck test suite\n'
printf 'scanner: %s\n' "$SCANNER"

for sh_bin in ${SHELLS:-sh}; do
	if ! command -v "$sh_bin" >/dev/null 2>&1; then
		printf '\n-- skipping %s (not installed) --\n' "$sh_bin"
		continue
	fi
	CURRENT_SHELL="$sh_bin"
	printf '\n######## shell: %s ########\n' "$sh_bin"
	test_exit_codes
	test_check_types
	test_true_negatives
	test_lockfiles
	test_process_check
	test_signature_validation
	test_argument_validation
	test_output_modes
	test_multi_campaign
	test_readonly
	test_no_secret_disclosure
	test_robustness
done

# These are interpreter-independent, so run them once.
CURRENT_SHELL="sh"
test_no_network
test_gnu_stat_compat
test_powershell_parity

printf '\n===============================\n'
printf 'passed: %s   failed: %s\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
printf 'all assertions passed\n'
