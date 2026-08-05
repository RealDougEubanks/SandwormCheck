#!/bin/sh
# Repository quality and security checks.
#
#   ./tools/checks.sh [--staged] [--quick]
#
# Called by the git hooks in .githooks/ and by CI, so the two cannot drift apart.
# Without this shared entry point, "it passed locally" and "it passed in CI" end
# up meaning different things.
#
#   --staged  check only files staged for commit (used by pre-commit)
#   --quick   skip the full test suite (used by pre-commit; pre-push and CI run it)
#
# Exit 0 if every check that could run passed, 1 otherwise.
#
# A check whose tool is missing is SKIPPED with a warning rather than failing, so
# the repository stays committable on a machine without shellcheck or PowerShell.
# CI installs both, and is the real gate.

set -u

STAGED=0
QUICK=0
for arg in "$@"; do
	case $arg in
	--staged) STAGED=1 ;;
	--quick) QUICK=1 ;;
	-h | --help)
		sed -n '2,20p' "$0"
		exit 0
		;;
	*)
		printf 'checks: unknown option: %s\n' "$arg" >&2
		exit 2
		;;
	esac
done

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$ROOT" || exit 1

FAIL=0
SKIP=0

pass() { printf '  ok      %s\n' "$*"; }
fail() {
	printf '  FAIL    %s\n' "$*"
	FAIL=$((FAIL + 1))
}
skip() {
	printf '  skip    %s\n' "$*"
	SKIP=$((SKIP + 1))
}
head_() { printf '\n== %s ==\n' "$*"; }

# List files in scope: staged (added/copied/modified only, so deletions and the
# other side of a rename are not opened) or everything tracked.
files() {
	if [ "$STAGED" -eq 1 ]; then
		git diff --cached --name-only --diff-filter=ACM
	else
		git ls-files
	fi
}

files_matching() {
	# files_matching <extended regex over the path>
	files | grep -E "$1" 2>/dev/null || :
}

# ---------------------------------------------------------------------------
head_ "shell lint"
SH_FILES=$(files_matching '\.sh$')
if [ -z "$SH_FILES" ]; then
	skip "no shell files in scope"
elif ! command -v shellcheck >/dev/null 2>&1; then
	skip "shellcheck not installed (brew install shellcheck / apt install shellcheck)"
else
	_bad=0
	for f in $SH_FILES; do
		[ -f "$f" ] || continue
		if ! shellcheck -s sh "$f"; then _bad=1; fi
	done
	if [ "$_bad" -eq 0 ]; then
		pass "shellcheck -s sh"
	else
		fail "shellcheck reported problems"
	fi
fi

# ---------------------------------------------------------------------------
head_ "PowerShell lint"
PS_FILES=$(files_matching '\.ps1$')
if [ -z "$PS_FILES" ]; then
	skip "no PowerShell files in scope"
elif ! command -v pwsh >/dev/null 2>&1; then
	skip "pwsh not installed; CI runs PSScriptAnalyzer"
else
	if ! pwsh -NoProfile -Command 'if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { exit 3 }' >/dev/null 2>&1; then
		skip "PSScriptAnalyzer module not installed (Install-Module PSScriptAnalyzer)"
	else
		_bad=0
		for f in $PS_FILES; do
			[ -f "$f" ] || continue
			_out=$(pwsh -NoProfile -Command "
				Import-Module PSScriptAnalyzer
				\$i = Invoke-ScriptAnalyzer -Path '$f' -Settings ./PSScriptAnalyzerSettings.psd1 -Severity Error,Warning
				if (\$i) { \$i | ForEach-Object { '{0}:{1}: {2}' -f '$f', \$_.Line, \$_.RuleName }; exit 1 }
			" 2>&1) || _bad=1
			[ -n "$_out" ] && printf '%s\n' "$_out"
		done
		if [ "$_bad" -eq 0 ]; then
			pass "PSScriptAnalyzer (Error+Warning)"
		else
			fail "PSScriptAnalyzer reported problems"
		fi
	fi
fi

# ---------------------------------------------------------------------------
# PowerShell 5.1 reads a BOM-less file as ANSI, so a stray non-ASCII byte can
# corrupt surrounding string literals on the exact platform we cannot test here.
head_ "PowerShell files are pure ASCII"
if [ -z "$PS_FILES" ]; then
	skip "no PowerShell files in scope"
else
	_bad=0
	for f in $PS_FILES; do
		[ -f "$f" ] || continue
		if LC_ALL=C grep -qn '[^ -~	]' "$f" 2>/dev/null; then
			printf '    %s: non-ASCII byte(s) on line(s): %s\n' "$f" \
				"$(LC_ALL=C grep -n '[^ -~	]' "$f" | cut -d: -f1 | tr '\n' ' ')"
			_bad=1
		fi
	done
	if [ "$_bad" -eq 0 ]; then
		pass "no non-ASCII bytes in .ps1"
	else
		fail "non-ASCII in .ps1 (Windows PowerShell 5.1 misreads these without a BOM)"
	fi
fi

# ---------------------------------------------------------------------------
# This repository is a security tool; committing a live credential would be
# worse than a normal leak. Deliberately conservative patterns to stay useful.
head_ "secret scan"
# Fixtures hold inert fakes and docs quote credential formats, so both are out of
# scope. Filtered with grep -v rather than a `case`, because bash 3.2 cannot parse
# a nested case inside a command substitution.
SECRET_SCOPE=$(files | grep -v '^tests/fixtures/' | grep -v '\.md$' || :)
SECRET_HITS=$(
	for f in $SECRET_SCOPE; do
		[ -f "$f" ] || continue
		LC_ALL=C grep -nE \
			-e 'ghp_[A-Za-z0-9]{36}' \
			-e 'github_pat_[A-Za-z0-9_]{22,}' \
			-e 'gh[pousr]_[A-Za-z0-9]{36,}' \
			-e 'AKIA[0-9A-Z]{16}' \
			-e 'ASIA[0-9A-Z]{16}' \
			-e 'npm_[A-Za-z0-9]{36}' \
			-e 'sk-[A-Za-z0-9]{32,}' \
			-e 'sk-ant-[A-Za-z0-9-]{20,}' \
			-e 'xox[abpsr]-[A-Za-z0-9-]{10,}' \
			-e 'AIza[0-9A-Za-z_-]{35}' \
			-e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
			-e 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}' \
			"$f" 2>/dev/null | sed "s|^|    $f:|"
	done
)
if [ -n "$SECRET_HITS" ]; then
	printf '%s\n' "$SECRET_HITS"
	fail "possible credential committed (see above)"
else
	pass "no credential patterns found"
fi

# ---------------------------------------------------------------------------
# A signature file that fails to load makes every scan exit 1. Catching it here
# is much cheaper than catching it on a fleet.
head_ "signature files load"
if [ ! -x ./sandwormcheck.sh ] && [ ! -f ./sandwormcheck.sh ]; then
	skip "scanner not present"
else
	_out=$(sh ./sandwormcheck.sh --path tests/fixtures/clean --signatures signatures \
		--quiet --no-color 2>&1)
	_rc=$?
	if [ "$_rc" -eq 0 ]; then
		pass "all signature files parse and the clean fixture is clean"
	else
		printf '%s\n' "$_out"
		fail "signature load or clean-fixture scan failed (exit $_rc)"
	fi
fi

# ---------------------------------------------------------------------------
# The scanner must never reach the network. See docs/spec.md section 7.
head_ "scanners make no network calls"
_net=$(grep -nE '(^|[^[:alnum:]_./-])(curl|wget|nc|ncat|telnet|ftp|scp|rsync|openssl[[:space:]]+s_client)([^[:alnum:]_-]|$)' \
	sandwormcheck.sh 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#' || :)
_net_ps=$(grep -niE '(Invoke-WebRequest|Invoke-RestMethod|System\.Net\.WebClient|DownloadString|DownloadFile|Net\.Sockets|Test-Connection)' \
	SandwormCheck.ps1 2>/dev/null | grep -v ':[[:space:]]*#' || :)
if [ -n "$_net$_net_ps" ]; then
	printf '%s\n%s\n' "$_net" "$_net_ps"
	fail "network primitive found in a scanner"
else
	pass "no network primitives in either scanner"
fi

# ---------------------------------------------------------------------------
head_ "generated signature file is in sync"
if [ -f tools/make-package-signatures.sh ] && [ -f signatures/compromised-packages.txt ]; then
	_committed=signatures/shai-hulud-2026-08-packages.conf
	# Reuse the committed header values so this compares content, not the clock.
	_camp=$(sed -n 's/^#![[:space:]]*campaign[[:space:]]\{1,\}//p' "$_committed" | head -1)
	_ver=$(sed -n 's/^#![[:space:]]*version[[:space:]]\{1,\}//p' "$_committed" | head -1)
	_upd=$(sed -n 's/^#![[:space:]]*updated[[:space:]]\{1,\}//p' "$_committed" | head -1)
	_gen=$(mktemp "${TMPDIR:-/tmp}/gencheck.XXXXXX")
	if sh tools/make-package-signatures.sh signatures/compromised-packages.txt \
		"$_camp" "$_ver" "$_upd" >"$_gen" 2>/dev/null &&
		cmp -s "$_gen" "$_committed"; then
		pass "shai-hulud-2026-08-packages.conf matches its input list"
	else
		fail "generated signature file is stale; re-run tools/make-package-signatures.sh"
	fi
	rm -f "$_gen"
else
	skip "generator or input list not present"
fi

# ---------------------------------------------------------------------------
head_ "executable bits"
_bad=0
for f in $(files_matching '\.sh$'); do
	[ -f "$f" ] || continue
	[ -x "$f" ] || {
		printf '    %s is not executable (chmod +x)\n' "$f"
		_bad=1
	}
done
if [ "$_bad" -eq 0 ]; then pass "shell scripts are executable"; else fail "some shell scripts lack +x"; fi

# ---------------------------------------------------------------------------
if [ "$QUICK" -eq 1 ]; then
	head_ "test suite"
	skip "--quick: the full suite runs on pre-push and in CI"
else
	head_ "test suite"
	if [ -f tests/run-tests.sh ]; then
		if sh tests/run-tests.sh >/tmp/checks-tests.$$ 2>&1; then
			pass "$(grep -oE 'passed: [0-9]+' /tmp/checks-tests.$$ | tail -1) assertions"
		else
			tail -25 /tmp/checks-tests.$$
			fail "test suite"
		fi
		rm -f /tmp/checks-tests.$$
	else
		skip "no test suite present"
	fi
fi

# ---------------------------------------------------------------------------
printf '\n===============================\n'
if [ "$FAIL" -eq 0 ]; then
	printf 'checks passed'
	if [ "$SKIP" -gt 0 ]; then printf ' (%s skipped)' "$SKIP"; fi
	printf '\n'
	exit 0
fi
printf '%s check(s) FAILED\n' "$FAIL"
exit 1
