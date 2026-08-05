#!/bin/sh
# Apply repository protections to SandwormCheck on GitHub.
#
#   ./tools/setup-repo-protection.sh --dry-run    show what would change
#   ./tools/setup-repo-protection.sh              apply
#
# Requires the gh CLI, authenticated with admin rights on the repository:
#   gh auth login
#
# Policy applied (chosen for a single-maintainer repository):
#
#   * main requires a pull request -- no direct pushes
#   * CI must pass before merging, and the branch must be up to date
#   * force pushes and branch deletion are blocked
#   * linear history required (no merge commits on main)
#   * conversations must be resolved before merging
#   * ADMINS ARE EXEMPT from the review requirement
#
# The last point is deliberate. Requiring an approving review with one developer
# would make every merge impossible, so the process is enforced (PR + green CI)
# without locking the owner out of their own repository. Set REQUIRE_APPROVALS=1
# and ENFORCE_ADMINS=true once a second maintainer exists.
#
# Also enables, where the plan allows: secret scanning, push protection,
# Dependabot alerts, and automated security fixes.
#
# Safe to re-run. Every call is a full PUT of the desired state, so this converges
# rather than accumulating.

set -eu

PROGNAME="setup-repo-protection"
REPO=${REPO:-RealDougEubanks/SandwormCheck}
BRANCH=${BRANCH:-main}
REQUIRE_APPROVALS=${REQUIRE_APPROVALS:-0}
ENFORCE_ADMINS=${ENFORCE_ADMINS:-false}

DRY=0
case "${1:-}" in
--dry-run | -n) DRY=1 ;;
"") ;;
-h | --help)
	sed -n '2,32p' "$0"
	exit 0
	;;
*)
	printf '%s: unknown option: %s\n' "$PROGNAME" "$1" >&2
	exit 2
	;;
esac

say() { printf '%s: %s\n' "$PROGNAME" "$*"; }
warn() { printf '%s: warning: %s\n' "$PROGNAME" "$*" >&2; }

command -v gh >/dev/null 2>&1 || {
	printf '%s: gh CLI not found (https://cli.github.com)\n' "$PROGNAME" >&2
	exit 1
}
gh auth status >/dev/null 2>&1 || {
	printf '%s: gh is not authenticated; run: gh auth login\n' "$PROGNAME" >&2
	exit 1
}

# Status check contexts must match the rendered job names in
# .github/workflows/test.yml, including the matrix suffix. If a job is renamed
# there and not here, protection silently stops requiring it -- which is why this
# script verifies them against the workflow file below.
CONTEXTS='
"lint + security (ubuntu-latest)",
"lint + security (macos-latest)",
"test suite (ubuntu-latest)",
"test suite (macos-latest)",
"PowerShell port (windows-latest)"
'

say "repository        : $REPO"
say "branch            : $BRANCH"
say "required reviews  : $REQUIRE_APPROVALS"
say "enforce on admins : $ENFORCE_ADMINS"
[ "$DRY" -eq 1 ] && say "MODE              : dry run, nothing will change"

# --- sanity: do the contexts exist in the workflow? ------------------------
WF=.github/workflows/test.yml
if [ -f "$WF" ]; then
	_missing=""
	for jobname in "lint + security" "test suite" "PowerShell port"; do
		grep -qF "$jobname" "$WF" || _missing="$_missing '$jobname'"
	done
	if [ -n "$_missing" ]; then
		warn "workflow job name(s) not found in $WF:$_missing"
		warn "required status checks would never pass; fix the names before applying"
		[ "$DRY" -eq 1 ] || exit 1
	else
		say "workflow job names verified against $WF"
	fi
else
	warn "$WF not found; cannot verify status check names"
fi

BODY=$(
	cat <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": [$(printf '%s' "$CONTEXTS" | tr -d '\n' | sed 's/,$//')]
  },
  "enforce_admins": $ENFORCE_ADMINS,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": $REQUIRE_APPROVALS,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": false
}
JSON
)

if [ "$DRY" -eq 1 ]; then
	printf '\n--- would PUT /repos/%s/branches/%s/protection ---\n%s\n' "$REPO" "$BRANCH" "$BODY"
	printf '\n--- would also enable ---\n'
	printf '  secret scanning, push protection, Dependabot alerts, automated security fixes\n'
	printf '  and set: squash-merge only, delete branch on merge\n'
	exit 0
fi

say "applying branch protection"
printf '%s' "$BODY" | gh api -X PUT "repos/$REPO/branches/$BRANCH/protection" \
	-H 'Accept: application/vnd.github+json' --input - >/dev/null
say "branch protection applied"

# --- repository-level security features -----------------------------------
# Availability depends on the plan and on the repository being public; a failure
# here is reported, not fatal, so the branch protection above still stands.
say "enabling secret scanning and push protection"
gh api -X PATCH "repos/$REPO" \
	-H 'Accept: application/vnd.github+json' \
	-f 'security_and_analysis[secret_scanning][status]=enabled' \
	-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' \
	>/dev/null 2>&1 || warn "could not enable secret scanning (plan or permissions?)"

say "enabling Dependabot alerts and automated security fixes"
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null 2>&1 ||
	warn "could not enable Dependabot alerts"
gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null 2>&1 ||
	warn "could not enable automated security fixes"

# --- merge hygiene ---------------------------------------------------------
# Squash-only keeps main linear, which required_linear_history above demands.
say "setting merge options: squash only, delete branch on merge"
gh api -X PATCH "repos/$REPO" \
	-H 'Accept: application/vnd.github+json' \
	-F allow_squash_merge=true \
	-F allow_merge_commit=false \
	-F allow_rebase_merge=false \
	-F delete_branch_on_merge=true \
	-F allow_auto_merge=true \
	>/dev/null 2>&1 || warn "could not set merge options"

printf '\n'
say "done. current protection:"
gh api "repos/$REPO/branches/$BRANCH/protection" \
	--jq '{
		pr_required: (.required_pull_request_reviews != null),
		approvals: .required_pull_request_reviews.required_approving_review_count,
		strict_status_checks: .required_status_checks.strict,
		checks: .required_status_checks.contexts,
		enforce_admins: .enforce_admins.enabled,
		force_pushes: .allow_force_pushes.enabled,
		deletions: .allow_deletions.enabled,
		linear_history: .required_linear_history.enabled
	}' 2>/dev/null || warn "could not read back protection state"
