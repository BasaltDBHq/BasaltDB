#!/bin/sh
# The stable release gate. Exit 0 only when a release candidate of <tag> on
# this commit passed: a push of <tag>-rc.<N> whose Release run ended in
# success with every end-to-end leg green. Any green rc counts, however many
# red ones the commit also has. Branches play no part: the gate checks the
# commit (GITHUB_SHA), wherever it is.
#
# Usage: rc-gate.sh <stable-tag>      e.g. rc-gate.sh v0.1.0-alpha
# Env:   GITHUB_REPOSITORY, GITHUB_SHA, GH_TOKEN (actions: read)
#        GH overrides the gh command (tests serve recorded API answers).
# Needs gh and jq. POSIX sh.
set -eu

# The e2e matrix in .github/workflows/release.yml. Every leg must pass; a
# skipped or missing leg is not a pass.
E2E_LEGS="e2e (macos-15)
e2e (macos-15-intel)
e2e (ubuntu-latest)"

if [ $# -ne 1 ]; then
	echo "usage: rc-gate.sh <stable-tag>" >&2
	exit 2
fi
stable=$1
: "${GITHUB_REPOSITORY:?rc-gate.sh: GITHUB_REPOSITORY is not set}"
: "${GITHUB_SHA:?rc-gate.sh: GITHUB_SHA is not set}"
GH=${GH:-gh}

case "$stable" in
v[0-9]*) ;;
*)
	echo "rc-gate.sh: need a v* tag, got '${stable}'" >&2
	exit 2
	;;
esac

runs=$($GH api "repos/${GITHUB_REPOSITORY}/actions/workflows/release.yml/runs?event=push&head_sha=${GITHUB_SHA}&per_page=100")

# Release runs of <stable>-rc.<digits> on this commit: "id conclusion tag".
candidates=$(printf '%s' "$runs" | jq -r --arg stable "$stable" --arg sha "$GITHUB_SHA" '
	.workflow_runs[]
	| select(.head_sha == $sha and .event == "push" and .path == ".github/workflows/release.yml")
	| select(.head_branch | startswith($stable + "-rc.") and (ltrimstr($stable + "-rc.") | test("^[0-9]+$")))
	| "\(.id) \(if .status == "completed" then .conclusion else .status end) \(.head_branch)"')

if [ -z "$candidates" ]; then
	echo "rc-gate.sh: refusing ${stable}: no release candidate ran on ${GITHUB_SHA}." >&2
	echo "Push ${stable}-rc.1 (or the next N) on this commit, wait for its Release run to pass, then push ${stable} again." >&2
	exit 1
fi

report=""
ok=""
while read -r id state tag; do
	if [ "$state" != success ]; then
		report="${report}  ${tag}: Release run ${id} is ${state}
"
		continue
	fi
	jobs=$($GH api "repos/${GITHUB_REPOSITORY}/actions/runs/${id}/jobs?filter=latest&per_page=100" </dev/null)
	missing=""
	while IFS= read -r leg; do
		got=$(printf '%s' "$jobs" | jq -r --arg name "$leg" '[.jobs[] | select(.name == $name)] | if length == 0 then "missing" else .[0] | (.conclusion // .status) end')
		if [ "$got" != success ]; then
			missing="${missing} ${leg}=${got}"
		fi
	done <<LEGS
$E2E_LEGS
LEGS
	if [ -n "$missing" ]; then
		report="${report}  ${tag}: Release run ${id} has end-to-end legs that did not pass:${missing}
"
		continue
	fi
	ok="$tag"
	break
done <<CANDIDATES
$candidates
CANDIDATES

if [ -n "$ok" ]; then
	echo "rc-gate.sh: ${ok} passed on ${GITHUB_SHA}; ${stable} may publish."
	exit 0
fi
echo "rc-gate.sh: refusing ${stable}: no release candidate on ${GITHUB_SHA} passed." >&2
printf '%s' "$report" >&2
echo "Fix on master, push ${stable}-rc.<N+1> on the new commit, and tag ${stable} there once it passes." >&2
exit 1
