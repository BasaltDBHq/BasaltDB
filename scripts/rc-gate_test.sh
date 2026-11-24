#!/bin/sh
# Tests for scripts/rc-gate.sh with recorded GitHub API answers
# (scripts/testdata/rc-gate). Read-only: no network, no token.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GATE="$ROOT/scripts/rc-gate.sh"
DATA="$ROOT/scripts/testdata/rc-gate"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rc-gate-test.XXXXXX")
trap 'rm -rf -- "${WORK:?}"' EXIT
fail=0

# gate <fixture> <stable tag>: runs the gate, output in $WORK/<fixture>.out.
gate() {
	cp -R "$DATA/$1" "$WORK/$1"
	RC_GATE_FIXTURE="$WORK/$1" GH="sh $DATA/fake-gh.sh" \
		GITHUB_REPOSITORY=BasaltDBHq/BasaltDB GITHUB_SHA=1111111111111111111111111111111111111111 \
		sh "$GATE" "$2" >"$WORK/$1.out" 2>&1
}

allowed() {
	if ! gate "$1" "$2"; then
		echo "FAIL rc-gate $1: want allowed, got refused:" >&2
		cat "$WORK/$1.out" >&2
		fail=1
	fi
}

refused() {
	if gate "$1" "$2"; then
		echo "FAIL rc-gate $1: want refused, got allowed:" >&2
		cat "$WORK/$1.out" >&2
		fail=1
	fi
}

says() {
	if ! grep -Fq -- "$2" "$WORK/$1.out"; then
		echo "FAIL rc-gate $1: output does not say '$2':" >&2
		cat "$WORK/$1.out" >&2
		fail=1
	fi
}

# Two rc tags on one commit, one red and one green: any green rc counts,
# whichever came first.
allowed red-then-green v0.1.0-alpha
says red-then-green "v0.1.0-alpha-rc.2 passed"
allowed green-then-red v0.1.0-alpha
says green-then-red "v0.1.0-alpha-rc.1 passed"

# No rc of this version on this commit: the stable tag's own run, an rc of
# another version, an rc on another commit and an rc lookalike do not count.
refused no-rc v0.1.0-alpha
says no-rc "no release candidate ran on 1111111111111111111111111111111111111111"
says no-rc "Push v0.1.0-alpha-rc.1"
if grep -q '/jobs' "$WORK/no-rc.log"; then
	echo "FAIL rc-gate no-rc: read the jobs of a run that is not a candidate" >&2
	fail=1
fi

# An rc tag on a commit that is on no branch: the gate checks the commit only.
allowed off-master v0.1.0-alpha
if grep -v '^repos/BasaltDBHq/BasaltDB/actions/' "$WORK/off-master.log"; then
	echo "FAIL rc-gate off-master: asked for something other than runs and jobs" >&2
	fail=1
fi

# A run that succeeded with a skipped end-to-end leg is not a pass.
refused leg-skipped v0.1.0-alpha
says leg-skipped "e2e (macos-15-intel)=skipped"

# An rc still running is not a pass yet.
refused in-progress v0.1.0-alpha
says in-progress "v0.1.0-alpha-rc.1: Release run 61 is in_progress"

# The legs the gate requires are the legs release.yml runs.
for runner in macos-15 macos-15-intel ubuntu-latest; do
	if ! grep -Eq "runner: ${runner}\$" "$ROOT/.github/workflows/release.yml"; then
		echo "FAIL rc-gate: release.yml has no e2e leg on ${runner}" >&2
		fail=1
	fi
done
if ! grep -Fq 'name: e2e (${{ matrix.runner }})' "$ROOT/.github/workflows/release.yml"; then
	echo "FAIL rc-gate: release.yml e2e job is not named 'e2e (<runner>)'" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "ok rc-gate"
