#!/bin/sh
# Read-only matrix for scripts/release-kind.sh and require-v-tag.sh. Does not publish.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KIND="$ROOT/scripts/release-kind.sh"
TAG="$ROOT/scripts/require-v-tag.sh"
fail=0

check_kind() {
	got=$(sh "$KIND" "$1" "$2")
	if [ "$got" != "$3" ]; then
		echo "FAIL kind event=$1 ref=$2 got=$got want=$3" >&2
		fail=1
	fi
}

check_tag_ok() {
	if ! sh "$TAG" "$1"; then
		echo "FAIL require-v-tag accepted not: $1" >&2
		fail=1
	fi
}

check_tag_no() {
	if sh "$TAG" "$1" 2>/dev/null; then
		echo "FAIL require-v-tag must refuse: $1" >&2
		fail=1
	fi
}

# branch / PR / dispatch: never publish
check_kind push refs/heads/master snapshot
check_kind push refs/heads/main snapshot
check_kind push refs/heads/cursor/fix-macos-release-smoke-f59c snapshot
check_kind pull_request refs/pull/72/merge snapshot
check_kind workflow_dispatch refs/heads/master ignore
check_kind workflow_dispatch refs/tags/v0.0.1-alpha.1 ignore
check_kind schedule refs/heads/master ignore

# only a v* tag push
check_kind push refs/tags/v0.0.1-alpha tag
check_kind push refs/tags/v0.0.1-alpha.1 tag
check_kind push refs/tags/v1.0.0 tag

# a release candidate: v<semver>-rc.<N>, only digits after -rc.
check_kind push refs/tags/v0.1.0-alpha-rc.1 rc
check_kind push refs/tags/v0.1.0-alpha-rc.12 rc
check_kind push refs/tags/v1.0.0-rc.1 rc
check_kind push refs/tags/v0.1.0-alpha tag
check_kind push refs/tags/v0.1.0-alpha-rc.1a tag
check_kind push refs/tags/v0.1.0-alpha-rc. tag
check_kind push refs/tags/x ignore
check_kind push refs/tags/x-rc.1 ignore
check_kind workflow_dispatch refs/tags/v0.1.0-alpha-rc.1 ignore

# lookalike tags and nightly must not publish
check_kind push refs/tags/nightly ignore
check_kind push refs/tags/0.0.1-alpha ignore
check_kind push refs/tags/latest ignore

check_tag_ok v0.0.1-alpha
check_tag_ok v0.0.1-alpha.1
check_tag_ok v1.0.0
check_tag_ok v0.1.0-alpha-rc.1
check_tag_no nightly
check_tag_no latest
check_tag_no 0.0.1-alpha
check_tag_no ''
check_tag_no main
check_tag_no master

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "ok release-kind matrix"
