#!/bin/sh
# Tests for scripts/release-notes.sh against a fixture CHANGELOG. Read-only.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NOTES="$ROOT/scripts/release-notes.sh"
FIXTURE="$ROOT/scripts/testdata/release-notes/CHANGELOG.md"
fail=0

want='### Added

- The first line of 0.1.0-alpha.

### Fixed

- A fix in 0.1.0-alpha.'
got=$(CHANGELOG="$FIXTURE" sh "$NOTES" v0.1.0-alpha)
if [ "$got" != "$want" ]; then
	printf 'FAIL release-notes v0.1.0-alpha:\n%s\n' "$got" >&2
	fail=1
fi

# The last section runs to the end of the file.
got=$(CHANGELOG="$FIXTURE" sh "$NOTES" v0.0.1-alpha)
if [ "$got" != "- The oldest one." ]; then
	printf 'FAIL release-notes v0.0.1-alpha:\n%s\n' "$got" >&2
	fail=1
fi

# A version that is a prefix of another is matched exactly.
got=$(CHANGELOG="$FIXTURE" sh "$NOTES" v0.1.0)
if [ "$got" != "- A different version whose name is a prefix of the one above." ]; then
	printf 'FAIL release-notes v0.1.0:\n%s\n' "$got" >&2
	fail=1
fi

for missing in v0.2.0 v0.1 Unreleased '' v0.1.0-alpha-rc.1; do
	if CHANGELOG="$FIXTURE" sh "$NOTES" "$missing" >/dev/null 2>&1; then
		echo "FAIL release-notes must refuse: '$missing'" >&2
		fail=1
	fi
done

# An empty section is refused too: a release with no notes is a mistake.
empty="${TMPDIR:-/tmp}/release-notes-empty.$$"
printf '## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-01-01\n\n- x\n' >"$empty"
if CHANGELOG="$empty" sh "$NOTES" v1.0.0 >/dev/null 2>&1; then
	echo "FAIL release-notes must refuse an empty section" >&2
	fail=1
fi
rm -f "$empty"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "ok release-notes"
