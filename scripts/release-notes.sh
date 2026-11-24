#!/bin/sh
# Print the release notes for a tag: the body of the "## [<version>]" section
# of CHANGELOG.md (the tag without its leading v), up to the next "## [".
# Exit 1 when the section is missing or empty, so a stable release never
# publishes without notes. POSIX sh. CHANGELOG overrides the file (tests).
#
# Usage: release-notes.sh <tag>      e.g. release-notes.sh v0.1.0-alpha
set -eu

if [ $# -ne 1 ]; then
	echo "usage: release-notes.sh <tag>" >&2
	exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
file=${CHANGELOG:-$ROOT/CHANGELOG.md}

case "$1" in
v[0-9]*) version=${1#v} ;;
*)
	echo "release-notes.sh: need a v* tag, got '${1}'" >&2
	exit 1
	;;
esac

# Print the section body with leading and trailing blank lines trimmed.
notes=$(awk -v head="## [${version}]" '
	index($0, "## [") == 1 {
		if (found) exit
		if (index($0, head) == 1) { found = 1; next }
	}
	found { lines[++n] = $0 }
	END {
		first = 1
		while (first <= n && lines[first] ~ /^[[:space:]]*$/) first++
		last = n
		while (last >= first && lines[last] ~ /^[[:space:]]*$/) last--
		for (i = first; i <= last; i++) print lines[i]
	}
' "$file")

if [ -z "$notes" ]; then
	echo "release-notes.sh: no notes for ${1}: add a \"## [${version}] - <date>\" section with its changes to CHANGELOG.md" >&2
	exit 1
fi
printf '%s\n' "$notes"
