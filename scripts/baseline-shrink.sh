#!/bin/sh
# Fails when the working tree adds a line to a shrink-only baseline that the
# base commit already has. The baselines are the paths in
# scripts/shrink-only.txt, at the base and here; a path the base does not
# have is a new baseline and is not checked. A directory's files are each a
# baseline, and a new file in a directory the base has adds every line it
# holds. Blank lines, trailing spaces and the order of lines do not count.
#
# usage: sh scripts/baseline-shrink.sh <base-commit>
set -eu

if [ $# -ne 1 ]; then
	echo "usage: $0 <base-commit>" >&2
	exit 2
fi
base=$1
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

entries() {
	sed -e 's/#.*//' -e 's/[[:space:]]*$//' | grep -v '^$' || true
}

lines() {
	sed -e 's/[[:space:]]*$//' | grep -v '^$' | LC_ALL=C sort -u || true
}

{
	git show "$base:scripts/shrink-only.txt" 2>/dev/null || true
	cat scripts/shrink-only.txt
} | entries | LC_ALL=C sort -u >"$tmp/paths"

fail=0
while IFS= read -r p; do
	git cat-file -e "$base:$p" 2>/dev/null || continue
	[ -e "$p" ] || continue
	find "$p" -type f | LC_ALL=C sort >"$tmp/files"
	while IFS= read -r f; do
		{ git show "$base:$f" 2>/dev/null || true; } | lines >"$tmp/old"
		lines <"$f" >"$tmp/new"
		LC_ALL=C comm -13 "$tmp/old" "$tmp/new" >"$tmp/added"
		if [ -s "$tmp/added" ]; then
			echo "$f adds lines to a shrink-only baseline (fix the violation instead):" >&2
			sed 's/^/	/' "$tmp/added" >&2
			fail=1
		fi
	done <"$tmp/files"
done <"$tmp/paths"
exit "$fail"
