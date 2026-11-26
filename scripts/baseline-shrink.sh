#!/bin/sh
# Fails when the working tree adds a line to a shrink-only baseline that the
# base commit already has. The baselines are the paths in
# scripts/shrink-only.txt, at the base and here; a path the base does not
# have is a new baseline and is not checked. A directory's files are each a
# baseline: a line that moves from one of its files to another, or a new
# file in it, adds lines. Blank lines, trailing spaces and the order of
# lines do not count.
#
# A change that moves code renames lines: scripts/baseline-renames.txt pairs
# them, one "old line<TAB>new line" per line (the same line twice for a line
# that moves to another file). A removed line paired with an added one is a
# rename, not growth; each pair is used once. A pair whose old line no
# baseline at the base holds fails, so the file is emptied once the renames
# are on the base.
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
git rev-parse -q --verify "$base^{commit}" >/dev/null || {
	echo "unknown base $base" >&2
	exit 2
}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

entries() {
	sed -e 's/#.*//' -e 's/[[:space:]]*$//' | grep -v '^$' || true
}

# tagged prints each non-blank line of stdin as "file<TAB>line".
tagged() {
	sed -e 's/[[:space:]]*$//' | grep -v '^$' | sed "s|^|$1	|" || true
}

{
	git show "$base:scripts/shrink-only.txt" 2>/dev/null || true
	cat scripts/shrink-only.txt
} | entries | LC_ALL=C sort -u >"$tmp/paths"

: >"$tmp/old"
: >"$tmp/new"
while IFS= read -r p; do
	git cat-file -e "$base:$p" 2>/dev/null || continue
	git ls-tree -r --name-only "$base" -- "$p" | while IFS= read -r f; do
		git show "$base:$f" | tagged "$f"
	done >>"$tmp/old"
	if [ -e "$p" ]; then
		find "$p" -type f | LC_ALL=C sort | while IFS= read -r f; do
			tagged "$f" <"$f"
		done >>"$tmp/new"
	fi
done <"$tmp/paths"

renames=scripts/baseline-renames.txt
if [ -f "$renames" ]; then
	sed -e '/^#/d' -e 's/[[:space:]]*$//' "$renames" | grep -v '^$' >"$tmp/renames" || true
else
	: >"$tmp/renames"
fi

# The old and new baselines as multisets of file and line; a rename pairs
# a removed line (any file) with an added one.
LC_ALL=C awk -F '	' -v renames="$renames" '
FILENAME == ARGV[1] { if (NF != 2 || $1 == "" || $2 == "") { bad[++nbad] = $0; next } ro[++nr] = $1; rn[nr] = $2; next }
FILENAME == ARGV[2] { old[$1 FS $2]++; oldline[$2] = 1; next }
{ new[$1 FS $2]++ }
END {
	fail = 0
	for (i = 1; i <= nbad; i++) { printf "%s: not \"old line<TAB>new line\": %s\n", renames, bad[i] > "/dev/stderr"; fail = 1 }
	for (i = 1; i <= nr; i++) if (!(ro[i] in oldline)) {
		printf "%s: no baseline at the base holds %s (empty the file once its renames are on the base)\n", renames, ro[i] > "/dev/stderr"; fail = 1
	}
	for (k in old) { d = old[k] - new[k]; if (d > 0) { split(k, a, FS); freed[a[2]] += d } }
	n = 0
	for (k in new) { d = new[k] - old[k]; if (d > 0) { for (j = 0; j < d; j++) add[++n] = k } }
	for (i = 1; i <= n; i++) {
		split(add[i], a, FS)
		ok = 0
		for (r = 1; r <= nr && !ok; r++) if (!used[r] && rn[r] == a[2] && freed[ro[r]] > 0) { used[r] = 1; freed[ro[r]]--; ok = 1 }
		if (!ok) { printf "%s adds a line to a shrink-only baseline (fix the violation instead):\n\t%s\n", a[1], a[2] > "/dev/stderr"; fail = 1 }
	}
	exit fail
}' "$tmp/renames" "$tmp/old" "$tmp/new"
