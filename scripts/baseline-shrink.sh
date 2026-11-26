#!/bin/sh
# Fails when the working tree adds a line to a shrink-only baseline that the
# base commit already has. The baselines are the paths in
# scripts/shrink-only.txt, at the base and here; a path the base does not
# have is a new baseline and is not checked. A directory's files are each a
# baseline: a line that moves to another of its files, or a new file in it,
# adds lines. Blank lines, comment lines (#), trailing spaces and the order
# of lines do not count.
#
# A change that moves a package renames its baseline lines and files:
# scripts/baseline-renames.txt lists the moves, one "old/pkg<TAB>new/pkg"
# per line. The base's baseline paths, file names and lines are rewritten
# through them (whole path segments only; in a file name the package may be
# written with "_" for "/", as archtest names its files) before they are
# compared with the working tree. A move is refused unless old/pkg is a
# directory at the base and gone here, and new/pkg is absent at the base
# and a directory here; so the file is emptied once its moves are on the
# base.
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

# tagged prints each line of stdin as "file<TAB>line", leaving out blank
# lines and comment lines (starting with #).
tagged() {
	sed -e 's/[[:space:]]*$//' -e '/^#/d' | grep -v '^$' | sed "s|^|$1	|" || true
}

renames=scripts/baseline-renames.txt
fail=0
: >"$tmp/moves"
if [ -f "$renames" ]; then
	entries <"$renames" >"$tmp/pairs"
	while IFS= read -r pair; do
		old=${pair%%"	"*}
		new=${pair#*"	"}
		if [ "$old" = "$pair" ] || [ -z "$old" ] || [ -z "$new" ] || [ "$new" != "${new%%"	"*}" ]; then
			echo "$renames: not \"old/pkg<TAB>new/pkg\": $pair" >&2
			fail=1
			continue
		fi
		if [ "$(git cat-file -t "$base:$old" 2>/dev/null)" != tree ] || [ -e "$old" ]; then
			echo "$renames: $old must be a package at the base and gone here" >&2
			fail=1
			continue
		fi
		if git cat-file -e "$base:$new" 2>/dev/null || [ ! -d "$new" ]; then
			echo "$renames: $new must be absent at the base and a package here" >&2
			fail=1
			continue
		fi
		printf '%s\t%s\n' "$old" "$new" >>"$tmp/moves"
	done <"$tmp/pairs"
fi

# map.awk rewrites through the moves: mp(s, "/") a path or a line, mp(s,
# "_") an archtest baseline file name.
cat >"$tmp/map.awk" <<'AWK'
BEGIN {
	FS = "\t"
	while ((getline l < moves) > 0) { split(l, m, "\t"); mo[++nm] = m[1]; mn[nm] = m[2] }
}
function seg(c) { return c == "" || c !~ /[A-Za-z0-9_.-]/ }
function mp(s, sep,    i, o, n, out, rest, p, before, after) {
	for (i = 1; i <= nm; i++) {
		o = mo[i]; n = mn[i]
		if (sep == "_") { gsub("/", "_", o); gsub("/", "_", n) }
		out = ""; rest = s
		while ((p = index(rest, o)) > 0) {
			before = p > 1 ? substr(rest, p - 1, 1) : substr(out, length(out), 1)
			after = substr(rest, p + length(o), 1)
			if ((sep == "_" ? (p == 1 && out == "" || before == "/") : seg(before)) && (after == "" || after == sep || (sep == "_" ? after == "." : seg(after)))) {
				out = out substr(rest, 1, p - 1) n
			} else {
				out = out substr(rest, 1, p - 1 + length(o))
			}
			rest = substr(rest, p + length(o))
		}
		s = out rest
	}
	return s
}
function mpfile(f,    d, b) {
	f = mp(f, "/")
	d = f; sub(/[^\/]*$/, "", d)
	b = substr(f, length(d) + 1)
	return d mp(b, "_")
}
AWK

{
	git show "$base:scripts/shrink-only.txt" 2>/dev/null || true
	cat scripts/shrink-only.txt
} | entries | LC_ALL=C sort -u >"$tmp/paths"

: >"$tmp/old"
: >"$tmp/heads"
while IFS= read -r p; do
	git cat-file -e "$base:$p" 2>/dev/null || continue
	git ls-tree -r --name-only "$base" -- "$p" | while IFS= read -r f; do
		git show "$base:$f" | tagged "$f"
	done >>"$tmp/old"
	echo "$p" | LC_ALL=C awk -v moves="$tmp/moves" "$(cat "$tmp/map.awk")"' { print mp($0, "/") }' >>"$tmp/heads"
done <"$tmp/paths"

: >"$tmp/new"
LC_ALL=C sort -u "$tmp/heads" | while IFS= read -r p; do
	[ -e "$p" ] || continue
	find "$p" -type f | LC_ALL=C sort | while IFS= read -r f; do
		tagged "$f" <"$f"
	done
done >>"$tmp/new"

# Base lines rewritten through the moves, then: no file holds a line more
# often than the rewritten base does.
LC_ALL=C awk -v moves="$tmp/moves" "$(cat "$tmp/map.awk")"'
FILENAME == ARGV[1] { split($0, a, "\t"); old[mpfile(a[1]) "\t" mp(a[2], "/")]++; next }
{ new[$0]++ }
END {
	fail = 0
	for (k in new) if (new[k] > old[k]) {
		split(k, a, "\t")
		printf "%s adds a line to a shrink-only baseline (fix the violation instead):\n\t%s\n", a[1], a[2] > "/dev/stderr"
		fail = 1
	}
	exit fail
}' "$tmp/old" "$tmp/new" || fail=1
exit "$fail"
