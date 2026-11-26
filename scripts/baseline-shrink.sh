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
# A baseline the base registers must still be here (after the package
# moves): a baseline that only shrinks may be emptied, never deleted. A
# change that renames or merges baseline files lists each file in
# scripts/baseline-renames.txt as "old/path.txt<TAB>new/path.txt"; several
# old files may name one new file. A file pair is refused unless old is a
# file the base registers and is gone here, and new is registered here, is
# absent at the base and is a file here. The new file's lines must come from
# its old files: each line, with a "(N times)" count taken off as weight N
# (1 without one) and its next-to-last ": " segment (a declaration) taken
# off when it has one, must match an old line stripped the same way, and no
# stripped line may weigh more in the new file than in the old ones. A pair
# the base has already applied (old gone at the base, new a file there) is
# skipped, so the pairs need not be removed after they merge.
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

# base_listed reports whether the base's shrink-only.txt registers $1.
base_listed() {
	git show "$base:scripts/shrink-only.txt" 2>/dev/null | entries | grep -qxF -- "$1"
}

renames=scripts/baseline-renames.txt
fail=0
: >"$tmp/moves"
: >"$tmp/filepairs"
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
		if ! git cat-file -e "$base:$old" 2>/dev/null && [ ! -e "$old" ] && [ "$(git cat-file -t "$base:$new" 2>/dev/null)" = blob ]; then
			continue # a file pair the base already has applied
		fi
		if [ "$(git cat-file -t "$base:$old" 2>/dev/null)" = blob ]; then
			if ! base_listed "$old" || [ -e "$old" ]; then
				echo "$renames: $old must be a baseline file the base registers, gone here" >&2
				fail=1
			elif ! entries <scripts/shrink-only.txt | grep -qxF -- "$new" || git cat-file -e "$base:$new" 2>/dev/null || [ ! -f "$new" ]; then
				echo "$renames: $new must be a baseline file registered here, absent at the base and a file here" >&2
				fail=1
			else
				printf '%s\t%s\n' "$old" "$new" >>"$tmp/filepairs"
			fi
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

# A baseline the base registers is still here, under its moved path, unless
# a file pair renames it.
git show "$base:scripts/shrink-only.txt" 2>/dev/null | entries | LC_ALL=C sort -u | while IFS= read -r p; do
	git cat-file -e "$base:$p" 2>/dev/null || continue
	m=$(echo "$p" | LC_ALL=C awk -v moves="$tmp/moves" "$(cat "$tmp/map.awk")"' { print mp($0, "/") }')
	[ -e "$m" ] && continue
	cut -f1 "$tmp/filepairs" | grep -qxF -- "$p" && continue
	echo "$p: a registered baseline is gone; empty it instead, or list its rename in $renames" >&2
	echo x
done >"$tmp/gone"
[ -s "$tmp/gone" ] && fail=1

# Each renamed file's lines come from its old files.
cut -f2 "$tmp/filepairs" | LC_ALL=C sort -u | while IFS= read -r n; do
	: >"$tmp/pold"
	awk -F '\t' -v n="$n" '$2 == n { print $1 }' "$tmp/filepairs" | while IFS= read -r o; do
		git show "$base:$o" | tagged x
	done >"$tmp/pold"
	tagged x <"$n" >"$tmp/pnew"
	LC_ALL=C awk -v moves="$tmp/moves" -v file="$n" "$(cat "$tmp/map.awk")"'
function strip(s,    w, k, a, i, out) {
	w = 1
	if (match(s, / \([0-9]+ times\)$/)) {
		w = substr(s, RSTART + 2, RLENGTH - 9) + 0
		s = substr(s, 1, RSTART - 1)
	}
	k = split(s, a, ": ")
	if (k >= 3) {
		out = a[1]
		for (i = 2; i <= k - 2; i++) out = out ": " a[i]
		s = out ": " a[k]
	}
	weight = w
	return s
}
FILENAME == ARGV[1] { sub(/^[^\t]*\t/, ""); k = strip(mp($0, "/")); old[k] += weight; next }
{ sub(/^[^\t]*\t/, ""); line[NR] = $0; k = strip($0); new[k] += weight; key[NR] = k }
END {
	fail = 0
	for (i in line) if (new[key[i]] > old[key[i]]) {
		printf "%s: renamed baseline line not in its old files, or counted more often:\n\t%s\n", file, line[i] > "/dev/stderr"
		fail = 1
	}
	exit fail
}' "$tmp/pold" "$tmp/pnew" || echo x
done >"$tmp/pairfail"
[ -s "$tmp/pairfail" ] && fail=1

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
