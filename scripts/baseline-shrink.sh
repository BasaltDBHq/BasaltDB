#!/bin/sh
# Fails when the working tree adds a line to a shrink-only baseline that the
# base commit already has. The baselines are the paths in
# scripts/shrink-only.txt, at the base and here; a path the base does not
# have is a new baseline, created in full (with the limits below). A directory's files are each a
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
# moves): a baseline that only shrinks is emptied, never deleted, and a
# registered directory keeps an empty .gitkeep. A count is " (N times)"
# with N >= 2 and no leading zero; any other "(... times)" ending fails.
# Lines are weighed by their count, so a count lowered in place passes and
# one raised fails.
#
# A change that renames or merges baseline files lists each file in
# scripts/baseline-renames.txt as "old/path.txt<TAB>new/path.txt"; several
# old files may name one new file, and an old path is in one pair at most.
# A file pair is refused unless old is a file the base registers, that no
# package move rewrites, and is gone here, and new is registered here,
# absent at the base and a file here. Each line of the new file, without
# its count, must equal a line of the old files without its count, or, when
# that old line has one ": " segment fewer, equal it without its
# next-to-last segment (a declaration); and no line may weigh more than the
# old lines it matches. A pair the base already has applied (old gone at
# the base, new a file there) is skipped; once its new file is renamed
# again the pair is stale and is deleted. Any other baseline registered
# here and absent at the base may hold no line of a baseline the base
# registers, with or without its declaration and count, unless the renames
# file declares it new with "new<TAB>path" (registered here, absent at the
# base; skipped once the base has it). Every archtest file named
# *baseline*.txt or under a *baseline* directory must be registered. Lines
# are read as archtest reads them: trimmed at both ends.
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

# tagged prints each line of stdin as "file<TAB>line", trimmed of leading
# and trailing white space as archtest reads it, leaving out blank lines and
# comment lines (starting with #).
tagged() {
	sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^#/d' | grep -v '^$' | sed "s|^|$1	|" || true
}

# base_listed reports whether the base's shrink-only.txt registers $1.
base_listed() {
	git show "$base:scripts/shrink-only.txt" 2>/dev/null | entries | grep -qxF -- "$1"
}

renames=scripts/baseline-renames.txt
fail=0
: >"$tmp/moves"
: >"$tmp/cands"
: >"$tmp/pairs"
: >"$tmp/declared"
[ -f "$renames" ] && entries <"$renames" >"$tmp/pairs"

# An old path is the old side of one pair at most.
cut -f1 "$tmp/pairs" | grep -vx new | LC_ALL=C sort | uniq -d >"$tmp/dups" || true
while IFS= read -r d; do
	echo "$renames: $d is the old side of more than one pair" >&2
	fail=1
done <"$tmp/dups"

while IFS= read -r pair; do
	old=${pair%%"	"*}
	new=${pair#*"	"}
	if [ "$old" = "$pair" ] || [ -z "$old" ] || [ -z "$new" ] || [ "$new" != "${new%%"	"*}" ]; then
		echo "$renames: not \"old<TAB>new\": $pair" >&2
		fail=1
		continue
	fi
	if [ "$old" = new ]; then
		# "new<TAB>path" declares a new baseline whose lines may equal a
		# registered baseline's; it is skipped once the base has it.
		git cat-file -e "$base:$new" 2>/dev/null && continue
		if ! entries <scripts/shrink-only.txt | grep -qxF -- "$new" || [ ! -e "$new" ]; then
			echo "$renames: declared new baseline $new must be registered here, absent at the base and present here" >&2
			fail=1
		else
			printf '%s\n' "$new" >>"$tmp/declared"
		fi
		continue
	fi
	if ! git cat-file -e "$base:$old" 2>/dev/null && [ ! -e "$old" ] && [ "$(git cat-file -t "$base:$new" 2>/dev/null)" = blob ]; then
		continue # a file pair the base already has applied
	fi
	if [ "$(git cat-file -t "$base:$old" 2>/dev/null)" = blob ]; then
		printf '%s\t%s\n' "$old" "$new" >>"$tmp/cands"
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

# map.awk rewrites through the moves: mp(s, "/") a path or a line, mp(s,
# "_") an archtest baseline file name. countless(s) takes a " (N times)"
# count off s and sets weight to N (1 without one); a count that is not N
# >= 2 without a leading zero sets bad. declless(s) takes off the
# next-to-last ": " segment (a declaration), or is "" when s has fewer than
# three segments.
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
function countless(s) {
	weight = 1; bad = 0
	if (match(s, /\([^()]*times\)$/)) {
		if (match(s, / \([1-9][0-9]* times\)$/) && substr(s, RSTART) != " (1 times)") {
			weight = substr(s, RSTART + 2, RLENGTH - 9) + 0
			return substr(s, 1, RSTART - 1)
		}
		bad = 1
	}
	return s
}
function declless(s,    k, a, i, out) {
	k = split(s, a, ": ")
	if (k < 3) return ""
	out = a[1]
	for (i = 2; i <= k - 2; i++) out = out ": " a[i]
	return out ": " a[k]
}
AWK

mapped() {
	printf '%s\n' "$1" | LC_ALL=C awk -v moves="$tmp/moves" "$(cat "$tmp/map.awk")"' { print mp($0, "/") }'
}

# A file pair renames a baseline file the base registers, that no package
# move rewrites and that is gone here, to a file registered here, absent at
# the base and a file here.
: >"$tmp/filepairs"
while IFS= read -r pair; do
	old=${pair%%"	"*}
	new=${pair#*"	"}
	if ! base_listed "$old" || [ "$(mapped "$old")" != "$old" ] || [ -e "$old" ]; then
		echo "$renames: $old must be a baseline file the base registers, outside every package move, gone here" >&2
		fail=1
	elif ! entries <scripts/shrink-only.txt | grep -qxF -- "$new" || git cat-file -e "$base:$new" 2>/dev/null || [ ! -f "$new" ]; then
		echo "$renames: $new must be a baseline file registered here, absent at the base and a file here" >&2
		fail=1
	else
		printf '%s\n' "$pair" >>"$tmp/filepairs"
	fi
done <"$tmp/cands"

{
	git show "$base:scripts/shrink-only.txt" 2>/dev/null || true
	cat scripts/shrink-only.txt
} | entries | LC_ALL=C sort -u >"$tmp/paths"

# old: the base's baseline lines; heads: their paths here; fresh: the
# baselines registered here that the base does not have.
: >"$tmp/old"
: >"$tmp/heads"
: >"$tmp/fresh"
while IFS= read -r p; do
	if ! git cat-file -e "$base:$p" 2>/dev/null; then
		echo "$p" >>"$tmp/fresh"
		continue
	fi
	git ls-tree -r --name-only "$base" -- "$p" | while IFS= read -r f; do
		git show "$base:$f" | tagged "$f"
	done >>"$tmp/old"
	mapped "$p" >>"$tmp/heads"
done <"$tmp/paths"

: >"$tmp/new"
LC_ALL=C sort -u "$tmp/heads" | while IFS= read -r p; do
	[ -e "$p" ] || continue
	find "$p" -type f | LC_ALL=C sort | while IFS= read -r f; do
		tagged "$f" <"$f"
	done
done >>"$tmp/new"

# freshlines: the lines of the new baselines that no file pair names and
# that are not declared new.
cut -f2 "$tmp/filepairs" | LC_ALL=C sort -u >"$tmp/pairnew"
: >"$tmp/freshlines"
: >"$tmp/freshall"
LC_ALL=C sort -u "$tmp/fresh" | while IFS= read -r p; do
	[ -e "$p" ] || continue
	find "$p" -type f | LC_ALL=C sort | while IFS= read -r f; do
		tagged "$f" <"$f" >>"$tmp/freshall"
		grep -qxF -- "$f" "$tmp/pairnew" && continue
		grep -qxF -- "$p" "$tmp/declared" && continue
		tagged "$f" <"$f"
	done
done >>"$tmp/freshlines"

# Every archtest baseline file (a *baseline*.txt, or a file under a
# *baseline* directory) is covered by a path shrink-only.txt registers.
entries <scripts/shrink-only.txt >"$tmp/here"
git ls-files --cached --others --exclude-standard -- internal/testkit/archtest |
	grep -E '^internal/testkit/archtest/(.*/)?[^/]*baseline[^/]*(\.txt$|/)' |
	LC_ALL=C sort -u | while IFS= read -r f; do
	[ -e "$f" ] || continue
	covered=
	while IFS= read -r p; do
		case $f in "$p" | "$p"/*) covered=1 ;; esac
	done <"$tmp/here"
	[ -n "$covered" ] && continue
	echo "$f: a baseline file that scripts/shrink-only.txt does not register" >&2
	echo x
done >"$tmp/unregistered"
[ -s "$tmp/unregistered" ] && fail=1

# A baseline the base registers is still here, under its moved path, unless
# a file pair renames it.
git show "$base:scripts/shrink-only.txt" 2>/dev/null | entries | LC_ALL=C sort -u | while IFS= read -r p; do
	git cat-file -e "$base:$p" 2>/dev/null || continue
	[ -e "$(mapped "$p")" ] && continue
	cut -f1 "$tmp/filepairs" | grep -qxF -- "$p" && continue
	echo "$p: a registered baseline is gone; empty it instead, or list its rename in $renames" >&2
	echo x
done >"$tmp/gone"
[ -s "$tmp/gone" ] && fail=1

# Every count here is " (N times)" with N >= 2.
LC_ALL=C awk -v moves="$tmp/moves" "$(cat "$tmp/map.awk")"'
{ split($0, a, "\t"); countless(a[2]); if (bad) { printf "%s: malformed count, want \" (N times)\" with N >= 2:\n\t%s\n", a[1], a[2] > "/dev/stderr"; f = 1 } }
END { exit f }' "$tmp/new" "$tmp/freshall" || fail=1

# A new baseline that no file pair names holds no line of a baseline the
# base registers, with or without its declaration and count.
LC_ALL=C awk -v moves="$tmp/moves" "$(cat "$tmp/map.awk")"'
FILENAME == ARGV[1] { split($0, a, "\t"); c = countless(mp(a[2], "/")); seen[c] = 1; d = declless(c); if (d != "") seen[d] = 1; next }
{
	split($0, a, "\t"); c = countless(a[2]); d = declless(c)
	if (c in seen || (d != "" && d in seen)) {
		printf "%s: a new baseline holds a line of a registered one (list the rename in scripts/baseline-renames.txt):\n\t%s\n", a[1], a[2] > "/dev/stderr"
		f = 1
	}
}
END { exit f }' "$tmp/old" "$tmp/freshlines" || fail=1

# Each renamed file's lines come from its old files: a line matches an old
# line as it is, or without its declaration when the old line has one
# segment fewer, and weighs no more than the old lines it matches.
cut -f2 "$tmp/filepairs" | LC_ALL=C sort -u | while IFS= read -r n; do
	awk -F '\t' -v n="$n" '$2 == n { print $1 }' "$tmp/filepairs" | while IFS= read -r o; do
		git show "$base:$o" | tagged x
	done >"$tmp/pold"
	tagged x <"$n" >"$tmp/pnew"
	LC_ALL=C awk -v moves="$tmp/moves" -v file="$n" "$(cat "$tmp/map.awk")"'
FILENAME == ARGV[1] { sub(/^[^\t]*\t/, ""); k = countless(mp($0, "/")); old[k] += weight; next }
{
	sub(/^[^\t]*\t/, ""); line[FNR] = $0
	k = countless($0); w = weight
	if (!(k in old)) { d = declless(k); if (d != "" && d in old) k = d }
	key[FNR] = k; new[k] += w
}
END {
	f = 0
	for (i in line) if (!(key[i] in old) || new[key[i]] > old[key[i]]) {
		printf "%s: renamed baseline line not in its old files, or counted more often:\n\t%s\n", file, line[i] > "/dev/stderr"
		f = 1
	}
	exit f
}' "$tmp/pold" "$tmp/pnew" || echo x
done >"$tmp/pairfail"
[ -s "$tmp/pairfail" ] && fail=1

# Base lines rewritten through the moves, then: no file holds a line,
# weighed by its count, more than the rewritten base does. A count lowered
# in place passes; one raised fails.
LC_ALL=C awk -v moves="$tmp/moves" "$(cat "$tmp/map.awk")"'
FILENAME == ARGV[1] { split($0, a, "\t"); k = mpfile(a[1]) "\t" countless(mp(a[2], "/")); old[k] += weight; next }
{ split($0, a, "\t"); k = a[1] "\t" countless(a[2]); new[k] += weight; text[k] = a[2] }
END {
	f = 0
	for (k in new) if (new[k] > old[k]) {
		split(k, a, "\t")
		printf "%s adds a line to a shrink-only baseline (fix the violation instead):\n\t%s\n", a[1], text[k] > "/dev/stderr"
		f = 1
	}
	exit f
}' "$tmp/old" "$tmp/new" || fail=1
exit "$fail"
