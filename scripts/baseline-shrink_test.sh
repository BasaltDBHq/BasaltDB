#!/bin/sh
# Cases for scripts/baseline-shrink.sh, in a throwaway git repository.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0
bl=internal/testkit/archtest/baseline
tab=$(printf '\t')

# setup builds a repository whose first commit (the base) has the archtest
# baseline directory and one baseline file registered, and no renames.
setup() {
	rm -rf "$work/r"
	mkdir -p "$work/r/scripts" "$work/r/$bl"
	: >"$work/r/$bl/.gitkeep"
	cp "$ROOT/scripts/baseline-shrink.sh" "$work/r/scripts/"
	printf '# baselines\n%s\nallow.txt\n' "$bl" >"$work/r/scripts/shrink-only.txt"
	printf '# moves\n' >"$work/r/scripts/baseline-renames.txt"
	printf 'a\nb\n' >"$work/r/$bl/internal_one.txt"
	printf 's.go imports net/http\ns.go imports internal/platform/db\n' >"$work/r/$bl/internal_status.txt"
	printf 'imports internal/status (no service)\nimports internal/statusx (no service)\n' >"$work/r/$bl/internal_platform_shim.txt"
	printf 'x\n' >"$work/r/allow.txt"
	for d in internal/status internal/statusx internal/platform/db internal/platform/store internal/platform/shim; do
		mkdir -p "$work/r/$d"
		printf 'package x\n' >"$work/r/$d/x.go"
	done
	git -C "$work/r" init -q
	git -C "$work/r" add -A
	git -C "$work/r" -c user.name=t -c user.email=t@t commit -qm base
}

check() { # want-exit description [base]
	if sh "$work/r/scripts/baseline-shrink.sh" "${3:-HEAD}" 2>/dev/null; then got=0; else got=1; fi
	if [ "$got" != "$1" ]; then
		echo "FAIL baseline-shrink: $2 (exit $got, want $1)" >&2
		fail=1
	fi
}

renames() { printf '%s\n' "$@" >>"$work/r/scripts/baseline-renames.txt"; }

setup
check 0 "an unchanged tree passes"

setup
check 1 "an unknown base fails" no-such-commit

setup
printf 'b\n' >"$work/r/$bl/internal_one.txt"
check 0 "a removed line passes"

setup
printf 'b\na\n\n' >"$work/r/$bl/internal_one.txt"
check 0 "reordered lines and a blank line pass"

setup
printf 'a\nb\nc\n' >"$work/r/$bl/internal_one.txt"
check 1 "an added line fails"

setup
printf '# why these stay\na\nb\n' >"$work/r/$bl/internal_one.txt"
check 0 "an added comment line passes"

setup
printf 'a  # why a stays\nb\n' >"$work/r/$bl/internal_one.txt"
check 0 "a reason added to a listed line passes"

setup
printf 'a\nb\nc  # a reason\n' >"$work/r/$bl/internal_one.txt"
check 1 "a new line with a reason fails"

setup
printf 'a  # one reason\nb\n' >"$work/r/$bl/internal_one.txt"
git -C "$work/r" -c user.name=t -c user.email=t@t commit -qam reason
printf 'a\t# another reason\nb\n' >"$work/r/$bl/internal_one.txt"
check 0 "a changed reason passes"

setup
printf 'y\n' >"$work/r/$bl/internal_two.txt"
check 1 "a new file in the archtest baseline directory fails"

setup
printf 'x\nz\n' >"$work/r/allow.txt"
check 1 "an added line in a baseline file fails"

setup
printf '%s\nallow.txt\nnew\n' "$bl" >"$work/r/scripts/shrink-only.txt"
mkdir "$work/r/new"
printf 'n\n' >"$work/r/new/n.txt"
check 0 "a new baseline is created in full"

setup
printf '' >"$work/r/scripts/shrink-only.txt"
printf 'a\nb\nc\n' >"$work/r/$bl/internal_one.txt"
check 1 "unlisting a baseline does not let it grow"

setup
rm -r "$work/r/$bl"
check 1 "a removed baseline fails"

setup
rm "$work/r/allow.txt"
check 1 "an unlisted removal of a baseline file fails"

setup
: >"$work/r/allow.txt"
check 0 "an emptied baseline passes"

setup
rm "$work/r/$bl"/*.txt
check 0 "an emptied baseline directory passes (its .gitkeep stays)"

setup
printf 'a\nb (2 times)\n' >"$work/r/$bl/internal_one.txt"
git -C "$work/r" -c user.name=t -c user.email=t@t commit -qam counts
printf 'a\nb\n' >"$work/r/$bl/internal_one.txt"
check 0 "a count lowered in place passes"
printf 'a\nb (3 times)\n' >"$work/r/$bl/internal_one.txt"
check 1 "a count raised in place fails"
printf 'a (2 times)\nb (2 times)\n' >"$work/r/$bl/internal_one.txt"
check 1 "a count added to a listed line fails"

for c in '(1 times)' '(02 times)' '(x times)' '(times)' '(0 times)'; do
	setup
	printf 'a\nb %s\n' "$c" >"$work/r/$bl/internal_one.txt"
	git -C "$work/r" -c user.name=t -c user.email=t@t commit -qam malformed
	check 1 "a malformed count $c fails"
done

setup
printf 'b\n' >"$work/r/$bl/internal_one.txt"
printf 'a\n' >"$work/r/$bl/internal_moved.txt"
check 1 "a line moved to another file fails"

# move_status moves internal/status to internal/health in the tree and in
# its baseline lines and file name, as wave 3's moves do.
move_status() {
	git -C "$work/r" mv internal/status internal/health
	git -C "$work/r" mv "$bl/internal_status.txt" "$bl/internal_health.txt"
	printf 'imports internal/health (no service)\nimports internal/statusx (no service)\n' >"$work/r/$bl/internal_platform_shim.txt"
}

setup
move_status
renames "internal/status${tab}internal/health"
check 0 "a package move rewrites its baseline lines and file name"

setup
move_status
check 1 "a package move without its pair fails"

setup
move_status
renames "internal/status${tab}internal/health"
printf 's.go imports net/http\ns.go imports internal/platform/db\ns.go imports os/exec\n' >"$work/r/$bl/internal_health.txt"
check 1 "a line added beside a move fails"

setup
printf 's.go imports net/http\ns.go imports internal/platform/store\n' >"$work/r/$bl/internal_status.txt"
renames "internal/platform/db${tab}internal/platform/store"
check 1 "a fixed import swapped for a different store import fails, paired or not"

setup
printf 's.go imports net/http\ns.go imports internal/platform/store\n' >"$work/r/$bl/internal_status.txt"
renames "s.go imports internal/platform/db${tab}s.go imports internal/platform/store"
check 1 "a line pair is no move and fails"

setup
move_status
mkdir -p "$work/r/internal/status"
printf 'package x\n' >"$work/r/internal/status/x.go"
renames "internal/status${tab}internal/health"
check 1 "a move whose old package is still here fails"

setup
git -C "$work/r" rm -rq internal/statusx
renames "internal/statusx${tab}internal/platform/store"
check 1 "a move onto a package the base has fails"

# own_baseline gives internal/status a baseline file of its own, listed in
# shrink-only.txt at the base.
own_baseline() {
	printf 'own\n' >"$work/r/internal/status/allow.txt"
	printf 'internal/status/allow.txt\n' >>"$work/r/scripts/shrink-only.txt"
	git -C "$work/r" add -A
	git -C "$work/r" -c user.name=t -c user.email=t@t commit -qm own
}

setup
own_baseline
move_status
renames "internal/status${tab}internal/health"
check 0 "a moved package's own baseline moves with it"

setup
own_baseline
move_status
renames "internal/status${tab}internal/health"
printf 'own\nmore\n' >"$work/r/internal/health/allow.txt"
check 1 "a moved package's own baseline still only shrinks"

# counted_base gives the base two name-keyed baseline files, one of them
# counted, registered beside the others.
counted_base() {
	printf 'p f.go: os.Lstat\np g.go: os/user.Lookup\n' >"$work/r/calls.txt"
	printf 'p h.go: H: os/user.Current (2 times)\n' >"$work/r/lookups.txt"
	printf 'calls.txt\nlookups.txt\n' >>"$work/r/scripts/shrink-only.txt"
	git -C "$work/r" add -A
	git -C "$work/r" -c user.name=t -c user.email=t@t commit -qm counted
}

# rename_calls replaces both files with one file, registered, holding $@.
rename_calls() {
	git -C "$work/r" rm -q calls.txt lookups.txt
	sed -e '/^calls.txt$/d' -e '/^lookups.txt$/d' "$work/r/scripts/shrink-only.txt" >"$work/r/scripts/s.tmp"
	printf 'all.txt\n' >>"$work/r/scripts/s.tmp"
	mv "$work/r/scripts/s.tmp" "$work/r/scripts/shrink-only.txt"
	printf '%s\n' "$@" >"$work/r/all.txt"
}

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat' 'p g.go: Check: os/user.Lookup' 'p h.go: H: os/user.Current (2 times)'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 0 "a listed rename into counted, declaration-keyed lines passes"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat' 'p g.go: Check: os/user.Lookup' 'p h.go: H: os/user.Current (2 times)'
check 1 "an unlisted rename fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat' 'p g.go: Check: os/user.Lookup' 'p h.go: H: os/user.Current (2 times)' 'p k.go: K: os.Remove'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a listed rename with an added line fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Remove' 'p g.go: Check: os/user.Lookup' 'p h.go: H: os/user.Current (2 times)'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a listed rename with a swapped line fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat' 'p g.go: Check: os/user.Lookup (2 times)' 'p h.go: H: os/user.Current (2 times)'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a listed rename whose count grows fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat' 'p g.go: Check: os/user.Lookup' 'p h.go: H: os/user.Current (3 times)'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a listed rename that raises a count fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat' 'p g.go: Check: os/user.Lookup' 'p g.go: Other: os/user.Lookup' 'p h.go: H: os/user.Current (2 times)'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a listed rename that splits one line over two declarations fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 0 "a listed rename that drops lines passes"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat'
sed -e '/^all.txt$/d' "$work/r/scripts/shrink-only.txt" >"$work/r/scripts/s.tmp"
mv "$work/r/scripts/s.tmp" "$work/r/scripts/shrink-only.txt"
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a rename onto an unregistered file fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat'
printf 'p f.go: os.Lstat\n' >"$work/r/calls.txt"
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a rename whose old file is still here fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat'
renames "calls.txt${tab}allow.txt" "lookups.txt${tab}all.txt"
check 1 "a rename onto a file the base has fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat'
renames "calls.txt${tab}all.txt" "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "an old path in two pairs fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat' 'p h.go: H: os/user.Current (1 times)'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
check 1 "a malformed count in a renamed file fails"

setup
counted_base
: >"$work/r/calls.txt"
: >"$work/r/lookups.txt"
printf 'fresh.txt\n' >>"$work/r/scripts/shrink-only.txt"
printf 'p f.go: os.Lstat\n' >"$work/r/fresh.txt"
check 1 "old files truncated and their lines in a new unpaired baseline fails"
printf 'p f.go: Rot: os.Lstat\n' >"$work/r/fresh.txt"
check 1 "the same with a declaration added fails"
printf 'p h.go: os/user.Current\n' >"$work/r/fresh.txt"
check 1 "the same with a declaration and count taken off fails"
printf 'q z.go: Z: os.Remove\n' >"$work/r/fresh.txt"
check 0 "a new unpaired baseline with lines of its own passes"

# shape_base gives the base a baseline whose lines already carry a file
# segment, as shape_baseline.txt's do.
shape_base() {
	printf 'p: a.go: F returns T\n' >"$work/r/shape.txt"
	printf 'shape.txt\n' >>"$work/r/scripts/shrink-only.txt"
	git -C "$work/r" add -A
	git -C "$work/r" -c user.name=t -c user.email=t@t commit -qm shape
	git -C "$work/r" rm -q shape.txt
	printf 'shape2.txt\n' >>"$work/r/scripts/shrink-only.txt"
	renames "shape.txt${tab}shape2.txt"
}

setup
shape_base
printf 'p: a.go: F returns T\n' >"$work/r/shape2.txt"
check 0 "a renamed shape-style file with the same lines passes"

setup
shape_base
printf 'p: b.go: F returns T\n' >"$work/r/shape2.txt"
check 1 "a renamed shape-style line moved to another file fails"

setup
own_baseline
move_status
git -C "$work/r" rm -qf internal/health/allow.txt
printf 'moved.txt\n' >>"$work/r/scripts/shrink-only.txt"
printf 'own\n' >"$work/r/moved.txt"
renames "internal/status${tab}internal/health" "internal/status/allow.txt${tab}moved.txt"
check 1 "a file pair whose old path a package move rewrites fails"

setup
counted_base
rename_calls 'p f.go: Rot: os.Lstat'
renames "calls.txt${tab}all.txt" "lookups.txt${tab}all.txt"
git -C "$work/r" add -A
git -C "$work/r" -c user.name=t -c user.email=t@t commit -qm renamed
check 0 "a file pair the base already has applied is skipped"
printf 'p f.go: Rot: os.Lstat\np z.go: Z: os.Remove\n' >"$work/r/all.txt"
check 1 "the renamed file only shrinks after its pair merges"

setup
counted_base
: >"$work/r/calls.txt"
printf 'fresh.txt\n' >>"$work/r/scripts/shrink-only.txt"
printf ' p f.go: os.Lstat\n' >"$work/r/fresh.txt"
check 1 "a copied line with a leading space in a new unpaired baseline fails"
printf '\tp f.go: os.Lstat\n' >"$work/r/fresh.txt"
check 1 "a copied line with a leading tab in a new unpaired baseline fails"

setup
printf 'fresh.txt\n' >>"$work/r/scripts/shrink-only.txt"
printf 'x\n' >"$work/r/fresh.txt"
check 1 "a new baseline holding a line a registered one also holds fails undeclared"
renames "new${tab}fresh.txt"
check 0 "the same new baseline declared new passes"
renames "new${tab}fresh.txt"
check 0 "a new baseline declared twice passes the one-pair rule"

setup
printf 'x\n' >"$work/r/fresh.txt"
renames "new${tab}fresh.txt"
check 1 "a declared new baseline that is not registered fails"

setup
renames "new${tab}allow.txt"
check 0 "a declaration of a baseline the base has is skipped"

setup
printf 'fresh.txt\n' >>"$work/r/scripts/shrink-only.txt"
printf 'x\n' >"$work/r/fresh.txt"
renames "new${tab}fresh.txt"
git -C "$work/r" add -A
git -C "$work/r" -c user.name=t -c user.email=t@t commit -qm declared
printf 'x\ny\n' >"$work/r/fresh.txt"
check 1 "a declared new baseline only shrinks once it is on the base"

setup
printf 'z\n' >"$work/r/internal/testkit/archtest/foo_baseline.txt"
check 1 "an archtest baseline file no path registers fails"
printf 'internal/testkit/archtest/foo_baseline.txt\n' >>"$work/r/scripts/shrink-only.txt"
check 0 "the same file registered passes"

setup
mkdir -p "$work/r/internal/testkit/archtest/more_baseline"
printf 'z\n' >"$work/r/internal/testkit/archtest/more_baseline/a.txt"
check 1 "a file in an archtest baseline directory no path registers fails"

setup
printf '  b\n\ta\n' >"$work/r/$bl/internal_one.txt"
check 0 "a listed line indented is the same line"

setup
: >"$work/r/allow.txt"
printf 'fresh.txt\n' >>"$work/r/scripts/shrink-only.txt"
printf 'x\n' >"$work/r/fresh.txt"
renames "new${tab}fresh.txt"
check 1 "old files emptied into a declared new baseline fail"

setup
counted_base
printf 'p h.go: H: os/user.Current\n' >"$work/r/lookups.txt"
printf 'fresh.txt\n' >>"$work/r/scripts/shrink-only.txt"
printf 'p h.go: os/user.Current\n' >"$work/r/fresh.txt"
renames "new${tab}fresh.txt"
check 1 "a declared new baseline holding a line whose registered count dropped fails"

setup
printf 'z\n' >"$work/r/internal/testkit/archtest/foo_allowlist.txt"
check 1 "an archtest allowlist file no path registers fails"
printf 'internal/testkit/archtest/foo_allowlist.txt\n' >>"$work/r/scripts/shrink-only.txt"
check 0 "the same allowlist registered passes"

exit "$fail"
