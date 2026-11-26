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
	cp "$ROOT/scripts/baseline-shrink.sh" "$work/r/scripts/"
	printf '# baselines\n%s\nallow.txt\n' "$bl" >"$work/r/scripts/shrink-only.txt"
	printf '# renames\n' >"$work/r/scripts/baseline-renames.txt"
	printf 'a\nb\n' >"$work/r/$bl/internal_one.txt"
	printf 'x\n' >"$work/r/allow.txt"
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
check 0 "a removed baseline passes"

setup
printf 'a2\nb\n' >"$work/r/$bl/internal_one.txt"
renames "a${tab}a2"
check 0 "a listed rename passes"

setup
printf 'a2\nb\nc\n' >"$work/r/$bl/internal_one.txt"
renames "a${tab}a2"
check 1 "a line beside a listed rename still fails"

setup
printf 'a\nb\na2\n' >"$work/r/$bl/internal_one.txt"
renames "a${tab}a2"
check 1 "a rename whose old line stays is growth"

setup
printf 'b\n' >"$work/r/$bl/internal_one.txt"
printf 'a\n' >"$work/r/$bl/internal_moved.txt"
check 1 "a line moved to another file without a rename fails"

setup
printf 'b\n' >"$work/r/$bl/internal_one.txt"
printf 'a\n' >"$work/r/$bl/internal_moved.txt"
renames "a${tab}a"
check 0 "a line moved to another file with a rename passes"

setup
renames "gone${tab}new"
check 1 "a rename whose old line no base baseline holds fails"

exit "$fail"
