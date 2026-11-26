#!/bin/sh
# Cases for scripts/baseline-shrink.sh, in a throwaway git repository.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0

# setup builds a repository whose first commit (the base) has one
# registered baseline directory and one registered baseline file.
setup() {
	rm -rf "$work/r"
	mkdir -p "$work/r/scripts" "$work/r/base"
	cp "$ROOT/scripts/baseline-shrink.sh" "$work/r/scripts/"
	printf '# baselines\nbase\nallow.txt\n' >"$work/r/scripts/shrink-only.txt"
	printf 'a\nb\n' >"$work/r/base/one.txt"
	printf 'x\n' >"$work/r/allow.txt"
	git -C "$work/r" init -q
	git -C "$work/r" add -A
	git -C "$work/r" -c user.name=t -c user.email=t@t commit -qm base
}

check() { # want-exit description
	if sh "$work/r/scripts/baseline-shrink.sh" HEAD 2>/dev/null; then got=0; else got=1; fi
	if [ "$got" != "$1" ]; then
		echo "FAIL baseline-shrink: $2 (exit $got, want $1)" >&2
		fail=1
	fi
}

setup
check 0 "an unchanged tree passes"

setup
printf 'b\n' >"$work/r/base/one.txt"
check 0 "a removed line passes"

setup
printf 'b\na\n\n' >"$work/r/base/one.txt"
check 0 "reordered lines and a blank line pass"

setup
printf 'a\nb\nc\n' >"$work/r/base/one.txt"
check 1 "an added line fails"

setup
printf 'y\n' >"$work/r/base/two.txt"
check 1 "a new file in a baseline directory fails"

setup
printf 'x\nz\n' >"$work/r/allow.txt"
check 1 "an added line in a baseline file fails"

setup
printf 'base\nallow.txt\nnew\n' >"$work/r/scripts/shrink-only.txt"
mkdir "$work/r/new"
printf 'n\n' >"$work/r/new/n.txt"
check 0 "a new baseline is created in full"

setup
printf '' >"$work/r/scripts/shrink-only.txt"
printf 'a\nb\nc\n' >"$work/r/base/one.txt"
check 1 "unlisting a baseline does not let it grow"

setup
rm -r "$work/r/base"
check 0 "a removed baseline passes"

exit "$fail"
