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

exit "$fail"
