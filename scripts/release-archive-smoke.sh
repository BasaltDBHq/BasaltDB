#!/bin/sh
# Smoke an extracted GoReleaser archive: the basalt binary runs on this
# OS/arch and prints its version. POSIX sh. Pass the matching archive extract.
set -eu

usage() {
	echo "usage: release-archive-smoke.sh <bin-dir>" >&2
	exit 2
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
	usage
fi
if [ $# -ne 1 ]; then
	usage
fi

BIN=$(CDPATH= cd -- "$1" && pwd)
BASALT="${BIN}/basalt"

if [ ! -x "$BASALT" ]; then
	echo "release-archive-smoke.sh: need executable basalt in $BIN" >&2
	exit 1
fi

got=$(uname -m)
if [ -n "${EXPECT_UNAME:-}" ] && [ "$got" != "$EXPECT_UNAME" ]; then
	echo "release-archive-smoke.sh: uname -m is $got, EXPECT_UNAME=$EXPECT_UNAME" >&2
	exit 1
fi

echo "runner $(uname -s) ${got}"
out=$("$BASALT" version)
case "$out" in
"basalt "*) ;;
*)
	echo "release-archive-smoke.sh: unexpected version output: $out" >&2
	exit 1
	;;
esac
echo "ok ${got}: ${out}"
