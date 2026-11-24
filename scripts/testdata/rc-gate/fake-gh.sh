#!/bin/sh
# Stands in for gh in scripts/rc-gate_test.sh: answers "gh api <path>" from
# the recorded JSON in $RC_GATE_FIXTURE and logs every path it was asked for.
set -eu
[ "$1" = api ] || { echo "fake-gh: only api is served" >&2; exit 2; }
echo "$2" >>"$RC_GATE_FIXTURE.log"
case "$2" in
*/actions/workflows/release.yml/runs\?*) cat "$RC_GATE_FIXTURE/runs.json" ;;
*/actions/runs/*/jobs\?*)
	id=${2#*/actions/runs/}
	id=${id%%/*}
	cat "$RC_GATE_FIXTURE/jobs-$id.json"
	;;
*)
	echo "fake-gh: unexpected path $2" >&2
	exit 2
	;;
esac
