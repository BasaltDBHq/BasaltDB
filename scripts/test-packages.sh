#!/bin/sh
# Print the Go packages of one CI test shard, one per line.
#
#   scripts/test-packages.sh 1     shard 1, the packages listed under "shard 1" in scripts/test-shards.txt
#   scripts/test-packages.sh rest  every package no shard lists
#
# "rest" is computed from go list, so a new package lands in it without any
# edit and every package is in exactly one shard. A package listed in
# test-shards.txt that no longer exists fails the script.
set -eu
cd "$(dirname "$0")/.."
shard=${1:?usage: test-packages.sh <shard|rest>}
all=$(go list ./...)
prefix=$(go list -m)/
listed=$(awk '/^[[:space:]]*(#|$)/{next} $1=="shard"{next} {print $1}' scripts/test-shards.txt | sed "s|^|$prefix|")
for p in $listed; do
	printf '%s\n' "$all" | grep -qxF "$p" || { echo "test-shards.txt lists unknown package ${p#"$prefix"}" >&2; exit 1; }
done
dups=$(printf '%s\n' "$listed" | sort | uniq -d)
[ -z "$dups" ] || { echo "test-shards.txt lists a package twice: $dups" >&2; exit 1; }
if [ "$shard" = rest ]; then
	printf '%s\n' "$all" | grep -vxF "$listed"
else
	awk -v want="$shard" '$1=="shard"{cur=$2; next} /^[[:space:]]*(#|$)/{next} cur==want{print $1}' scripts/test-shards.txt | sed "s|^|$prefix|"
fi
