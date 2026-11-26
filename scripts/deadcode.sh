#!/bin/sh
# Dead code check: runs deadcode (golang.org/x/tools/cmd/deadcode) on the basalt
# binary and on internal/testkit/pkgroot, which calls the public API under
# pkg/, for linux and for darwin. A function counts as dead when it is
# unreachable on every OS that compiles its file. The result must match
# scripts/deadcode-allowlist.txt exactly: a new dead function fails, and so
# does a listed one that is no longer dead (delete its line). The list only
# shrinks.
#
# usage: deadcode.sh <path to the deadcode binary>
set -eu
cd "$(dirname "$0")/.."
dc=${1:?usage: deadcode.sh <deadcode binary>}
allow=scripts/deadcode-allowlist.txt
roots="./cmd/basalt ./internal/testkit/pkgroot"
prefix=$(go list -m)/
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for os in linux darwin; do
	# No pipe: a load error must stop the check, not yield an empty report.
	# shellcheck disable=SC2016,SC2086
	GOOS=$os GOARCH=amd64 CGO_ENABLED=0 "$dc" \
		-f '{{range .Funcs}}{{$.Path}}.{{.Name}}{{"\t"}}{{.Position.File}}{{"\n"}}{{end}}' \
		$roots >"$tmp/dead.$os"
	# shellcheck disable=SC2016,SC2086
	GOOS=$os GOARCH=amd64 CGO_ENABLED=0 go list -deps \
		-f '{{$d := .Dir}}{{range .GoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}' \
		$roots >"$tmp/files.$os"
	sed "s|^$PWD/||" "$tmp/files.$os" >"$tmp/rel.$os"
done

# Dead on one OS and live on the other (its file is compiled there and the
# function is not reported) means live.
awk -F '\t' -v prefix="$prefix" '
	FILENAME ~ /rel\.linux$/  { lfile[$0] = 1; next }
	FILENAME ~ /rel\.darwin$/ { dfile[$0] = 1; next }
	FILENAME ~ /dead\.linux$/ { ldead[$1 "\t" $2] = 1; key[$1 "\t" $2] = 1; next }
	FILENAME ~ /dead\.darwin$/ { ddead[$1 "\t" $2] = 1; key[$1 "\t" $2] = 1; next }
	END {
		for (k in key) {
			split(k, p, "\t")
			if ((ldead[k] || !lfile[p[2]]) && (ddead[k] || !dfile[p[2]])) {
				name = p[1]
				if (index(name, prefix) == 1) name = substr(name, length(prefix) + 1)
				print name
			}
		}
	}
' "$tmp/rel.linux" "$tmp/rel.darwin" "$tmp/dead.linux" "$tmp/dead.darwin" | LC_ALL=C sort -u >"$tmp/dead"

awk '/^[[:space:]]*(#|$)/{next} {print $1}' "$allow" | LC_ALL=C sort -u >"$tmp/allowed"

new=$(LC_ALL=C comm -23 "$tmp/dead" "$tmp/allowed")
gone=$(LC_ALL=C comm -13 "$tmp/dead" "$tmp/allowed")
status=0
if [ -n "$new" ]; then
	echo "New dead code: no caller reaches these functions from cmd/basalt or the pkg/ API." >&2
	echo "Delete them, or call them where they belong. Do not add them to $allow." >&2
	echo "(A new exported function under pkg/ goes into internal/testkit/pkgroot.)" >&2
	printf '%s\n' "$new" | sed 's/^/  /' >&2
	status=1
fi
if [ -n "$gone" ]; then
	echo "These $allow entries are no longer dead code; delete their lines:" >&2
	printf '%s\n' "$gone" | sed 's/^/  /' >&2
	status=1
fi
[ "$status" -ne 0 ] || echo "deadcode: $(wc -l <"$tmp/dead" | tr -d ' ') known dead functions, nothing new"
exit "$status"
