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

# pkgroot may import only pkg/ packages from this module: an import of any
# other module package would make internal code look live.
bad=$(go list -f '{{join .Imports "\n"}}' ./internal/testkit/pkgroot |
	awk -v prefix="$prefix" 'index($0, prefix) == 1 && index($0, prefix "pkg/") != 1')
if [ -n "$bad" ]; then
	echo "internal/testkit/pkgroot imports module packages outside pkg/:" >&2
	printf '%s\n' "$bad" | sed "s|^$prefix|  |" >&2
	exit 1
fi

# deadcode reports only packages a root reaches, so a package no root reaches
# would hide all its code. Every module package must be reached on linux or
# darwin, except:
#   - internal/testkit/... and scripts/...;
#   - the test helpers named below. A package with a path element ending in
#     "test" must be on that list, so a new helper is added on purpose;
#   - packages with no non-test Go function (nofunc): they cannot hold dead
#     code, and the check fails when one gains a function;
#   - api/plugin, the exported plugin contract package: its consumers and the
#     contract tests call its helpers.
helpers="e2e/release/installscript
internal/core/approval/approvaltest
internal/core/channel/channeltest
internal/core/linkcodec/linkcodectest
internal/core/links/linkstest
internal/core/passkey/passkeytest
internal/core/revert/reverttest
internal/core/textrule/textruletest
internal/platform/mcpserver/mcptest
internal/platform/postgres/guard/guardtest
internal/platform/vault/pagetest
internal/platform/vault/vaulttest
internal/plugin/out/plugintransport/adaptertest
internal/plugin/out/plugintransport/testnotifier
internal/plugin/out/plugintransport/testnotifier/cmd/basalt-test-notifier
pkg/trustprofile/trustprofiletest"
nofunc="api/connect
api/mcp/vault
internal/app/servedagent"
contract="api/plugin"
exempt="$helpers
$nofunc
$contract"
for os in linux darwin; do
	# shellcheck disable=SC2086
	GOOS=$os GOARCH=amd64 CGO_ENABLED=0 go list -deps $roots
done | LC_ALL=C sort -u >"$tmp/reached"
go list ./... | sed "s|^$prefix||" | awk '!/^(internal\/testkit|scripts)(\/|$)/' | LC_ALL=C sort >"$tmp/all"
printf '%s\n' "$exempt" | LC_ALL=C sort >"$tmp/exempt"
sed "s|^$prefix||" "$tmp/reached" | LC_ALL=C sort >"$tmp/reached.rel"

unlisted=$(awk -F/ '{for (i = 1; i <= NF; i++) if ($i ~ /test$/) {print; next}}' "$tmp/all" |
	LC_ALL=C comm -23 - "$tmp/exempt")
if [ -n "$unlisted" ]; then
	echo "New test helper packages (a path element ends in \"test\"); add them to helpers in scripts/deadcode.sh if they are test helpers, or rename them:" >&2
	printf '%s\n' "$unlisted" | sed 's/^/  /' >&2
	exit 1
fi
stale=$(LC_ALL=C comm -13 "$tmp/all" "$tmp/exempt")
if [ -n "$stale" ]; then
	echo "scripts/deadcode.sh exempts packages that no longer exist; delete them from its lists:" >&2
	printf '%s\n' "$stale" | sed 's/^/  /' >&2
	exit 1
fi
unreached=$(LC_ALL=C comm -23 "$tmp/all" "$tmp/reached.rel" | LC_ALL=C comm -23 - "$tmp/exempt")
if [ -n "$unreached" ]; then
	echo "No root (cmd/basalt, internal/testkit/pkgroot) reaches these packages, so deadcode cannot see them:" >&2
	printf '%s\n' "$unreached" | sed 's/^/  /' >&2
	echo "Use them from the binary, call their pkg/ API from pkgroot, or delete them." >&2
	exit 1
fi
for p in $nofunc; do
	# shellcheck disable=SC2016
	files=$(go list -f '{{$d := .Dir}}{{range .GoFiles}}{{$d}}/{{.}} {{end}}' "./$p")
	# shellcheck disable=SC2086
	if [ -n "$files" ] && grep -q '^func ' $files; then
		echo "$p is listed in scripts/deadcode.sh as having no functions, but now has one; reach it from a root instead" >&2
		exit 1
	fi
done

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
