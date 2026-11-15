#!/bin/sh
# Publish @basaltdb/cli plus per-platform optionalDependencies from GoReleaser dist/.
# Skips cleanly when NPM_TOKEN is empty. Version comes from VERSION (v* tag) or argv.
set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/require-v-tag.sh"

if [ -z "${NPM_TOKEN:-}" ]; then
	echo "NPM_TOKEN is empty; skipping npm publish."
	echo "Scope @basaltdb is owned by personal npm account basaltdb (unscoped name basaltdb is a different project)."
	echo "Set repo secret NPM_TOKEN on BasaltDBHq/BasaltDB to publish @basaltdb/cli and @basaltdb/{linux-x64,linux-arm64,darwin-x64,darwin-arm64}."
	exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST="${DIST:-$ROOT/dist}"
VER_RAW="${VERSION:-${1:-}}"
require_v_tag "$VER_RAW"
VER="${VER_RAW#v}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

set_version() {
	pkg_json="$1"
	node -e "
const fs = require('fs');
const p = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
p.version = process.argv[2];
if (p.optionalDependencies) {
  for (const k of Object.keys(p.optionalDependencies)) {
    p.optionalDependencies[k] = process.argv[2];
  }
}
fs.writeFileSync(process.argv[1], JSON.stringify(p, null, 2) + '\n');
" "$pkg_json" "$VER"
}

extract_archive() {
	archive="$1"
	dest="$2"
	mkdir -p "$dest"
	case "$archive" in
	*.tar.gz) tar -xzf "$archive" -C "$dest" ;;
	*)
		echo "unknown archive $archive" >&2
		exit 1
		;;
	esac
}

publish_platform() {
	os="$1"
	arch="$2"
	npm_dir="$3"
	ext="$4"
	archive="$DIST/basaltdb_${VER}_${os}_${arch}.${ext}"
	if [ ! -f "$archive" ]; then
		echo "missing $archive" >&2
		exit 1
	fi
	extract="$TMP/$npm_dir"
	extract_archive "$archive" "$extract"
	pkg="$ROOT/npm/platforms/$npm_dir"
	mkdir -p "$pkg/bin"
	cp "$extract/basalt" "$pkg/bin/basalt"
	chmod +x "$pkg/bin/basalt"
	cp "$ROOT/LICENSE" "$pkg/LICENSE"
	set_version "$pkg/package.json"
	echo "publishing @basaltdb/$npm_dir@$VER (tag $NPM_DIST_TAG)"
	(cd "$pkg" && npm publish --access public --tag "$NPM_DIST_TAG")
}

NPM_DIST_TAG=latest
case "$VER" in
*alpha*) NPM_DIST_TAG=alpha ;;
*beta*) NPM_DIST_TAG=beta ;;
*rc*) NPM_DIST_TAG=rc ;;
esac

echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >"$HOME/.npmrc"

publish_platform linux amd64 linux-x64 tar.gz
publish_platform linux arm64 linux-arm64 tar.gz
publish_platform darwin amd64 darwin-x64 tar.gz
publish_platform darwin arm64 darwin-arm64 tar.gz

cp "$ROOT/LICENSE" "$ROOT/npm/cli/LICENSE"
set_version "$ROOT/npm/cli/package.json"
echo "publishing @basaltdb/cli@$VER (tag $NPM_DIST_TAG)"
(cd "$ROOT/npm/cli" && npm publish --access public --tag "$NPM_DIST_TAG")
