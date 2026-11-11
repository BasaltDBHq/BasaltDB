#!/bin/sh
# Publish server.json to the official MCP registry.
# Skips cleanly when MCP_REGISTRY_TOKEN is empty.
set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/require-v-tag.sh"

if [ -z "${MCP_REGISTRY_TOKEN:-}" ]; then
	echo "MCP_REGISTRY_TOKEN is empty; skipping MCP registry publish."
	echo "Official MCP registry publish is deferred until BasaltDBHq/BasaltDB is public."
	echo "server.json name / npm mcpName: io.github.basaltdbhq/basaltdb"
	exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VER_RAW="${VERSION:-${1:-}}"
require_v_tag "$VER_RAW"
VER="${VER_RAW#v}"

node -e "
const fs = require('fs');
const p = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
p.version = process.argv[2];
if (p.repository && process.env.GITHUB_REPOSITORY) {
  p.repository.url = 'https://github.com/' + process.env.GITHUB_REPOSITORY;
}
if (p.packages) {
  for (const pkg of p.packages) {
    if (pkg.registryType === 'npm') pkg.version = process.argv[2];
  }
}
fs.writeFileSync(process.argv[1], JSON.stringify(p, null, 2) + '\n');
" "$ROOT/server.json" "$VER"

# mcp-publisher reads a token from MCP_REGISTRY_TOKEN or a login store.
export MCP_REGISTRY_TOKEN
npx --yes mcp-publisher publish "$ROOT/server.json"
