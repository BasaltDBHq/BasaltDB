#!/usr/bin/env bash
# Runs the compose example end to end without systemd: builds the image, sets
# up the guard and the engine's files, starts the engine (root under tini,
# dropped to basalt by basalt engine --user) and the agent, checks the drop
# and the isolation, makes agent calls, restarts the engine, then removes the
# guard and everything the example made. make test-compose runs it.
set -euo pipefail

cd "$(dirname "$0")"
project="basalt-smoke-$$"
dc() { docker compose -p "$project" "$@"; }
admin='postgres://postgres:example-admin-password@postgres:5432/app?sslmode=disable'

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		echo "--- engine log" >&2
		dc logs engine >&2 || true
	fi
	dc down -v --remove-orphans >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

fail() {
	echo "smoke: FAIL: $*" >&2
	exit 1
}
step() { echo "smoke: $*"; }

# mcp sends JSON-RPC lines to basalt mcp in the agent container, as agent.
mcp() {
	{
		echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
		echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
		for line in "$@"; do echo "$line"; done
		sleep 3
	} | dc exec -T agent basalt mcp --agent demo_bot
}

wait_socket() {
	for _ in $(seq 1 60); do
		if dc exec -T agent test -S /run/basalt/demo_bot.sock 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	fail "the engine's socket did not appear"
}

# wait_served waits until the engine log says n times that it serves the agent.
wait_served() {
	for _ in $(seq 1 60); do
		if [ "$(dc logs engine 2>&1 | grep -c 'msg="serving agent" agent=demo_bot')" -ge "$1" ]; then
			return 0
		fi
		sleep 1
	done
	fail "the engine did not serve demo_bot (start $1)"
}

step "build"
dc build -q engine

step "start postgres"
dc up -d --wait postgres

step "setup: basalt init as the engine's user (no systemd, so no service install)"
dc run --rm -T --no-deps --user basalt -e BASALT_ADMIN_DATABASE_URL="$admin" engine \
	basalt init --demo --os-user agent --config /etc/basalt/engine.json --socket-dir /run/basalt \
	--skip-passkey --yes </dev/null

step "start the engine and the agent"
dc up -d engine agent
wait_served 1
wait_socket

step "the engine runs as basalt on every thread, with no_new_privs"
basalt_uid=$(dc exec -T engine id -u basalt)
status=$(dc exec -T engine sh -c 'for f in /proc/[0-9]*/status; do grep -q "^Name:[[:space:]]*basalt$" "$f" && cat "$f"; done')
echo "$status" | grep -q "^Uid:[[:space:]]*$basalt_uid[[:space:]]*$basalt_uid[[:space:]]*$basalt_uid[[:space:]]*$basalt_uid$" ||
	fail "engine uids: $(echo "$status" | grep '^Uid:')"
echo "$status" | grep -q "^NoNewPrivs:[[:space:]]*1$" || fail "no_new_privs is not set"
echo "$status" | grep -q "^CapEff:[[:space:]]*0000000000000000$" || fail "the engine kept capabilities"
dc logs engine 2>&1 | grep -q "dropped root; running as basalt" || fail "no drop line in the engine log"

step "isolation: the agent sees the socket and nothing else of the engine"
dc exec -T agent test ! -e /etc/basalt/engine.json || fail "the agent container sees engine.json"
mounts=$(dc exec -T agent sh -c "awk '\$2 ~ /basalt/ {print \$2}' /proc/mounts")
[ "$mounts" = "/run/basalt" ] || fail "the agent container mounts more than the socket directory: $mounts"
dc exec -T agent test ! -e /var/lib/basalt/. || fail "the agent container sees the engine's state"
dc exec -T agent sh -c 'cat /run/basalt/engine.lock' 2>/dev/null && fail "the agent reads the engine's lock file"
dc exec -T --user agent engine cat /etc/basalt/agents/demo_bot.url >/dev/null 2>&1 &&
	fail "the agent's OS user reads the credential in the engine container"
dc exec -T --user agent engine cat /etc/basalt/engine.json >/dev/null 2>&1 &&
	fail "the agent's OS user reads engine.json in the engine container"

step "agent calls over the socket"
out=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT count(*) AS n FROM basalt_demo.leads"}}}' \
	'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write","arguments":{"sql":"UPDATE basalt_demo.leads SET status = '"'"'CONTACTED'"'"' WHERE id = 1","intent":"Mark lead 1 contacted (smoke test)"}}}')
echo "$out" | grep -q '"id":2' || fail "no query answer: $out"
echo "$out" | grep -q '30' || fail "query did not count 30 leads: $out"
echo "$out" | grep -q 'APPLIED' || fail "write was not APPLIED: $out"

step "restart the engine"
dc restart engine
wait_served 2
wait_socket
out=$(mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT status FROM basalt_demo.leads WHERE id = 1"}}}')
echo "$out" | grep -q 'CONTACTED' || fail "query after restart: $out"
[ "$(dc logs engine 2>&1 | grep -c 'dropped root; running as basalt')" -ge 2 ] || fail "the restarted engine did not drop root"

step "the person's log, as the engine's user"
dc exec -T --user basalt -e XDG_CACHE_HOME=/var/lib/basalt/cli engine basalt log --agent demo_bot --config /etc/basalt/engine.json | grep -q 'basalt_demo.leads' ||
	fail "basalt log does not show the write"

step "uninstall: remove the guard, then the containers and volumes"
dc stop engine
dc run --rm -T --no-deps --user basalt -e BASALT_ADMIN_DATABASE_URL="$admin" engine basalt uninstall --yes </dev/null
step "PASS"
