#!/usr/bin/env bash
# Runs a plugin under its real systemd unit and checks the unit's isolation
# from inside and outside it: basalt init installs the engine service, a
# signed local plugin (./probe) is trusted and installed by hand as a config
# entry (its copy under /opt/basalt/plugins and its entry in engine.json, as
# root), basalt service install writes its unit, and the engine is
# restarted. Then:
#   - the install made the plugin base /opt/basalt and its run/ as root's;
#   - the plugin, from inside its unit, finds no network (empty egress), no
#     chmod, a read-only copy, a /tmp of its own, the engine's directories and
#     /home hidden, no other process, no new privileges and no capabilities;
#     the same checks run as its OS user outside the unit see none of that;
#   - from outside, the process runs as the plugin's own user with its own
#     network namespace (loopback only) and the unit's memory limit;
#   - an agent's OS user cannot connect to the plugin's socket, the engine's
#     user can, and the engine connects and records network ENFORCED;
#   - Fedora's stock service.d/10-timeout-abort.conf is applied by systemd and
#     the engine still connects; a drop-in that turns the network back on is
#     applied by systemd and the engine refuses the plugin until it is gone;
#   - under the engine unit's own sandbox settings, the engine's user writes a
#     program into its state directory, starts it, and reaches it on a Unix
#     socket (./spawn), as an engine that runs a plugin itself would;
#
# Not covered here since basalt plugin is gone: removing a config entry's
# unit, user and socket directory (there is no command for it), and an agent
# adding a plugin through request_plugin, which this setup's agent cannot do
# (it has its own OS user, which the person socket refuses); the engine's
# tests cover that path.
#
# It changes the machine as root (users, units, /opt/basalt, /etc/basalt), so
# it runs only on a throwaway CI runner with systemd and passwordless sudo:
# make test-systemd, with BASALT_ADMIN_DATABASE_URL set to a Postgres admin URL.
set -euo pipefail

cd "$(dirname "$0")/../.."

fail() {
	echo "systemd-smoke: FAIL: $*" >&2
	exit 1
}
step() { echo "systemd-smoke: $*"; }

[ -n "${BASALT_ADMIN_DATABASE_URL:-}" ] || fail "set BASALT_ADMIN_DATABASE_URL"
[ "$(id -u)" -ne 0 ] || fail "run as the person (a user with passwordless sudo), not root"
[ "$(ps -o comm= -p 1)" = systemd ] || fail "systemd is not PID 1 here"

agent=demo_bot
agent_user="basalt-smoke-agent"
engine_unit="basalt-engine.service"
name=sandbox-probe
unit=basalt-plugin-$name-default.service
basalt=/usr/local/bin/basalt
marker=/tmp/basalt-systemd-smoke-marker
hidden=/etc/basalt,/var/lib/basalt,/run/basalt
fedora_dropin=/usr/lib/systemd/system/service.d/10-timeout-abort.conf
bad_dropin=/etc/systemd/system/$unit.d/50-smoke-network.conf
work=$(mktemp -d)

dump() {
	status=$?
	if [ "$status" -ne 0 ]; then
		for u in "$engine_unit" "$unit"; do
			echo "--- systemctl status $u" >&2
			sudo systemctl status --no-pager "$u" >&2 || true
			echo "--- systemctl cat $u" >&2
			sudo systemctl cat --no-pager "$u" >&2 || true
			echo "--- journal of $u" >&2
			sudo journalctl --no-pager -o short-precise -n 200 -u "$u" >&2 || true
		done
	fi
	exit "$status"
}
trap dump EXIT

# wait_for runs its arguments until they succeed, for up to 60 seconds.
wait_for() {
	local what=$1
	shift
	for _ in $(seq 1 120); do
		if "$@"; then
			return 0
		fi
		sleep 0.5
	done
	fail "timed out waiting for $what"
}

# run_log prints the journal of the plugin unit's current run.
run_log() {
	local id
	id=$(systemctl show -p InvocationID --value "$unit")
	[ -n "$id" ] || return 0
	sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID="$id"
}

# new_run waits for a run of the plugin unit other than $1 that has finished
# its checks, and prints its invocation id.
new_run() {
	local prev=$1 id log
	for _ in $(seq 1 120); do
		id=$(systemctl show -p InvocationID --value "$unit")
		if [ -n "$id" ] && [ "$id" != "$prev" ]; then
			log=$(sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID="$id")
			if grep -qx 'probe done' <<<"$log"; then
				echo "$id"
				return 0
			fi
		fi
		sleep 0.5
	done
	fail "no new run of $unit finished its checks"
}

# The checks read whole outputs before grep: grep -q stops at its first
# match, and with pipefail a writer cut off by that closed pipe fails.
run_has() {
	local log
	log=$(run_log)
	grep -qx "$1" <<<"$log"
}

status_out() { "$basalt" status --agent "$agent" 2>&1 || true; }
unavailable() {
	local out
	out=$(status_out)
	grep -q "PLUGIN_UNAVAILABLE" <<<"$out"
}
connected() { run_has 'probe initialized' && ! unavailable; }
# dropin_refused: status names a systemd drop-in as why the plugin is not
# reached, the cause the engine gives only after it checked the drop-ins.
dropin_refused() {
	local out
	out=$(status_out)
	grep -qF "a systemd drop-in or another unit file of the same name changes its service unit" <<<"$out"
}

restart_engine() { sudo systemctl restart "$engine_unit"; }

# connect_as tries the plugin's socket as an OS user and prints OK or the
# error number's name.
connect_as() {
	sudo -u "$1" python3 -c '
import errno, socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
    print("OK")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)))
' "$sock"
}

step "the runner"
uname -r
systemctl --version | head -1
stat -c '%U:%G %a %n' / /opt /usr/local /usr/local/bin
for d in / /opt /usr /usr/local /usr/local/bin; do
	[ "$(stat -c '%u' "$d")" = 0 ] && [ $((0$(stat -c '%a' "$d") & 022)) = 0 ] ||
		fail "$d must be root's and writable by root alone, as on a stock distribution"
done

step "build basalt and the probe plugin"
CGO_ENABLED=0 go build -trimpath -o "$work/basalt" ./cmd/basalt
mkdir -p "$work/src/bin"
CGO_ENABLED=0 go build -trimpath -o "$work/src/bin/$name" ./scripts/systemd-smoke/probe
sudo install -o root -g root -m 0755 "$work/basalt" "$basalt"

step "basalt init installs the engine service"
sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$agent_user"
# The hosted runner has no desktop, so no administrator dialog: basalt init
# says so and stops, never falling back to running the engine as this user.
# It never reads the admin connection string, which this job's environment
# holds: the setup page takes it.
[ ! -e /usr/bin/pkexec ] || sudo mv /usr/bin/pkexec /usr/bin/pkexec.smoke-aside
if "$basalt" init --demo >"$work/nodialog.out" 2>&1 </dev/null; then
	cat "$work/nodialog.out" >&2
	fail "basalt init went on without an administrator dialog"
fi
grep -q "cannot be shown here" "$work/nodialog.out" || {
	cat "$work/nodialog.out" >&2
	fail "basalt init did not say there is no administrator dialog"
}
[ ! -e /etc/systemd/system/basalt-engine.service ] || fail "a unit was installed without an administrator dialog"
# A stand-in pkexec answers yes through sudo, so the real install script
# runs as root; it takes only the arguments basalt init passes.
sudo tee /usr/bin/pkexec >/dev/null <<'EOF'
#!/bin/sh
[ "$1" = --disable-internal-agent ] || exit 127
shift
exec sudo -n "$@"
EOF
sudo chmod 0755 /usr/bin/pkexec
# init installs the service, waits for the engine's setup page and prints
# the link (then the agent's MCP line); there is no browser to open here.
"$basalt" init --demo >"$work/init.out" 2>"$work/init.err" </dev/null || {
	cat "$work/init.out" "$work/init.err" >&2
	fail "basalt init"
}
link=$(head -1 "$work/init.out")
case $link in http://localhost:8787/setup/\#1.*) ;; *) cat "$work/init.out" >&2; fail "basalt init printed no setup link" ;; esac
grep -qx "basalt mcp --agent $agent" "$work/init.out" || fail "basalt init printed no MCP line for $agent"
if sudo test -e /etc/basalt/engine.json; then fail "an engine.json exists before the setup page ran"; fi
# The person's part of the page: the check, a passkey, the run.
CGO_ENABLED=0 go build -trimpath -o "$work/setup" ./scripts/systemd-smoke/setup
printf '%s\n' "$BASALT_ADMIN_DATABASE_URL" | "$work/setup" "$link" >"$work/setup.out" || fail "the setup page's install"
[ "$(cat "$work/setup.out")" = "$agent" ] || fail "the setup set up $(cat "$work/setup.out"), not $agent"
wait_for "the engine's agent socket" sudo test -S "/run/basalt/$agent.sock"
# The steps below restart the engine several times within seconds: clear
# systemd's start-rate count so its default limit (5 starts in 10s)
# measures the steps, not the install.
sudo systemctl reset-failed "$engine_unit"
# Started by the dialog before engine.json existed, the engine waited for it
# and served only its setup page: no exit on the missing file, no crash loop.
if sudo journalctl --no-pager -o cat -u "$engine_unit" | grep -E 'engine.json: no such file|crashed [0-9]+ times' >&2; then
	fail "the engine exited on its missing config instead of waiting for it"
fi
sudo journalctl --no-pager -o cat -u "$engine_unit" | grep -q 'no engine config yet: serving only the setup page' ||
	fail "the engine started with no config did not serve its setup page"
for d in /opt/basalt /opt/basalt/run; do
	got=$(stat -c '%U:%G %a' "$d") || fail "basalt service install did not make $d"
	[ "$got" = "root:root 755" ] || fail "$d is $got, not root:root 755"
	echo "$d: $got"
done

step "sign the plugin, trust its key, install it by hand as a config entry"
# Signing is the plugin SDK's basalt-plugin, not the basalt binary; trusting a
# key is placing its public file in the root-owned trust store.
plugin_tool="github.com/basaltdbhq/basalt-plugin-go/cmd/basalt-plugin@${BASALT_PLUGIN_SDK_REF:-cbf5a09dddfebe69a8e3efd6ba704c76418f00d6}"
sum=$(sha256sum "$work/src/bin/$name" | cut -d' ' -f1)
cat >"$work/src/basalt-plugin.json" <<EOF
{
  "manifestVersion": 1, "name": "$name", "version": "0.1.0", "publisher": "Basalt CI",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "feed.observe": { "contract": "feed/1" } },
  "endpoint": { "local": { "transport": "jsonrpc-unix", "command": "bin/$name",
    "args": ["-hidden", "$hidden", "-marker", "$marker"] } },
  "files": { "bin/$name": "sha256:$sum" },
  "network": { "egress": [] }
}
EOF
keys=$(go run "$plugin_tool" keygen --out "$work/keys")
key_id=$(echo "$keys" | awk '$1 == "key" && $2 == "id" {print $3}')
pub=$(echo "$keys" | awk '$1 == "public" && $2 == "key" {print $3}')
[ -n "$key_id" ] && [ -n "$pub" ] || fail "keygen printed: $keys"
go run "$plugin_tool" sign "$work/src" --key "$work/keys/$key_id.key"
sudo install -d -o root -g root -m 0755 /opt/basalt/plugin-trust
sudo install -o root -g root -m 0644 "$pub" "/opt/basalt/plugin-trust/$key_id.pem"
# The installed copy: <root>/<name>/<instance>/<manifest sha256>/, root's,
# directories 0755, the command 0755 and every other file 0644.
manifest_sha=$(sha256sum "$work/src/basalt-plugin.json" | cut -d' ' -f1)
copy_dir=/opt/basalt/plugins/$name/default/$manifest_sha
for d in /opt/basalt/plugins "/opt/basalt/plugins/$name" "/opt/basalt/plugins/$name/default" "$copy_dir" "$copy_dir/bin"; do
	sudo install -d -o root -g root -m 0755 "$d"
done
sudo install -o root -g root -m 0644 "$work/src/basalt-plugin.json" "$work/src/basalt-plugin.json.sig" "$copy_dir/"
sudo install -o root -g root -m 0755 "$work/src/bin/$name" "$copy_dir/bin/$name"
# The entry in engine.json, which keeps its owner and mode.
config_owner=$(sudo stat -c '%U:%G' /etc/basalt/engine.json)
config_mode=$(sudo stat -c '%a' /etc/basalt/engine.json)
sudo cat /etc/basalt/engine.json | jq --arg n "$name" --arg s "$manifest_sha" --arg a "$agent" \
	'.plugins = [{"name": $n, "instance": "default", "manifestSha256": $s, "enabled": true, "agents": [$a]}]' >"$work/engine.json"
sudo install -o "${config_owner%%:*}" -g "${config_owner##*:}" -m "$config_mode" "$work/engine.json" /etc/basalt/engine.json
# basalt service install writes every local config entry's unit.
installed=$(sudo "$basalt" service install 2>&1) || fail "basalt service install: $installed"
touch "$marker"
run=$(systemctl show -p InvocationID --value "$unit")
restart_engine
run=$(new_run "$run")

user=$(systemctl show -p User --value "$unit")
case "$user" in basalt-plugin-*) ;; *) fail "$unit runs as '$user'" ;; esac
sock=/opt/basalt/run/$user/p.sock
copy=$(systemctl show -p WorkingDirectory --value "$unit")
case "$copy" in /opt/basalt/plugins/$name/default/*) ;; *) fail "$unit runs from '$copy'" ;; esac

step "inside the unit, the plugin finds its sandbox"
log=$(run_log)
grep '^probe ' <<<"$log"
grep -q '^probe FAIL' <<<"$log" && fail "a check inside the unit failed"
for c in no-inet-socket no-inet6-socket no-chmod read-only-copy private-tmp home-hidden \
	other-processes-hidden no-new-privileges no-bounding-capabilities \
	"hidden /etc/basalt" "hidden /var/lib/basalt" "hidden /run/basalt"; do
	grep -q "^probe ok $c: " <<<"$log" || fail "no passing check '$c' inside the unit"
done

step "outside the unit, as the plugin's user, the same checks see none of it"
sudo -u "$user" env "BASALT_PLUGIN_SOCKET=$sock" /bin/sh -c 'cd "$1" && shift && exec "$@"' sh "$copy" \
	"$copy/bin/$name" -control -hidden "$hidden" -marker "$marker" ||
	fail "a check outside the unit saw the sandbox: it does not show the unit's effect"

step "from outside: its own user, network namespace and memory limit"
pid=$(systemctl show -p MainPID --value "$unit")
[ "$pid" -gt 0 ] || fail "$unit has no main process"
proc_status=$(sudo cat "/proc/$pid/status")
uid=$(id -u "$user")
grep -Eq "^Uid:[[:space:]]+${uid}[[:space:]]+${uid}[[:space:]]+${uid}[[:space:]]+${uid}$" <<<"$proc_status" ||
	fail "the plugin's uids: $(grep '^Uid:' <<<"$proc_status")"
[ "$uid" -ne 0 ] && [ "$uid" -ne "$(id -u basalt)" ] || fail "the plugin runs as root or the engine's user"
grep -Eq '^Seccomp:[[:space:]]+2$' <<<"$proc_status" || fail "no system call filter"
echo "runs as $user (uid $uid), with a system call filter"
[ "$(sudo readlink "/proc/$pid/ns/net")" != "$(sudo readlink /proc/1/ns/net)" ] ||
	fail "the plugin shares the host's network namespace"
links=$(sudo nsenter --net="/proc/$pid/ns/net" ip -o link show | awk -F': ' '{print $2}')
[ "$links" = lo ] || fail "the plugin's network namespace has more than loopback: $links"
pg_port=$(echo "$BASALT_ADMIN_DATABASE_URL" | sed -E 's#^[^@]*@[^:/]*:([0-9]+).*#\1#')
bash -c "exec 3<>/dev/tcp/127.0.0.1/$pg_port" || fail "control: Postgres is not reachable on 127.0.0.1:$pg_port"
sudo nsenter --net="/proc/$pid/ns/net" bash -c "exec 3<>/dev/tcp/127.0.0.1/$pg_port" 2>/dev/null &&
	fail "the plugin's network namespace reaches the host's 127.0.0.1:$pg_port"
echo "its own network namespace: links '$links'; the host's 127.0.0.1:$pg_port is reachable outside it, not inside"
cgroup=$(sudo awk -F: '$1 == "0" {print $3}' "/proc/$pid/cgroup")
mem=$(cat "/sys/fs/cgroup$cgroup/memory.max")
[ "$mem" = $((1024 * 1024 * 1024)) ] || fail "memory.max is $mem"
echo "memory.max $mem"

step "socket access: an agent's OS user cannot connect, the engine's user can"
sudo test -S "$sock" || fail "no socket at $sock"
got=$(connect_as "$agent_user")
[ "$got" = EACCES ] || fail "the agent's OS user connecting got $got, not EACCES"
echo "$agent_user: $got"
got=$(connect_as basalt)
[ "$got" = OK ] || fail "the engine's user connecting got $got"
echo "basalt: $got"

step "the engine connects and records network ENFORCED"
wait_for "the engine to initialize the plugin" connected
plugins=$("$basalt" log --agent "$agent" 2>&1 >/dev/null | grep '^Plugins:' || true)
echo "$plugins"
grep -qF "$name/default 0.1.0 (signer $key_id, LOCAL, files OS_USER, network ENFORCED)" <<<"$plugins" ||
	fail "basalt log does not record the plugin served with network ENFORCED"

step "Fedora's stock drop-in: systemd applies it and the engine still connects"
sudo mkdir -p "$(dirname "$fedora_dropin")"
sudo tee "$fedora_dropin" >/dev/null <<'EOF'
# This file is part of the systemd package.
# See https://fedoraproject.org/wiki/Changes/Shorter_Shutdown_Timer.
#
# To facilitate debugging when a service fails to stop cleanly,
# TimeoutStopFailureMode=abort is set to "crash" services that fail to stop in
# the time allotted. This will cause the service to be terminated with SIGABRT
# and a coredump to be generated.
#
# To undo this configuration change, create a mask file:
#   sudo mkdir -p /etc/systemd/system/service.d
#   sudo ln -sv /dev/null /etc/systemd/system/service.d/10-timeout-abort.conf

[Service]
TimeoutStopFailureMode=abort
EOF
sudo systemctl daemon-reload
dropins=$(systemctl show -p DropInPaths --value "$unit")
grep -qF "$fedora_dropin" <<<"$dropins" || fail "systemd does not apply $fedora_dropin: $dropins"
echo "DropInPaths: $dropins"
[ "$(systemctl show -p TimeoutStopFailureMode --value "$unit")" = abort ] || fail "TimeoutStopFailureMode is not abort"
restart_engine
run=$(new_run "$run")
wait_for "the engine to initialize the plugin with Fedora's drop-in" connected

step "a drop-in that turns the network on: systemd applies it, the engine refuses the plugin"
sudo mkdir -p "$(dirname "$bad_dropin")"
printf '[Service]\nPrivateNetwork=no\n' | sudo tee "$bad_dropin" >/dev/null
sudo systemctl daemon-reload
dropins=$(systemctl show -p DropInPaths --value "$unit")
grep -qF "$bad_dropin" <<<"$dropins" || fail "systemd does not apply $bad_dropin: $dropins"
echo "DropInPaths: $dropins"
[ "$(systemctl show -p PrivateNetwork --value "$unit")" = no ] || fail "the drop-in did not turn PrivateNetwork off"
restart_engine
run=$(new_run "$run")
pid=$(systemctl show -p MainPID --value "$unit")
[ "$(sudo readlink "/proc/$pid/ns/net")" = "$(sudo readlink /proc/1/ns/net)" ] ||
	fail "control: with the drop-in the plugin should share the host's network namespace"
wait_for "status to name the drop-in as the cause" dropin_refused
status_out | grep -A3 PLUGIN_UNAVAILABLE
run_has 'probe initialized' && fail "the engine connected to a plugin whose unit a drop-in changed"

step "drop-in removed: the engine connects again"
sudo rm -f "$bad_dropin"
sudo rmdir "$(dirname "$bad_dropin")"
sudo systemctl daemon-reload
restart_engine
run=$(new_run "$run")
wait_for "the engine to initialize the plugin again" connected

sudo rm -f "$fedora_dropin"
sudo systemctl daemon-reload

step "the engine's own sandbox lets its user start a program from its state directory"
# A transient unit gets every [Service] setting of the installed engine unit
# but what it runs and RuntimeDirectory (systemd removes a unit's runtime
# directory when it stops, and /run/basalt holds the running engine's
# sockets). In it, ./spawn writes a copy of itself into the state directory,
# starts it as a child and reaches it on a socket in the unit's /tmp and on
# one under the state directory.
CGO_ENABLED=0 go build -trimpath -o "$work/spawn" ./scripts/systemd-smoke/spawn
spawn_bin=/usr/local/bin/basalt-smoke-spawn
spawn_unit="basalt-smoke-spawn.service"
sudo install -o root -g root -m 0755 "$work/spawn" "$spawn_bin"
props=()
in_service=0
while IFS= read -r line; do
	case "$line" in
	'[Service]') in_service=1 ;;
	'['*) in_service=0 ;;
	'' | '#'*) ;;
	*)
		[ "$in_service" = 1 ] || continue
		case "${line%%=*}" in
		ExecStart | Type | Restart | RestartSec | RuntimeDirectory | RuntimeDirectoryMode) ;;
		*) props+=(-p "$line") ;;
		esac
		;;
	esac
done </etc/systemd/system/"$engine_unit"
for ((i = 1; i < ${#props[@]}; i += 2)); do echo "copied from $engine_unit: ${props[i]}"; done
state=$(systemctl show -p StateDirectory --value "$engine_unit")
[ "$state" = basalt ] || fail "the engine unit's StateDirectory is '$state'"
[ -e "$marker" ] || fail "control: the host's marker $marker is gone"
sudo systemd-run --quiet --unit="$spawn_unit" -p RemainAfterExit=yes "${props[@]}" \
	"$spawn_bin" -state /var/lib/basalt -marker "$marker" -read-only /usr/local
spawn_finished() {
	local s
	s=$(systemctl show -p SubState --value "$spawn_unit")
	[ "$s" = exited ] || [ "$s" = failed ]
}
wait_for "the spawn check to finish" spawn_finished
# Every sandbox setting systemd reports is the engine unit's: each key copied
# from the unit file, and the ones the engine unit leaves at their defaults.
copied=()
for ((i = 1; i < ${#props[@]}; i += 2)); do copied+=("${props[i]%%=*}"); done
for p in "${copied[@]}" User Group UMask NoNewPrivileges ProtectSystem ProtectHome PrivateTmp PrivateDevices \
	ProtectKernelTunables ProtectKernelModules ProtectControlGroups RestrictSUIDSGID LockPersonality \
	MemoryDenyWriteExecute SystemCallFilter RestrictAddressFamilies RestrictNamespaces NoExecPaths \
	ExecPaths ReadWritePaths ReadOnlyPaths InaccessiblePaths StateDirectory StateDirectoryMode \
	ProtectProc ProcSubset PrivateUsers PrivateNetwork CapabilityBoundingSet MemoryHigh MemoryMax; do
	want=$(systemctl show -p "$p" --value "$engine_unit")
	got=$(systemctl show -p "$p" --value "$spawn_unit")
	[ "$got" = "$want" ] || fail "$p is '$got' in the spawn unit, '$want' in the engine unit"
	echo "$p=$want"
done
id=$(systemctl show -p InvocationID --value "$spawn_unit")
spawn_log=$(sudo journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID="$id")
[ -n "$spawn_log" ] || fail "the spawn check logged nothing ($(systemctl show -p Result --value "$spawn_unit"))"
grep '^spawn ' <<<"$spawn_log" || fail "the spawn check printed no result line"
[ "$(systemctl show -p ExecMainStatus --value "$spawn_unit")" = 0 ] || fail "the spawn check exited non-zero"
grep -q '^spawn FAIL' <<<"$spawn_log" && fail "a spawn check failed"
for c in "runs-as: uid $(id -u basalt) " no-new-privileges control-read-only-system control-private-tmp \
	write-copy exec-from-state-dir child-socket-dir reach-socket-in-temp-dir reach-socket-in-state-dir; do
	grep -q "^spawn ok $c" <<<"$spawn_log" || fail "no passing spawn check '$c'"
done
grep -qx 'spawn done' <<<"$spawn_log" || fail "the spawn check did not finish"
sudo systemctl stop "$spawn_unit"
sudo rm -f "$spawn_bin"
sudo test -S "/run/basalt/$agent.sock" || fail "the engine's agent socket is gone after the spawn check"
left=$(sudo ls -A /var/lib/basalt)
grep -q '^spawn-' <<<"$left" && fail "the spawn check left its copy in the state directory"

step "PASS"
