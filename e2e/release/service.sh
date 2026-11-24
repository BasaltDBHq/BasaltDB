#!/bin/sh
# The engine service on a CI runner, which has no administrator dialog.
#
#   service.sh install <basalt-binary>   run the install script of `basalt init` under sudo
#   service.sh remove                    run the remove script of `basalt init` under sudo
#   service.sh cleanup <out-dir>         collect the engine's logs, then remove the service
#                                        whatever state it is in (safe to run twice)
#
# The scripts are the fixed text osservice builds for the dialog, printed by
# ./installscript. POSIX sh.
set -eu

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
os=$(uname -s)

case "$os" in
Darwin) config='/Library/Application Support/Basalt/engine.json' ;;
*) config=/etc/basalt/engine.json ;;
esac

# tool builds the script printer once per run.
tool() {
	dir=${E2E_TOOL_DIR:-${TMPDIR:-/tmp}/basalt-e2e-tool}
	mkdir -p "$dir"
	(cd "$root" && go build -o "$dir/installscript" ./e2e/release/installscript)
	echo "$dir/installscript"
}

# as_root runs the script printed by the remaining arguments under sudo.
as_root() {
	t=$(tool)
	f=$(mktemp "${TMPDIR:-/tmp}/basalt-e2e-script.XXXXXX")
	"$t" "$@" >"$f"
	sudo sh "$f"
	rm -f "$f"
}

case "${1:-}" in
install)
	as_root install "${2:?usage: service.sh install <basalt-binary>}"
	;;
remove)
	as_root remove
	;;
cleanup)
	out=${2:?usage: service.sh cleanup <out-dir>}
	mkdir -p "$out"
	if [ "$os" = Darwin ]; then
		sudo cat /Library/Logs/Basalt/engine.log >"$out/engine.log" 2>&1 || true
		sudo launchctl print system/dev.basaltdb.engine >"$out/service-state.txt" 2>&1 || true
	else
		sudo journalctl -u basalt-engine --no-pager >"$out/engine.log" 2>&1 || true
		sudo systemctl status basalt-engine --no-pager >"$out/service-state.txt" 2>&1 || true
	fi
	# The remove script refuses while the engine's config exists. A run that
	# failed before its Remove leaves it, so it goes first.
	sudo rm -f "$config"
	as_root remove || echo "service.sh: the remove script did not finish" >&2
	;;
*)
	echo "usage: service.sh install <basalt-binary> | remove | cleanup <out-dir>" >&2
	exit 2
	;;
esac
