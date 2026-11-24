#!/bin/sh
# The end-to-end test of the release binaries, persona 1, on this machine:
# sh e2e/release/run.sh <bin-dir>
#
# <bin-dir> holds the basalt binary of the archive under test. The machine
# needs Go and Node, passwordless sudo and a network; GitHub's runners have
# them. It changes the machine (a Postgres server, an engine service as root),
# so run it on a CI runner only. It prints `e2e: <step> ok` for each step and
# exits 0 only when every step passed. The engine's service is removed on exit,
# and E2E_OUT (default e2e/release/out) holds the logs and, on a failure, a
# screenshot and the page text.
set -eu

usage() {
	echo "usage: run.sh <bin-dir>" >&2
	exit 2
}
[ $# -eq 1 ] || usage
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
bin_dir=$(CDPATH= cd -- "$1" && pwd)
[ -x "$bin_dir/basalt" ] || {
	echo "run.sh: need an executable basalt in $bin_dir" >&2
	exit 1
}
out=${E2E_LOG_DIR:-${E2E_OUT:-$here/out}}
mkdir -p "$out"
os=$(uname -s)

trap 'sh "$here/service.sh" cleanup "$out" || true' EXIT

# The service runs the binary as root, so init refuses one that anyone but
# root could change or that sits under a folder anyone but root can write.
# /usr/local/bin is Homebrew's on the Intel macOS runner and /opt is open to
# everyone on the Ubuntu one: use a folder of our own under a root-owned parent.
if [ "$os" = Darwin ]; then
	inst=/Library/BasaltE2E
else
	inst=/usr/local/lib/basalt-e2e
	# The engine refuses a plugin base whose parent is writable by others, and
	# the hosted runner ships /opt that way. The runner is thrown away after.
	sudo chmod go-w /opt
fi
sudo mkdir -p "$inst"
sudo chown 0:0 "$inst"
sudo chmod 755 "$inst"
sudo install -m 755 -o 0 -g 0 "$bin_dir/basalt" "$inst/basalt"
ls -ld / /opt "$inst" "$inst/basalt"
"$inst/basalt" version

# ---- Postgres ----
pw=$(openssl rand -hex 16)
echo "::add-mask::$pw"
if [ "$os" = Darwin ]; then
	brew install postgresql@16
	pgbin=$(brew --prefix postgresql@16)/bin
	brew services start postgresql@16
	psql_super() { "$pgbin/psql" -v ON_ERROR_STOP=1 -d postgres "$@"; }
	psql_url() { "$pgbin/psql" -v ON_ERROR_STOP=1 "$@"; }
	isready() { "$pgbin/pg_isready" -h 127.0.0.1; }
else
	sudo systemctl start postgresql
	psql_super() { sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres "$@"; }
	psql_url() { psql -v ON_ERROR_STOP=1 "$@"; }
	isready() { pg_isready -h 127.0.0.1; }
fi
n=0
until isready; do
	n=$((n + 1))
	[ "$n" -le 60 ] || {
		echo "run.sh: Postgres did not come up" >&2
		exit 1
	}
	sleep 2
done
psql_super -c "CREATE ROLE e2e_owner LOGIN SUPERUSER PASSWORD '$pw'"
psql_super -c "CREATE DATABASE e2e OWNER e2e_owner"
admin_url="postgres://e2e_owner:$pw@127.0.0.1:5432/e2e?sslmode=disable"
psql_url "$admin_url" -c "CREATE TABLE public.items (id int PRIMARY KEY, name text)" \
	-c "INSERT INTO public.items SELECT g, 'item-' || g FROM generate_series(1, 20) g"
echo "e2e: postgres ok"

# ---- Node and the browser ----
cd "$here"
npm ci
if [ "$os" = Darwin ]; then
	npx playwright install chromium
else
	npx playwright install --with-deps chromium
fi

E2E_BIN="$inst/basalt" E2E_ADMIN_URL="$admin_url" E2E_OUT="$out" E2E_DIR="$here" node flow.mjs
echo "e2e: all steps ok"
