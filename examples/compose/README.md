# BasaltDB in containers: the compose example

Three containers: Postgres, the engine, and an agent. The agent's container mounts the engine's socket directory and nothing else, so it can call the engine's tools but cannot read the engine's config or the agent's Postgres credential. Nothing here uses systemd: the engine container runs `tini` as PID 1, and `basalt engine --user basalt` does what the systemd unit does elsewhere (see [docs/install.md, Containers](../../docs/install.md#containers-without-systemd)).

| Container | Runs as | Mounts |
|---|---|---|
| `postgres` | postgres | its data |
| `engine` | root under tini, then `basalt` (the engine drops root before it reads anything) | `/etc/basalt` (config, credential), `/var/lib/basalt` (state), `/run/basalt` (sockets) |
| `agent` | `agent` (uid 1001) | `/run/basalt` only |

Both containers use one image built from this repository ([`Dockerfile`](Dockerfile)): the `basalt` binary installed root-owned in `/usr/local/libexec`, the users `basalt` and `agent`, and `tini`. The agent's uid must be the same in both containers, because the engine admits the agent by the uid on its socket.

## Run it

From this directory, with Docker and Compose v2:

```sh
docker compose build
docker compose up -d --wait postgres
```

Set up the guard and the engine's files. `basalt init` runs once, as the engine's OS user `basalt`, so the config and the credential it writes are that user's alone (`0600`, in `/etc/basalt`, which is `0750`):

```sh
docker compose run --rm -T --no-deps --user basalt \
  -e BASALT_ADMIN_DATABASE_URL='postgres://postgres:example-admin-password@postgres:5432/app?sslmode=disable' \
  engine basalt init --demo --os-user agent \
  --config /etc/basalt/engine.json --socket-dir /run/basalt --skip-passkey --yes </dev/null
```

`--demo` makes the sample schema `basalt_demo` and the agent `demo_bot`. `--skip-passkey` keeps the example short: without a passkey, writes that need an approval stay held. The admin connection string is used once and not stored.

Start the engine and the agent:

```sh
docker compose up -d engine agent
docker compose logs engine
```

The engine's first line is `basalt engine: dropped root; running as basalt (uid ..., gid ...); no_new_privs set`, then `serving agent agent=demo_bot socket=/run/basalt/demo_bot.sock`.

## The agent

The agent's MCP client runs in the agent container, as `agent`:

```sh
docker compose exec agent basalt mcp --agent demo_bot
```

For a client on the host, use that line as the MCP server command. To try one call by hand:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"try","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT count(*) FROM basalt_demo.leads"}}}' \
  | docker compose exec -T agent basalt mcp --agent demo_bot
```

## What the agent cannot see

```sh
docker compose exec agent grep basalt /proc/mounts           # one mount: /run/basalt
docker compose exec agent ls -l /run/basalt                   # the sockets (0666) and engine.lock (0600, basalt's)
docker compose exec --user agent engine cat /etc/basalt/agents/demo_bot.url   # Permission denied
```

The last line shows the second layer: even inside the engine's container, the agent's OS user cannot read the credential, because only `basalt` can.

## Your commands

For now this setup is same-user mode: `init` wrote `"mode": "SAME_USER"` and no `personUids`, so there is no person socket, and the CLI reads the config and the credential itself. That is a temporary limit until `basalt init` can set up a container (with the person's uid and the person socket, as for a service). Until then, run the CLI in the engine container as the engine's user:

```sh
docker compose exec --user basalt -e XDG_CACHE_HOME=/var/lib/basalt/cli engine \
  basalt log --agent demo_bot --config /etc/basalt/engine.json
```

Anyone who can run `docker compose exec` on this host can do the same, so treat access to Docker as access to the credential.

## Restart and remove

```sh
docker compose restart engine     # drops root again on every start
docker compose stop engine
docker compose run --rm -T --no-deps --user basalt \
  -e BASALT_ADMIN_DATABASE_URL='postgres://postgres:example-admin-password@postgres:5432/app?sslmode=disable' \
  engine basalt uninstall --yes </dev/null
docker compose down -v
```

`basalt uninstall` removes the guard, the agent roles and the demo schema; `down -v` removes the containers and every volume, the credential with them.

## Tested

[`smoke.sh`](smoke.sh) runs all of the above and checks the result: the engine's uids and `NoNewPrivs` from `/proc`, no capabilities left, the isolation, a query and a write over the socket, a restart, `basalt log`, and the removal. `make test-compose` runs it; CI runs it on every pull request.

## Hardening in `compose.yaml`

- The engine keeps only `CHOWN`, `FOWNER`, `DAC_READ_SEARCH`, `SETUID` and `SETGID`, which it needs while it is still root to make its directories and change its ids. `DAC_READ_SEARCH` is only for a restart: the state directory is then `basalt`'s and `0700`, and root needs it to reopen and check that directory. After the drop the engine has no capability at all.
- `no-new-privileges:true` on both containers, besides the engine's own `no_new_privs`.
- The Postgres password is an example. Use your own database and pass the admin connection string from a secret store; it is only needed for `init` and `uninstall`.
