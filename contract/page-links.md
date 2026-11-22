## Page links

Owner decisions, Decided Nov 12. Every link is built from one pages base URL (`pagesUrl` in `engine.json`; one Go constant `links.Portal` and one JS constant `PORTAL` for the portal): the engine's local pages `http://localhost:8787` by default until hosting exists, or the portal `https://portal.basaltvault.app`. Only the origins in [Page origins](#page-origins) are accepted. The paths are RESTful and the same on both:

| Page | Path |
|---|---|
| Approve a held write | `/approvals/<approvalId>` (long link: `#2.<request>` appended) |
| Sign a revert | `/reverts/<revertId>` (long link: `#2.<request>` appended) |
| Approve a plugin ([The plugin approval page](plugins-approval.md#the-plugin-approval-page)) | `/plugins/<approvalId>` (long link: `#2.<request>` appended) |
| Register a passkey | `/passkeys/register#1.<request>` |
| Check which passkeys a device has (M4.1) | `/passkeys/check#1.<request>` |
| Forget a removed passkey (M4.1) | `/passkeys/forget#1.<request>` |
| Run a setup code through the connect service (planned, [Connect](connect.md#the-connect-page)) | `/connect#<code>`, or `/connect` with a paste box. Portal only: the local pages have no such page |
| A run (reserved, later) | `/runs/<runId>` |


### Page origins

Chat-only operator CO-8. The origins a link may point at, and that the engine and the CLI accept for passkeys, are a closed list compiled into the binary (Go: `links.Portal` and the checks of `internal/engine/config`; JS: `relyingParty` in `web/lib/codec.js`):

- `https://portal.basaltvault.app`, always (RP ID `basaltvault.app`).
- `http://localhost:<port>` (the host is `localhost` exactly: a passkey's origin, and so the page a link opens, is `localhost` only, RP ID `localhost`, so a `pagesUrl`, `approvalPage` or `--pages-url` on `127.0.0.1`, `[::1]` or another spelling is refused, not rewritten, with `the local pages run only at localhost; use http://localhost:<port>`), only when `operatedBy` is `PERSON`: the engine runs on the person's own machine, so the loopback page is theirs.

Neither `engine.json`, a flag, nor the bot can add an origin. `*.pages.dev` (Cloudflare's preview and branch URLs, which serve the same files but whose passkeys would not belong to `basaltvault.app`) and every other host are refused in both modes. Where the list is checked:

- **`pagesUrl`**, when `engine.json` is loaded: an origin not in the list is refused, naming the setting and saying `use https://portal.basaltvault.app or a local http://localhost:<port>`. With `"operatedBy": "AGENT"`, a local `pagesUrl` (also the default `http://localhost:8787` when `pagesUrl` is absent) is refused with `pagesUrl <value>: an agent-operated engine uses the portal's pages (https://portal.basaltvault.app); local pages would be on the agent's machine`, unless `devLocalPages` is `true`.
- **`--passkey-origin`** (`basalt init`) and **`--pages-url`** (`basalt passkey check` and `remove`, `basalt service install`): an origin not in the list is a usage error (exit `2`). `basalt init --operated-by=agent` with a local `--passkey-origin` is a usage error unless `--dev-local-pages` is given.
- **The pages** (`web/lib/codec.js`) run only at `https://portal.basaltvault.app` (no port) or `http://localhost:<port>`, and refuse anything else (`this page only runs at https://portal.basaltvault.app or http://localhost:<port>`) before they touch a passkey.

**`--dev-local-pages`** (development only, design section 5.2). `basalt init --operated-by=agent --dev-local-pages --passkey-origin http://localhost:<port>` lets the owner test `AGENT` mode against loopback pages on their own laptop. Init writes `"devLocalPages": true` to `engine.json` and saves `--dev-local-pages` in `initArgs`; running init again without it removes the key. It is a usage error without `--operated-by=agent`, and with a `--passkey-origin` that is not local. A config with `devLocalPages` set is refused when it is loaded if `operatedBy` is not `AGENT`, if `pagesUrl` is not local, or if `pagesAddr` is `"off"`: the exception holds only while the engine serves the pages on a loopback address. While it is set, the warning `DEV_LOCAL_PAGES: these pages are on the agent's machine; never use this with a bot you do not control` is carried:

- by every `personMessage` the engine returns to the agent (tool errors, results, warnings and `status` problems, the `DEV_LOCAL_PAGES` problem's own included, once) as its first line, followed by an empty line, and not counted in its 500 characters, so every link the agent hands over comes with it;
- by `status` (the tool and `basalt status`) as the problem `DEV_LOCAL_PAGES` (`WARNING`, [Next steps](next-steps.md#next-steps)). Its one step is a `PERSON` `RUN_COMMAND` on the engine's machine even though `operatedBy` is `AGENT`: the exception exists only on the owner's own laptop, so the [agent-operated variants](next-steps.md#next-steps-on-an-agent-operated-engine) do not apply to it;
- on stderr by `basalt init` when it writes the key, and in the engine's log (level `WARN`) when it starts.
