# Approving held writes and reverts

A write of 11 to 50 rows, or any `DELETE`, is held until you approve it with your passkey. A revert only runs once you sign it. Postgres checks the passkey signature; the engine, the CLI and the pages only carry it. The rules are in [CONTRACT.md](../CONTRACT.md) (Approvals, Revert, Local pages).

## The usual path: the agent hands you a short link

When a write is held, the agent gets `APPROVAL_REQUIRED` with a `personMessage` and shows it to you as is:

```
Held for your approval: Update 27 rows in basalt_demo.leads. Approve: http://localhost:8787/approvals/<id>#s=<secret> (or run: basalt approve --agent demo_bot --open <id>). Expires 2026-11-12 07:02 UTC.
```

1. Open the link. The engine serves the approval page itself and the page lists every row with its old and new values. Cascaded rows are marked, and you have to confirm them separately.
2. Press **Approve** (it names the op and the rows, for example "Approve: delete 1 row + 2 cascaded") and confirm with your passkey. The page sends the signature to the engine, which hands it to Postgres. The page then says "Approved. The agent will continue."
3. The agent has already repeated the write with `approvalId`. That call waits up to 90 seconds for your signature and returns `APPLIED` as soon as you sign, so you do not have to tell it that you approved. If you take longer, the agent does not wait again: it ends its turn saying the write waits for your approval. Approve when you are ready, then tell the agent; its next write with `approvalId` applies at once.

Each short link carries a secret after `#s=`: the id alone opens nothing, and the secret never reaches a server log because browsers do not send the fragment. One link is live per held write, and links survive an engine restart: the engine keeps the secrets' hashes in its state directory (`<stateDir>/<agent>.links.json`, mode `0600`). If the agent lost the link, it calls `list_pending` with `reissueLink: true`, which issues a new link and turns the old one off; a plain `list_pending` touches no link. From the terminal, `basalt approve --open <id>` does the same when the engine serves the pages. To refuse a write, close the page: the write stays blocked and expires after 24 hours.

A revert works the same way: `basalt revert --agent NAME --run <runId> --open` opens the revert page, you sign it there, and the command prints the result. Pasting the code the page shows into the prompt still works too.

## Rows the agent cannot read

A write can touch rows in tables the agent's role cannot `SELECT`, cascaded rows above all: deleting a lead also deletes its notes, even when the agent may not read notes. The agent never sees those values, and the page first shows such a row with dots (••••••) under its table, tagged "hidden from the agent". You can still see them before you approve or sign.

- **Show values.** On a page the engine served (the short link), above the rows: "2 of these rows are in tables the agent cannot read. You can see their values with your passkey; the agent still cannot." Press **Show values with passkey** and confirm with your passkey. The page never asks on its own.
- **One prompt for all.** Every hidden row then shows its values, and its table is tagged "shown to you only" ("Shown to you only. The agent cannot read this table." above the rows). Approving or signing still asks for your passkey again: the first prompt only lets you see the rows. **Hide values** hides them on the page again; showing them once more needs no passkey, since the page still has them.
- **Checked on the page.** Before it shows a row, the page checks that the values are exactly the ones your signature covers (each hidden row carries a hash of them). If the engine sent anything else, the page shows none of them and says "The engine sent values that do not match the rows you sign, so none are shown."
- **Secret columns.** A column classified `SECRET` ([PII classification](../CONTRACT.md#pii-classification)) is never shown: it reads "secret · not shown". Postgres left the value out, so the page cannot check that row against what you sign, and it says so under the table, naming the row: "Row id = 8 has a secret column, so this page can't check it against what you sign." `IDENTIFIER` and `FREE_TEXT` columns show as they are; the page is yours, and only what goes to the model is tokenized.
- **When it refuses.** If your passkey could not be checked, the page says "Your passkey didn't confirm. Nothing was shown; try again." and you can press Show values with passkey again. If the hidden rows changed since the agent asked, it says "These rows changed since the agent asked. This approval can no longer apply; ask the agent to try the write again." (for a revert: "ask the agent to prepare it again").
- **What the agent sees.** Nothing about the values. Its tools, its views in `basalt_meta` and its chat show the rows as hidden, as before. The ledger records that you looked (`ROWS_REVEALED`, with counts and hashes only).
- **Long links.** A long link (a `#2.` link) has no engine behind it, so the rows stay hidden, with "Values are hidden on this link. Open the short link to see them." under the table name. The CLI cannot show them either: `basalt approve --show` prints `[values hidden]`; use `--open` for the engine's page.

This needs `basalt_meta` versions 29 (reverts), 30 (approvals) and 31 (a fix so a reveal cannot deadlock with your signature). An engine on an older guard serves the agent degraded until you run `basalt upgrade` (see [next-steps.md](next-steps.md)).

## Reverting from the agent

You can ask the agent to undo a run without opening a terminal ("revert the run that qualified this week's leads"). The agent prepares the revert; only you can sign it.

1. The agent finds the run with `list_runs` (its own runs only, newest first) and looks at what it did with `run_history`.
2. It checks the current data with `preview_revert` and `query`: which rows would be restored, and which a person changed since (those are left as they are: people win).
3. It recommends one of: revert the run, revert one change, or do not revert. It says why.
4. When you agree, it calls `request_revert` with the `runId`, `changeId` or `taskId` and an `intent`, and shows you the `personMessage` with the short link to the revert page.
5. It then calls `request_revert` with the `revertId` and waits once, about 90 seconds. Sign on the page within that time and it reports `APPLIED`. If you take longer, it ends its turn saying the revert waits for your signature; sign when you are ready and tell it.

If the link was lost, the agent calls `request_revert` with `reissueLink: true` for a fresh short link (the old one stops working). If the page cannot reach the engine, it shows a `basalt-revert.1....` code: paste it into the chat and the agent delivers it with `signature`. The database verifies your passkey either way.

A large plan is signed once, like any other. After you sign, the agent applies it in batches with `apply_revert_batch` until every line is done.

An agent asks for a revert of its own work only: one of its changes, one of its runs, or its own changes in a task it ran in (`taskId`). It may narrow that to some of its runs in the task or some tables (`runs`, `tables`). A change, run or task that is not its own is answered `NOT_FOUND`, the same as an id that does not exist. A task revert holds only that agent's lines. To include other agents' changes, widen the revert on its page (below). If another agent's run looks wrong, ask that agent. Whichever way the revert starts, only you sign it. A revert is a change like any other, so it can itself be reverted the same way.

## Changing what a revert covers

The revert page shows what the agent proposed. You can sign it as it is, change its scope, or reject it. On a computer the choices sit in a panel to the right of the rows. On a phone, tap the scope line above the rows ("bot, 1 table · Change") to open them, and use the Sign and Reject buttons at the bottom of the screen.

- **Leave things out.** Under "Included", tap a table to leave it out. The agent's own chip stays: its proposal is its own work. After you include other agents' changes (below), you can also leave out agents and runs. The page asks the engine for the new rows and shows them before you sign. This needs no passkey.
- **Include other agents' changes.** For a task, the page offers "Include other agents' changes". It asks for your passkey first, then shows every agent's rows in the task, the agents' runs and the tables they wrote. The title then carries "You widened this". You can then leave out agents, runs or tables without another passkey prompt. Signing the widened revert asks for your passkey a second time: the first prompt only lets you see and choose the rows.
- **What the agent sees.** The agent that asked never sees what you added. Its link stops working when you widen, and its tools show only the status, the totals and that you widened the revert. Keep the page open until you sign: reloading it needs a new link from the agent, and you would widen again.
- **If the agent resets it.** If the agent asks for a new link (`reissueLink`), the revert goes back to its own proposal and your page says "The agent reset this revert to its own work." Ask the agent for the new link, and widen again if you still want the other agents' changes.
- **Reject.** Reject stops the revert. You can leave a note of up to 500 characters, which the agent reads; the page says so. Rejecting needs no passkey, and nothing is reverted. The agent's wait ends with `REJECTED`, and it does not ask again unless you tell it to.

Changing the scope needs the page served by the engine, from the short link the agent gives you. A long link (a `#2.` link) shows the scope read only and can only be signed as it is; to decline from it, close the page. A revert you do not sign expires within the hour.

To start a task revert yourself, run `basalt revert --agent NAME --task <taskId> --open` with an agent that ran in the task. It prepares that agent's own lines (possibly none) and opens the page, where you include the others.

## The CLI path

The CLI path is a full alternative to the link:

- `basalt approve --agent NAME --open <approvalId>` opens the approval page in your default browser (`open` on macOS, `xdg-open` on Linux). When the engine serves the pages, you get a new short link whose page sends the signature to the engine, so there is nothing to paste: the command waits and ends when you have signed (the agent's earlier link stops working, and the agent still applies the write by its approval id). If you paste a code at that point, it is taken too. Without local pages you get the long link, whose page shows a code to paste.
- `basalt approve --agent NAME --show <approvalId>` prints the link, for use on another device, and waits for the signature the same way.
- `basalt approve --agent NAME '<code>'` relays the code that a long-link page shows, for example a page opened on another device.

Add `--config PATH` when the engine runs from a non-default config. The commands that the agent passes on already include it.

## Where the pages come from

Every link is built from one base URL, `pagesUrl` in `engine.json`. `basalt init --passkey-origin` sets it, and the default is the engine's local pages at `http://localhost:8787`, which stays the default until the hosted console (`https://console.basaltvault.app`) is live. The paths are the same on both: `/approvals/<id>`, `/reverts/<id>` and `/passkeys/register`. When the base is local, the engine serves the approval, revert and registration pages on `127.0.0.1:<port>` and logs `serving approval pages`. The page files are built into the binary: after editing anything under `web/`, rebuild (`make build`) and restart the engine to see it.

- `"pagesAddr": "off"` in `engine.json` turns the pages off. Any address that is not a loopback IP is refused.
- If the port is taken (an old `make serve-web` from an earlier checkout, or a second engine), the engine refuses to start and names the address. `lsof -nP -iTCP:8787 -sTCP:LISTEN` shows what holds it; stop that process and start the engine again.
- With the hosted console as the base (`https://console.basaltvault.app`, not live yet), the engine serves no pages, and held writes carry the long link (`/approvals/<id>#2....`) that holds the whole preview. Open that link with `basalt approve --open` rather than copying it, because terminals and chats can cut it short. The page says so when it gets a truncated link.

The short link only works on the machine where the engine runs. An optional hosted relay, the Vault, is meant to carry portal short links to an engine with no inbound port; it is off by default and its page side is not finished. See [vault.md](vault.md).

## Authenticators

Passkeys belong to the origin they were registered on: RP ID `localhost` for the local pages, and RP ID `basaltvault.app` (fixed) for the hosted console at `https://console.basaltvault.app`. Registration asks for one algorithm, ES256 (`pubKeyCredParams: [{ alg: -7 }]` in [`web/lib/register.js`](../web/lib/register.js)), a discoverable credential, and user verification. Every authenticator below supports ES256. Every database's local pages share RP ID `localhost`, so a person with several databases has several `localhost` passkeys. `basalt init` names a new one `<database> · <agent> · <date>` (for example `postgres · demo_bot · 2026-11-13`; `--passkey-label` picks another name), and the pages ask only for this database's passkeys: links and the engine's pages carry its active credential ids, which the browser uses to offer only those. If the prompt finds none, the page says this device may not hold this database's passkey.

**macOS.** Touch ID (iCloud Keychain), or any of the options listed for Linux.

**Linux desktop.** Linux has no built-in passkey store, so use one of these:

- **Your phone, through the browser's QR code (hybrid) flow.** Chrome or Edge shows a QR code. Scan it with your phone, and the phone signs over Bluetooth. Both devices need Bluetooth on, and the computer needs a Bluetooth adapter.
- **A USB or NFC security key** (YubiKey 5 or another FIDO2 key). Because user verification is required, the key needs a PIN. Set one with `ykman fido access change-pin` or the browser's security key settings. Because the credential is discoverable, it takes one of the key's resident-credential slots.
- **A password manager extension that stores passkeys** (for example 1Password or Bitwarden). The extension handles the prompt instead of the browser.

The passkey is bound to the page's origin. A passkey registered on `http://localhost:8787` signs only on `http://localhost:8787`, so always use the same port.

Checked on real devices (Nov 13, 2026): a Touch ID platform passkey, through the engine's pages, approved a held write and signed a revert. A phone through the QR flow is not offered for RP ID `localhost` (Chrome on macOS shows no phone option), so approving from a phone needs the pages on a real domain: the hosted portal.

## Engine on a headless Linux server

The engine's pages listen on the server's loopback only. Until a hosted relay exists (parked in the roadmap), approve from your own computer through an SSH tunnel that uses **the same port on both ends**:

```sh
ssh -N -L 8787:127.0.0.1:8787 you@server
```

Then open the short link (`http://localhost:8787/approvals/<id>#s=<secret>`) in the browser on your computer. Inside the tunnel the browser's origin is `http://localhost:8787`, which is the page origin the engine expects. The engine's Host and Origin checks accept it, and your passkey for `localhost` signs it. Use `127.0.0.1` as the tunnel target rather than `localhost`, so that SSH does not try the server's `::1` first, where the engine is not listening.

- The port has to match on both ends. A tunnel from local port 9000 gives the page the origin `http://localhost:9000`, and the engine refuses the signature relay from it (`403`).
- Register the passkey through the same tunnel. Keep it open while `basalt init` waits for the code, since init serves the registration page on the server's port in the same way.
- `basalt approve --show <id>` on the server prints the short link to open on your side. It waits until you sign or the approval expires, and the link the agent showed stops working.
- Without a tunnel there is no page to open on your computer until the hosted console is live, so keep the tunnel open while you approve.
