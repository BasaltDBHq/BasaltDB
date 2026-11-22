# Approving held writes and reverts

A write of 11 to 50 rows, or any `DELETE`, is held until you approve it with your passkey. A revert only runs once you sign it. Postgres checks the passkey signature; the engine, the CLI and the pages only carry it. The rules are in [CONTRACT.md](../CONTRACT.md) (Approvals, Revert, Local pages).

## The usual path: the agent hands you a short link

When a write is held, the agent gets `APPROVAL_REQUIRED` with a `personMessage` and shows it to you as is:

```
Held for your approval: Update 27 rows in basalt_demo.leads. Approve: http://localhost:8787/approvals/<id>#s=<secret> Expires 2026-11-12 07:02 UTC.
```

1. Open the link. The engine serves the approval page itself and the page lists every row with its old and new values. Cascaded rows are marked, and you have to confirm them separately.
2. Press **Approve** (it names the op and the rows, for example "Approve: delete 1 row + 2 cascaded") and confirm with your passkey. The page sends the signature to the engine, which hands it to Postgres. The page then says "Approved. The agent will continue."
3. The agent has already repeated the write with `approvalId`. That call waits up to 90 seconds for your signature and returns `APPLIED` as soon as you sign, so you do not have to tell it that you approved. If you take longer, the agent does not wait again: it ends its turn saying the write waits for your approval. Approve when you are ready, then tell the agent; its next write with `approvalId` applies at once.

### Check the receipt

After every signature the engine reads what Postgres recorded and signs a receipt of it with its own key. The agent's next result carries it, with one line for you at the top of its `personMessage`:

```
Approved: Update 27 rows in basalt_demo·leads (approval <id>), receipt from engine R68W FYxA cGgI jMEN.
```

A revert's line starts with `Signed:` instead. **Compare it with what you meant to sign:** the rows and table, the id from the page's address, and the engine fingerprint with the one the agent's `status` shows. The line comes from Postgres, not from the page, so a page that made you sign something else is caught here: the line names what was actually signed. If it does not match, tell the agent to stop and revert the change. If you see `No receipt: the engine's key file is refused`, your signature still applied, but nothing confirms what it was: fix the key file (the agent's `status` says how). A revert whose scope was changed on the signing page has no receipt either (the agent cannot see what it covers); if you did not change it, say so at once.

Each short link carries a secret after `#s=`: the id alone opens nothing, and the secret never reaches a server log because browsers do not send the fragment. One link is live per held write, and links survive an engine restart: the engine keeps the secrets' hashes in its state directory (`<stateDir>/<agent>.links.json`, mode `0600`). If the agent lost the link, it calls `list_pending` with `reissueLink: true`, which issues a new link and turns the old one off; a plain `list_pending` touches no link. To refuse a write, close the page: the write stays blocked and expires after 24 hours.

A revert works the same way: the agent gives you the link to the revert page, and you sign it there.

## Rows the agent cannot read

A write can touch rows in tables the agent's role cannot `SELECT`, cascaded rows above all: deleting a lead also deletes its notes, even when the agent may not read notes. The agent never sees those values, and the page first shows such a row with dots (••••••) under its table, tagged "hidden from the agent". You can still see them before you approve or sign.

- **Show values.** On a page the engine served (the short link), above the rows: "2 of these rows are in tables the agent cannot read. You can see their values with your passkey; the agent still cannot." Press **Show values with passkey** and confirm with your passkey. The page never asks on its own.
- **One prompt for all.** Every hidden row then shows its values, and its table is tagged "shown to you only" ("Shown to you only. The agent cannot read this table." above the rows). Approving or signing still asks for your passkey again: the first prompt only lets you see the rows. **Hide values** hides them on the page again; showing them once more needs no passkey, since the page still has them.
- **Checked on the page.** Before it shows a row, the page checks that the values are exactly the ones your signature covers (each hidden row carries a hash of them). If the engine sent anything else, the page shows none of them and says "The engine sent values that do not match the rows you sign, so none are shown."
- **Secret columns.** A column classified `SECRET` ([PII classification](../contract/pii-classification.md#pii-classification)) is never shown: it reads "secret · not shown". Postgres left the value out, so the page cannot check that row against what you sign, and it says so under the table, naming the row: "Row id = 8 has a secret column, so this page can't check it against what you sign." `IDENTIFIER` and `FREE_TEXT` columns show as they are; the page is yours, and only what goes to the model is tokenized.
- **When it refuses.** If your passkey could not be checked, the page says "Your passkey didn't confirm. Nothing was shown; try again." and you can press Show values with passkey again. If the hidden rows changed since the agent asked, it says "These rows changed since the agent asked. This approval can no longer apply; ask the agent to try the write again." (for a revert: "ask the agent to prepare it again").
- **What the agent sees.** Nothing about the values. Its tools, its views in `basalt_meta` and its chat show the rows as hidden, as before. The ledger records that you looked (`ROWS_REVEALED`, with counts and hashes only).
- **Long links.** A long link (a `#2.` link) has no engine behind it, so the rows stay hidden, with "Values are hidden on this link. Open the short link to see them." under the table name.

This needs `basalt_meta` versions 29 (reverts), 30 (approvals) and 31 (a fix so a reveal cannot deadlock with your signature). An engine on an older guard serves the agent degraded until you update the guard from the setup page (see [next-steps.md](next-steps.md)).

## Reverting from the agent

You can ask the agent to undo a run ("revert the run that qualified this week's leads"). The agent prepares the revert; only you can sign it.

1. The agent finds the run with `list_runs` (its own runs only, newest first) and looks at what it did with `run_history`.
2. It checks the current data with `preview_revert` and `query`: which rows would be restored, and which a person changed since (those are left as they are: people win).
3. It recommends one of: revert the run, revert one change, or do not revert. It says why.
4. When you agree, it calls `request_revert` with the `runId`, `changeId` or `taskId` and an `intent`, and shows you the `personMessage` with the short link to the revert page.
5. It then calls `request_revert` with the `revertId` and waits once, about 90 seconds. Sign on the page within that time and it reports `APPLIED`. If you take longer, it ends its turn saying the revert waits for your signature; sign when you are ready and tell it.

If the link was lost, the agent calls `request_revert` with `reissueLink: true` for a fresh short link (the old one stops working). If the page cannot reach the engine (the portal, until the relay is live), it shows a `basalt-revert.1....` code: paste it into the chat and the agent delivers it with `signature`. The database verifies your passkey either way.

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

## Commands that stay until the relay is live

`basalt approve` and `basalt revert` go once the hosted relay is live, together with the pasted codes. Until then they have two jobs:

- **Persona 2, a bot's computer.** The portal's page shows a code, and `basalt approve '<code>'` relays an approval code to Postgres from the machine that holds the agent's credential. `write` with `approval` and `request_revert` with `signature` do the same through the agent, which is the usual way.
- **A revert too large for the agent to prepare, or one that covers a whole task.** `basalt revert --agent NAME --task <taskId> --open` prepares that agent's own lines (possibly none) and opens the page, where you include the others.

On an engine that runs as a service, a person who is not root runs both with `sudo`, because they read the agent's credential. Add `--config PATH` when the engine runs from a non-default config.

## Where the pages come from

Every link is built from one base URL, `pagesUrl` in `engine.json`. On a person's own computer it is the engine's local pages at `http://localhost:8787`. On a bot's computer it is the portal, `https://portal.basaltvault.app`, because local pages would sit on the bot's machine. The paths are the same on both: `/approvals/<id>`, `/reverts/<id>` and `/setup/`. The page files are built into the binary: after editing anything under `web/`, rebuild (`make build`) and restart the engine to see it.

- `"pagesAddr": "off"` in `engine.json` turns the local pages off. Any address that is not a loopback IP is refused.
- If the port is taken (an old `make serve-web` from an earlier checkout, or a second engine), the engine refuses to start and names the address. `lsof -nP -iTCP:8787 -sTCP:LISTEN` shows what holds it; stop that process and start the engine again.

The pages run on two origins only, compiled into `basalt`: the portal, and `http://localhost:<port>` when you operate the engine yourself. Cloudflare's `*.pages.dev` addresses and every other host are refused.

The short link only works on the machine where the engine runs. An optional hosted relay, the Vault, is meant to carry portal short links to an engine with no inbound port; it is on by default when an agent operates the engine and off otherwise, and its page side is not finished, so until it connects, the engine hands over long links instead (`/approvals/<id>#2....`, which hold the whole preview). See [vault.md](vault.md), and [relay-privacy.md](relay-privacy.md) for what the relay sees and keeps.

## Revoking an engine

If the server is lost or compromised, `basalt engine revoke` revokes the engine your database records, from your own computer. `status` then reports `ENGINE_REVOKED`, and a revoked engine is never recorded again. The agent's `status` tool shows the record as `engineRecord` (`RECORDED`, `NOT_RECORDED`, `REVOKED` or `UNKNOWN`). A compromised server can ignore the flag, but it still cannot sign anything you did not.

## Authenticators

Passkeys belong to the origin they were registered on: RP ID `localhost` for the local pages, and RP ID `basaltvault.app` (fixed) for the portal at `https://portal.basaltvault.app`. Registration asks for one algorithm, ES256 (`pubKeyCredParams: [{ alg: -7 }]` in [`web/lib/register.js`](../web/lib/register.js)), a discoverable credential, and user verification. Every authenticator below supports ES256. Every database's local pages share RP ID `localhost`, so a person with several databases has several `localhost` passkeys. The setup page names a new one `<database> · <agent> · <date>` (for example `postgres · demo_bot · 2026-11-13`), and the pages ask only for this database's passkeys: links and the engine's pages carry its active credential ids, which the browser uses to offer only those. If the prompt finds none, the page says this device may not hold this database's passkey.

**macOS.** Touch ID (iCloud Keychain), or any of the options listed for Linux.

**Linux desktop.** Linux has no built-in passkey store, so use one of these:

- **Your phone, through the browser's QR code (hybrid) flow.** Chrome or Edge shows a QR code. Scan it with your phone, and the phone signs over Bluetooth. Both devices need Bluetooth on, and the computer needs a Bluetooth adapter.
- **A USB or NFC security key** (YubiKey 5 or another FIDO2 key). Because user verification is required, the key needs a PIN. Set one with `ykman fido access change-pin` or the browser's security key settings. Because the credential is discoverable, it takes one of the key's resident-credential slots.
- **A password manager extension that stores passkeys** (for example 1Password or Bitwarden). The extension handles the prompt instead of the browser.

The passkey is bound to the page's origin. A passkey registered on `http://localhost:8787` signs only on `http://localhost:8787`, so always use the same port.

Checked on real devices (Nov 13, 2026): a Touch ID platform passkey, through the engine's pages, approved a held write and signed a revert. A phone through the QR flow is not offered for RP ID `localhost` (Chrome on macOS shows no phone option), so approving from a phone needs the pages on a real domain: the hosted portal.

## A machine with no desktop

The local setup and approval pages need a browser on the machine that runs the engine, so `basalt init` stops on a headless one. Run a bot there with `basalt init --remote`: its pages are the portal's, and you open them on any device ([bot-setup.md](bot-setup.md)).
