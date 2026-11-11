# Approving held writes and reverts

A write of 11 to 50 rows, or any `DELETE`, is held until you approve it with your passkey. A revert only runs once you sign it. Postgres checks the passkey signature; the engine, the CLI and the pages only carry it. The rules are in [CONTRACT.md](../CONTRACT.md) (Approvals, Revert, Local pages).

## The usual path: the agent hands you a short link

When a write is held, the agent gets `APPROVAL_REQUIRED` with a `personMessage` and shows it to you as is:

```
Held for your approval: Update 27 rows in basalt_demo.leads. Approve: http://localhost:8787/approvals/<id> (or run: basalt approve --agent demo_bot --open <id>). Expires 2026-11-12 07:02 UTC.
```

1. Open the link. The engine serves the approval page itself and the page lists every row with its old and new values. Cascaded rows are marked, and you have to confirm them separately.
2. Approve with your passkey. The page sends the signature to the engine, which hands it to Postgres. The page then says "Approved. The agent will continue."
3. The agent has already repeated the write with `approvalId`. That call waits up to 90 seconds for your signature and returns `APPLIED` as soon as you sign. You do not have to tell it that you approved.

If the agent lost the link, it can call `list_pending` again, which returns the same message. To refuse a write, close the page: the write stays blocked and expires after 24 hours.

A revert works the same way: `basalt revert --agent NAME --run <runId> --open` opens the revert page, you sign it there, and the command prints the result. Pasting the code the page shows into the prompt still works too.

## The CLI path

The CLI path is a full alternative to the link:

- `basalt approve --agent NAME --open <approvalId>` opens the approval page in your default browser (`open` on macOS, `xdg-open` on Linux).
- `basalt approve --agent NAME --show <approvalId>` prints the link, for use on another device.
- `basalt approve --agent NAME '<code>'` relays the code that a long-link page shows, for example a page opened from a Telegram message.

Add `--config PATH` when the engine runs from a non-default config. The commands that the agent passes on already include it.

## Where the pages come from

Every link is built from one base URL, `pagesUrl` in `engine.json`. `basalt init --passkey-origin` sets it, and the default is the engine's local pages at `http://localhost:8787`, which stays the default until the hosted console (`https://console.basaltvault.app`) is live. The paths are the same on both: `/approvals/<id>`, `/reverts/<id>` and `/passkeys/register`. When the base is local, the engine serves the approval, revert and registration pages on `127.0.0.1:<port>` and logs `serving approval pages`. The page files are built into the binary, so `make serve-web` is only needed when you are working on the pages themselves.

- `"pagesAddr": "off"` in `engine.json` turns the pages off. Any address that is not a loopback IP is refused.
- If the port is taken (for example, `make serve-web` is still running on it), the engine logs `approval pages not served` and held writes carry the long link. Stop the other server and restart the engine.
- With the hosted console as the base (`https://console.basaltvault.app`, not live yet), the engine serves no pages, and held writes carry the long link (`/approvals/<id>#1....`) that holds the whole preview. Open that link with `basalt approve --open` rather than copying it, because terminals and chats can cut it short. The page says so when it gets a truncated link.

Telegram always sends the long link. The short link only works on the machine where the engine runs.

## Authenticators

Passkeys belong to the origin they were registered on: RP ID `localhost` for the local pages, and RP ID `basaltvault.app` (fixed) for the hosted console at `https://console.basaltvault.app`. Registration asks for one algorithm, ES256 (`pubKeyCredParams: [{ alg: -7 }]` in [`web/lib/register.js`](../web/lib/register.js)), a discoverable credential, and user verification. Every authenticator below supports ES256.

**macOS.** Touch ID (iCloud Keychain), or any of the options listed for Linux.

**Linux desktop.** Linux has no built-in passkey store, so use one of these:

- **Your phone, through the browser's QR code (hybrid) flow.** Chrome or Edge shows a QR code. Scan it with your phone, and the phone signs over Bluetooth. Both devices need Bluetooth on, and the computer needs a Bluetooth adapter.
- **A USB or NFC security key** (YubiKey 5 or another FIDO2 key). Because user verification is required, the key needs a PIN. Set one with `ykman fido access change-pin` or the browser's security key settings. Because the credential is discoverable, it takes one of the key's resident-credential slots.
- **A password manager extension that stores passkeys** (for example 1Password or Bitwarden). The extension handles the prompt instead of the browser.

The passkey is bound to the page's origin. A passkey registered on `http://localhost:8787` signs only on `http://localhost:8787`, so always use the same port.

Not yet checked on real devices (held for the owner): phone approval through the QR flow for RP ID `localhost`.

## Engine on a headless Linux server

The engine's pages listen on the server's loopback only. Until a hosted relay exists (parked in the roadmap), approve from your own computer through an SSH tunnel that uses **the same port on both ends**:

```sh
ssh -N -L 8787:127.0.0.1:8787 you@server
```

Then open the short link (`http://localhost:8787/approvals/<id>`) in the browser on your computer. Inside the tunnel the browser's origin is `http://localhost:8787`, which is the page origin the engine expects. The engine's Host and Origin checks accept it, and your passkey for `localhost` signs it. Use `127.0.0.1` as the tunnel target rather than `localhost`, so that SSH does not try the server's `::1` first, where the engine is not listening.

- The port has to match on both ends. A tunnel from local port 9000 gives the page the origin `http://localhost:9000`, and the engine refuses the signature relay from it (`403`).
- Register the passkey through the same tunnel. Keep it open while `basalt init` waits for the code, since init serves the registration page on the server's port in the same way.
- `basalt approve --show <id>` on the server prints the short link to open on your side.
- Without a tunnel, use the long link (`basalt approve --show <id> --pages-url http://localhost:8787`), served by `make serve-web` on your computer. Paste the code it shows into `basalt approve` on the server.
