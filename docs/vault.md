# The Vault: what it sees and how to turn it off

The Vault is a hosted relay at `relay.basaltvault.app`. It exists for one case: an engine that has no inbound port, such as one on a server or in a container, and a person who wants to approve a held write or a revert from a browser anywhere. The engine dials out to the Vault. The portal page (`https://portal.basaltvault.app`) dials in. The Vault pairs the two sockets and passes bytes between them. It is optional: on by default when an agent operates the engine, off otherwise, and you can turn it off in `engine.json`. Approvals work without it: when it is off or down, the engine hands over long links instead ([approving.md](approving.md)).

The protocol is in [CONTRACT.md, Vault channel](../contract/vault-channel.md#vault-channel). The Vault service itself is closed source and is not in this repository, so this page describes what the engine does and what the protocol allows the Vault to see. It cannot show what the service does with what it sees.

For a short statement of what the relay sees, stores and logs, see [relay-privacy.md](relay-privacy.md).

For a reviewer who wants the whole protocol in one document (keys, handshake, frames, receipts, threats, test vectors and open questions), see [security/vault-channel-spec.md](security/vault-channel-spec.md).

## What is built, and what is not

Built on `master`:

- The engine dials out to the Vault and keeps one connection. It signs in with a key of its own, made on its first start (below).
- The engine registers the short links it hands out, and answers the page's sessions with the same checks as its local pages.
- If the Vault does not register a link within 5 seconds, or is not reachable, the engine hands over the long link instead.
- The `vault` setting in `engine.json`. The agent's `status` tool shows the Vault state and the engine id.

Not built yet:

- **The portal page does not open a Vault session yet.** The page-side client (`web/`) is still to come, so a portal short link cannot complete an approval end to end today. Leave the Vault off unless you are testing it.
- The engine id on portal pages.

## What leaves your machine

- **The engine's public key and its id.** The id is the first 16 bytes of the SHA-256 of that key, in base64url. The engine proves it holds the private key by signing a challenge from the Vault. The private key stays in `<stateDir>/channel.json`, mode `0600`, and is never sent.
- **Link tokens, never secrets.** A short link looks like `https://portal.basaltvault.app/approvals/<id>#s=<secret>`. The engine derives a 22-character link token from the secret with HKDF and registers only that token, with its expiry. It never sends the secret, or the pre-shared key derived from it. The `#s=` part stays in your browser: browsers do not send the fragment to any server.
- **Padded, encrypted frames.** Once a page connects, the page and the engine run a Noise handshake (`Noise_NNpsk0_P256_AESGCM_SHA256`) keyed by the link secret. Everything after that, the approval or revert rows included, travels inside AES-256-GCM frames that the Vault forwards without being able to read them, or change them without the session failing. Each frame is padded to at least 1,024 bytes and then to the next power of two, up to 32,768.

No database credential, SQL, row, ledger entry, passkey signature or private key goes to the Vault.

## What the Vault sees

The Vault sees metadata:

- Engine ids and public keys, when each engine is connected, and from which IP address.
- Link tokens: when they are registered, used and removed, and when they expire.
- Page IP addresses and user agents.
- How many sessions and frames there were, their padded sizes, their timing, and how each session closed.

Padding hides the exact size of one frame, not the shape of a session. A large response, such as a big revert, shows up as many full frames. From the rhythm, the Vault can usually tell that a page read an item and then sent something back, so it can guess that an approval or revert was signed, and roughly when. It cannot tell which item, which rows, or what the result was.

The Vault never sees link secrets, session keys, item ids, rows, statements, signatures or results. The portal's static host, which is separate from the relay, does see the path `/approvals/<id>` when you open a page.

The contract asks the service to keep connection metadata for 7 days at most and not to log session bytes. This repository cannot check either.

## What a dishonest Vault can do

The Vault is treated as untrusted. It never holds a key that opens a session. A Vault that drops, delays, repeats, reorders or alters messages can make a session fail. It cannot make the engine or the page accept anything.

It can refuse service, so that the page cannot reach the engine. It can also try to route a link to a different engine, which would put a wrong fingerprint on the page. A relayed signature is checked by Postgres against the rows you were shown, so the Vault cannot turn it into approval of another write. On the relay the page cannot pin the engine's key, so the check against that is yours: compare the engine id that the agent's `status` tool prints with the one the page shows, once the page shows it.

## Turn it on or off

The setting is `vault` in `engine.json`: `ON` or `OFF`. If the value is missing from the file, the Vault is off. There is no flag for it.

- **Defaults.** `basalt init --remote` turns it on for a new, agent-operated engine and keeps the value in `engine.json` on a rerun. An engine a person operates on their own computer has it off.
- **It needs the portal's pages.** The Vault carries portal links, and a passkey registered for `localhost` cannot sign on the portal, so the engine uses the Vault only when `pagesUrl` is `https://portal.basaltvault.app`.
- **Turn it off by hand.** Set `"vault": "OFF"` in `engine.json` and restart the engine. The engine reads `vault` when it starts. After a restart it closes its socket, and the Vault drops any token it still holds when that token expires. Links already handed out through the Vault stop working.

## Check the state

The agent's `status` tool reports the Vault state and the engine id, in this form:

```
Vault:        CONNECTED (approvals use portal short links)
Engine id:    AbCd EfGh IjKl MnOp (id AbCdEfGhIjKlMnOpQrStUv)
```

| State | Meaning |
|---|---|
| `OFF` | The setting is `OFF`, or `pagesUrl` is not the portal. Approval links are the engine's own. |
| `CONNECTING` | The engine is dialling or signing in. Approvals use long links until it is connected. |
| `CONNECTED` | The engine is signed in. Approvals use portal short links. |
| `UNREACHABLE` | No answer from the Vault for 30 seconds. Approvals still work, through long links, and the engine keeps retrying. |
| `KEY_ERROR` | The key file is refused. The Vault stays off and approvals use long links. |

The engine id is a fingerprint of the engine's public key. Compare the one the agent's `status` tool shows with the portal page, later.

## Check the portal

The pages you sign on come from the portal's static host. The release workflow's `portal-check` job runs `make portal-verify` after every release. It fetches every file embedded in the release's `basalt` binary from `https://portal.basaltvault.app`, compares the bytes with `web/portal.sha256`, and fails on any file that differs, is missing or unexpected. A maintainer or anyone with a checkout can run the same: `make portal-verify` (`go run ./scripts/portal-verify`, which also takes `--portal-url`). The engine's own daily check reports `PORTAL_MISMATCH` in `status`.

It catches a portal that was changed for everyone. It cannot catch a page served to you alone, or one that treats a command-line client differently from your browser, since it sees only what the host serves it. Run it from a machine and network other than the ones you sign on. See [Deploy the portal](deploy-portal.md).

Each release carries `portal.sha256` next to the binaries, the manifest of the pages that release was built from (the release page on GitHub lists it among the assets).

## The engine's key file

The engine makes its key file at its first start, whatever the `vault` setting says, because the same key will sign receipts. It is `<stateDir>/channel.json`, owned by the engine's OS user, mode `0600`. Anyone who can read it can pose as your engine to the Vault. They still cannot read a session without its link secret, and they cannot approve anything, because only your passkey signs and Postgres verifies it.

If the file has the wrong owner or mode, or does not parse, the engine does not replace it. The state is `KEY_ERROR`. Fix the owner and mode (`chown` to the engine's user, `chmod 600`). If you delete the file, the engine makes a new key and a new engine id on its next start.
