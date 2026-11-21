# What the relay keeps, and for how long

The relay (the "Vault", `relay.basaltvault.app`) pairs an engine that has no inbound port with the portal page you approve on, and passes encrypted bytes between them. This page says what it can see, what it cannot, and what it stores. For the setup and the switch to turn it off, see [vault.md](vault.md).

The relay service is closed source during the preview, so this page is a statement of how it is built and run, not something you can check in this repository. What the protocol lets it see is in the [Vault channel contract](../contract/vault-channel.md#what-the-vault-sees), which the engine and the page enforce. Nothing you rely on for safety depends on the relay being honest: it cannot sign, approve or read anything.

## What it sees

- Engine ids and their public keys, and when each engine is connected.
- Link tokens: when they are registered, used and unregistered, and when they expire.
- The network address of each engine and each page, and the page's user agent. The host that serves the relay (Cloudflare) sees these as well, as any web host does.
- How many sessions and frames there are, their padded sizes and their timing, and the close codes.

From the sizes and timing it can usually tell that a page read an item and then sent a signature, so that an approval was probably signed, and when. It cannot tell which item, which rows or what the result was.

## What it never sees

- Database content: rows, statements, headlines, results.
- Credentials: database passwords and connection strings, and any private key.
- Your passkey or its signature, and the receipts.
- Link secrets (the part after `#s=` in a link) and the session keys. Sessions are encrypted end to end between the engine and the page.
- Plaintext of any session. It forwards bytes it cannot open.

## What it stores, and for how long

- **Link bindings.** For each registered link token, which engine registered it and when it expires. It is dropped at the link's expiry, at most 24 hours after it was registered, or sooner if the engine unregisters it. While it holds, another engine cannot register the same token.
- **Rate counters.** To slow down abuse, it counts public-key operations per engine and client. A client is an IPv4 address or an IPv6 /64, kept as an unsalted hash and for at most a minute. A hash keeps the address out of plain view, but it is not anonymous: someone who guesses an address can check it against the hash.
- **Page-socket times per link.** The times at which pages opened a session on a link, to cap them at 20 in 10 minutes. They are dropped with the link.

It has no accounts and keeps no session content.

## Logs

Request logs are off. The relay writes one kind of log line: an event name with an engine id and a close code. It carries no URL, no address, no link token and no session bytes. Where connection metadata is kept at all, for example by the host's own tooling, it is kept at most 7 days.

## If you do not want this

Run with the relay off (`basalt init --vault=off`). Approvals still work through long links, or through your own tunnel ([approving.md](approving.md#your-own-tunnel-without-the-vault)).
