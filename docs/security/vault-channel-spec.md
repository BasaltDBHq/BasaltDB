# The Vault channel: a spec for outside reviewers

This document describes the end-to-end encrypted channel between a BasaltDB engine and the portal page a person approves on, carried by a relay the person does not have to trust. It is written to be read alone: every byte layout, derivation and check is stated here, so you can review the design without reading the rest of the repository. Links point to evidence (the contract section, a schema, a test vector), never to something you need in order to understand a step.

It describes the protocol as it is built. Where an older design differs, the [contract](../../contract/vault-channel.md) and the code win, and this document follows them. Two machine-checked guards keep it honest: `TestChannelSpecMatchesContract` (in `internal/channel`) compares the constants in the blocks marked `constants` below with the code, and the shared test vectors (section 9) pin every byte layout and every refusal.

How to report a problem: [SECURITY.md](../../SECURITY.md).

## 1. Goal, parties and trust

**Goal.** A person approves a held database write or a revert in a browser, from anywhere, for an engine that has no inbound port (on a server, in a container). The approval is a WebAuthn passkey signature made in the browser. The engine dials out to a hosted relay (the "Vault", `relay.basaltvault.app`); the browser page dials in; the relay pairs the two sockets and forwards bytes. The channel's job is to let the page read an item from the engine and send back the person's signature, so that the relay, and anyone on the network path, learns no content and can alter nothing without the session failing.

**Parties.**

| Party | What it is |
|---|---|
| Person | Owns the database and the passkey. Reads the page, compares fingerprints, taps the authenticator. |
| Portal page | JavaScript served as static files from `portal.basaltvault.app`. Runs the initiator side of the handshake in WebCrypto. Keeps no state between sessions. |
| Engine | A Go process next to the agent. Holds the link secrets it issued, a P-256 signing key and a P-256 box key, and answers the page's requests with the same handlers it serves on loopback. |
| Vault (relay) | Closed-source service. Pairs sockets and forwards opaque bytes. This document specifies only what the protocol lets it see and do. |
| Postgres | The person's database, with a guard schema installed. It verifies the passkey signature over a binding of the exact rows, and it is the only place an approval takes effect. |

**Who is trusted for what.**

- The Vault is **untrusted**. A Vault that drops, delays, duplicates, reorders, replays, truncates, reflects or alters any message can make a session fail, never make either side accept something. It never holds a key that opens a session.
- The network path between the page and the Vault, and between the Vault and the engine, is untrusted.
- The engine is trusted for what it shows and for its signed receipts, but it cannot approve anything: only the person's passkey signs, and Postgres checks that signature against the real pending item.
- The portal page's code is trusted by the person, because the page is what builds what the person signs. This is the main accepted risk (section 7).
- The agent (the software that proposes writes) is not trusted. Nothing in this channel gives it a signing power.

The channel carries link sessions only, for the approval and revert pages. A transport that skipped the relay (a direct connection through the person's own tunnel) existed earlier and is **removed**: this document does not describe it as built. Pairing, envelopes, device codes and accounts (a later phase) are listed in section 10 and are design only.

## 2. Keys and ids

All cryptography is P-256 (ECDH and ECDSA), SHA-256, HMAC-SHA-256, HKDF-SHA-256 (RFC 5869) and AES-256-GCM, from WebCrypto in the page and the Go standard library in the engine. No third-party crypto, and no primitive of our own: the handshake is a Noise pattern, and every other step is a signature, an HKDF or an AEAD call.

**Encodings.**

- A public key inside a handshake message is the 65-byte uncompressed SEC1 point `0x04 || X || Y`.
- A public key as an identity is the 91-byte DER SubjectPublicKeyInfo (`id-ecPublicKey`, `prime256v1`, uncompressed point): the 26 bytes `3059301306072a8648ce3d020106082a8648ce3d030107034200` followed by the 65-byte point, base64url without padding (122 characters). Any other encoding (compressed point, explicit curve parameters, another curve, trailing bytes) and any point not on the curve is refused.
- An ECDH output is the 32-byte x-coordinate.
- A signature is ECDSA P-256 over SHA-256, encoded as 64 bytes `r || s` (IEEE P1363), base64url without padding (86 characters). Any other length is refused. A high-S signature is accepted (plain ECDSA verification accepts both `s` and `n - s`, and nothing uses a signature's bytes as an identifier).
- Bytes in JSON are base64url without padding unless a field says otherwise. In test vectors they are lowercase hex.

**Engine keys.** The engine has two keys, made on its first start: a **signing key** (ECDSA P-256, its identity) and a **box key** (ECDH P-256; made now so the key file keeps its shape, used only by the later phase). The box key's public key is signed by the signing key: `basalt-engine-box-key.1\n` + `engineId` + `\n` + the box key's SPKI as base64url text. Neither key does the other's job. They are kept in one file, mode `0600`, owned by the engine's OS user, written atomically; a file that fails any check is refused and never replaced.

**Engine id.** `engineId` = base64url of the first 16 bytes of `sha256(signing key SPKI DER)`: 22 characters. It is self-certifying and a fingerprint, not a random id. People compare its first 16 characters in four groups of four (`AbCd EfGh IjKl MnOp`), the **fingerprint**. Pinned by `engine-id.json`.

**Link secret.** For each approval or revert page the engine issues a link with a 16-byte random secret `s`, as the 22-character base64url fragment of the URL: `https://portal.basaltvault.app/approvals/<id>#s=<secret>`. Browsers do not send a fragment to any server. The page reads `s` from `location.hash`. The engine keeps `sha256(s)` and two derived values per link, with an expiry (at most 24 hours), one live link per item, compared in constant time.

**Derivations** (HKDF-SHA-256 with input keying material `s`, an **empty** salt):

- `linkToken` = HKDF(ikm `s`, salt empty, info `basalt-vault-link.1`, 16 bytes), base64url: 22 characters. The Vault's routing key for the link.
- `psk` = HKDF(ikm `s`, salt empty, info `basalt-vault-psk.1`, 32 bytes). The session's pre-shared key.

Neither reveals `s`, and neither gives the other. The page derives both from the fragment and never sends `s` or `psk` to the Vault: the page socket's path carries `linkToken` only. The secret itself travels only inside the encrypted session, in a request header, so the engine can check the request is for the session's own link. Pinned by `link-derivation.json`.

**Signing contexts.** The engine's signing key signs only the inputs below. Each input starts with its own context line (ending in a newline), so no signature made for one purpose verifies as another. A new context is a protocol change.

| Context line | Over |
|---|---|
| `basalt-vault-engine.1\n` | The Vault's challenge and the engine's Vault host (socket authentication, section 5) |
| `basalt-vault-session-sig.1\n` | The handshake hash `h` after the `e, ee` tokens of message 2 (section 3) |
| `basalt-receipt.1\n` | A receipt's payload bytes (section 6) |
| `basalt-engine-box-key.1\n` | The engine id and the box key's public key |
| `basalt-engine-rotate.1\n` | Reserved: a key rotation statement. No shipped command signs it; the rotation command is removed |
| `basalt-connect-collect.1\n` | A request to a separate setup service, not this channel; listed so the full set of contexts is visible |
| `basalt-connect-reach.1\n` | A report to the same setup service; listed for the same reason |

Pinned by `signature.json`.

```constants channel
protocol-name = Noise_NNpsk0_P256_AESGCM_SHA256
prologue = basalt-vault-prologue.1\n<transport>\n<linkToken base64url>
transport-word = RELAY
version-byte = 0x01
type-hello = 0x01
type-welcome = 0x02
type-frame = 0x03
message-1-length = 99
message-2-max = 1024
point-length = 65
spki-length = 91
signature-length = 64
link-token-length = 16
psk-length = 32
secret-length = 16
engine-id-bytes = 16
fingerprint-chars = 16
hkdf-info-link-token = basalt-vault-link.1
hkdf-info-psk = basalt-vault-psk.1
context-vault-auth = basalt-vault-engine.1\n
context-session = basalt-vault-session-sig.1\n
context-receipt = basalt-receipt.1\n
context-box-key = basalt-engine-box-key.1\n
context-rotate = basalt-engine-rotate.1\n
context-connect-collect = basalt-connect-collect.1\n
context-connect-reach = basalt-connect-reach.1\n
padding-min = 1024
padding-max = 32768
padding-length-prefix = 4
content-max = 32764
frame-max = 32786
nonce = 4 zero bytes, then the counter as 8 bytes big-endian
nonce-example = counter 0x0102030405060708 gives 000000000102030405060708
```

## 3. Handshake

**Pattern.** `Noise_NNpsk0_P256_AESGCM_SHA256` from the Noise Protocol Framework (revision 34), with an engine signature in the second payload. The page is the initiator, the engine the responder. There are no static keys in the Noise sense: both sides are anonymous to Noise, the `psk` authenticates the page's link, and the signature carries the engine's identity.

**Functions.**

- `DH`: P-256 ECDH, output the 32-byte x-coordinate. (Noise's `DHLEN` is both a public key's length and a DH output's; here they differ, 65 and 32. An `e` token writes, reads and hashes the 65-byte point; both lengths meet Noise's minimum of 32.)
- `HASH`: SHA-256. `HKDF`: Noise's (section 4.3), built from HMAC-SHA-256, so a zero-length input key works in WebCrypto.
- Cipher: AES-256-GCM with the Noise nonce: 4 zero bytes followed by the 64-bit big-endian counter.
- The protocol name is 31 bytes, so `h` starts as the name padded with one zero byte to 32 bytes, and `ck = h`.
- Because the pattern has a `psk` token (Noise section 9.2), every `e` token is followed by `MixKey(e.public_key)` as well as `MixHash(e.public_key)`, on both sides, for both ephemeral keys.

**Prologue.** The UTF-8 bytes of `basalt-vault-prologue.1\n` + the transport word + `\n` + `linkToken` as its 22-character base64url text (not the raw bytes), with nothing after it. The transport word is `RELAY`, the only one: the word stays in the prologue so a later transport would get its own, and a message 1 built with any other word fails its tag check. `MixHash(prologue)` is the first step. Each side builds the prologue from what it knows itself (the page from its link; the engine from the token it looked up), so a session moved to another link fails.

**Message 1, page to engine** (tokens `psk, e`). Exactly 99 bytes:

```
offset  length  field
0       1       version = 0x01
1       1       type    = 0x01 (HELLO)
2       16      linkToken, raw bytes
18      65      e: the page's ephemeral public key, uncompressed point
83      16      AES-GCM tag of EncryptAndHash of the empty payload
```

Steps, in order, on both sides:

1. `h = "Noise_NNpsk0_P256_AESGCM_SHA256"` padded with a zero byte to 32; `ck = h`; `h = SHA256(h || prologue)`.
2. `psk` token: `MixKeyAndHash(psk)`: `temp = HMAC(ck, psk)`; `o1 = HMAC(temp, 0x01)`; `o2 = HMAC(temp, o1 || 0x02)`; `o3 = HMAC(temp, o2 || 0x03)`; `ck = o1`; `h = SHA256(h || o2)`; `k = o3`; counter `n = 0`.
3. `e` token: write the 65 bytes; `h = SHA256(h || e)`; then `MixKey(e)`: `temp = HMAC(ck, e)`; `o1 = HMAC(temp, 0x01)`; `o2 = HMAC(temp, o1 || 0x02)`; `ck = o1`; `k = o2`; `n = 0`.
4. Payload: always empty. `ct = AES-256-GCM(k, nonce(n), associated data h, empty)` is the 16-byte tag; `h = SHA256(h || ct)`; `n = 1`.

The tag is under a key derived from `psk`: it proves the page holds the link before the engine does any public-key work. The fixed length refuses any other payload.

**Message 2, engine to page** (tokens `e, ee`). At most 1024 bytes:

```
offset  length  field
0       1       version = 0x01
1       1       type    = 0x02 (WELCOME)
2       65      e: the engine's ephemeral public key
67      n       AES-GCM ciphertext (payload plus 16-byte tag) of EncryptAndHash
```

Steps on the engine (the page mirrors them): `e` token as in step 3 above (`MixHash` then `MixKey` of the engine's 65-byte point); `ee` token: `MixKey(DH(e_engine, e_page))`; take `signed = h` here; the payload is UTF-8 JSON `{"engineKey":<SPKI base64url>,"sig":<base64url>}` in that field order ([schema](../../api/mcp/vault/handshake-payload.schema.json)), where `sig` is the engine's signature over `basalt-vault-session-sig.1\n` followed by the 32 raw bytes of `signed`, that is `h` after `e` and `ee` and **before** the payload is hashed in. Then `ct = AES-256-GCM(k, nonce(0), associated data h, payload)`; `h = SHA256(h || ct)`.

**Split.** `k1, k2 = HKDF(ck, empty input, 2 outputs)`. `k1` encrypts page to engine, `k2` engine to page, each with its own counter from 0. Both sides erase the ephemeral private keys and `ck`. The final `h` may be logged as the session id; keys never are.

**Checks on message 1 (engine), in the order the code runs them.**

1. The handshake rate for the token (every token counts, held or not, so the answer says nothing of whether the engine holds it): over the limit closes with `RATE_LIMITED`.
2. The version byte: not 1 closes with `UNSUPPORTED_VERSION`. Then the type byte and the exact length of 99 bytes: wrong closes with `PROTOCOL`.
3. The token: message 1's `linkToken` must equal the one the relay announced for this session (`SESSION_OPEN`), and the engine must hold a live link for it (not expired, not revoked). A token that fails either still goes through step 4 under an all-zero `psk` and is refused afterwards, so a dead token and a live one with a wrong `psk` take the same work.
4. The tag, by decrypting the empty payload under the `psk`-derived key. The `e` token hashes and mixes the 65 bytes as they are, so this needs no point arithmetic.
5. Only then: `e` is a valid point on the curve.
6. The link's open-session limit, and only then the engine's public-key work for message 2.

Every failure from step 3 to step 5 closes with `LINK_REFUSED`, alike, so a probe cannot tell a live token from a dead one by the answer. A test pins the order (`TestEngineChecksTagBeforePoint`).

**Checks on message 2 (page), in order.** Version (`UNSUPPORTED_VERSION`), type (`PROTOCOL`), size at most 1024 bytes (`TOO_LARGE`); then `e` is a valid point, decryption succeeds, the payload parses as the closed schema (exactly those two fields, no unknown field, no trailing data), `engineKey` is a valid 91-byte SPKI, and `sig` verifies over `basalt-vault-session-sig.1\n || h`. Any failure from the point onward closes with `HANDSHAKE_FAILED` and the page shows nothing from the engine. On success the page computes `engineId` from `engineKey`.

**Engine identity is not pinned on the relay.** The link carries no engine id and the page keeps nothing between sessions, so the page accepts whatever key a holder of the link's `psk` signs with. The person's check is to compare the fingerprint the page shows with the one the engine's status shows. See section 7.

**Close codes** (WebSocket close codes, with the name as the close reason; registry [`close-codes.json`](../../api/mcp/vault/close-codes.json)). A code that arrives from the Vault only decides what the page shows; nothing else trusts it.

| Code | Name | Sent by | When |
|---|---|---|---|
| 4000 | `PROTOCOL` | page, engine, Vault | A message out of place or malformed |
| 4001 | `UNSUPPORTED_VERSION` | page, engine, Vault | A version byte or `AUTH` version other than 1 |
| 4002 | `AUTH_FAILED` | Vault | Engine socket: bad key header, or bad or late `AUTH` |
| 4003 | `REPLACED` | Vault | Engine socket: a newer authenticated socket for the same id |
| 4004 | `LINK_UNKNOWN` | Vault | No engine registered the token, it expired, or it was unregistered |
| 4005 | `ENGINE_OFFLINE` | Vault | The token's engine has no socket |
| 4006 | `LINK_REFUSED` | engine | Message 1 refused, or a link revoked or expired mid-session |
| 4007 | `HANDSHAKE_FAILED` | page | Message 2 refused |
| 4008 | `FRAME_INVALID` | page, engine | A frame that does not decrypt with the next counter, or has non-canonical padding |
| 4009 | `TOO_LARGE` | page, engine, Vault | A message over its limit |
| 4010 | `RATE_LIMITED` | engine, Vault | Too many handshakes, requests or connections |
| 4011 | `SESSION_LIMIT` | engine, Vault | Too many open sessions for the link or the engine |
| 4012 | `TIMEOUT` | page, engine, Vault | Handshake over 10 s, idle 5 minutes, or 30 minutes lifetime or link expiry |
| 4013 | `ENGINE_REVOKED` | engine | The engine's key is revoked in the database of the session's agent: it closes that agent's open sessions with this code (section 8) |
| 4014 | `ENGINE_SHUTDOWN` | engine | The engine is stopping |

```constants close-codes
4000 PROTOCOL
4001 UNSUPPORTED_VERSION
4002 AUTH_FAILED
4003 REPLACED
4004 LINK_UNKNOWN
4005 ENGINE_OFFLINE
4006 LINK_REFUSED
4007 HANDSHAKE_FAILED
4008 FRAME_INVALID
4009 TOO_LARGE
4010 RATE_LIMITED
4011 SESSION_LIMIT
4012 TIMEOUT
4013 ENGINE_REVOKED
4014 ENGINE_SHUTDOWN
```

Evidence: [contract, Handshake](../../contract/vault-channel.md#handshake), `handshake.json`.

## 4. Frames

After the handshake, every binary WebSocket message in either direction is one frame:

```
offset  length  field
0       1       version = 0x01
1       1       type    = 0x03 (FRAME)
2       n       AES-256-GCM ciphertext of the padded plaintext, plus 16-byte tag
```

The ciphertext is Noise's `EncryptWithAd` under the direction's key and counter, with the **two header bytes as associated data**.

**Nonces.** Each direction has its own key (`k1` or `k2`) and an implicit counter starting at 0 and increasing by 1 per frame. The nonce is 4 zero bytes followed by the 8-byte big-endian counter and is never sent: the receiver uses its own count. So a frame dropped, repeated, reordered, reflected to its sender or taken from another session does not decrypt, and the receiver closes with `FRAME_INVALID` and drops the session. When a refused frame fails the session's channel while a worker is still answering the request before it, the worker cannot seal its answer: the session ends once, with the close code the frame's error carries (`FRAME_INVALID`), not with a second close of its own. There is no rekey; the session limits end a session long before a counter could wrap.

**Padding.** The plaintext is `len` (4 bytes, big-endian) `||` content (`len` bytes) `||` zero bytes up to `max(1024, the next power of two >= 4 + len)` bytes, at most 32768. Content is therefore at most 32764 bytes per frame, so every Noise message stays under 65535 bytes. A receiver refuses (`FRAME_INVALID`) a plaintext whose size is not exactly that bucket for its `len`, a `len` over 32764, and any non-zero padding byte. Sizes on the wire are then 1024, 2048, ... 32768 bytes plus 18 (2 header, 16 tag): one frame leaks a size bucket, not a row count. Pinned by `padding.json`.

**Receive order.** A receiver checks size (over 32786 bytes: `TOO_LARGE`), then the version byte (`UNSUPPORTED_VERSION`), then the type (`PROTOCOL`), then decrypts and unpads (`FRAME_INVALID`). A text WebSocket message, or a binary message with another header, closes with `PROTOCOL`.

**Content** is UTF-8 JSON, one of ([schema](../../api/mcp/vault/frame-message.schema.json)):

- `REQUEST`, page to engine: `{ "type", "id", "method", "path", "headers", "body", "more" }`.
- `RESPONSE`, engine to page: `{ "type", "id", "status", "headers", "body", "more" }`.
- `CONTINUE`, either way: `{ "type", "id", "body", "more" }`, the next piece of a body.

`body` is text (the engine's pages API speaks JSON). A body too large for one frame continues in `CONTINUE` frames, appended in order up to the one with `more: false`. A message is acted on only once its last frame arrives, so a truncated message is never used. `id` is 1 for a session's first request and one more for each next; a response and its continuations carry the request's `id`. One request is in flight at a time: a `REQUEST` before the previous response ended closes with `PROTOCOL`.

**Requests.** Only these routes are dispatched; any other is answered `404` with the same body as an unknown id:

- `GET /api/v1/approvals/{approvalId}` and `POST /api/v1/approvals/{approvalId}/approve`;
- `GET /api/v1/reverts/{revertId}` and `POST /api/v1/reverts/{revertId}/apply`;
- `POST /api/v1/reverts/{revertId}/scope` and `POST /api/v1/reverts/{revertId}/reject`;
- `POST` `.../reveal` on an approval or a revert (reading rows hidden from the agent).

A `reject` revokes the revert's link, so its session ends with `LINK_REFUSED` once the answer went out.

The path's id must be the item of the session's link, and the request header `basalt-link-secret` must be that link's secret (its `sha256` and its `linkToken` both match); otherwise `404`. Request headers are lowercase; a request carries `basalt-link-secret` and `origin` (`https://portal.basaltvault.app`), and on `POST` `content-type: application/json`; any other header is answered `400`. The engine hands the request to the same handlers as on loopback, with the same checks and statuses. When a revert's scope is widened, its link is rotated inside the open session: later requests carry the new secret and the old one is answered `404`.

**Limits** (enforced by the engine and the page; the relay must carry messages up to these sizes):

```constants vault
message-1 = exactly 99 bytes
message-2 = at most 1024 bytes
frame = at most 32786 bytes
route-message = at most 32804 bytes
control-message = at most 4096 bytes
request-body = at most 16384 bytes
response-body = at most 16 MiB, checked by the page only
handshake-time = 10 seconds
idle-session = 5 minutes
session-lifetime = 30 minutes
requests-per-session = 64
sessions-per-link = 4
sessions-per-engine = 64
handshakes-per-link = 20 per 10 minutes
route-type = 0x10
session-id-bytes = 16
```

Evidence: [contract, Frames](../../contract/vault-channel.md#frames), [Limits](../../contract/vault-channel.md#limits), `frame.json`.

## 5. The Vault's interface, and what it sees

**The engine's socket.** `wss://relay.basaltvault.app/v1/engines/<engineId>`, compiled into the binary.

1. The engine opens it with the header `basalt-engine-key: <signing key SPKI, base64url>`. The Vault refuses (`AUTH_FAILED`) a key that is not a valid P-256 SPKI or does not hash to the path's `engineId`.
2. The Vault sends `CHALLENGE` with 32 random bytes: fresh per socket, single use, valid 30 seconds.
3. The engine answers `AUTH` with `version` 1 and `sig` over `basalt-vault-engine.1\n` + the challenge (as sent, base64url text) + `\n` + the host, where the host is the engine's own Vault host, never one the Vault names. A bad or late answer: `AUTH_FAILED`.
4. The Vault sends `READY`. One live socket per engine id: a newer authenticated socket replaces the older, which is closed with `REPLACED`. After every `READY` the engine registers every live link again.

Control messages are text WebSocket messages of at most 4 KiB, JSON ([schema](../../api/mcp/vault/control-message.schema.json)). Session bytes are binary `ROUTE` messages: `0x01` `||` `0x10` `||` `sid` (16 bytes) `||` the page's message exactly as received, or the engine's message for the page.

| Message | Direction | Fields | Meaning |
|---|---|---|---|
| `REGISTER_LINK` | engine to Vault | `ref`, `linkToken`, `expiresAt` | Route page sockets for this token to me until `expiresAt` (at most 24 hours and 5 minutes ahead) |
| `UNREGISTER_LINK` | engine to Vault | `ref`, `linkToken` | Stop routing it, and close its page sockets. Only the engine the token is bound to can |
| `OK` | Vault to engine | `ref` | Request `ref` succeeded |
| `ERROR` | Vault to engine | `ref`, `code` | `LINK_CONFLICT`, `LINK_LIMIT`, `INVALID_EXPIRY`, `UNKNOWN_SESSION`, `RATE_LIMITED`, `PROTOCOL` |
| `SESSION_OPEN` | Vault to engine | `sid`, `linkToken` | A page connected for the token; its message 1 follows as a `ROUTE` |
| `SESSION_CLOSE` | either way | `sid`, `code` | The session ended; the Vault closes the page's socket with the same code |

**No control message is trusted.** A forged `SESSION_OPEN` costs one refused handshake; a forged `OK` gives a link the page cannot reach (the engine falls back to a long link); a forged `SESSION_CLOSE` or `ERROR` ends a session or a registration. None can open a session, read one or make the engine act on a request.

**The page's socket.** `wss://relay.basaltvault.app/v1/links/<linkToken>`, opened by a portal page (the Vault refuses another `Origin`; a check against other sites' pages, not a security boundary). The Vault closes with `LINK_UNKNOWN` when no engine registered the token or it expired, and with `ENGINE_OFFLINE` when its engine has no socket. Otherwise it sends `SESSION_OPEN` to the engine and forwards every binary message both ways unchanged and in order. The page sends nothing but handshake message 1 and frames, and keeps no state between sessions.

**A token belongs to one engine.** The Vault binds each registered token to the engine id that registered it on an authenticated socket, and refuses (`LINK_CONFLICT`) a registration of a live token by any other engine id until the token expires or is unregistered. Known limit: if the Vault loses that binding, an engine that also holds the link secret could register the token first. The impact is that of the unpinned relay identity (section 7).

**What the Vault sees (metadata only).**

- Engine ids and their public keys; when each engine is connected, and from which network address.
- Link tokens: when they are registered, used and unregistered, and their expiry.
- Page network addresses and user agents.
- How many sessions and frames there are, their padded sizes, their timing, and close codes.

Padding hides one frame's exact size, not these: how many frames a message took (a large response shows as many full frames), which way each went, and the rhythm of a session. From them the Vault can usually tell that a page read an item and then posted a signature: that an approval or revert was probably signed, and when, though not which item, rows or result.

What the relay stores to run: which engine registered each link token and its expiry; counters of public-key operations per engine and client (a hash of the client's network address, kept for at most a minute); and the times pages opened sessions on a link, to cap them. [relay-privacy.md](../relay-privacy.md) states this for people. This document does not specify the service's hosting, storage or operations, which are not part of the protocol.

**What the Vault never sees.** Link secrets, `psk`s or session keys; item ids, rows, statements, headlines, signatures, receipts or results; any database credential; any private key.

**What the Vault must do** (nothing in the engine or the page relies on these; each is about service and privacy, not about what gets accepted): forward session bytes unchanged and in order; keep sessions apart; route a token only to the engine that registered it first; drop tokens at their expiry; accept the sizes above; send fresh single-use challenges; never log session bytes.

Evidence: [contract, The engine's socket](../../contract/vault-channel.md#the-engines-socket-to-the-vault), [What the Vault sees](../../contract/vault-channel.md#what-the-vault-sees).

## 6. Receipts

A receipt is a statement signed by the engine of what a relayed signature did. Token: `basalt-receipt.1.` + `payload` + `.` + `sig`.

- `payload`: base64url of UTF-8 JSON, a closed object ([schema](../../api/mcp/vault/receipt.schema.json)): `format` (always 1), `kind` (`APPROVAL` or `REVERT`), `itemId` (UUID), `status` (`APPROVED`, or for a revert `APPLIED` or `APPLYING`), `headline` (1 to 500 characters), `rowsHash` (64 lowercase hex characters: the hash of the binding the passkey signed, from Postgres's record), `agent`, `engineId` (22 characters), `at` (UTC, whole seconds, `YYYY-MM-DDThh:mm:ssZ`), and `changeId` (UUID) when there is one.
- `sig`: ECDSA over `basalt-receipt.1\n` followed by the payload's **decoded bytes**, base64url. Signing the exact bytes means no one needs canonical JSON.
- The engine signs a receipt only after Postgres accepted the signature, and builds the payload from its own read of the item then: nothing the page, a code or the agent sent goes into it except through Postgres, and the agent cannot make one.

**How to verify one.** You need an **expected engine key from outside the receipt**: the engine the person already knows (the engine id or fingerprint its status reports, or an earlier message of the same agent). Then, in this order:

1. Check `sig` against that key over `basalt-receipt.1\n || payload bytes`.
2. Parse the payload strictly: UTF-8, one JSON object, exactly the schema's keys, none twice, none unknown, no nulls.
3. Check `engineId` equals the id of the expected key.
4. Check the payload against the closed schema.

A receipt checked only against a key that came with it (the session's own `engineKey`, or one the relay or the agent hands over) proves only that whoever holds that key signed it, not which engine that is. In the page, a receipt can be verified only against the session's key, which on the relay is not pinned, so the page shows it with the fingerprint and asks the person to compare; the check that counts is against the engine the person knows. Pinned by `receipt.json`.

## 7. Threat table

| Attacker | Can | Cannot |
|---|---|---|
| Passive network observer, or the relay (honest or not) | See the metadata in section 5. Deny service. Guess that an approval was signed, and when. | Read or change a session; pose as either side; learn link secrets, item ids, rows or signatures. |
| Active relay: drops, delays, repeats, reorders, reflects, splices, truncates | Make a session fail. | Make either side accept a message: counters and AEAD tags refuse every one, and the handshake hash binds the transcript. |
| Relay that routes a link to an engine of its own (needs the link secret as well) | Present another key: a fake fingerprint on the page, fake receipts in the page, and denial of service. | Forge an approval: Postgres accepts a signature only over a real pending item's binding. |
| Someone who saw a link (the secret) | Open a session and read that one item's preview, until the link expires or is replaced. Register the token from another engine if the relay lost its binding (above). | Approve anything: that needs the person's passkey. |
| Holder of the engine's key file | Pose as the engine to the relay and sign receipts in its name. | Read a session without a link secret; approve anything. |
| Replayer of recorded traffic | Nothing useful. A replayed message 1 meets a fresh engine ephemeral key and the replayer lacks the page's private ephemeral key; a replayed message 2 fails against the page's fresh key; frames fail on counters. | Approve twice: Postgres refuses a used approval or revert. |
| Later thief of the link secret, links file or engine key | Nothing on recorded sessions: every session key depends on two ephemeral keys, so past sessions stay closed. | Decrypt a recorded session. |
| **A compromised portal** (a page changed for one person or for everyone) | Show the person something other than the real rows, and obtain their signature over a real item they were not shown; or keep a signature and not send it. | Sign for the person, or obtain a signature Postgres would accept for an item that is not real and pending. |

**Accepted residual risks.** These are stated plainly because the design does not remove them.

- **A compromised portal.** The page is the code that builds what the person signs and shows what they sign. If the page is changed, the person can be shown other rows than the ones in the binding they sign. The design's mitigations are partial: the person's passkey signs only a real pending item's binding; the engine's receipt names the real item and its rows hash, built from Postgres's record, so a page that made the person sign another item than the one shown is caught when the receipt is compared in the chat; and a check of the served page files against the copy in the binary exists today (`basalt portal verify`; it is being moved into the release workflow) and cannot catch a page served to one person alone.
- **Signature substitution.** A hostile page can relay the person's signature for a different real item of the same database than the one shown. The most it obtains is the person's signature over a real item that was pending; the receipt names that item.
- **Unpinned relay engine identity.** On the relay the link carries no engine id and the page remembers nothing, so the engine's identity is trust on first use, checked only by the person comparing the fingerprint on the page with the one the engine's status or the agent's earlier messages gave. Whoever holds a link secret and gets the relay to route the token to their own engine can show another fingerprint and issue receipts that verify only against their own key. This is accepted; a pin was only possible on the removed direct transport.
- **Relay metadata.** The relay sees that a page read an item and probably signed, and when (section 5).

## 8. Known limits and open questions

**Known limits, as built.**

- No engine revocation. Nothing revokes an engine's key: a person who wants an engine cut off removes BasaltDB from the database, which drops every `basalt_*` role, so the engine can no longer log in. A row revoked by hand in SQL is only reported in the engine's status; the engine still hands over relay links for it, and the relay holds no engine record. A compromised engine still cannot sign anything a person did not.
- An old signing key stays valid at the relay after a rotation or revocation: the relay never reads the person's database, so whoever holds the old key can still authenticate as the old engine id. It gives them only the old id's routing; its links were revoked.
- The relay may lose its token binding (restart, failover). The engine re-registers live links after every `READY` and, on `LINK_CONFLICT` for a link it holds, revokes that link.
- The engine counts handshakes per token before it looks the token up, and runs a dead token's tag check under a zero `psk`, to keep the answer and the time the same. The rate check runs before the token lookup, and the contract says the same.
- No rekey. The session limits make it unnecessary.

**Questions for the reviewer.**

1. **Transcript binding.** The signature covers `h` after `e, ee`, which includes the prologue (version, transport, `linkToken`), both ephemeral keys and message 1's tag, but not message 2's payload. Is there a gap in what the engine's signature binds, or in what `Split` derives from? Is signing `h` before the payload is mixed in sound, given the payload is itself encrypted under a key derived from the same state?
2. **Signature context separation.** Seven context lines share one signing key, each the first line of the signed input. Can any of the formats of section 2 and 6 be made to parse as another context's input? Is a one-line prefix enough where inputs are structured text or JSON?
3. **Padding leakage.** Buckets are 1024 bytes to 32768 by powers of two. What can an observer of frame counts, buckets, direction and timing infer about which item was read, how many rows a revert holds, or whether a signature was sent?
4. **Replay across links.** The link token is derived from the secret and is in the prologue and in message 1. Can message 1, or a session's frames, be moved to another link, another engine or another transport and accepted? Does the unauthenticated `linkToken` in message 1 (bound only through the prologue and the tag) open any oracle?
5. **Key compromise.** After a leak of the link secret, the links file, the engine signing key or the box key, what does each give an attacker, and for how long? Is forward secrecy as claimed against each?
6. **Noise on P-256.** The pattern is not one of Noise's standard names. Are there issues in using the 32-byte x-coordinate as the DH output while hashing 65-byte points, in `MixKey` after every `e` token, or in a 12-byte nonce with receiver-side counters?
7. **Message 1 as an oracle.** Messages 1 for dead tokens still run a tag check under a zero `psk`. Do the answers or the timing leak whether a token is live?
8. **The unpinned identity.** Is trust on first use with a fingerprint comparison a reasonable bound for the relay path? Is a 16-character comparison long enough, and is there a better place to anchor the engine key?
9. **High-S signatures** are accepted and no signature is used as an identifier. Is anything in the protocol a malleability concern anyway?
10. **Compromised portal.** Is there a cheap check, in the protocol and not in the page, that would let a person detect a page that showed other rows than the ones signed?

## 9. Test vectors

The vectors are shared by the Go engine and the page's JavaScript: both read the same files and a mismatch fails the project's checks. Private keys in them are fixed 32-byte scalars so the bytes are reproducible. ECDSA signatures are randomized, so each vector pins one valid signature and a writer under test uses it instead of signing. A case's `expect` is `ACCEPT`, `REFUSE` or a close code, so refusals are pinned too. Format: [`vectors.schema.json`](../../api/mcp/vault/vectors.schema.json).

| File | Kind | Pins |
|---|---|---|
| `api/mcp/vault/testdata/link-derivation.json` | `LINK_DERIVATION` | `linkToken` and `psk` from a link secret (4 cases) |
| `api/mcp/vault/testdata/engine-id.json` | `ENGINE_ID` | Engine id and fingerprint from a key; refusal of a compressed point, explicit parameters, a trailing byte, a truncated key, an off-curve point and a P-384 key (8 cases) |
| `api/mcp/vault/testdata/padding.json` | `PADDING` | The bucket for each content length, and refusal of non-zero padding, a wrong bucket, a length past the end or over 32764 (11 cases) |
| `api/mcp/vault/testdata/handshake.json` | `HANDSHAKE` | Prologue, message 1 and 2 bytes, `h` and both session keys; refusal of a wrong `psk`, an unknown token, a tampered tag, an off-curve or compressed point, a wrong `psk` on message 2, version and length faults, reflected messages, a tampered message 2, a signature by another key or under the receipt context, a compressed engine key, an unknown payload field, an oversize message 2, and the order of checks (25 cases) |
| `api/mcp/vault/testdata/frame.json` | `FRAME` | Request and response frames, padding buckets, a frame that fills the largest bucket and its continuation; refusal of reordered, replayed, reflected and spliced frames, a tampered tag or body, a truncated frame, bad padding, version and type faults, an oversize frame, and the order of checks (22 cases) |
| `api/mcp/vault/testdata/signature.json` | `SIGNATURE` | One valid signature for every context of section 2, and refusal of a signature under another context, another key, other bytes, an ASN.1 DER encoding and a zero signature; a high-S signature is accepted (14 cases) |
| `api/mcp/vault/testdata/receipt.json` | `RECEIPT` | A valid approval and revert receipt; refusal of another engine's signature, a key claiming another id, a changed `rowsHash`, the session context, a missing field, an unknown field and `format` 2 (10 cases) |

**Run them.**

```
go test -count=1 ./api/mcp/vault/ ./internal/channel/
node --test web/lib/channel.test.mjs
```

The first command runs the vectors against a test-only Go reference (`api/mcp/vault`) and the engine's own implementation (`internal/channel`); the second runs them against the page's WebCrypto code. To regenerate the files: `go test ./api/mcp/vault -run TestGenerateVaultVectors -update-vectors`. Two tests look at this document: `TestChannelSpecMatchesContract` checks the `constants` blocks above against the code, and that each vector file is named here.

## 10. Out of scope

- **Phase 1b is design only and is not built:** pairing, envelopes sealed to the box key, device codes, a pending list, notifications and accounts. The box key exists in the key file but nothing uses it. Nothing in this document describes behavior you can test for those.
- **The direct transport** is removed, in the code and in the vectors. Nothing here describes it beyond saying so.
- **The relay service itself:** its source, hosting, storage and operations. Only the protocol it speaks and what it is allowed to see are in scope.
- **Postgres and the guard schema,** and the WebAuthn ceremony: Postgres verifies the passkey signature over the binding of the rows, which this channel only carries.
- **The setup service** that uses two of the signing contexts is a separate service and not part of this channel.
