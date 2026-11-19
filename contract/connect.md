## Connect

Planned, except [the connect link](#the-connect-link), which `basalt init --remote` prints and the next steps hand over. The connect service and the connect page are not served yet. This section is the protocol of the **connect service**, the second way to run a [setup code](setup-from-laptop.md#the-setup-code): the person opens a link their bot sent, creates a passkey, pastes the database's admin connection string, and approves. The connect service runs the setup code against that database once, as [`basalt init --setup-code`](setup-from-laptop.md#basalt-init---setup-code-the-persons-own-computer) does on the person's own computer, and forgets the connection string. The laptop command stays, and is always the way that needs no hosted service.

**A hosted service, used only at setup.** The connect service is run by Basalt Vault at `https://connect.basaltvault.app`. It is closed source; this section and [`connect.proto`](../api/connect/proto/basalt/connect/v1/connect.proto) are the whole protocol it speaks (as the [Vault channel](vault-channel.md#vault-channel) is for the relay, VC-13). It is used only while a person runs a setup from the connect page:

- The engine never calls it. `basalt init --remote` only prints a link (below), and nothing is registered anywhere before the person opens it: no registration call, no new signing context, no pending setup stored by Vault.
- It has no accounts and no sign-in. It stores nothing: no database, no queue, no disk. Each request stands alone.
- It is not on the data path and has no part in approvals or reverts. After the setup, the engine talks to the person's database as it does after the laptop command.
- When Vault is off, down or over a limit, the person runs the laptop command instead: the engine prints no link with the Vault off, and the page names the laptop command with every refusal.

The setup itself is the same as the laptop command's: the same checks in the same order, the same SQL from the same code (a public setup package in this repository, which the service pins at an engine version), one transaction, and `basalt_meta.record_setup`. The record does not say that Vault ran it.

### The connect link

`https://portal.basaltvault.app/connect#<code>`, where `<code>` is the setup code as `basalt init --remote` prints it. The code is in the fragment, so it reaches the page and not the portal's server. Like an approval link, the link holds everything the page needs; there is no short form.

- **When it is printed.** `basalt init --remote` prints it when the engine's `operatedBy` is `AGENT`, its `vault` is `ON` ([Configuration and status](vault-channel.md#configuration-and-status)), its `pagesUrl` is the portal (not with `devLocalPages`), and the whole link is at most the engine's [`linkBudget`](showing-links.md#the-link-budget) characters. A setup code is at most 1500 characters, so with the default budget of 1800 the link always fits. When it does not fit, init prints the code and says to paste it at `portal.basaltvault.app/connect`. There is no network call either way.
- **Where it is handed over.** In the text output after the code block, in the `--json` result's `connectUrl` and `personMessage` ([`remote-init-result.schema.json`](../api/mcp/setup/remote-init-result.schema.json)), and in every `personMessage` that hands the person a pending setup code on such an engine ([Next steps on an agent-operated engine](next-steps.md#next-steps-with-the-connect-link)). It follows [Links in `personMessage`](showing-links.md#links-in-personmessage): a line of its own, with a `links` entry labelled `Connect your database`. The message says the link uses Basalt Vault, a hosted service, and that the laptop command is the other way.
- **The order.** The link first, the laptop command second. Both run the same code, so whichever runs first uses it and the other is refused `USED`.

### `SetupService` calls

ConnectRPC, package `basalt.connect.v1`, service `SetupService`. Each call is a `POST` to `https://connect.basaltvault.app/basalt.connect.v1.SetupService/<Method>`. The connect page sends `Content-Type: application/json` with the request's proto3 JSON form and needs no generated client; other clients may use the protobuf form. Field names in JSON are the camelCase forms of the proto's, byte values are base64url without padding, and enum values are SCREAMING_SNAKE_CASE strings. Proto3 JSON leaves out a field at its default value, so an absent field is `false`, `0`, empty or an empty list. The package is `v1`: a breaking change is a new package, and the page and the service ship it together.

| Call | Input | Output | Database |
|---|---|---|---|
| `DescribeSetup` | `code` | `summary`: the decoded code (kind, agent, role, prefix, target, tables, statement timeout, guard versions, expiry), its setup fingerprint, the engine fingerprint when the code carries an engine key, and the summary `lines` of [step 5](setup-from-laptop.md#basalt-init---setup-code-the-persons-own-computer) that need no database. `challenge`: [the passkey challenge](#the-passkey-challenge) | None |
| `CheckSetup` | `code`, `databaseUrl` | `questions` (the row-level security question per table, as the laptop command asks it: `kind` `ROW_LEVEL_SECURITY`, `table`, `text`, `choices` `ALL_ROWS` or `NONE`), `passkeyNeeded`, `notes` (the lines that need the database: the statement timeout now in force, tables outside `public` flagged, the nothing-to-upgrade line), `nothingToDo` | Connects and reads. Changes nothing |
| `RunSetup` | `code`, `databaseUrl`, `answers`, `challenge` and `passkey` when a passkey is registered | `warnings`, `passkeys` (each registered passkey's credential id, label and [check code](#the-passkey-check-code)), `nothingToDo` | Connects and runs the setup in one transaction |

- **Every call stands alone.** `RunSetup` does not rely on `DescribeSetup` or `CheckSetup` having run: it repeats every refusal of both, in the same order, and computes the questions itself. It refuses an answer to a question it did not compute and a question left without an answer (`ANSWERS_INVALID`). The service keeps nothing between calls: the page holds the connection string in memory and sends it with `CheckSetup` and again with `RunSetup`.
- **What `RunSetup` runs.** Step 6 of the laptop command, with the confirmed answers in place of the prompts: the missing migrations, the role, the grants, the confirmed agent policies, `attach`, `record_setup`, and, when the code carries an engine key, `record_engine` with no address (the page asks for none, so a recorded address is kept and no other engine is offered for revoking). When a passkey is registered, `register_passkey` runs in the same transaction, after the migrations, so a failure leaves the database as it was.
- **A passkey is needed** when the code is `INSTALL`, or when the database has no active passkey registered on the portal. Then `RunSetup` without `passkey` is refused `PASSKEY_REQUIRED`. With one not needed, a `passkey` is registered all the same, as the laptop command's `--add-passkey` does.
- **Nothing to do.** An `UPGRADE` code whose `guard.to` is at or below the installed guard's version: `CheckSetup` and `RunSetup` return `nothingToDo` and the laptop command's line in `notes`, and `RunSetup` changes and records nothing, except as the laptop command does for an engine key not yet recorded.
- **Answers are fixed text.** Every `lines`, `notes`, `text` and `warnings` entry, and every refusal's message, is built from fixed words and values decoded from the code or read from the catalog; none holds the connection string or a database driver's own message.

### Connect refusals

A refusal is a ConnectRPC error whose detail is a `basalt.connect.v1.Refusal`: `reason` (below), `message` (the fixed message, in the laptop command's words where it has one) and `retryAfterSeconds` (set when trying again later can work). In the JSON error body, each entry of `details` has `type` `basalt.connect.v1.Refusal`, `value` (the detail's protobuf bytes, base64), and `debug`, the same detail in proto3 JSON, which the service always sends so a page without a protobuf decoder can read it. The error's own `message` is the refusal's message.

| Reason | ConnectRPC code | When |
|---|---|---|
| `NOT_A_SETUP_CODE`, `INVALID`, `UNSUPPORTED_FORMAT`, `DAMAGED` | `invalid_argument` | Decoding, as in [The setup code](setup-from-laptop.md#the-setup-code) |
| `EXPIRED`, `SETUP_ID_IN_FUTURE`, `EXPIRY_TOO_FAR`, `GUARD_TOO_OLD` | `invalid_argument` | Step 1 of the laptop command, by the service's clock |
| `BINARY_TOO_OLD` | `unavailable` | `guard.to` is newer than the guard of the engine version the service pins. Message: `Basalt Vault is being updated: try again shortly, or use the laptop command.` |
| `CONNECTION_STRING_REFUSED` | `invalid_argument` | The pasted string breaks [The pasted connection string](#the-pasted-connection-string) rules. The message names the rule, never the string |
| `ADDRESS_REFUSED` | `invalid_argument` | The host resolves to an address the service never connects to ([Where the runner connects](#where-the-runner-connects)) |
| `DATABASE_UNREACHABLE` | `unavailable` | No connection: an unreachable host, a closed port and a timeout give the same message |
| `CERTIFICATE_NOT_VERIFIED` | `failed_precondition` | The server's certificate does not verify. The message names the two ways forward: for Supabase, paste the pooler connection string; otherwise use the laptop command |
| `LOGIN_FAILED` | `failed_precondition` | The database refused the login |
| `TARGET_MISMATCH` | `failed_precondition` | Step 3 of the laptop command |
| `PREFIX_MISMATCH`, `USED`, `SUPERSEDED`, `ROLE_EXISTS`, `ROLE_MISSING`, `ENGINE_REVOKED` | `failed_precondition` | Step 4 of the laptop command, in its order |
| `ANSWERS_INVALID` | `invalid_argument` | `RunSetup` only |
| `PASSKEY_REQUIRED` | `failed_precondition` | `RunSetup` only |
| `CHALLENGE_EXPIRED`, `CHALLENGE_INVALID`, `PASSKEY_INVALID` | `invalid_argument` | `RunSetup` only ([The passkey challenge](#the-passkey-challenge)) |
| `SETUP_FAILED` | `failed_precondition` | The transaction failed: nothing changed. The message is fixed per kind of failure (for example, the admin role lacks a privilege) |
| `TIME_LIMIT` | `deadline_exceeded` | The call ran past 60 seconds; the transaction rolled back |
| `RATE_LIMITED`, `BUSY` | `resource_exhausted` | [Connect limits](#connect-limits). Always with `retryAfterSeconds` |
| `REQUEST_TOO_LARGE` | `resource_exhausted` | A body over 16 KiB |

The page shows the message and, for every reason but `RATE_LIMITED` and `BUSY`, the laptop command as the other way. These reasons are the connect service's; they are not [Error codes](error-codes.md#error-codes) of the MCP tools.

### The passkey challenge

The person creates the approval passkey on the connect page (RP ID `basaltvault.app`, origin `https://portal.basaltvault.app`), with a challenge the service made and does not store:

- `DescribeSetup` returns `challenge` (32 random bytes), `userId` (16 random bytes), `userName` and `displayName` (labels for the passkey picker, as in the [passkey registration request](approvals.md#codes)), `expiresAt` (15 minutes later), and `mac`, a keyed hash over all of them and the code's setup fingerprint, made with a secret only the service holds. `mac` is opaque to the page.
- The page creates the passkey with that challenge and user id, and sends `RunSetup` the challenge unchanged and `passkey`: the browser's answer, with the fields of the [passkey registration response](approvals.md#codes) and an optional `label`.
- `RunSetup` checks, before it connects: `mac` against the challenge's fields and the fingerprint of the code in the same request (`CHALLENGE_INVALID`), `expiresAt` by its clock (`CHALLENGE_EXPIRED`), and the registration with the engine's own check: the challenge, the origin, the RP ID, the ES256 key (`PASSKEY_INVALID`). It stores the key with `userId` as its user handle.

So a registration is refused after 15 minutes, for another setup, or after the code was swapped. The challenge is not what lets a setup run: the admin connection string is. Someone who has only the link can run nothing.

### The passkey check code

The page's guard against a substituted passkey. The connect page computes it in the browser from the public key the browser returned, and shows it with the result; it never shows a code the service sent in its place, and says something is wrong when the service's `checkCode` for that credential differs. After the setup is picked up, the engine names each active passkey of the database with its check code, computed from the key in `basalt_meta.passkeys`. One passkey with the same code is the expected result. A different code, or a passkey the person did not create, means stop and remove it. This detects a substituted key; it does not prevent one.

The code is the first 10 bytes of `sha256("basalt-passkey-check.1\n" ‖ x ‖ y)`, where `x` and `y` are the 32-byte P-256 coordinates of the key, in lowercase hex as five groups of four. For the P-256 base point (`x` = `6b17d1f2…d898c296`, `y` = `4fe342e2…37bf51f5`) it is `dbf5 ff76 2025 209d d866`.

### The pasted connection string

The person types it into the page; the page holds it in a variable only, never in storage, and clears it after `RunSetup`. The service:

1. Keeps it only in the memory of one request. It never writes it to a log, a trace, an error report, a metric label, a disk or another service. In `connect.proto`, `databaseUrl` carries the field option `(basalt.connect.v1.sensitive) = true`. Logs are built from an allow list of fields, request bodies are never logged, and a panic is reported without its arguments.
2. Maps every error of the Postgres driver to a fixed message before it leaves the setup package. The service's own cloud identity has no permissions and no access to other services, so a mistake there reaches nothing else.
3. Accepts only a `postgres://` or `postgresql://` URL with one host, a port, a database, a user and a non-empty password, and no parameter but `application_name`, `channel_binding`, `connect_timeout`, `sslmode`, `sslnegotiation`, `sslsni`, `target_session_attrs`, `min_protocol_version` and `max_protocol_version`. This is deliberately narrower than the list root accepts in a credential file ([`basalt init --remote`](setup-from-laptop.md#basalt-init---remote-the-engines-machine), step 8): `default_query_exec_mode` and `require_auth` are left out. Several hosts, a socket path and every other parameter (`hostaddr`, `passfile`, `service`, `sslrootcert`, `sslcert`, `sslkey` and the like) are refused `CONNECTION_STRING_REFUSED`. It reads nothing from the environment: no `PG*` variable reaches the connection.
4. Requires TLS with a certificate that verifies for the host name against the system's trusted authorities (`verify-full`), whatever the string's `sslmode` says. The admin password is never sent over a connection whose other end is not proven.
5. Requires it to name the same database as the code's `target`, as [step 3](setup-from-laptop.md#basalt-init---setup-code-the-persons-own-computer) does (`TARGET_MISMATCH`).

### Where the runner connects

The person types the host, so the service could be pointed anywhere:

- The host name is resolved once, each address is checked, and the connection is made to that exact address, with the host name kept for TLS. When a name has IPv4 and IPv6 addresses, IPv4 is used.
- Only global unicast addresses are used. Refused (`ADDRESS_REFUSED`), for IPv4 and IPv6, among others: loopback, link-local (which holds cloud metadata addresses), private ranges, carrier-grade NAT (`100.64.0.0/10`), `0.0.0.0/8`, `192.0.0.0/24`, benchmarking (`198.18.0.0/15`), reserved (`240.0.0.0/4`) and broadcast, multicast, unspecified addresses, documentation ranges, and IPv6 forms that wrap or route to an IPv4 address (IPv4-mapped, IPv4-compatible, NAT64, 6to4 `2002::/16`, Teredo `2001::/32`). A name with any refused address among those it resolves to is refused as a whole.
- Any port. An unreachable host, a closed port and a timeout return the same message after the same minimum delay, so the service tells a caller little about a host that is not a database they can log in to.
- One setup per request, 60 seconds per call, and a cap on calls running at once.

### Connect limits

No accounts, so the limits are by what the service can see: requests per IP address, different targets per IP address, failed logins per target (so the service cannot be used to guess database passwords), setups run per target, and the body size (16 KiB). A **target** is the database a setup is for: the Supabase project ref when the code has one, otherwise host, port and database, so one person's mistakes on a shared pooler host lock out no one else. The client's address is the one the hosting front end adds to `X-Forwarded-For`, never an entry the caller supplied; which entry that is belongs to the service's configuration. At the cap on calls running at once, a call is refused `BUSY`, not queued. The numbers are the service's configuration, not part of the contract.

### The connect page

`/connect` on the portal ([Page links](page-links.md#page-links)), a static page with its own script, covered by `basalt portal verify` like the other portal pages. It runs only at `https://portal.basaltvault.app`, the one origin the service allows (CORS, no cookies), so another site's page cannot use the service from a visitor's browser. CORS does not stop a script that calls the API directly: the [limits](#connect-limits) and the [address rules](#where-the-runner-connects) are what protect the service. Its order is fixed:

1. Read the code from the link's fragment, or from a paste box. `DescribeSetup`.
2. Show the summary and the setup fingerprint, and say which host this page must be on.
3. The passkey, before anything is pasted. For an `INSTALL` code the person creates one. For an `AGENT` or `UPGRADE` code the person signs once with the passkey they already have, which only this site can ask for; the page sends nothing of it. This step is a habit that helps a returning person notice a fake site, where their passkey is not offered; it is not counted as a protection.
4. Paste the connection string. `CheckSetup`.
5. Show a refusal, or the notes and the questions. When `passkeyNeeded` and no passkey was created yet, create one now.
6. Approve: `RunSetup`. Show the result, the warnings and the passkey's check code.
7. Say: tell your bot "done". The engine notices a finished setup only when the bot asks for its status or at its hourly heartbeat.

The page's content security policy is as strict as the approval pages' (no inline script, no third-party script, integrity hashes on its own scripts, no framing, no referrer), and allows connections to `https://connect.basaltvault.app` for this page only. The page and the service answer with `Cache-Control: no-store`.

### What the connect service sees

Everything the setup needs, for the length of one call: the setup code (with the agent's SCRAM verifier, which is [sensitive](setup-from-laptop.md#the-setup-code)), the admin connection string, the person's answers, the new passkey's public key, and the database itself, with admin rights. So while a setup runs, Vault is trusted as the person's own computer is on the laptop path: it could change the database or register a passkey of its own. The check code makes a substituted passkey visible; nothing in this version makes the rest visible. A person who does not want to trust Vault with that runs the laptop command. The service never sees the agent's password, which stays on the bot's machine.
