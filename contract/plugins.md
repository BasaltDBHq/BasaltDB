## Plugins

**`basalt plugin` is removed** (Simplify for beta, SB-2). A plugin is added, changed or removed through the agent's [`request_plugin`](mcp-tools.md#mcp-tools) tool and approved on the [plugin approval page](plugins-approval.md#the-plugin-approval-page); its health is in the agent's `status`; a config entry (an entry of `engine.json`) is edited by hand as root. Where a section of the contract still names a `basalt plugin` command, read it as that: install, change, enable and remove become `request_plugin` for engine-kept entries and a hand edit for config entries, and list and check become `status`.

Served in part. The engine serves the `engine.json` entries and `request_plugin`, signing and verification, the transports, and supervision: at start it verifies each enabled entry, starts it, checks its health, restarts it with a backoff and stops it, and `status` shows `PLUGIN_UNAVAILABLE` and `PLUGIN_NOT_TRUSTED`. In service mode `basalt service install` also writes, start, stop and remove each local entry's service unit, OS user and socket directory, the engine connects to those units' sockets, and `basalt init` refuses an agent OS user in the engine's group ([Service units](plugins-runtime.md#service-units)). The engine records the ledger events of [In the ledger](plugins-ledger.md#in-the-ledger) at each start, and `status` reports them; the `model` detail key is recorded once a hook's contract lets a plugin report one. In same-user mode the engine also applies plugin changes while it runs: it starts an entry that requires approval once its approval is signed, and stops an entry that is turned off, removed or no longer matches, with no restart ([Plugin changes while the engine runs](plugins-approval.md#plugin-changes-while-the-engine-runs)). While it serves agents the engine calls `feed.observe` and `approval.deliver` ([Notifier messages](plugins-runtime.md#notifier-messages)). On an agent-operated engine that runs as the agent's own OS user the engine also keeps engine-kept entries and hands over the portal link ([Plugin approval through the portal](plugins-approval.md#plugin-approval-through-the-portal)). Still planned: the other hooks' calls during serving (`wire.detect`, `classify.suggest`). Install by passkey approval in same-user mode is served ([Plugin approval](plugins-approval.md#plugin-approval) and the sections after it): an entry that requires approval is accepted signed or not and served to an agent only with a matching signed approval ([Plugin approvals at engine start](plugins-approval.md#plugin-approvals-at-engine-start)); every other entry needs a trusted signature, as [Signing and the trust store](#signing-and-the-trust-store) says. This section fixes the platform every plugin follows: the hooks, the manifest, the `engine.json` entries, consent, the transports, the protocol messages every plugin answers, failure, isolation and the ledger record. Each hook's own messages are added to this section by that hook's contract. Schemas: [`api/plugin/`](../api/plugin/), with valid and invalid examples in `api/plugin/testdata/` and the ConnectRPC mapping in [`api/plugin/proto/basalt/plugin/v1/plugin.proto`](../api/plugin/proto/basalt/plugin/v1/plugin.proto); the contract test (`api/plugin/contract_test.go`) checks every example and that the `.proto` has the same fields as the schemas.

### The principle

Core enables, plugins extend. Others extend Basalt without forking it, and core keeps only what Basalt's guarantees need.

| Plugins own | Core keeps |
|---|---|
| Where they run: a child process, a Unix socket, a remote host | The contract: hook points, messages, versions |
| Their latency, cost, uptime, model and hosting | What each hook may see and do |
| How they detect: patterns, heuristics, named-entity recognition, models | Failure: a data-path plugin that fails or misses its deadline fails the call closed |
| Their own credentials, in their own files | Consent and record: the person approves hooks, egress and agents; the ledger records them |
| | Signing and verification of what is installed |
| | The core floor of PII detection: exact dictionary matches and the validated email, `+` phone, card and IBAN patterns |

A plugin can only add. It never approves, reverts or signs, never lets through a write the guard refuses, never removes or changes a token core made, and never rewrites bytes on the wire. With no plugin installed Basalt keeps every guarantee it states elsewhere in this file: the core floor holds on its own. No `plugins` key in `engine.json` means no plugins.

### The lifecycle

The stages are store-neutral, so the hooks do not change when another store adapter lands. A plugin sees the stage, never the adapter's mechanism (a Postgres hold is `BS002` from a guard trigger; another store holds its own way).

```
engine   start → load plugins → serve agents → stop
action   proposed (intent) → checked → previewed → held | applied | refused → recorded
held     → signed by the person → applied   (or left unsigned until it expires)
revert   planned → signed by the person → applied | conflicted | rejected
data     store data and the person's text → wire to the AI provider (tokenized)
feed     every recorded entry, in chain order (cursor = chain seq)
```

Where plugins hook in:

```
person / harness ──request──▶ [ capabilities claimed → core floor → wire.detect plugins → tokenize → final scan (core) ] ──▶ AI provider
                 ◀─response── [ tokens → values in text, no plugin ]                                                      ◀──
ledger (per agent) ──▶ engine reads after the plugin's cursor ──▶ [ feed.observe plugins ]
held write, prepared revert, reissued link ──▶ [ approval.deliver plugins ] ──▶ the person
setup page labels ──▶ [ classify.suggest plugins ] ──▶ suggestions the person accepts or not
```

Never hookable: approve, revert, sign, the agent's SQL or store calls, writes to the store, the ledger itself, and the approval, revert and plugin approval pages.

### Per-agent scope

One engine serves many agents ([One engine, many agents](cli.md#cli)). A plugin entry sits at the engine's level and serves **only the agents listed in its `agents`**. A notifier listed for `product_a` and `product_b` never hears about `client_x`; a detector listed for `product_a` never sees `client_x`'s text.

- **Every call names the agents it serves.** The engine refuses, before any byte is sent, a call naming an agent the entry does not list.
- **Mixed sessions.** When one request to the AI provider holds text from several agents (one harness connected to several), only the `wire.detect` entries listed for **every** agent in the session run on it; the core floor always runs, with every agent's dictionary. An entry skipped this way is recorded in each of those agents' ledgers with reason `MIXED_SESSION`, and `status` warns: protection that dropped is never silent. The record and the warning are defined with the `detector/1` contract. The person splits the session to get every detector back. Running a detector on only its own agents' part of the text is not done: once the model mixes the sources, where each piece came from is lost.
- **Instances.** To keep one client's data out of a shared plugin process (no shared cache or model context), the person adds a second entry of the same plugin with its own `instance` and `agents`. On the engine's side two entries share nothing: each has its own connection, call slots, feed cursors and `auth.credentialFile`. Two **local** entries also run as separate processes with separate installed copies and sockets, and in service mode under separate service units and OS users; in same-user mode both run as the engine's user (no boundary, [Isolation and trust](plugins-runtime.md#isolation-and-trust)). Two **remote** entries reach whatever runs at their URLs: if both name the same host, that host may share anything between them, and only the engine-side state is separate. An `instance` should not be another agent's name: it appears in the ledger detail of the agents the entry serves.

### Hooks

Four hooks in v1. A fifth, `wire.verdict`, is reserved. Hook names are the lowercase dotted strings below, an exception to the SCREAMING_SNAKE_CASE enum rule because they name a place in the lifecycle, not a state; transport names (`jsonrpc-stdio`) are lowercase kebab-case for the same reason.

| Hook | When | Sees | Power | On error or timeout |
|---|---|---|---|---|
| `wire.detect` | Every request the engine's wire proxy sends to the AI provider, for a listed agent | Plain text of the segments no earlier step claimed | Add-only spans; core makes every token | The request fails closed (`DETECTOR_FAILED`, with the failure class) |
| `feed.observe` | After an entry is recorded in a listed agent's ledger | Events, as CloudEvents: what the agent did to data and what happened to its approvals and reverts, metadata only, never row values or free text | None | Nothing blocks; delivery resumes from the cursor |
| `approval.deliver` | The engine holds a write, prepares a revert or reissues a link, for a listed agent | The notice, a CloudEvent: agent, headline, expiry and the link in the agent's own answer | None over the action | Nothing blocks; the agent hands the person the link as without plugins |
| `classify.suggest` | During the check of a local setup page's labels step (the install, the `LABELS` fix) | The catalog of the listed agents' readable columns, never values | Raise-only suggestions, never auto-accepted | The check goes on without them and says so |

- **`wire.detect`** returns spans `{segment, start, end, type, role, confidence}` and the `model` it ran. Before any detector runs, core claims every piece of text that is itself a Basalt capability: approval and revert links (short and long) and passkey page links, request files and pasted request or response blocks (`basalt-approval.1.…`, `basalt-revert.1.…`), setup codes (`basalt-setup.1.…`), and, planned, plugin approval links and codes (`/plugins/<approvalId>`, `basalt-plugin.1.…`). They pass to the provider as without plugins, but no segment sent to a plugin contains one. Then, in order: existing tokens, core patterns, `NAME_CUE` plugins, the dictionary, `VALUE`-only plugins in config order. The final scan runs core only. Its message contract is `detector/1`.
- **`feed.observe`** gets events read from each listed agent's ledger through that agent's own access, after the entry's cursor (the chain `seq`), at least once and in chain order per agent; a plugin dedups by the event's `source` and `id` (the install id and `seq`) and acknowledges the last `seq` it handled. An event is one ledger row of the kinds [Notifier messages](plugins-runtime.md#notifier-messages) lists, and carries only what that row holds at its `seq`: ids, the operation, the table, row counts, a refusal's error code, an expiry. `table` is the statement's own table (for an object or file store, later, a bucket or folder), never a key or file name. Not delivered: row values (plain or tokenized), row keys, statements, intents, refusal messages, approval or revert links, and anything about plugins or passkeys. A new cursor starts at the agent's chain head, with no history ([The cursor](plugins-runtime.md#the-cursor)). Message contract `feed/1`.
- **`approval.deliver`** gets a notice that carries exactly the link in the agent's own answer for that item, or no link when that answer had none that stands alone; the engine never issues a link for a notice ([Notifier messages](plugins-runtime.md#notifier-messages)). That link is the one stated exception to "never a value, a statement or an intent": a long link carries the whole request in it (the statement, its parameters, the intent and the affected rows). The link lets a channel show the held rows; signing still needs the person's passkey, checked in the store. Installing it is a separate permission, shown in plain words: anyone who can read where it delivers can see the rows of held writes, and a link may carry the whole request. Message contract `deliver/1`.
- **`classify.suggest`** gets schema, table and column names, types and column comments, limited to columns the listed agents' roles can read, and returns `{column, class, entityType, confidence, why}`. A suggestion may be stricter than core's, never looser; `--yes` never accepts one, and the review labels it with the plugin. It never runs in a process that holds the admin credential. Message contract `classify/1`.
- **`wire.verdict`** is reserved: a manifest that declares it is refused in v1.

### What a plugin never receives

Whatever its hooks, a plugin never receives: a database credential, the engine's or an agent's credential file, `pii.key`, the vault, the dictionary, tokens, column classes, which values are stored, the Vault channel's keys, an approval or revert link (except, in an `approval.deliver` notice, the link the agent's own answer handed over), or the name or data of an agent its entry does not list. No log line, error, ledger row or plugin event carries a value a plugin saw or returned: errors name the entry (`name`, `instance`) and a failure class only. One narrow exception: the ledger records the `model` name and version a plugin reports (short identifiers, [In the ledger](plugins-ledger.md#in-the-ledger)).

### Manifest

`basalt-plugin.json` in the plugin's directory ([`manifest.schema.json`](../api/plugin/manifest.schema.json)). A manifest is accepted only with a valid signature from a trusted key ([Signing and the trust store](#signing-and-the-trust-store)); an entry that requires approval also accepts one with no known signer ([Signer states](plugins-approval.md#signer-states)).

```json
{
  "manifestVersion": 1,
  "name": "acme-ner",
  "version": "1.4.0",
  "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": {
    "wire.detect": {
      "contract": "detector/1",
      "roles": ["VALUE", "NAME_CUE"],
      "entityTypes": ["PERSON_NAME", "ADDRESS", "acme-ner.EMPLOYEE_ID"]
    }
  },
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner", "args": ["--serve"] } },
  "files": { "bin/acme-ner": "sha256:…" },
  "network": { "egress": [] }
}
```

A remote plugin has `"endpoint": { "remote": { "transport": "connectrpc", "url": "https://ner.acme.example" } }`, no `files`, and its host in `network.egress`.

- **`name`** matches `^[a-z][a-z0-9-]{1,39}$`. **`protocol`** lists the protocol versions the plugin speaks and includes `basalt-plugin/1`.
- **`hooks`**: one or more of `wire.detect`, `feed.observe`, `approval.deliver`, `classify.suggest`, each with its `contract`. An unknown hook and `wire.verdict` are refused. **`wire.detect` may not share a manifest with `feed.observe`** (one plugin seeing plain values on the wire and ledger events could pair them to learn which values are stored) **or with `approval.deliver`** (a detector never receives links). `feed.observe` and `approval.deliver` may share one.
- **`endpoint`**: exactly one of `local` (`transport` `jsonrpc-stdio`, `jsonrpc-unix` or `connectrpc`; `command`, one of `files`; `args`) or `remote` (`transport` `connectrpc`; `url`, `https://` only, with no user name, password, query or fragment).
- **`files`**: every file a local plugin ships, by path relative to the manifest (no segment starting with `.`), with its `sha256:` hash. A remote plugin has none.
- **`network.egress`**: the `host:port` entries the plugin may reach, lowercase; empty means none. A remote endpoint's host, with port `443` when its URL names none, must be exactly one of them.
- **Entity types.** A plugin may return the well-known token types (`EMAIL`, `PHONE`, `PERSON_NAME`, `ADDRESS`, `OTHER`, `CARD`, `IBAN`) and types namespaced by its own `name` (`acme-ner.EMPLOYEE_ID`); a namespaced type with another prefix is refused, so two plugins never share a type or a token key. Namespaced types get a generic token shape and their own token key, and the person sees them at install.
- **`entitlement`** is reserved and refused. Unknown top-level fields are ignored, so a later minor addition does not break an older engine; a breaking change is a new `manifestVersion`.
- **Where each rule is checked.** The schema checks shapes, the hook rules and `remote` without `files`. Four rules JSON Schema cannot state are checked by the engine when the engine stages a copy (`request_plugin`) and at every start, and refuse with `PLUGIN_REFUSED` `BAD_MANIFEST`: the remote host is in `egress`, a namespaced type's prefix is the manifest's `name`, a local `command` is one of `files`, and the entry's [ledger record](plugins-ledger.md#in-the-ledger) fits in 4 KiB whatever its instance, signer and isolation (a long `egress` list is what breaks it).

### Signing and the trust store

An entry that does not require approval is always signed, with no unsigned mode: a person building their own plugin signs it with their own key (the plugin SDK's `basalt-plugin keygen` and `sign`, [Author tools](#signing-and-the-trust-store)) and a person who runs the engine puts that key's public file in the trust store. An entry that requires approval ([Plugin approval](plugins-approval.md#plugin-approval), same-user mode) is accepted signed or not, because the person's passkey approval decides and the page says plainly who vouches for the plugin. This section is the rule for an entry that does not require approval; [Signer states](plugins-approval.md#signer-states) says what differs for one that does.

- **The signature** sits next to the manifest in `basalt-plugin.json.sig` ([`signature.schema.json`](../api/plugin/signature.schema.json)): `{ "keyId", "alg": "ES256", "sig" }`. `sig` is ECDSA P-256 with SHA-256 ([Primitives and encodings](vault-channel.md#primitives-and-encodings): 64 bytes `r ‖ s`, base64url without padding) over the context line `basalt-plugin-manifest.1\n` followed by the manifest file's exact bytes, with no parsing or reformatting first. Any change to the manifest, one byte or whitespace included, fails it. The context line keeps a manifest signature from being any other Basalt signature.
- **Key ids.** A publisher key is a P-256 key; its id is base64url of the first 16 bytes of `sha256` of its DER SubjectPublicKeyInfo (22 characters), as for engine ids. The engine always computes a key's id from the key itself, for the embedded Basalt key as for every stored one; a file name or label is never trusted. Public key files are PEM `PUBLIC KEY` (SubjectPublicKeyInfo); private key files are PEM `PRIVATE KEY` (PKCS#8). base64url fields (`keyId`, `sig`) are decoded strictly: padding, other characters or non-zero unused trailing bits are refused. A high-S signature is accepted, as everywhere in this file; nothing uses a signature's bytes as an identifier.
- **What the signature proves.** For a local plugin: who published the manifest, and, through the `sha256` of every file in `files`, that no shipped file changed. For a **remote** plugin the signature covers the manifest only: who published its endpoint, egress and hooks. It proves nothing about what runs on that host, which can change at any time without the manifest changing. That is why the ledger records `endpoint: REMOTE` and the install screen says so ([Isolation and trust](plugins-runtime.md#isolation-and-trust)).
- **Where plugins live.** Installed copies and the trust store sit side by side in one base directory, `<base>/plugins` (`<root>`) and `<base>/plugin-trust`. In service mode `<base>` is `/opt/basalt` on Linux and `/Library/Basalt` on macOS: root's, outside the config directory, which may belong to the engine's OS user, so that user can never change what is installed or trusted. In same-user mode `<base>` is `<configDir>`, the directory that holds `engine.json`. A plugin install creates a missing `<base>`, `<root>` or `plugin-trust/` only after the path rule holds for the nearest directory that exists, each with mode `0755` and owned by the user running them: root under `sudo` in service mode, so `/Library/Basalt` and `/opt/basalt` are root's and writable by no one else. A directory that appears while it creates it is refused, never reused.
- **Trust roots.** The Basalt publisher keys built into the binary (none is built in yet), and the public key files in `<base>/plugin-trust/`. The `basalt` binary has no command that adds one: a person who trusts a publisher puts the publisher's public key file there as `<keyId>.pem`, as the engine's user in same-user mode and as root in service mode, and restarts the engine. The engine records `PLUGIN_TRUST_ADDED` in every agent's ledger at its next start for a key it finds that no ledger records yet ([In the ledger](plugins-ledger.md#in-the-ledger)); the built-in publisher key is never recorded: nobody added it. A file in `<base>/plugin-trust/` that holds anything but exactly one PEM `PUBLIC KEY` block with a P-256 key, or whose name is not `<its computed key id>.pem`, is not a trusted key: a signature naming it fails verification (`NOT_TRUSTED` at `add`, `PLUGIN_NOT_TRUSTED` at start).
- **Author tools.** Making a key and signing a plugin are not commands of `basalt`. They are in the plugin SDK, `github.com/basaltdbhq/basalt-plugin-go`, as `basalt-plugin keygen --out DIR` and `basalt-plugin sign <dir> --key FILE`, with `manifest <dir>` (writes the manifest's `files` hashes) and `check <dir>` (runs a plugin folder and sends it the samples). They read no `engine.json`, trust store or ledger. What they write is fixed here, and the engine's tests verify a signature the SDK made against the shared vector in `internal/plugin/testdata/sign-vector/`, which the SDK holds too:
  - `keygen` writes `DIR/<keyId>.key` (PEM `PRIVATE KEY`, mode `0600`) and `DIR/<keyId>.pub` and never overwrites a file.
  - `sign` writes `<dir>/basalt-plugin.json.sig` as the signature rule above says, in the layout `{ "keyId", "alg", "sig" }` with two-space indent and a final newline, after it checks every file in `files` against its hash. It refuses a key file that group or others can read or write, a symlink, or a file owned by another user. The engine checks the manifest against [Manifest](#manifest) at `add`, whatever signed it.
- **Verification**, when the engine stages a copy (refused `PLUGIN_REFUSED` `UNSAFE_PATH` for a path the path rule refuses, `BAD_MANIFEST` for a rule of [Manifest](#manifest), else `NOT_TRUSTED`) and again at every engine start (the entry is not started and `status` shows `PLUGIN_NOT_TRUSTED`), in this order:
  1. The path rule below holds for the copy being verified (at `add`, the temporary copy) and for the trust store.
  2. At start, the installed manifest's `sha256` is the entry's `manifestSha256`.
  3. The `.sig` passes its schema, its `keyId` names a trusted key, and the signature verifies.
  4. The manifest passes [Manifest](#manifest).
  5. For a local plugin, every file in `files` is a regular file (not a symlink) with the stated hash, and the copy holds nothing else besides the manifest and its `.sig`.
- **Installed copies.** The engine first copies the manifest, its `.sig` and the listed files of the upload into a new temporary directory under `<root>/<name>/<instance>/`, reading each source file once. It then runs the checks above on that copy, records that copy's `manifestSha256`, and renames the copy into place as `<root>/<name>/<instance>/<manifest-sha256>/`. So what the person approved is exactly what is installed, whatever happens to the source directory meanwhile; a check that fails removes the temporary copy. The engine (and, in service mode, the plugin's unit) runs the installed copy. A remote plugin's copy is the manifest and its `.sig` only. `<root>` is `<base>/plugins`: `/opt/basalt/plugins` on Linux and `/Library/Basalt/plugins` on macOS in service mode (written with `sudo`), and `<configDir>/plugins` in same-user mode. Each entry has its own copy, so changing one instance never touches another.
- **The path rule.** At every path component from `/` down to each installed file, and from `/` down to each key in `<base>/plugin-trust/`: no component is a symlink (a root-owned one above `<root>` or `plugin-trust/`, such as macOS's `/etc`, is followed), and no one but its owner can write it: no group or other write bit, and no ACL entry that allows writing (macOS extended ACLs, Linux POSIX ACLs; `UNSAFE_PATH` names the path and says it `has an ACL entry that lets another user write it`). An allow entry counts whoever it names, the owner included, since the engine does not resolve the entry's user; deny entries, such as the `everyone deny delete` macOS puts on a home directory, never count. On Linux a named user's or group's write is limited by the ACL's mask, which shows as the group bits, so the write bit already refuses it; on macOS an ACL entry works beside the mode, and only this check sees it. Above `<root>` and `plugin-trust/`, `<base>` included, the owner is root or the required owner; from `<root>` and `plugin-trust/` down, the owner is the required owner. A trust store that does not exist yet holds no keys; the directories above it that exist still follow the rule. In service mode the required owner is root, with no exception for the config directory: that is why service mode keeps nothing of plugins there. In same-user mode it is the engine's own user, which is no boundary ([Isolation and trust](plugins-runtime.md#isolation-and-trust)). So no user but the required owner and root can rename a directory on the way and put a tree of their own in its place.

### Config

`engine.json` gains `plugins`, an array of entries ([`config.schema.json`](../api/plugin/config.schema.json)):

```json
"plugins": [
  { "name": "acme-ner", "instance": "default", "manifestSha256": "…", "enabled": true,
    "agents": ["product_a", "product_b"], "timeoutMs": 2000, "minConfidence": 0.6,
    "config": { "languages": ["en", "id"] },
    "auth": { "credentialFile": "/etc/basalt/plugins/acme-ner.token" } },
  { "name": "acme-ner", "instance": "client_x", "manifestSha256": "…", "enabled": true,
    "agents": ["client_x"], "timeoutMs": 2000 }
]
```

- **`agents`** is required: the agents the entry serves, each one of the engine's agents (`PLUGIN_REFUSED` `UNKNOWN_AGENT` otherwise). An empty list serves none.
- **`instance`** matches `^[a-z][a-z0-9_]{0,31}$`, default `default`. `(name, instance)` is unique, and every per-plugin path, socket, service unit, OS user and cursor is keyed by both.
- **`timeoutMs`** is the deadline of one call, from 50 to 60,000; default 300 for a local plugin, 2,000 for a remote one. It is the person's setting, not a latency budget: it only stops a plugin that no longer answers from hanging the engine.
- **`minConfidence`** (0 to 1, default 0): the engine drops a plugin's spans below it. Dropping only removes the plugin's own additions.
- **`config`** is opaque to the engine and passed to the plugin in `initialize`. At most 16 KiB (16,384 bytes) as compact JSON, and never a secret: a string in it, keys included, that parses as a URL with a user name or password, or that holds `password=` in any case, is refused before anything is written (the same idea as the `service install --init-arg` rule of [CLI](cli.md#cli), applied to a plugin's settings, where a plain URL without credentials is allowed). A key repeated in one object, at any depth, is refused too: Postgres keeps its last value and a plugin may read its first, so a plugin approval would bind a value the plugin never reads. A plugin that needs a credential (a chat token) reads its own file, as its own user.
- **`auth.credentialFile`**, remote entries only: an absolute path. The engine reads the file and sends its contents as `Authorization: Bearer <contents>`; the plugin never receives the path, and the contents never appear in a log or error. The engine reads it once, when it connects to the entry, so a new token takes effect when the entry starts again. The file must be a regular file (not a symlink) owned by the engine's user and readable by that user only (mode `0600` or narrower), at most 16 KiB, holding one token of visible ASCII characters; one trailing newline is dropped. A file that is missing, unreadable, empty, readable by group or others, or holds anything else is refused, and the entry is not started; the error names the file and the rule, never its contents.
- **`approval`** ([Plugin approval](plugins-approval.md#plugin-approval)): `"REQUIRED"` or absent; any other value is refused when the config is loaded. With it the engine serves the entry to an agent only with a matching plugin approval signed by a person's passkey ([Plugin approvals at engine start](plugins-approval.md#plugin-approvals-at-engine-start)). A plugin install or enable writes it when it opens an approval. On an agent-operated engine every entry requires approval, with or without the key. Plugin approvals are same-user mode only: in service mode a config with the key is refused when it is loaded, as before, and no entry requires approval, agent-operated or not.
- The engine reads `plugins` at start. In same-user mode it also reads them every second while it runs and applies what [Plugin changes while the engine runs](plugins-approval.md#plugin-changes-while-the-engine-runs) says: an entry that requires approval starts, changes and stops without a restart, and any entry stops without one; adding or changing an entry that does not require approval still takes effect at the next start. In service mode the engine reads `plugins` at start only. The engine writes `engine.json` under `<config>.lock`, by rename, so the engine never reads half a file; it prints the engine restart command when the change needs one, and otherwise says that the running engine applies it.
