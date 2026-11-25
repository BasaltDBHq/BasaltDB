## Stores

A store is the system an agent's actions land in. The engine records every action in a ledger kept next to the store, and checks a few things itself before it calls the store. Each agent is bound to exactly one store, and tool names carry no store prefix.

| Kind | Status |
|---|---|
| `POSTGRES` | Built. This is the only kind the engine serves. |
| `MYSQL`, `S3`, `DRIVE` | Designed, not served. An `engine.json` that names one is refused. |

**Binding.** `engine.json` binds an agent to its store with `agents[].store`:

```json
{ "agents": [ { "name": "tracker_bot", "osUser": "basalt-tracker-bot", "store": { "kind": "POSTGRES", "credentialFile": "/etc/basalt/agents/tracker-bot.url" } } ] }
```

`store.credentialFile` is the file that holds the agent's credential for that store (for `POSTGRES`, the connection string of its own `<prefix>_agent_<name>` role, as described under "One engine, many agents" in [CLI](cli.md#cli)). It replaces the `credentialFile` that used to sit directly on the agent; the old place is not read, and an `engine.json` that still has it is refused, whichever command loads it, with the edit that fixes it: `agent "<name>": "credentialFile" now goes inside "store"; replace "credentialFile": "<path>" with "store": {"kind": "POSTGRES", "credentialFile": "<path>"}`. An unknown `kind` is a config error that names the agent.

**Guarantee levels.** A store is not always able to refuse what the engine would refuse, so each property has a level that says what holds when the engine is wrong or bypassed (for example, an attacker holds the engine's credential):

| Level | Meaning |
|---|---|
| `STORE` | The store itself refuses an action that breaks the rule, whatever path it takes. |
| `STORE_HISTORY` | The store does not refuse it, but keeps history the agent's credential cannot destroy, so a bypass is caught afterwards and can be reverted. |
| `ENGINE` | Only the engine enforces it. A bypass is neither refused nor necessarily seen. |

For `POSTGRES`: requiring an intent, recording changes with their old and new rows, row limits (cascades counted), approval and revert are `STORE` (the guard triggers and the signature checks in `basalt_meta`). Recording reads is `ENGINE`, and in same-user mode reads are not recorded at all. Parsing and classifying the statement, the function allowlist and the repeatable-read check are done by the engine first.

**Capabilities.** What the engine may rely on, per store. `POSTGRES` has these values:

| Capability | `POSTGRES` |
|---|---|
| `InStoreEnforcement`: the store refuses an unguarded agent write | yes |
| `InStoreLedger`: the ledger is written in the action's own transaction | yes |
| `InStoreSignatureCheck`: the store verifies an approval's signature | yes |
| `TransactionalPreview`: a trial run that rolls back | yes |
| `ConditionalWrites`: compare-and-set on the version | yes (`xmin`, checked in the trigger) |
| `TargetConflicts`: the unit a person's change wins over an agent's | row |
| `Cascades`: a write reaches targets the action did not name | yes |
| `RetainsHistory`: the store itself keeps before values | no (the ledger does) |

**Versions.** A target's version is a string the store defines. `POSTGRES` uses `xmin:<n>`, as `basedOn.version` in the [change record](change-record.md#the-change-record) already shows. The designed kinds would use `hash:<sha256>` (`MYSQL`), `s3:<versionId>` and `drive:<revisionId>`.

**The ledger.** The ledger lives with the store it records: for `POSTGRES`, in `basalt_meta` in the same database. An agent can never write the ledger's location. For a `POSTGRES` agent that is the grants: no direct access to `basalt_meta`, only the functions listed under [`basalt_meta`](basalt-meta.md#basalt_meta). A store whose credential could write its ledger location would have to say so in its capabilities and rely on the hash chain and the head the engine pins.

**Tools.** `query` and `write` are SQL-store tools: they are served only for a store that speaks SQL (`POSTGRES` today), and the dialect is the store's. The other tools keep their schemas whatever the store. Because an agent has one store, no tool takes a `store` argument; an agent bound to more than one would need one, and that is a later contract change.

### What every store writes

Every text that describes a change to the person's data, whatever store holds it, has three parts. A text is the binding and the lines a person signs, a change record, a plugin feed event, or a tool error. All of them share this model; only the texts a person signs and their lines also follow the [text rules](#text-rules), which fix their bytes. Postgres is one store among them: it writes the same form as every other store, with no exception of its own.

| Part | Holds | Defined by |
|---|---|---|
| Shared | What Basalt decides and the person agrees to: ids, agent, intent, counts, hashes, expiry, action, conflict, change ids, `resource`, and the values `key`, `old`, `now`, `set` (`before` and `after` in a change record) | This contract, the same for every store |
| Shape | Which kind of data the values describe: `shape`, [below](#shapes) | This contract. A page draws per shape |
| Store part | `store: {kind, …}`: `name` (in a binding), `verb` (the store's own word for the operation), `code` (the store's own error code) and store-only extras. A held request's body is `request: {kind, …}` | Each store's adapter, documented per store |

- **`resource`** names what was changed, in the store's own form: `public.leads` (Postgres, `schema.table`), `crm.leads` (MongoDB, `database.collection`), `acme-docs/invoices/` (S3, a bucket and prefix). A page shows it as untrusted plain text.
- **`store.kind`** is the store's kind, as under [Stores](#stores): `POSTGRES` today. A page uses it as a label only, so a new store in a known shape and request family needs no page change. Text that names the store ("Postgres checks these exact rows again") takes the name from `store.kind`.
- **`store.name`** (in a binding): the name the store gives what the agent is bound to, for display. For `POSTGRES` it is `current_database()`.
- **Two forms for a store's code, one rule.** A text that travels on its own (a signed text, a change record, a feed event) says which store wrote it, so it carries `store: {kind, …}`, and a store's error code sits in `store.code`. An answer to the agent is about the agent's own store, which the agent already knows, so it carries a flat `storeCode`: [tool errors](error-codes.md#error-codes), and the revert answers (`preview_revert` items, `revert_plan` lines and `apply_revert_batch` items). `storeCode` is present whenever the store raised the error, on any code: a timeout keeps `QUERY_TIMEOUT` and carries `storeCode` `57014`.

#### Shapes

| `shape` | Stores | `key` | `old`, `now`, `set`, `before`, `after` | The page draws |
|---|---|---|---|---|
| `RECORD` | Postgres, MySQL, MongoDB, DynamoDB, Firestore | The record's identity fields: `{"id": 7}`, `{"_id": "65a1…"}` | Field → value; a nested value is drawn as JSON | The fields before and after |
| `OBJECT` | S3, GCS, Azure Blob, Drive, Dropbox | `{"path": "invoices/7.pdf"}` | Reserved: version, size, content hash, modified time, content type | The file and the version it goes to |

`RECORD` is specified in full. `OBJECT` is reserved: its field list is fixed when the first file store is designed, and until then a page refuses to offer signing for a text with `shape` `OBJECT`. A page also refuses to offer signing for a `shape` it does not know.

#### Operations

`op` is Basalt's safety class. The store's own word for the operation goes beside it, in `store.verb`. Which operation it names depends on the text:

- **On a line** (a preview line, a revert line, a ledger `ROW_CHANGE` row), `verb` is the store's word for that line's own `op`, which can differ from the request's. In Postgres it is `INSERT`, `UPDATE` or `DELETE`: a child row set to `NULL` by `ON DELETE SET NULL` under a `DELETE` has `op` `UPDATE` and `verb` `UPDATE`, a row an `INSERT … ON CONFLICT DO UPDATE` updated has `UPDATE`, and a revert line's `verb` names its inverse write.
- **On a change record, a feed event and the ledger's other rows** (`CHANGE`, `READ`, `REFUSED`), `verb` is the request's own command: in Postgres the statement's command, `SELECT`, `INSERT`, `UPDATE`, `DELETE` or the DDL command; in MongoDB `insertOne`, `find`, ….

| `op` | Means |
|---|---|
| `READ` | Sees data and changes nothing |
| `INSERT` | Adds something new |
| `UPDATE` | Changes something that exists |
| `DELETE` | Removes something |
| `OTHER` | Anything else (in Postgres, DDL): refused and recorded |
| `REVERT` | A person's revert; change records only |

`MERGE` (an insert or update as one operation) is reserved and not emitted: a Postgres upsert (`INSERT … ON CONFLICT`) keeps the classification it has today.

#### Request families

A held request's body is `request: {kind, …}`, where `kind` is the store's family: the one the agent's tools already use. A family has one request form and one request view on the pages, so a new store of a known family reuses both.

| `request.kind` | Stores | Form |
|---|---|---|
| `SQL` | Postgres, MySQL | `{"kind": "SQL", "params": [...], "statement": "…"}`: the statement as the agent sent it and the values bound to `$1`, `$2`, … |

`DOCUMENT` is reserved, designed with the first document store. A page refuses to offer signing for a `request.kind` it has no view for.

#### Agent names

Every text names an agent `agent:<name>`, with `<name>` the agent's name in `engine.json` (`agent:bot`), never the store's login for it. That holds for every agent name in a signed text (an approval's `agent`, a revert's `select.agents`, `proposed.agents`, `requestedBy`, the keys of `agentRows`, the values of `changeAgents`, a plugin approval's `agents`, `requestedBy`, `change.agentsAdded` and `change.agentsRemoved`) and for the agent in the plugin feed (`feed/1`) and the notices (`deliver/1`): the params' `agent`, the event's `subject` and `data.agent`. The store's adapter maps the name to its login one to one within an install (below). `person:<id>` is reserved for a person named in a text. A change record's `actor` stays `{"kind": "AGENT", "name": "<name>"}`: it is typed already.

#### Store logins

Each login or user Basalt creates in a store carries the install's prefix and belongs to one group the operator can list, so a database administrator can find everything Basalt owns during a security issue. The rule holds for every store:

| Store | Login | Group |
|---|---|---|
| `POSTGRES` | `<prefix>_agent_<name>` (`basalt_agent_bot`) | Member of the role `<prefix>_agents` |
| MongoDB (designed) | `<prefix>_agent_<name>` | The role `<prefix>_agents` |
| IAM-based (S3, designed) | `<prefix>_agent_<name>` | The path `/<prefix>/` or a tag |

Texts say `agent:<name>`; the login is `<prefix>_agent_<name>`, a fixed rule within an install. The guard records each agent's name with its login when the agent is set up and writes texts from that record, so a text never strips a prefix it does not know. Stored columns compared with the session's login (`ledger.agent`, `runs.agent`, `reverts.requested_by`, the grant and own-work checks) keep the login.

#### Text rules

The passkey signs `sha256` of a binding's text, and `rowsHash` covers the lines' exact bytes, so this contract fixes the layout of every text a person signs and of every line, whichever store writes it. Postgres's `jsonb` text already follows these rules, so they change no byte Postgres writes.

- **Objects.** Keys are unique within an object. They are sorted by the key's own UTF-8 bytes before escaping: shorter first, then bytewise (`{"\n": 2, "A": 1}`: both are one byte, and 0x0A sorts before 0x41). `{`, then the entries joined by `, `, then `}`. An entry is `"key": value`, the key escaped like a string. The rule holds at every depth.
- **Arrays.** `[`, then the values joined by `, `, then `]`, in the store's order.
- **Strings.** Escaped as `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`; any other character below U+0020 as `\u00xx` (lowercase hex); every other character as it is.
- **Literals.** `true`, `false` and `null`, lowercase.
- **Numbers.** A number from the person's data is a valid JSON number as the store holds it (Postgres keeps `1.50` as `1.50`). Basalt's own integers (`rows`, `skipped`, the values of `agentRows`) are plain decimal digits: no sign, no leading zero, no fraction or exponent (`0`, `27`). Clients read a number and never rewrite it.
- **Timestamps** Basalt writes (`expiresAt`) are strings of exactly the form `YYYY-MM-DDTHH:MM:SS.ffffffZ`: UTC, always six fraction digits, and `Z`, never `+00:00` (`2026-11-11T07:02:11.123456Z`; in Postgres `to_char(t AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`, as the guard writes it). A value from the person's data keeps the store's form ([Wire format](../CONTRACT.md#wire-format)).
- **Lines** are ordered bytewise by their text (`COLLATE "C"` in Postgres). `rowsHash` is the lowercase hex `sha256` of the lines joined by `\n`. A redacted line's `rowHash` is the lowercase hex `sha256` of the array `[key, old or now, set]` written by these rules.
- **Clients never re-serialize.** They hash and parse a text as given. The engine checks that every signed text and line it relays follows these rules and refuses one that does not.
- **Vectors** in the contract are generated by code (the guard or the codec), never written by hand. A vector file whose texts the code has not generated yet in the current form says so in its `description` and marks each such case `"pending": true` in place of its texts; a test that reads a pending case fails.

**Clean state.** These texts have no version field. The guard writes this form from its first entry, and no reader accepts a text in the form before it: a dev or demo install made before reinstalls `basalt_meta`.
