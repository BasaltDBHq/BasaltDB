## Stores

A store is the system an agent's actions land in. The engine records every action in a ledger kept next to the store, and checks a few things itself before it calls the store. Each agent is bound to exactly one store, and tool names carry no store prefix.

| Kind | Status |
|---|---|
| `POSTGRES` | Built. This is the only kind the engine serves. |
| `MYSQL`, `S3`, `DRIVE` | Designed, not served. An `engine.json` that names one is refused. |

**Binding.** `engine.json` binds an agent to its store with `agents[].store`:

```json
{ "agents": [ { "name": "tracker-bot", "osUser": "basalt-tracker-bot", "store": { "kind": "POSTGRES", "credentialFile": "/etc/basalt/agents/tracker-bot.url" } } ] }
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
