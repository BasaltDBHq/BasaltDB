## The change record

One record per action an agent asks for, whether applied, held or refused. It has the shared part, the `shape` and the store part of [What every store writes](stores.md#what-every-store-writes). Shape:

```json
{
  "changeId": "0193a4c2-…",
  "at": "2026-11-10T06:02:11Z",
  "actor": { "kind": "AGENT", "name": "tracker_bot", "runId": "…", "taskId": "…" },
  "intent": "Merge duplicate case reports from yesterday",
  "resource": "public.cases",
  "shape": "RECORD",
  "key": { "id": 4211 },
  "op": "UPDATE",
  "store": { "kind": "POSTGRES", "verb": "UPDATE" },
  "request": { "kind": "SQL", "params": ["merged", 4211], "statement": "UPDATE cases SET status = $1 WHERE id = $2" },
  "before": { "status": "open" },
  "after": { "status": "merged" },
  "basedOn": { "version": "xmin:88123" },
  "durationMs": 12,
  "rows": 1,
  "policy": { "decision": "ALLOW", "rule": "default.single-row-update" },
  "status": "APPLIED"
}
```

| Field | Values |
|---|---|
| `status` | `APPLIED`, `APPROVAL_PENDING`, `REFUSED`, `APPROVAL_EXPIRED`, `REVERTED` |
| `op` | Basalt's ([Operations](stores.md#operations)): `READ`, `INSERT`, `UPDATE`, `DELETE`, `OTHER` (a refused request that is none of these), `REVERT` (M3: a person's revert) |
| `store` | `{kind, verb}`: the store's kind and its own word for the request's operation ([Operations](stores.md#operations): in Postgres the statement's command, `SELECT` for a read); `verb` is absent in exactly two cases: on `REVERT`, and on `OTHER` when the store did not give its command |
| `request` | The request by family ([Request families](stores.md#request-families)): for `SQL`, `{kind, params, statement}` |
| `resource`, `shape`, `key` | What the action targets: the request's own resource and its shape, and, optionally, `key`, the target's identity fields. `resource` is absent when the action named none, and `shape` is absent exactly when `resource` is. A read and a refused action name a resource qualified as the agent's session resolved it (Postgres `schema.table`, the form a write's own record has), so the agent's `leads` is `public.leads` on all three: a refused write names its target, the first table it writes in statement order (a data-modifying `WITH` query's before the statement's own `INSERT`, `UPDATE`, `DELETE` or `MERGE` target), as an applied write would; a read or a refused read names the first table the request names, in the order the SQL check lists them |
| `actor.kind` | `AGENT`, `PERSON` |
| `policy.decision` | `ALLOW`, `HOLD`, `REFUSE` |

`actor` stays `{kind: "AGENT", name}` with the agent's name (it is typed already; [Agent names](stores.md#agent-names)). As served by `run_history`, a record also carries `revertId` (on a revert's own record) and `revertedBy` (the revert changes that restored rows of it), `cascadedRows` and `rowChanges` (one entry per row written, cascades included, with `resource`, `shape`, `op`, `key`, `before`, `after`, and `redacted` or `pruned` when values are hidden). On `run_history`, a value or image too large for the agent is left out and named in `largeValues` ([Large values](mcp-tools.md#large-values)); `before`, `after` and `policy` at the top level arrive with M2: `run_history` does not serve them yet, and its closed schema adds them when it does.

Reads (M1.5): every `query` the engine runs is a change record with `op: READ`, `store.verb` the store's word (`SELECT`), `status: APPLIED`, `rows` = rows returned, its request (statement and parameters) and duration, and no `rowChanges`; it carries the run's `intent` when it ran in a run. The rows it saw are kept by version in `basalt_meta` (see `reads` and the `READ` ledger row).

`basedOn` (M1.5): a `rowChanges` entry for an `UPDATE` or `DELETE` of a row the run had read carries `basedOn: { "version": "<the store's version>", "changeId": "<the read>" }`, `version` an opaque string the store writes and compares (Versions, under [Stores](stores.md#stores): `xmin:<n>` in Postgres, an etag, a version id); one the run never read carries `blindWrite: true` (allowed, owner decision #15). Cascaded rows and inserts carry neither. A change with exactly one non-cascaded row that was read also carries that `basedOn` at the top level, as in the shape above. A `REFUSED` record carries `reason: { code, message }` with a code from [Error codes](error-codes.md#error-codes) (`STORE_ERROR` for an error the store raised). `before` values are kept 30 days; other ledger metadata 1 year.
