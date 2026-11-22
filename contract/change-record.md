## The change record

One record per action an agent asks for, whether applied, held or refused. Shape:

```json
{
  "changeId": "0193a4c2-…",
  "at": "2026-11-10T06:02:11Z",
  "actor": { "kind": "AGENT", "name": "tracker-bot", "runId": "…", "taskId": "…" },
  "intent": "Merge duplicate case reports from yesterday",
  "target": { "table": "public.cases", "key": { "id": 4211 } },
  "op": "UPDATE",
  "statement": "UPDATE cases SET status = $1 WHERE id = $2",
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
| `op` | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `OTHER` (a refused statement that is none of these), `REVERT` (M3: a person's revert) |
| `actor.kind` | `AGENT`, `PERSON` |
| `policy.decision` | `ALLOW`, `HOLD`, `REFUSE` |

As served by `run_history`, a record also carries `revertId` (on a revert's own record) and `revertedBy` (the revert changes that restored rows of it), `params`, `cascadedRows` and `rowChanges` (one entry per row written, cascades included, with `key`, `before`, `after`, and `redacted` or `pruned` when values are hidden). On `run_history`, a value or image too large for the agent is left out and named in `largeValues` ([Large values](mcp-tools.md#large-values)); `before`, `after` and `policy` at the top level arrive with M2.

Reads (M1.5): every `query` the engine runs is a change record with `op: SELECT`, `status: APPLIED`, `rows` = rows returned, its statement, parameters and duration, and no `rowChanges`; it carries the run's `intent` when it ran in a run. The rows it saw are kept by version in `basalt_meta` (see `reads` and the `READ` ledger row).

`basedOn` (M1.5): a `rowChanges` entry for an `UPDATE` or `DELETE` of a row the run had read carries `basedOn: { "version": "xmin:<n>", "changeId": "<the read>" }`; one the run never read carries `blindWrite: true` (allowed, owner decision #15). Cascaded rows and inserts carry neither. A change with exactly one non-cascaded row that was read also carries that `basedOn` at the top level, as in the shape above. A `REFUSED` record carries `reason: { code, message }` with an error code from the table below. `before` values are kept 30 days; other ledger metadata 1 year.
