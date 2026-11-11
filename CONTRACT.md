# BasaltDB contracts

Normative contract for the surfaces BasaltDB exposes: **MCP tools** served by the engine (through the per-agent shim), the **`basalt` CLI**, the **approval and revert pages**, and the **`basalt_meta` schema** the guard installs in the person's Postgres. The product is defined in [`docs/redesign/specs/2026-11-11-basalt-foundation-final.md`](docs/redesign/specs/2026-11-11-basalt-foundation-final.md); this file fixes the wire rules. There is no REST API, no OpenAPI/AsyncAPI and no event stream. The one HTTP surface is the engine's loopback [local pages](#local-pages): the pages plus a same-origin relay for them, not an API for other clients. From M3.5 the same pages API also runs inside the end-to-end encrypted [Vault channel](#vault-channel), the one hosted piece before M4 (owner decision VC-1).

## Process: contract first

- A new MCP tool, a change to a tool's input or output schema, a new error code or a new `basalt_meta` table or function lands in a **contract-only PR** first: tool schemas under `api/mcp/`, this file if a convention changes, and the contract test that checks the served tool list against the schemas. No behaviour change in the same PR unless CI needs it.
- Every tool in `api/mcp/` declares a status, `IMPLEMENTED` or `PLANNED`. A contract test fails if a served tool is missing from the schemas, or an `IMPLEMENTED` tool is not served.
- One file per tool, `api/mcp/tools/<name>.json`: `name`, `status`, `milestone`, `description`, `inputSchema` (JSON Schema, `additionalProperties: false`), `outputSchema`, and `errors` (codes from the table below). The engine embeds these files and lists each tool's `inputSchema` as written, so the schema has one source. The contract test (`api/mcp/contract_test.go`) checks camelCase property names, SCREAMING_SNAKE_CASE enum values, closed input schemas, and that every declared error code is in this file.
- Breaking changes are allowed until M4 (nothing has shipped). Record each one in the PR description.

## Wire format

- JSON keys we define (MCP arguments and results, the change record, CLI `--json` output, config) are **camelCase**. Exception: column names and values from the person's tables pass through exactly as Postgres returns them.
- **Enum values are SCREAMING_SNAKE_CASE** everywhere (Go consts, JSON, `validate` `oneof`, `basalt_meta` values, docs). Go identifiers stay PascalCase (`StatusApplied = "APPLIED"`).
- **IDs:** UUIDv7 for every id BasaltDB generates (`changeId`, run, task, approval), canonical text on the wire, `uuid` in Postgres. Row versions are `"xmin:<n>"`.
- **Timestamps:** RFC 3339 UTC with `Z` (`2026-11-10T06:02:11Z`).
- Named Go types for anything (de)serialized; DTOs separate from domain structs.

## The change record

One record per action an agent asks for, whether applied, held or refused. Shape (from the foundation):

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

As served by `run_history` and `basalt log --json`, a record also carries `revertId` (on a revert's own record) and `revertedBy` (the revert changes that restored rows of it), `params`, `cascadedRows` and `rowChanges` (one entry per row written, cascades included, with `key`, `before`, `after`, and `redacted` or `pruned` when values are hidden). `before`, `after` and `policy` at the top level arrive with M2.

Reads (M1.5): every `query` the engine runs is a change record with `op: SELECT`, `status: APPLIED`, `rows` = rows returned, its statement, parameters and duration, and no `rowChanges`; it carries the run's `intent` when it ran in a run. The rows it saw are kept by version in `basalt_meta` (see `reads` and the `READ` ledger row).

`basedOn` (M1.5): a `rowChanges` entry for an `UPDATE` or `DELETE` of a row the run had read carries `basedOn: { "version": "xmin:<n>", "changeId": "<the read>" }`; one the run never read carries `blindWrite: true` (allowed, owner decision #15). Cascaded rows and inserts carry neither. A change with exactly one non-cascaded row that was read also carries that `basedOn` at the top level, as in the shape above. A `REFUSED` record carries `reason: { code, message }` with an error code from the table below. `before` values are kept 30 days; other ledger metadata 1 year.

## Error codes

Tool errors return an MCP tool result with `isError: true` and a JSON body `{ "code": "<CODE>", "message": "…", "reason": "…", "sqlState": "…" }`. `reason` is set for `STATEMENT_REFUSED` and `QUERY_TIMEOUT`; `sqlState` is set when Postgres raised the error. Codes are stable once `IMPLEMENTED`.

Planned (actionable errors, owner decisions AE-1 to AE-14; not emitted yet): the body also carries `nextSteps` (required, at least one step), `personMessage` (when the person must know or act), `errorId` (on `UNAVAILABLE` and `INTERNAL`), and `reason` for every code with more than one case. Schema: [`api/mcp/errors/tool-error.schema.json`](api/mcp/errors/tool-error.schema.json); rules in [Next steps](#next-steps).

From M2, an `APPROVAL_REQUIRED` body also carries `approval: { "approvalId", "expiresAt", "rows", "headline", "approvalUrl", "approveCommand", "personMessage" }` (see [Approvals](#approvals) and [Handing a held action to the person](#handing-a-held-action-to-the-person)):

- `headline`: the held write in one line, cascade stated (`Delete 1 row in public.leads + 2 cascaded rows (public.lead_notes 2)`), as `basalt approve --show` prints it.
- `approvalUrl`: the **short link** `<base>/approvals/<approvalId>` when the engine serves the [local pages](#local-pages); otherwise the long link `<base>/approvals/<approvalId>#1.<request>` (below, [Page links](#page-links)). Clients that render links may show it.
- `approveCommand`: `basalt approve --agent NAME [--config PATH] --open <approvalId>` (`--config` only when the engine runs from a non-default config; planned, AE-3: then with the absolute path). The person runs it in a terminal and it opens the approval page in their browser. A first-class path, not only a fallback.
- `personMessage`: the message the agent shows the person verbatim: what is held, the headline, the link, the equivalent command and the expiry, with the link on its own line ([Showing links](#showing-links), which has an example). Planned (M3.5): `approval.links` and the body's `links` carry the link with a label, as there.

`headline` and `personMessage` are new (M4.1); `approvalUrl` changes from always-long to short-when-served (M4.1, a breaking change). `list_pending` items carry the same four fields, so an agent that lost the link gets it again there.

| Code | When |
|---|---|
| `INTENT_REQUIRED` | A write without an intent (guard SQLSTATE `BS001`) |
| `STALE_READ` | An `UPDATE` or `DELETE` of a row whose version changed since the run last read or wrote it (`BS004`). A row the run never read is a blind write, not refused |
| `STATEMENT_REFUSED` | DDL, multiple statements, data-changing `WITH`, `COPY`, or a function outside the allowlist (engine policy, or `BS007` from the guard) |
| `ROW_LIMIT_EXCEEDED` | More than 50 rows in one action, cascades included (`BS003`) |
| `QUERY_TIMEOUT` | A `SELECT` hit the row or time limit (time limit: SQLSTATE `57014`); also `request_revert` when preparing the revert hit its 100-second limit (reason `TIME_LIMIT`; the message gives the person's `basalt revert ... --open` command) |
| `APPROVAL_REQUIRED` | The action is held; the result carries the approval id and expiry (`BS002`) |
| `APPROVAL_EXPIRED` | The approval was not given within 24 hours (`BS005`) |
| `APPROVAL_INVALID` | The approval does not exist, is used, belongs to another agent, or no longer matches the rows (`BS005`) |
| `REVERT_INVALID` | M3. The revert authorisation does not exist, is already applied, carries a bad signature, or its rows changed since the preview (`BS005`). For a batch of a large plan: the plan is not this agent's, not signed or already finished, or a line is not in the plan, repeated, or already applied |
| `REVERT_EXPIRED` | M3. The revert was not signed within 1 hour of `prepare_revert`, or a signed large plan was not finished within 24 hours of the signature (`BS005`) |
| `NOTHING_TO_REVERT` | M3. Every row in the scope would be skipped, or the scope wrote no rows (`BS009`). Planned (AE-8): also `preview_revert` and `request_revert`, in place of `NOT_FOUND`, with reason `READS_ONLY` (the scope wrote no row a revert could restore: only reads, or rows it both inserted and deleted), `ALL_CHANGED_BY_PEOPLE` (every row would be skipped, not all as `ALREADY_REVERTED`) or `ALREADY_REVERTED` (every row was last written by a revert of the scope; the next steps name that revert's `changeId` and when it ran) |
| `PERMISSION_DENIED` | The agent's role lacks the privilege; the database refused (`42501`) |
| `NOT_FOUND` | The run named in the arguments does not exist for this agent; for `request_revert`, also a change or revert that is not this agent's; also an approval or revert that is not this agent's, and a page link without its secret or replaced (reasons in [Next steps per code](#next-steps-per-code)). Unknown ids and other agents' ids only: an own scope with nothing to undo is `NOTHING_TO_REVERT` |
| `SQL_ERROR` | Any other error Postgres raised for the agent's statement (syntax, unknown column, constraint); `sqlState` says which |
| `INVALID_ARGUMENT` | Arguments fail schema validation, or an unknown argument was passed |
| `UNAVAILABLE` | The database or the guard cannot be reached; planned (chat-only operator): also the agent's [setup from the laptop](#setup-from-your-laptop) has not run yet (reasons `SETUP_PENDING`, `SETUP_EXPIRED`) |
| `INTERNAL` | A defect in the engine or the guard (`BS006`, `BS008`) |

`STATEMENT_REFUSED` reasons: `PARSE_ERROR`, `MULTIPLE_STATEMENTS`, `WRONG_TOOL` (a write sent to `query` or a read sent to `write`), `DDL_NOT_ALLOWED`, `STATEMENT_NOT_ALLOWED` (`SET`, `DO`, `COPY`, `EXPLAIN`, transaction control and other utility statements), `SELECT_INTO`, `LOCKING_READ`, `MERGE_NOT_ALLOWED`, `DATA_MODIFYING_WITH`, `FUNCTION_NOT_ALLOWED`, and from M2 `NOT_REPEATABLE` (a write that would be held contains a value that changes between transactions; pass it as a parameter). `QUERY_TIMEOUT` reasons: `TIME_LIMIT`, `ROW_LIMIT`. Planned (AE-5): `STATEMENT_REFUSED` gains `NO_PRIMARY_KEY` and `NOT_ALLOWED` (the guard's `BS007`, which carries no reason today), and the other codes with more than one case get reasons; [Next steps per code](#next-steps-per-code) lists them all.

New codes and reasons go through the contract-first process. Each one needs its entry in [Next steps per code](#next-steps-per-code) and [`api/mcp/errors/next-steps.json`](api/mcp/errors/next-steps.json).

## Next steps

Planned (owner decisions AE-1 to AE-14, design [`docs/redesign/specs/2026-11-12-actionable-errors.md`](docs/redesign/specs/2026-11-12-actionable-errors.md)). Every error body and every result the agent must act on tells it what to do next and what to tell the person. No bare error strings to agents.

- **`nextSteps`**: an ordered array of steps, first step first ([`next-step.schema.json`](api/mcp/errors/next-step.schema.json)). Each step has `actor` (`AGENT` or `PERSON`), `action`, and `text` (one plain sentence, at most 200 characters), plus what the action needs: `tool` and `arguments` (filled in by the engine: complete for `CALL_TOOL`, where `repeatCall: true` merges them over the arguments of the call that returned the step and `null` removes one; the ids it knows for `REVISE_CALL`), `command`, `url`, `maxRows`, `waitSeconds`.
- **Actions.** `AGENT`: `CALL_TOOL` (call `tool` with `arguments`), `REVISE_CALL` (change the statement or arguments as `text` says, then call `tool`), `RETRY_SMALLER_BATCHES` (split into writes of at most `maxRows` rows, same intent and run), `ASK_PERSON`, `END_TURN` (end the turn; the person acts next), `STOP` (do not retry, do not work around). `PERSON`: `OPEN_LINK` (`url`, optionally `command` that opens the same page), `RUN_COMMAND` (`command`), `TELL_AGENT`. No step is conditional: each result carries its own steps. Planned (chat-only operator, CO-1): `AGENT` also `RUN_COMMAND` (`command`), only when the engine's `operatedBy` is `AGENT`.
- **Who runs machine steps** (planned, chat-only operator, design [`docs/redesign/specs/2026-11-12-chat-only-operator.md`](docs/redesign/specs/2026-11-12-chat-only-operator.md) sections 2 and 3). A machine step runs a command on the engine's machine: start or restart the engine, install or upgrade `basalt`, `basalt init --remote`. When `operatedBy` is `PERSON` it is a `PERSON` step, as above; when it is `AGENT` it is an `AGENT` `RUN_COMMAND`, with `command` as complete as a person's and `text` written to the agent. A step that needs the admin connection string is always a `PERSON` step, whatever `operatedBy` says: on an agent-operated engine it runs on the person's own computer (`text` says so) and is never addressed to the agent (CO-9). The catalog writes this two ways: a machine step whose entry reads the same in both modes has actor `OPERATOR`, a catalog-only value the engine resolves to `AGENT` or `PERSON` from `operatedBy` (the shim, when it cannot read the config, resolves it to `PERSON`); an entry whose steps differ on an agent-operated engine has a variant in `agentOperated` ([Next steps on an agent-operated engine](#next-steps-on-an-agent-operated-engine)) that replaces its steps there. On the wire the actor is always `AGENT` or `PERSON`.
- **Setup code steps** (planned). An `AGENT` `RUN_COMMAND` of `basalt init --remote ... --json` makes a [setup code](#the-setup-code). Its output carries its own `personMessage` and `nextSteps` (the person runs `basalt init --setup-code <code>` on their own computer, then tells the agent; [`remote-init-result.schema.json`](api/mcp/setup/remote-init-result.schema.json)): the agent shows them to the person and follows them in place of the rest of the entry's steps. An agent runs a machine step at most once for one problem; when `status` reports the same problem right after, it asks the person instead (`ASK_PERSON`), never loops.
- **`personMessage`**: plain text, at most 500 characters not counting its URL lines, that the agent shows the person verbatim. Set whenever the person must know or act. Each URL in it stands on a line of its own, and `links` lists them with labels ([Showing links](#showing-links); until M3.5 the engine writes one line). The agent also shows each `PERSON` step's `command` and `url` unchanged.
- **Commands** are complete and copy-pasteable: every `basalt` command names `--agent <name>` and its ids, and `--config <absolute path>` unless the config is the default the CLI finds by itself (`/etc/basalt/engine.json` on Linux, `/Library/Application Support/Basalt/engine.json` on macOS). No placeholders. Never a secret (connection string, password, token); a command that needs the admin connection string asks for it itself. A short link's `#s=` secret appears only in `url` and `personMessage`. "Run `basalt init` again" steps use the flags init saved in `engine.json` ([CLI](#cli)), plus the one change the step is for.
- **Steps never suggest getting around a limit**: no split below the hold threshold to avoid an approval, no other path around a refusal, no retry loop on a refusal. Over 50 rows the agent stops and asks; only on the person's explicit yes does it split into held batches of up to 50 rows, each needing the person's approval.
- **Results.** `preview_revert`, `request_revert`, `revert_plan`, `apply_revert_batch` and each `list_pending` item carry `nextSteps` and `personMessage` when there is something to do. `query` and `write` carry `warnings: [{ code, message, table, personMessage, nextSteps }]` ([`warning.schema.json`](api/mcp/errors/warning.schema.json)), absent when empty, with `RLS_HIDES_ROWS` (row-level security hides every row of a table in the statement from the agent role and the statement returned or changed 0 rows); `run_start` carries `GUARD_UPGRADE_AVAILABLE`.
- **`status`.** The MCP tool `status` (below) reports what is ready and lists `problems`, each with `code`, `severity` (`ERROR` or `WARNING`), `personMessage` and `nextSteps`. The agent calls it at the start of a session, after the person says they fixed something, and after a failure that looks like setup. When `operatedBy` is `PERSON` the agent never starts, stops, restarts or upgrades anything itself.
- **Pages.** The local pages' JSON errors carry `personMessage` and the entry's `PERSON` steps.
- **Startup failures.** `basalt mcp` that cannot reach the engine serves `status` and the tool list from its embedded contracts and answers every other call `UNAVAILABLE` reason `ENGINE_UNREACHABLE` (it holds no credential and reaches no database). An engine whose guard misses a **breaking** migration serves the agent degraded: `status` works, every other tool answers `UNAVAILABLE` reason `GUARD_OUTDATED` with the `basalt upgrade` steps; it checks again on each call and serves normally once upgraded, with no restart. Missing only **non-breaking** migrations: served normally, with `GUARD_UPGRADE_AVAILABLE` (see [`basalt_meta`](#basalt_meta)).
- **The catalog.** [`api/mcp/errors/next-steps.json`](api/mcp/errors/next-steps.json) fixes, per code and reason (and per tool where a tool differs), per result case, per warning and per `status` problem, the `(actor, action)` sequence the engine returns and whether `personMessage` is set. The tables below are the same list. The contract test checks both agree and that every code in [Error codes](#error-codes), every warning and every `status` problem has an entry; the engine's test checks every returned `nextSteps` against it.

### Next steps per code

`—` in Reason: the code's only or default case (no `reason`). Steps: `A` agent, `P` person, `O` operator (a machine step, resolved by `operatedBy`); `+pm`: `personMessage` set. These are the steps of a person-operated engine; [the next table](#next-steps-on-an-agent-operated-engine) lists the entries an agent-operated engine replaces.

| Code | Reason | Tool | Steps |
|---|---|---|---|
| `INTENT_REQUIRED` | — | — | A `REVISE_CALL` |
| `STALE_READ` | — | — | A `CALL_TOOL` (`query` of the row), A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `PARSE_ERROR` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `MULTIPLE_STATEMENTS` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `WRONG_TOOL` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `DDL_NOT_ALLOWED` | — | A `STOP`, A `ASK_PERSON`; +pm |
| `STATEMENT_REFUSED` | `STATEMENT_NOT_ALLOWED` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `SELECT_INTO` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `LOCKING_READ` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `MERGE_NOT_ALLOWED` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `DATA_MODIFYING_WITH` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `FUNCTION_NOT_ALLOWED` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `NOT_REPEATABLE` | — | A `REVISE_CALL` |
| `STATEMENT_REFUSED` | `NO_PRIMARY_KEY` | — | A `STOP`; +pm |
| `STATEMENT_REFUSED` | `NOT_ALLOWED` | — | A `STOP` |
| `ROW_LIMIT_EXCEEDED` | — | — | A `STOP`, A `ASK_PERSON`, A `RETRY_SMALLER_BATCHES` (`maxRows` 50, only on an explicit yes); +pm |
| `QUERY_TIMEOUT` | `ROW_LIMIT` | — | A `REVISE_CALL` |
| `QUERY_TIMEOUT` | `TIME_LIMIT` | — | A `REVISE_CALL` |
| `QUERY_TIMEOUT` | `TIME_LIMIT` | `preview_revert` | A `STOP`, P `RUN_COMMAND` (`basalt revert ... --dry-run`), P `RUN_COMMAND` (`basalt revert ... --open`), A `END_TURN`; +pm |
| `QUERY_TIMEOUT` | `TIME_LIMIT` | `request_revert` | A `STOP`, P `RUN_COMMAND` (`basalt revert ... --open`), P `TELL_AGENT` (the revert id it prints), A `END_TURN`; +pm |
| `APPROVAL_REQUIRED` | `HELD` | — | P `OPEN_LINK`, A `CALL_TOOL` (`write` with `approvalId`, waits once); +pm |
| `APPROVAL_REQUIRED` | `HELD_NO_PAGES` | — | P `RUN_COMMAND` (`basalt approve ... --open`), A `CALL_TOOL`; +pm |
| `APPROVAL_REQUIRED` | `NO_PASSKEY` | — | P `RUN_COMMAND` (`basalt init ... --add-passkey`), P `OPEN_LINK`, A `END_TURN`; +pm |
| `APPROVAL_REQUIRED` | `WAIT_ENDED` | — | P `OPEN_LINK`, P `TELL_AGENT`, A `END_TURN`, A `CALL_TOOL` (`write` with `approvalId`, no wait); +pm |
| `APPROVAL_EXPIRED` | — | — | A `ASK_PERSON`, A `REVISE_CALL`; +pm |
| `APPROVAL_INVALID` | `NOT_SIGNED` | — | P `OPEN_LINK`, A `END_TURN`; +pm |
| `APPROVAL_INVALID` | `ALREADY_USED` | — | A `CALL_TOOL` (`run_history`), A `STOP` |
| `APPROVAL_INVALID` | `DIFFERENT_WRITE` | — | A `CALL_TOOL` (`write` with the held arguments) |
| `APPROVAL_INVALID` | `NOT_THIS_AGENT` | — | A `CALL_TOOL` (`list_pending`) |
| `APPROVAL_INVALID` | `ROWS_CHANGED` | — | A `REVISE_CALL` (`query`), A `REVISE_CALL` (`write`, held anew); +pm |
| `APPROVAL_INVALID` | `BAD_SIGNATURE` | — | P `OPEN_LINK`, A `END_TURN`; +pm |
| `APPROVAL_INVALID` | `PASSKEY_REVOKED` | — | P `RUN_COMMAND` (`basalt passkey list`), P `RUN_COMMAND` (`basalt init ... --add-passkey`), P `OPEN_LINK`, A `END_TURN`; +pm |
| `REVERT_INVALID` | `LINE_INVALID` | — | A `CALL_TOOL` (`revert_plan`, pending lines) |
| `REVERT_INVALID` | `PLAN_NOT_SIGNED` | — | A `CALL_TOOL` (`revert_plan`), A `END_TURN` |
| `REVERT_INVALID` | `PLAN_FINISHED` | — | A `CALL_TOOL` (`revert_plan`), A `STOP` |
| `REVERT_INVALID` | `NOT_THIS_AGENT` | — | A `STOP` |
| `REVERT_INVALID` | `ROWS_CHANGED` | — | A `REVISE_CALL` (`request_revert` again, same scope); +pm |
| `REVERT_INVALID` | `BAD_SIGNATURE` | — | P `OPEN_LINK` (the revert link), A `END_TURN`; +pm |
| `REVERT_INVALID` | `PASSKEY_REVOKED` | — | P `RUN_COMMAND` (`basalt passkey list`), P `RUN_COMMAND` (`basalt init ... --add-passkey`), P `OPEN_LINK` (the revert link), A `END_TURN`; +pm |
| `REVERT_EXPIRED` | `NOT_SIGNED` | — | A `ASK_PERSON`, P `RUN_COMMAND` (`basalt revert ... --open`); +pm |
| `REVERT_EXPIRED` | `NOT_FINISHED` | — | A `ASK_PERSON`, P `RUN_COMMAND` (`basalt revert ... --open`); +pm |
| `NOTHING_TO_REVERT` | `READS_ONLY` | — | A `STOP`; +pm |
| `NOTHING_TO_REVERT` | `ALL_CHANGED_BY_PEOPLE` | — | A `STOP`; +pm |
| `NOTHING_TO_REVERT` | `ALREADY_REVERTED` | — | A `ASK_PERSON` (undo that revert?), A `REVISE_CALL` (`request_revert` with the revert's `changeId`); +pm |
| `PERMISSION_DENIED` | — | — | A `STOP`, A `ASK_PERSON`, P `RUN_COMMAND` (`basalt init ...` with the table added), P `TELL_AGENT`; +pm |
| `NOT_FOUND` | `RUN` | — | A `CALL_TOOL` (`list_runs`) |
| `NOT_FOUND` | `CHANGE` | — | A `CALL_TOOL` (`list_runs`) |
| `NOT_FOUND` | `APPROVAL` | — | A `CALL_TOOL` (`list_pending`) |
| `NOT_FOUND` | `REVERT` | — | A `ASK_PERSON` (the revert id `basalt revert` printed) |
| `NOT_FOUND` | `LINK` | — | P `TELL_AGENT` (pages only); +pm |
| `SQL_ERROR` | — | — | A `REVISE_CALL` |
| `SQL_ERROR` | `NO_ROWS_NOW` | — | A `REVISE_CALL` (`query`) |
| `INVALID_ARGUMENT` | — | — | A `REVISE_CALL` |
| `INVALID_ARGUMENT` | `STALE_CURSOR` | — | A `CALL_TOOL` (same call, no `cursor`) |
| `UNAVAILABLE` | `DATABASE_UNREACHABLE` | — | A `CALL_TOOL` (same call after 10 s), A `ASK_PERSON`; +pm |
| `UNAVAILABLE` | `CREDENTIAL_REJECTED` | — | P `RUN_COMMAND` (restart the engine), P `TELL_AGENT`, A `STOP`; +pm |
| `UNAVAILABLE` | `GUARD_MISSING` | — | P `RUN_COMMAND` (`basalt init ...`, saved flags), P `TELL_AGENT`, A `STOP`; +pm |
| `UNAVAILABLE` | `GUARD_OUTDATED` | — | P `RUN_COMMAND` (`basalt upgrade ...`), P `TELL_AGENT`, A `STOP`; +pm |
| `UNAVAILABLE` | `ENGINE_UNREACHABLE` | — | P `RUN_COMMAND` (start the engine), P `TELL_AGENT`, A `STOP`; +pm |
| `UNAVAILABLE` | `PAGES_OFF` | — | A `CALL_TOOL` (`list_pending`, hand over `approveCommand`) |
| `UNAVAILABLE` | `SETUP_PENDING` | — | P `RUN_COMMAND` (`basalt init --setup-code <the pending code>`, on their own computer), P `TELL_AGENT`, A `END_TURN`, A `CALL_TOOL` (`status`); +pm |
| `UNAVAILABLE` | `SETUP_EXPIRED` | — | O `RUN_COMMAND` (`basalt init --remote --new-code ...`, saved flags), A `END_TURN`; +pm |
| `INTERNAL` | — | — | A `STOP`; +pm |

Results and warnings:

| Tool or warning | Case | Steps |
|---|---|---|
| `preview_revert` | `PREVIEW` (a change or run of this agent) | A `ASK_PERSON`, A `REVISE_CALL` (`request_revert` with the scope; the agent adds the person's reason as `intent`); +pm |
| `preview_revert` | `PREVIEW_TASK` | A `ASK_PERSON`, P `RUN_COMMAND` (`basalt revert ... --task <id> --open`); +pm |
| `request_revert` | `REQUESTED` (request form) | P `OPEN_LINK`, A `CALL_TOOL` (wait form, once); +pm |
| `request_revert` | `WAIT_ENDED` (`PENDING` after a wait) | P `OPEN_LINK` (the short link the agent gave earlier, no `url`; the long link only when the engine serves no pages), P `TELL_AGENT`, A `END_TURN`, A `CALL_TOOL` (wait form, no wait), A `CALL_TOOL` (`reissueLink: true`, only if the link is lost); +pm |
| `request_revert` | `APPLYING` | A `CALL_TOOL` (`revert_plan`, `pending: true`, `limit: 200`) |
| `request_revert` | `APPLIED` | A `STOP`; +pm |
| `request_revert` | `EXPIRED` | A `ASK_PERSON`, A `REVISE_CALL` (request form again); +pm |
| `list_pending` item | `PENDING` | P `OPEN_LINK`; +pm |
| `list_pending` item | `EXPIRED` | A `ASK_PERSON`, A `REVISE_CALL`; +pm |
| `revert_plan` | `PENDING` | P `OPEN_LINK`, P `TELL_AGENT`, A `END_TURN`; +pm |
| `revert_plan` | `APPLYING` | A `CALL_TOOL` (`apply_revert_batch` with the pending line numbers) |
| `revert_plan` | `APPLIED` | A `STOP`; +pm |
| `revert_plan` | `EXPIRED` | A `ASK_PERSON`, P `RUN_COMMAND` (`basalt revert ... --open`); +pm |
| `apply_revert_batch` | `APPLYING` | A `CALL_TOOL` (`revert_plan`, `pending: true`, `limit: 200`) |
| `apply_revert_batch` | `APPLIED` | A `STOP`; +pm |
| `RLS_HIDES_ROWS` | — | A `ASK_PERSON`, P `RUN_COMMAND` (`basalt init ... --agent-rls=all-rows`), P `TELL_AGENT`; +pm |
| `GUARD_UPGRADE_AVAILABLE` | — | P `RUN_COMMAND` (`basalt upgrade ...`); +pm |

Status problems (`status` tool, every one +pm):

| Problem | Severity | Steps |
|---|---|---|
| `ENGINE_UNREACHABLE` | `ERROR` | P `RUN_COMMAND` (start the engine), P `TELL_AGENT`, A `STOP` |
| `DATABASE_UNREACHABLE` | `ERROR` | A `ASK_PERSON` (check the database is up) |
| `CREDENTIAL_REJECTED` | `ERROR` | P `RUN_COMMAND` (restart the engine), P `TELL_AGENT`, A `STOP` |
| `GUARD_MISSING` | `ERROR` | P `RUN_COMMAND` (`basalt init ...`, saved flags), P `TELL_AGENT`, A `STOP` |
| `GUARD_OUTDATED` | `ERROR` | P `RUN_COMMAND` (`basalt upgrade ...`), P `TELL_AGENT`, A `STOP` |
| `GUARD_UPGRADE_AVAILABLE` | `WARNING` | P `RUN_COMMAND` (`basalt upgrade ...`) |
| `NO_PASSKEY` | `WARNING` | P `RUN_COMMAND` (`basalt init ... --add-passkey`) |
| `SETUP_NOT_RUN` | `ERROR` | P `RUN_COMMAND` (`basalt init --setup-code <the pending code>`, on their own computer), P `TELL_AGENT`, A `END_TURN`, A `CALL_TOOL` (`status`) |
| `SETUP_EXPIRED` | `ERROR` | O `RUN_COMMAND` (`basalt init --remote --new-code ...`, saved flags), A `END_TURN` |
| `SETUP_CHANGE_PENDING` | `WARNING` | P `RUN_COMMAND` (`basalt init --setup-code <the pending code>`, on their own computer), P `TELL_AGENT` |

### Next steps on an agent-operated engine

Planned (chat-only operator). When `operatedBy` is `AGENT`, each entry below replaces the steps of the entry of the same kind, code and reason above (`agentOperated` in [`next-steps.json`](api/mcp/errors/next-steps.json)); every other entry keeps its steps, with `O` resolved to `A`. Each replaces a `PERSON` step that would run a command with the admin connection string, or start the engine, on the agent's machine. `A RUN_COMMAND (init --remote)` is `basalt init --remote ... --json` with the saved flags plus the one change the step is for; it prints a setup code whose steps the agent follows next ([Setup code steps](#next-steps)).

| Entry | Code | Reason | Steps |
|---|---|---|---|
| error | `PERMISSION_DENIED` | — | A `STOP`, A `ASK_PERSON` (whether to add the table), P `TELL_AGENT` (to add it), A `END_TURN`, A `RUN_COMMAND` (when the person told it to: init --remote with the table added, an `AGENT` code); +pm |
| error | `APPROVAL_REQUIRED` | `NO_PASSKEY` | A `RUN_COMMAND` (init --remote: an `AGENT` code with no change; the person's computer registers a portal passkey); +pm |
| error | `UNAVAILABLE` | `CREDENTIAL_REJECTED` | A `RUN_COMMAND` (init --remote --new-code: an `AGENT` code with a new password); +pm |
| error | `UNAVAILABLE` | `GUARD_MISSING` | A `RUN_COMMAND` (init --remote: an `INSTALL` code); +pm |
| error | `UNAVAILABLE` | `GUARD_OUTDATED` | A `RUN_COMMAND` (init --remote: an `UPGRADE` code); +pm |
| error | `UNAVAILABLE` | `ENGINE_UNREACHABLE` | A `RUN_COMMAND` (start the engine), A `CALL_TOOL` (same call, `repeatCall`) |
| warning | `RLS_HIDES_ROWS` | — | A `ASK_PERSON`, A `RUN_COMMAND` (init --remote: an `AGENT` code; the person answers the row-level security question on their computer); +pm |
| warning | `GUARD_UPGRADE_AVAILABLE` | — | A `RUN_COMMAND` (init --remote: an `UPGRADE` code); +pm |
| problem | `ENGINE_UNREACHABLE` | — | A `RUN_COMMAND` (start the engine), A `CALL_TOOL` (`status`) |
| problem | `CREDENTIAL_REJECTED` | — | A `RUN_COMMAND` (init --remote --new-code: an `AGENT` code with a new password); +pm |
| problem | `GUARD_MISSING` | — | A `RUN_COMMAND` (init --remote: an `INSTALL` code); +pm |
| problem | `GUARD_OUTDATED` | — | A `RUN_COMMAND` (init --remote: an `UPGRADE` code); +pm |
| problem | `GUARD_UPGRADE_AVAILABLE` | — | A `RUN_COMMAND` (init --remote: an `UPGRADE` code); +pm |
| problem | `NO_PASSKEY` | — | A `RUN_COMMAND` (init --remote: an `AGENT` code with no change); +pm |

Not covered here: entries whose `PERSON` step opens a page or reads the ledger on the engine's machine (`basalt approve ... --open`, `basalt revert ... --open`, `basalt passkey list`: `APPROVAL_REQUIRED` `HELD_NO_PAGES`, `APPROVAL_INVALID` and `REVERT_INVALID` `PASSKEY_REVOKED`, `REVERT_EXPIRED`, `QUERY_TIMEOUT` `TIME_LIMIT` for `preview_revert` and `request_revert`, `preview_revert` `PREVIEW_TASK`, `revert_plan` `EXPIRED`). On an agent-operated engine there is no person at that machine; their variants come with the links fallback contract (chat-only operator design, PR 7, and the vault channel's transports), and until then these entries keep the steps above, which assume a person at the engine's machine.

## MCP tools

The first release serves exactly these tools (foundation, "First release", plus the two large-revert tools of owner decision N12-1), and the agent-assisted revert tools `list_runs` (owner decisions N12-R1 and N12-R2) and `request_revert` (N12-R3 to N12-R9), both forms.

| Tool | Milestone | Purpose |
|---|---|---|
| `run_start` | M1 | Start a run with an intent and optional shared `taskId` |
| `query` | M1 | Run one `SELECT`; the engine records the read (M1.5: as a change record, with the rows it saw by version) |
| `write` | M1 | Run one `INSERT`, `UPDATE` or `DELETE` with an intent |
| `run_history` | M1 | The change records of a run |
| `list_pending` | M2 | Held actions waiting for approval |
| `preview_revert` | M3 | What reverting a change, run or task would restore, and its conflicts |
| `revert_plan` | M3 | Nov 12: the lines of a large revert plan and its progress |
| `apply_revert_batch` | M3 | Nov 12: apply a batch of lines of a large revert plan the person signed |
| `list_runs` | M4.1 | This agent's own runs, newest first, with what each did |
| `request_revert` | M4.1 | Prepare a revert for the person to sign and hand them the link; then wait once for their signature |
| `status` | M4.1 | Planned (AE-9). Whether Basalt is ready for this agent, and each problem's next steps; served by the shim when the engine is down |

`status` (planned, AE-9): no arguments. Returns `agent`, `operatedBy` (`PERSON` or `AGENT`), `ready` (no `ERROR` problem), `engine` (`reachable`, `build`), `guard` (`state`: `OK`, `UPGRADE_AVAILABLE`, `OUTDATED`, `NEWER`, `MISSING`, `UNKNOWN`; `installed`, `build`, `missingBreaking`, `missingNonBreaking`), `pages` (`served`, `url`), `passkeys` (`registered`, `active`) and `problems`, each with `code`, `severity`, `message`, `personMessage` and `nextSteps` ([Next steps](#next-steps)). Served by the engine, and by `basalt mcp` itself when the engine does not answer (then `engine.reachable` is false, `guard.state` `UNKNOWN`, and `operatedBy` comes from the config the shim can read, else `PERSON`). Also served while the guard is outdated. Read-only; never a secret, and unlike `basalt status` it never names the credential file. Errors: `INVALID_ARGUMENT`, `INTERNAL`; it never answers `UNAVAILABLE`, problems are its result. Planned (chat-only operator, design section 9): it also returns `enforcement` and `setup`. `enforcement` is `GUARD_ONLY` when `operatedBy` is `AGENT`, when the engine runs in same-user mode, or when the shim cannot read the config (the agent could use its credential directly; the guard still enforces intent, row limits, holds and signatures), else `ENGINE_AND_GUARD`. `setup` is `{ "state", "setupId", "kind", "expiresAt", "fingerprint" }` (`fingerprint` while pending) with `state` `PENDING` (a [setup code](#the-setup-code) was made and its setup is not recorded yet), `EXPIRED` (the same, past `expiresAt`), `DONE` (no setup pending; `setupId` and `kind` name the agent's latest recorded setup) or `NONE` (no setup pending and none recorded, or the engine is down and none is pending). A pending `INSTALL` code is the problem `SETUP_NOT_RUN` and an expired one `SETUP_EXPIRED`, both `ERROR`; a pending `AGENT` or `UPGRADE` code is `SETUP_CHANGE_PENDING`, a `WARNING` (the tools keep working); zero active passkeys stays `NO_PASSKEY`.

`preview_revert` (M3): exactly one of `changeId`, `runId`, `taskId`, plus `limit` and `cursor` (no `sort`: lines come in their signed order). Returns `scope`, `scopeId`, the `rows` and `skipped` totals of the whole preview, the `command` the person runs (`basalt revert --agent <name> --run <id>`), and one page of lines as objects (see [Revert](#revert)). It runs the revert on trial and rolls it back; it never reverts. The cursor names the last line of the page by its hash, so a preview whose rows changed between pages is refused with `INVALID_ARGUMENT` (start again). A scope with nothing to revert is `NOT_FOUND` (planned, AE-8: `NOTHING_TO_REVERT`). A scope of any size can be previewed, within the agent role's statement timeout: a preview that runs out is `QUERY_TIMEOUT` `TIME_LIMIT`, and its next steps give the person `basalt revert ... --dry-run` and `--open`, whose prepare may take 10 minutes.

`revert_plan` (large reverts, N12): `revertId`, optional `pending` (only lines not yet applied), `limit` and `cursor` (keyset on the line number; no `sort`: lines come in execution order). Returns the plan's `status` (`PENDING` until the person signs, `APPLYING`, `APPLIED`, `EXPIRED`), `scope`, `scopeId`, totals `lines`, `restored`, `skipped`, `pending`, `expiresAt` (sign by), `applyBy` (after the signature), `maxBatch` (200), and one page of `items`: `{line, outcome, batch, conflict, sqlState, plan}` with `outcome` `PENDING`, `RESTORED` or `SKIPPED` and `plan` the signed revert line as an object. Only the agent that prepared the revert sees it (`NOT_FOUND` otherwise). A revert of up to 1000 lines is applied in one call and has no plan to page (`INVALID_ARGUMENT`).

`apply_revert_batch` (large reverts, N12): `revertId` and `lines`, 1 to 200 unique line numbers from `revert_plan`. Postgres applies those lines only if the person signed the plan, the caller prepared it, it has not expired, and every line is in the plan and still pending; otherwise nothing is written (`REVERT_INVALID`, `REVERT_EXPIRED`). Each line is re-checked with its row locked: a row someone changed after the plan was built is skipped (people win), never overwritten. Returns `revertId`, `batch`, `status`, the plan's totals `restored`, `skipped`, `pending`, and this batch's `items: [{line, outcome, conflict, sqlState}]`. The loop: `revert_plan` with `pending: true` and `limit: 200`, then `apply_revert_batch` with those line numbers, until `pending` is 0. Apply lines in number order: it is the order that worked on trial.

`list_runs` (N12-R1, N12-R2): the calling agent's own runs, read from `agent_runs` and `agent_changes` (no other agent's runs, ever). Arguments `limit`, `cursor` (id-only keyset on `runId`, UUIDv7 so time-ordered), `sort` (`id` or `-id`, default `-id`), and optional `startTime` and `endTime` (RFC 3339) filtering on the run's start: `startTime` inclusive, `endTime` exclusive; `endTime` not after `startTime` is `INVALID_ARGUMENT`. Without them the newest runs come first by `limit` and `cursor`; the agent does not have to ask the person for a period. Each item: `runId`, `taskId`, `intent`, `startedAt`, `lastChangeAt` (absent when the run has no change record), counts `applied` (writes `APPLIED`), `held` (`APPROVAL_PENDING`), `refused`, `reverted` (writes `REVERTED`; a partly reverted write stays `APPLIED`), `reads`, `rowsWritten` (rows of applied and reverted writes, cascades included), and `tables` (the tables it wrote to, at most 10 in name order, `tablesTruncated` when there are more). Counts and tables come from one aggregate per run over `agent_changes`; a revert's own change record (`op` `REVERT`) belongs to no run and is not counted. Paging by `runId` uses the `runs_agent` index (`basalt_meta` version 14). Listing every agent's runs is not part of this tool: it belongs to the hosted Vault, later.

`request_revert` (N12-R3 to N12-R9): the agent hands the person a revert to sign, with no terminal. An agent can never sign a revert; it can only deliver the person's signature. Two forms, told apart by their arguments:

- **Request.** Exactly one of `changeId` or `runId`, plus `intent` (1 to 500 characters: why the person reverts, as the agent heard it; it is in the binding and on the page). The scope must be the agent's own: a `changeId` or `runId` of another agent is `NOT_FOUND`. There is no `taskId`: reverting a whole task stays a person's action (`basalt revert --task`, later the Vault); an agent that thinks another agent's run is wrong asks that agent, which decides from its own context and requests the revert of its own run. The engine prepares the revert exactly as `basalt revert` does (`basalt_meta.prepare_revert` with the agent credential, with the statement timeout lifted to 100 seconds for that call only, so the MCP call stays in the client's foreground; a prepare that runs out is `QUERY_TIMEOUT` reason `TIME_LIMIT`, and its message gives the person's `basalt revert --agent <name> --<scope> <id> --open` command, whose prepare may take 10 minutes; there is no background prepare), issues the revert's short link ([Link secrets](#link-secrets)), and returns at once with `status` `PENDING`, `revertId`, `scope`, `scopeId`, `intent`, `batched`, the totals `rows` (restored) and `skipped`, `expiresAt`, `revertUrl` and `personMessage`. `waitForSignature`, `reissueLink` and `signature` are refused in this form: the person cannot sign a link before the agent has shown it. `NOTHING_TO_REVERT` when every row would be skipped or the scope wrote none (planned reasons in [Error codes](#error-codes)). A `changeId` may be a revert's own change of this agent's work: reverting it brings the agent's values back (a redo; [Revert](#revert), owner decision AE-14), with people still winning and the person still signing.
- **Wait.** Only `revertId` (a revert this agent requested; `NOT_FOUND` otherwise), optional `waitForSignature` (0 to 110 seconds, default 90), `reissueLink` and `signature`. The engine reads the revert's state about once a second until it is no longer `PENDING` or the time is up, and returns the same fields: `APPLIED` with `changeId` (a revert of up to 1000 lines is applied when the person's page relays the signature, M3-2); `APPLYING` for a signed large plan, with `changeId`, `applyBy`, `progress` (`restored`, `skipped`, `pending`, `batches`) and `nextSteps` (the `revert_plan` and `apply_revert_batch` loop of [Large plans](#large-plans), arguments filled in; [Next steps](#next-steps)); `PENDING` when the wait ran out, with nothing reverted; `EXPIRED`. Without `signature` the wait changes nothing: it only reads `agent_reverts`. Without `reissueLink` it issues no link and `revertUrl` is absent (the link already given keeps working); with `reissueLink` on a `PENDING` revert it issues a new one, the old one stops working, and the call returns at once with the new `revertUrl` and `personMessage` (no wait: the person needs the link before anyone can sign), so `reissueLink: true` with `waitForSignature` is `INVALID_ARGUMENT`. A `PENDING` answer after a wait carries the no-repeat `nextSteps` (end the turn, then call once more when the person says they signed), with `waitForSignature: 0` too. It never hands out the long link while the engine serves the pages: the person signs at the short link the agent gave them earlier, which the agent still has (the engine keeps only its hash); if it is lost or the person asks for a new one, the agent calls `request_revert` with `revertId` and `reissueLink: true` for a fresh short link. Only when the engine serves no pages does the step carry the long link, as the request did. `EXPIRED` says nothing was reverted (or, for a signed plan not finished in time, what was) and that a new request is needed.
- **Delivering the signature.** `signature` is the `basalt-revert.1.` code the revert page shows the person (a revert response, [Lines, binding and codes](#lines-binding-and-codes)), for when the page cannot relay it: the engine does not serve the local pages, or the person reaches the agent only through a chat (another bot, Telegram) and has no terminal. Like `write`'s `approval`, the engine checks the code is for `revertId`, checks it locally against the registered passkeys, and submits it with `apply_revert` as `basalt revert --apply` does; Postgres verifies the passkey signature. A revert of up to 1000 lines is then applied (`APPLIED`); a large plan's signature is recorded and the agent applies it in batches (`APPLYING`). A code for another revert, a bad signature or rows changed since the preview is `REVERT_INVALID`; an expired revert is `REVERT_EXPIRED`. The code is the person's signature over that revert's binding (its id, `rowsHash` and expiry): an agent holding it can submit that exact revert or not, nothing else. With `signature` the call does not wait (`waitForSignature` or `reissueLink: true` with it is `INVALID_ARGUMENT`). A `signature` that does not decode as a revert code (an approval code, for one) is `INVALID_ARGUMENT`; the engine also refuses with `REVERT_INVALID`, before Postgres, a code signed by a passkey that is not registered or was revoked, one that does not verify against the revert's binding, and one for a revert already signed (a replay); `REVERT_EXPIRED` for an expired revert. Reasons, for the [next steps](#next-steps-per-code): `BAD_SIGNATURE` (another revert's code, or one that does not verify), `PASSKEY_REVOKED` (unknown or revoked passkey), `PLAN_FINISHED` (already signed), `ROWS_CHANGED` (Postgres: rows changed since the preview), `NOT_SIGNED` or `NOT_FINISHED` for `REVERT_EXPIRED`. Postgres checks every code again; nothing is written on any refusal.
- **One wait per turn**, as for the [waiting write](#approvals): the agent shows `personMessage`, then in the same turn calls the wait form once. When it returns `PENDING`, its `personMessage` and `nextSteps` tell the agent not to wait again but to end its turn with the link and the expiry; when the person says they signed, a later call with `revertId` returns at once. MCP cannot start a client turn when the person signs, so a finished turn is not woken.
- Nothing in either form signs a revert, and nothing applies one without the person's signature: only their passkey signs, checked inside Postgres; `apply_revert_batch` still runs only lines of a plan the person signed.

`write` in M2: two optional arguments, `approvalId` (uuid) and `approval` (an approval response code, below; needs `approvalId`). To apply a held write the agent repeats the same `sql`, `params`, `intent` and `runId` and adds `approvalId`; with `approval` the engine first submits the person's signed approval (the agent relays it; it cannot make one). A different statement, parameters or run under the approval is `APPROVAL_INVALID`; an approval not yet signed is `APPROVAL_INVALID` with a message saying so. A held write returns `APPROVAL_REQUIRED` with `approval` in the error body; the held change record has status `APPROVAL_PENDING` until it is applied (the record is then replaced by the `APPLIED` one, which carries `approvalId`) or expires (`APPROVAL_EXPIRED`). The ledger keeps the `APPROVAL_PENDING` and `APPROVED` rows either way.

- **Lists** are cursor-paginated (keyset, no offset): arguments `limit` (default 50, max 200, clamped by the handler) and `cursor` (opaque base64url); result `{ "items": [...], "nextCursor": "..." }`, `nextCursor` absent on the last page. Unknown arguments are rejected with `INVALID_ARGUMENT`, never ignored.
- One named params struct per list tool, embedding `pagination.Params`, passed by value through every layer; the same struct backs the CLI flags.
- Agents cannot approve or sign a revert through MCP. Approve and revert need a passkey signature checked inside Postgres. `apply_revert_batch` only runs lines of a plan the person already signed. `request_revert` prepares a revert, waits for the person's signature, and may deliver the person's signed `basalt-revert.1.` code (`signature`), as `write` delivers `approval`; an agent can never sign a revert, only deliver the person's signature.

## CLI

`basalt init`, `basalt log --run`, `basalt approve`, `basalt revert` (foundation, "First release"), plus `basalt version`, from M4.1 `basalt passkey`, and from M5.1 `basalt classify`. Machine output with `--json` uses the wire format above. Paged output prints the next cursor on **stderr**. Exit codes: `0` ok, `1` error, `2` usage. Flag values a person types are lowercase kebab-case with an explicit default (`--agent-rls=ask|all-rows|none`), an input spelling only: anything stored, sent or written to the ledger uses the SCREAMING_SNAKE_CASE enum it maps to.

- `basalt init --agent NAME [--write schema.table,…] [--read schema.table,…]`: shows the setup SQL (agent password redacted), asks to confirm unless `--yes`, installs or upgrades `basalt_meta`, creates the agent role (an existing role keeps its password unless `--rotate-password`), attaches the guard (with the guard's row-level security policy on tables that have RLS enabled, version 8), registers the passkey, then sets up the engine. Before showing the SQL it finds the agent's tables where row-level security hides every row from the agent role and, with `--agent-rls=ask` (the default; the values are `ask`, `all-rows`, `none`) at a terminal, asks once per table `<schema.table> hides its rows with row-level security. Let <name> see all <n> rows of this table? [y/N]`; tables without RLS are never asked about. Yes adds the agent policy of version 11 to the SQL. `--agent-rls=all-rows` adds it for every such table without asking (the only way without a terminal or with `--yes`); `--agent-rls=none` skips the question. After installing, init warns for each agent table where RLS still hides every row (`basalt: warning: row-level security is on for ... and no policy lets <role> see rows; the agent will read 0 rows. ...`); `basalt log` and the engine log warn the same. At a terminal it asks once `Install the engine as a background service? ... [Y/n]` (`--yes` answers yes, `--no-service` no; without a terminal the answer is no). Yes: one `sudo basalt service install --config ... --user ... --agent NAME --os-user ... --credential-stdin` (the agent's connection string on stdin, never in arguments) creates the engine's OS user, writes the engine config (agent `name`, `osUser`, `credentialFile`) and the `0600` credential file (`<config dir>/agents/NAME.url`) owned by that user in the service's system directories, installs and starts (or restarts) the unit; init then checks the engine answers MCP `initialize` on the agent's socket and prints the `basalt mcp --agent NAME` line. No, or any of `--config`, `--socket-dir`, `--credential-file` given: init writes the config and credential itself (under the person's config directory when the paths are the system defaults) and prints the one `basalt engine --config ...` command. With the `claude` CLI on `PATH`, at a terminal, it offers `claude mcp add basalt-NAME -- basalt mcp --agent NAME` and runs it only on yes. The admin connection string comes from `BASALT_ADMIN_DATABASE_URL` or a hidden prompt and is never written anywhere. `--dry-run` prints the SQL and the engine setup (the sudo command and its steps) and runs nothing. M5.1: after installing, init prints `basalt: N columns the agent can read are not classified yet; run basalt classify` when there are any ([PII classification](#engine-basalt-log-and-basalt-init)).
- `basalt log [--run ID] [--full] [--sort -id|id]`: the agent's change records, newest first (`--sort` defaults to `-id`; `id` is oldest first; any other value is a usage error), read with the agent credential (`--agent NAME` looks it up in the engine config, or `--credential-file`, or `BASALT_DATABASE_URL`). Text output is compact (M4.1): one line per change; with `--run`, each row it wrote below it as its key and only the columns that changed, `{"id":4} status NEW -> CONTACTED` (an insert or a delete shows the key only), keeping the `(cascaded)`, `(read at xmin:N)` and `(blind write)` markers and `values hidden` or `values pruned`. Consecutive reads (`SELECT` records) collapse into one line: how many, the rows they returned and their tables (`3 reads, 42 rows: public.leads (2), public.notes (1)`). `--full` prints whole before and after rows and every read on its own line, as before M4.1. `--json` is unchanged. Warnings on stderr: broken ledger chain, unguarded tables, no engine heartbeat for 7 days, the last `DEAD_MAN` row (the engine came back after more than 7 days of silence), and from M4.1 no active passkey, and each passkey not used to sign an approval or revert for 90 days or more (counted from registration when never used), naming its label and id with `basalt passkey remove` as the fix for a lost one. The chain is checked incrementally with `verify_chain_from` from the head this user's `basalt log` last verified (kept under the user cache directory, per database and role); `--full-check` runs `verify_chain()` from the anchor instead. M5.1: with a guard of version 15 or later it also prints the PII line `PII: N columns classified, M unclassified; dictionary of K values, last scan <time>` on stderr, and warns about unclassified columns and columns that need a review ([PII classification](#engine-basalt-log-and-basalt-init)).
- `basalt classify [--review=changed|all] [--set schema.table.column=class[:entity-type]]... [--phone-region=auto|XX] [--yes] [--dry-run] [--json] [--check]` (M5.1): suggests a class for every column the agents can read and records the classes the person confirms, with the admin connection string given as for init. Every flag and its default: [`basalt classify`](#basalt-classify).
- Engine config (`engine.json`) also takes `stateDir` (default `/var/lib/basalt` on Linux, the systemd `StateDirectory`; `/Library/Application Support/Basalt/state` on macOS): the engine keeps each agent's last verified chain head there (`<stateDir>/<agent>.head.json`, mode `0600`) and verifies from it on start and every hour.
- AE-10, AE-12 (AE-11 is planned). **Init saves its flags.** `basalt init` writes the flags it was run with to `engine.json`, per agent, as `initArgs` (an array of strings): `--agent`, `--write`, `--read`, `--prefix`, `--statement-timeout`, `--socket-dir`, `--os-user`, `--engine-user`, `--credential-file` (a path, not a secret; AE-15, provisional), `--passkey-origin`, `--agent-rls`, `--operated-by` and `--remote` (planned, [Setup from your laptop](#setup-from-your-laptop)). Init saves a flag only when its value is not the default, except `--agent` and `--os-user`, as `--flag=value`; a value that is a connection URL or holds `password=` is refused before anything is written. The engine reads them to build its commands. Never the admin connection string (init still prompts for it, or reads `BASALT_ADMIN_DATABASE_URL`), never `--database-url`, and never the one-shot flags (`--yes`, `--dry-run`, `--no-service`, `--skip-passkey`, `--add-passkey`, `--passkey-label`, `--rotate-password`, `--new-code`). Every "run `basalt init` again" step uses exactly those flags plus the one change it is for, and `--config` by the [Next steps](#next-steps) rule. **Re-running init keeps the agent's password** when its role exists (the credential file is left as it is; if it is missing, init sets a new password); `--rotate-password` sets a new one, prints the engine restart command, and only then do the steps say to restart the engine.
- Planned (AE-11). `basalt upgrade --agent NAME [--config PATH]`: applies only the `basalt_meta` migrations this build has and the database lacks. It never rotates the agent's password, adds no policies, registers no passkey, and needs no engine restart (the engine checks the version on each call). The admin connection string is asked once (hidden prompt, or `BASALT_ADMIN_DATABASE_URL`) and never stored; the CLI refuses when it names a different database than the agent's credential. It prints what it applied. With `operatedBy: AGENT` the upgrade goes through an `UPGRADE` [setup code](#the-setup-code) instead: `basalt init --remote` on the engine's machine, `basalt init --setup-code` on the person's own computer.
- Planned (AE-13). `basalt status [--agent NAME] [--config PATH] [--json]`: the twin of the `status` tool, for the person. Prints the config path, whether the engine runs (pid, OS user), the socket and state directories, the pages URL and whether the engine serves it, `operatedBy`, and per agent: guard version against the build (up to date, upgrade available, upgrade required), passkey registered, and each problem with its `personMessage` and commands. Never prints a secret or a file's contents. `--json` is the `status` tool's result plus `configPath`, `engine.pid`, `engine.osUser`, `socketDir`, `stateDir`.
- `basalt uninstall`: drops the guard's RLS policies, `basalt_meta` and the roles, with the admin connection string given the same way as for init.
- `basalt approve <response-code>` (M2): decodes a `basalt-approval.1.` code, checks it locally against the stored passkey, and submits it with `submit_approval` using the agent credential (looked up as for `basalt log`). `basalt approve --show <approvalId>` prints the approval link for a held action, after a headline on stderr that states its cascaded rows (owner decisions, Decided Nov 12). `basalt approve --open <approvalId>` does the same but opens the link in the default browser (`open` on macOS, `xdg-open` on Linux) instead of printing it; when no browser opens it prints the link on stdout. The links use the pages base URL `--pages-url`, else the engine config's `pagesUrl` when the agent is named with `--agent`, else the engine's local pages `http://localhost:8787` ([Page links](#page-links)). M4.1: when the engine serves the [local pages](#local-pages) (it answers `GET /healthz` on the config's pages address), `--show` and `--open` with `--reissue` use a newly issued short link (revoking the item's earlier one, [Link secrets](#link-secrets)) and the page relays the signature itself, so no code is pasted; without `--reissue` they use the long link, whose page shows a code to paste; `basalt approve '<code>'` stays for a code from the long-link page. The CLI is only a relay; Postgres checks the signature.
- `basalt revert --change ID | --run ID | --task ID [--intent TEXT] [--dry-run] [--json]` (M3): prepares the revert with `prepare_revert` using the agent credential (looked up as for `basalt log`), prints every line on stdout (restored rows with the columns that change back, then skipped rows with the reason), prints the revert link on stderr, reads the pasted `basalt-revert.1.` code, checks it locally, and calls `apply_revert`. Without a code it exits `1` and nothing is reverted. Prints rows restored and rows skipped with reasons; exit `0` even when some rows were skipped. `--dry-run` prints the preview only (`preview_revert`). `basalt revert --apply <code>` applies a prepared revert later, within its hour. `--intent` defaults to `Revert <scope> <id>`. `--open` opens the revert link in the default browser instead of printing it (printed on stderr when no browser opens). The revert link uses the same pages base URL as `basalt approve` (`--pages-url`, the config's `pagesUrl`, else `http://localhost:8787`). M4.1: when the engine serves the local pages, the CLI prints (or with `--open` opens) the short link `<base>/reverts/<revertId>` and waits for the page's relay to apply the revert, polling its status, while still accepting a pasted code; it prints the same result either way. `preview_revert`'s `command` gains `--open` (and `--config` as for `approveCommand`). The CLI is only a relay; Postgres checks the signature and runs the revert. For a large plan (over 1000 lines) it prints the plan size and the lines the link carries instead of every line, and the code signs the plan: the agent then applies it in batches (`apply_revert_batch`), and `basalt revert --status <revertId>` prints its progress (restored, skipped, pending, batches, `applyBy`) and the lines skipped so far.
- `basalt init` (M2) registers the person's passkey: it prints and opens a registration link, reads the pasted `basalt-passkey.1.` code, verifies it, and stores the public key with the admin credential, unless a passkey is registered already. `--skip-passkey` defers it, `--add-passkey` registers another, `--passkey-label` names it, and `--passkey-origin` picks the pages the passkey belongs to: the engine's local pages `http://localhost:<port>` (default `http://localhost:8787`, RP ID `localhost`) or the hosted console `https://console.basaltvault.app` (RP ID `basaltvault.app`). Init writes it to the engine config as `pagesUrl`. M4.1: for a local origin init serves the built-in pages on that port (127.0.0.1) while it waits for the code, unless the port is taken.
- **Revert line order** (M4.1). The text output of `basalt revert` (the lines, `--dry-run`, and the skipped lines of `--status`) is ordered for reading: rows to restore first, re-inserts before restored updates before deletes, then skipped rows; inside each group by table, then by primary key in natural order (numbers by value, text with digit runs compared by value: `1, 3, 5, 10`, never `1, 10, 3`), redacted lines last in their table by row hash. Only the display changes: `--json`, the link, the binding and `rowsHash` keep the signed order.
- `basalt passkey list [--json]` (M4.1): the database's active passkeys, read with the agent credential (looked up as for `basalt log`): credential id (base64url), label, RP ID, when registered and when last used (`never`). `--json` prints `[{ "credentialId", "label", "rpId", "origin", "createdAt", "lastUsedAt" }]` (`lastUsedAt` null when never used). Never prints key material. At most 100 passkeys (the bound the relays use), so it has no cursor.
- `basalt passkey remove <credentialId> [--force] [--yes] [--pages-url URL] [--open]` (M4.1): revokes a passkey in Postgres with the admin connection string (`BASALT_ADMIN_DATABASE_URL` or a hidden prompt, as for init). The id is the full base64url id or a unique prefix of at least 8 characters. It shows the label, RP ID and last use and asks `Remove passkey ...? [y/N]` unless `--yes`. The last active passkey is refused unless `--force` is given and the person types its label at the prompt (asked even with `--yes`); held writes and reverts then cannot be signed until `basalt init --add-passkey`. It calls `revoke_passkey`, which records a `PASSKEY_REVOKED` ledger row. Revoking does not touch the device: it then prints the forget link (`<base>/passkeys/forget#1.<request>`, mode `FORGET`, [Passkey management](#passkey-management)) on stdout, to open on each device that holds the passkey so its password manager drops it; `--open` opens it in the default browser instead (printed when no browser opens). `<base>` is `--pages-url`, else the passkey's registered origin; a base other than that origin gets no link, since only a page on the passkey's origin can signal about it.
- `basalt passkey check [--pages-url URL] [--open]` (M4.1): which registered passkeys this device can still produce. Reads the active passkeys with the agent credential (looked up as for `basalt log`), prints the check link (`<base>/passkeys/check#1.<request>`, mode `CHECK`; `--open` opens it as for `basalt approve --open`) for the passkeys registered on the pages base (`--pages-url`, else the engine config's `pagesUrl`, else `http://localhost:8787`) and names any registered on another origin with the `--pages-url` that checks them; when the base is local and the engine is not serving it, the CLI serves the pages there while it waits, as `basalt init` does for registration. It reads the pasted `basalt-passkey-check.1.` code, verifies each assertion in it locally against the stored public key and the check challenge, and prints each passkey as `found on this device` or `not found on this device`. For each one not found it asks `Remove <label> (<id>)? [y/N]`; yes runs the `basalt passkey remove` steps (admin connection string asked once). Nothing is written unless a removal is confirmed. A check signature authorizes nothing (see [Passkey management](#passkey-management)).

## Setup from your laptop

Planned, M4 (chat-only operator: owner decisions CO-1, CO-9, CO-10, CO-12 to CO-17 and CO-19; design [`docs/redesign/specs/2026-11-12-chat-only-operator.md`](docs/redesign/specs/2026-11-12-chat-only-operator.md) sections 2 to 4 and 9; provisional details in the [owner decisions](docs/redesign/specs/2026-11-11-owner-decisions.md#decided-nov-12-2026-remote-init-contract), RI-1 to RI-17). For an engine on a machine the person cannot reach, run by their bot: the bot runs `basalt init --remote` there with no admin credential and gets a setup code; the person runs `basalt init --setup-code <code>` on their own computer with the admin connection string. **The admin connection string never touches a machine the bot controls (CO-9)**: no command on an agent-operated engine's machine asks for it or accepts it.

### Who operates the engine

- `basalt init --operated-by=person|agent`, default `person`, is saved in `engine.json` as the top-level `"operatedBy": "PERSON"` or `"AGENT"` (absent means `PERSON`). One engine per machine, one operator. It decides who runs machine steps ([Next steps](#next-steps)) and is independent of how setup runs: the chat-only case is `--operated-by=agent --remote`; a person may also run init with the admin credential on a machine they control and hand that engine to a bot.
- With `AGENT`, `pagesUrl` is the portal `https://portal.basaltvault.app` (CO-6, CO-8): the loopback pages would belong to the bot's machine. Renaming the hosted pages from `console` to `portal` and the compiled-in origin list are their own contract change (design PR 7c).
- **In the ledger (CO-15).** Every `HEARTBEAT` row's detail carries `operatedBy` next to `engineVersion` (and `chainBrokenAt` when the chain is broken), so the ledger shows the periods when enforcement was guard-only. A change shows at the next heartbeat.

### `basalt init --remote` (the engine's machine)

`basalt init --remote --agent NAME [--write schema.table,…] [--read schema.table,…] [--prefix P] [--statement-timeout D] [--operated-by person|agent] [--database-url URL] [--new-code] [--config PATH] [--json]`

1. **No admin credential.** `--database-url` is the connection string without a password (Supabase shows it with a `[YOUR-PASSWORD]` placeholder), required on the agent's first run and read from the credential file after that. A URL with a password, in the user part or as a `password` parameter, is refused before anything else (exit `1`), and never written, logged or echoed: `This connection string contains a password. basalt init --remote does not need it and it must not be shared with an agent: change your database password now.` `BASALT_ADMIN_DATABASE_URL` is ignored and there is no prompt.
2. **The agent's password stays here.** Init generates it (256 bits, as `basalt init` does), writes the agent's connection string (user `<prefix>_agent_<name>`, or `<prefix>_agent_<name>.<ref>` through Supabase's pooler) to the `0600` credential file, and puts only its SCRAM-SHA-256 verifier in the code. A new password for an agent whose role already logs in goes to `<credentialFile>.pending` (`0600`) instead: the old one keeps working until the person runs the code, and the engine swaps the files when it sees the setup recorded (below).
3. **The kind of code.** `INSTALL` when the agent's role cannot log in with its credential (or there is none yet). Otherwise `AGENT` when `--write`, `--read` or `--statement-timeout` change, or with `--new-code` (then with a new password and verifier); else `UPGRADE` when the installed guard (read with the agent credential, allowed from version 13) is older than this build's; else an `AGENT` code with no change and no verifier (it re-applies the grants, and the person's computer registers a portal passkey when none is active). A code of any kind also applies the migrations the database lacks up to `guard.to`.
4. **One pending code per agent.** While an unexpired code is pending and nothing changed, init prints the same code again (`reused: true`: same `setupId`, same expiry). A change or `--new-code` makes a new one with a new `setupId` and expiry; the old one is then refused by the person's computer once the new one has run (newer setup, below). An expired code is replaced by a new one.
5. **Config.** Init writes `engine.json` as `basalt init` does (`initArgs`, [CLI](#cli)), plus `operatedBy`, `pagesUrl` and, per agent, the pending setup: `"setup": { "setupId", "kind", "guardVersion", "expiresAt", "code", "fingerprint" }` (`guardVersion` is the code's `guard.to`; `code` is the setup code, kept so `status` and a re-run hand out the same one). Nothing secret goes in `engine.json`. `setupId` is a UUIDv7 of the clock now, and `expiresAt` is its time plus 24 hours, truncated to the second.
6. **Output.** Exit `0`: the setup is pending, not failed. Text: the code in a block of its own, its [fingerprint](#the-setup-code), and what the person does with it. `--json`: [`remote-init-result.schema.json`](api/mcp/setup/remote-init-result.schema.json), with `fingerprint`, `personMessage` (install `basalt` from the official release page on their own computer, run the command, check that it shows the same fingerprint, never paste the database password into the chat) and `nextSteps`: P `RUN_COMMAND` (`basalt init --setup-code <code>`, on their own computer), P `TELL_AGENT`, A `END_TURN`, A `CALL_TOOL` (`status`). A code longer than 1500 characters is refused (exit `1`), saying to name fewer tables.
7. Init does not install or start the engine: on an agent-operated machine the agent does it (an `AGENT` `RUN_COMMAND`).

### The setup code

`basalt-setup.1.<payload>.<check>`, one line, shown in a code block (so chat apps do not read `_` as emphasis).

- `payload`: base64url without padding of deflate-raw of the JSON in [`setup-code.schema.json`](api/mcp/setup/setup-code.schema.json): `format` (1), `setupId` (UUIDv7), `kind`, `prefix`, `target`, `guard` (`from`, `to`), `build`, `agent` (`name`, `write`, `read`, `verifier`, `statementTimeoutMs`; absent for `UPGRADE`), `expiresAt`. Only non-secret parameters: never the agent's password, never anything of the admin. Encoders write compact JSON in the schema's key order, deflated at level 9; decoders accept any raw deflate stream and any key order.
- `check`: base64url without padding of the first 4 bytes of sha256 over the bytes before the last `.` (`basalt-setup.1.<payload>`), 6 characters.
- **Decoding**, in order: drop every whitespace character (a wrapped copy still works); not `basalt-setup.` → `NOT_A_SETUP_CODE` (`This is not a Basalt setup code.`); a version other than `1.` → `UNSUPPORTED_FORMAT`; a check that does not match → `DAMAGED` (`This setup code is damaged; copy it again.`); a payload that is not base64url, inflates past 64 KiB, is not JSON or fails the schema → `INVALID`; `format` other than 1 → `UNSUPPORTED_FORMAT` (`This setup code is newer than basalt on this computer: update it from the release page.`). The golden fixtures [`setup-code.fixtures.json`](api/mcp/setup/setup-code.fixtures.json) pin each case, and pin the verifier for a password and salt; the contract test checks them.
- **Rules the schema cannot state:** `guard.from` ≤ `guard.to` (`<` for `UPGRADE`); at least one table in `write` or `read`; no table in both; the role `<prefix>_agent_<name>` at most 63 bytes; `expiresAt` no later than the `setupId`'s UUIDv7 time (its first 48 bits, milliseconds since the epoch) plus 24 hours. Failing one is `INVALID`. These do not depend on the clock; the clock checks are the person's computer's and Postgres's (below).
- **Fingerprint.** `sha256(utf8("basalt-setup-fingerprint.1\n" + setupId + "\n" + verifier))`, `verifier` empty when the code has none; its first 10 bytes (80 bits, too many to grind a matching substitute within the 24 hours) in lowercase hex as five groups of four (`3f9a 21c0 7d44 e1b2 90ac`). `basalt init --remote` prints it, `status` returns it while the setup is pending, the agent's `personMessage` names it, and `basalt init --setup-code` shows it before asking. It lets the person check that the code they run is the one their own agent made, not one another chat member posted with their own verifier. It is a matching aid: it proves nothing about who made the code.
- **`verifier`**: `SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>` (RFC 5802 and RFC 7677, standard base64): salt 16 random bytes, 4096 iterations, `SaltedPassword` = PBKDF2-HMAC-SHA-256 of the password, `StoredKey` = sha256(HMAC(`SaltedPassword`, `Client Key`)), `ServerKey` = HMAC(`SaltedPassword`, `Server Key`). Postgres stores a verifier given as `PASSWORD` as is, whatever `password_encryption` says; the verifier lets nobody log in.
- **Kinds (CO-14).** `INSTALL`: the guard, a **new** agent role with its password from the verifier, its grants, a portal passkey; a role that already exists is refused (the code-maker would otherwise set the password of a role that is not theirs). `AGENT`: an existing agent's tables (a role that does not exist is refused), replaced by `write` and `read` as given (grants on tables no longer listed are revoked); with `verifier` its password is rotated, without it kept. `UPGRADE`: migrations only; password, grants and policies unchanged.
- **`target`**: the database the bot's engine connects to (`host`, `port`, `database`, and `supabaseRef` when the connection string names a Supabase project: a pooler user `postgres.<ref>` or a host `db.<ref>.supabase.co`).
- **Valid for 24 hours, single use (CO-13).** `expiresAt` is 24 hours after `basalt init --remote` made the code. Because the code-maker writes `expiresAt` and `setupId`, neither is trusted as given: the person's computer (its clock) and `record_setup` (the database's `now()`) refuse an expired code, a `setupId` whose time is more than the **clock skew of 5 minutes** ahead of now, and an `expiresAt` more than 24 hours plus 5 minutes ahead of now. Expiry itself is checked without skew: a code is expired from `expiresAt` on. Single use is enforced in Postgres (`basalt_meta.setups`, version 16): the person's computer records `setupId` in the install's transaction. A code is also refused when the agent's latest recorded setup is newer (UUIDv7 ids are time-ordered), so an older unused code cannot reset the password to an old verifier.
- From M4.1 the code also carries the engine's identity key (CO-18); that key and its format are added by the vault channel's contract.

### `basalt init --setup-code` (the person's own computer)

`basalt init --setup-code <code> [--yes] [--agent-rls=ask|all-rows|none] [--add-passkey] [--passkey-label LABEL] [--dry-run]`. macOS and Linux only in M4 (CO-19). It writes no engine config and no credential file and never touches a local engine's config.

1. **Decode and validate** as above. Then, by this computer's clock, exit `1` with nothing changed, in this order: `EXPIRED`, now at or past `expiresAt` (`This setup code expired on <time UTC>. Ask <agent> for a new one.`); `SETUP_ID_IN_FUTURE`, the `setupId`'s time more than 5 minutes ahead of now, and `EXPIRY_TOO_FAR`, `expiresAt` more than 24 hours and 5 minutes ahead of now (both `This setup code claims a time in the future. Check this computer's clock, or ask <agent> for a new code.`); `BINARY_TOO_OLD`, `guard.to` newer than this binary's guard (`Update basalt on this computer to at least <build>.`).
2. **The admin connection string** from `BASALT_ADMIN_DATABASE_URL` or a hidden prompt, never written anywhere.
3. **Target (CO-17).** The admin connection string must name the same database as `target`: with `supabaseRef`, the same project ref (from the pooler user or the direct host) and database name, so the pooler and the direct host of one project match; otherwise the same host, port and database. A mismatch is refused, never asked about (exit `1`, nothing changed): `This setup code is for database <database> of <Supabase project <ref> | <host>:<port>> (the agent connects there). Your admin connection string points at <...>. Either run this command with the admin connection string of <...>, or ask <agent> for a new code for the database you meant (basalt init --remote --new-code --database-url <that database, without password>).`
4. **The database's state**, read with the admin connection string, refused in this order (exit `1`, nothing changed): `PREFIX_MISMATCH`, `basalt_meta` is installed with another prefix (its owner role is not `<prefix>_guard`: `This setup code is for prefix <prefix>, but this database's Basalt uses <installed>.`); `USED` and `SUPERSEDED` (read from `basalt_meta.setups`, and enforced again by `record_setup`: `This setup code was already used on <time UTC>. Ask <agent> for a new one.`, or `A newer setup for <agent> already ran on <time UTC>. Ask <agent> for a new code.`); `ROLE_EXISTS`, an `INSTALL` code whose role already exists (`<role> already exists. This code would replace its password: ask <agent> for a new code, or run basalt init --remote --new-code for that agent if it is yours.`), also enforced in Postgres, since the `INSTALL` SQL creates the role with a plain `CREATE ROLE`, never `IF NOT EXISTS`; `ROLE_MISSING`, an `AGENT` code whose role does not exist. The fixtures' `laptop` cases pin this order.
5. **Show, then ask.** First the summary, whose lines are fixed so the person reads the same words every time: by kind, `This creates the agent <name> (role <role>). Its password comes from the code: only whoever made this code can log in as <role>.` (`INSTALL`), `This replaces the password of the existing agent <name> (role <role>): only whoever made this code can then log in as <role>. Run it only if <name> itself gave you this code.` (`AGENT` with a verifier), `This changes the tables of the existing agent <name> (role <role>); its password stays.` (`AGENT` without), or `This upgrades Basalt's guard from version <from> to <to>; no agent changes.`; then `Prefix <prefix>, statement timeout <n> ms.` (for `AGENT`, with `(now <m> ms)` when the role's current `statement_timeout` differs; `UPGRADE`: `Prefix <prefix>.`); then `Setup fingerprint: <fingerprint>. Check that <name> shows the same fingerprint.` (`your agent` for `UPGRADE`). Then in words what the agent gets (`<agent> will be able to read … and change rows in …, up to 10 rows at a time without asking you, 11 to 50 with your passkey, never more. It cannot change your tables' structure.`), tables outside `public` flagged (for Supabase, `auth` and `storage` more strongly); then the row-level security question per table, as `basalt init` asks it (`--agent-rls`); then the SQL (the role's password shown as the verifier); then `Run this? [y/N]` unless `--yes`. **All or nothing (CO-16):** every requested table or none; to change the list the bot makes a new code. `--dry-run` prints and runs nothing.
6. **One transaction:** the missing migrations, the role (`CREATE ROLE ... PASSWORD '<verifier>'` for `INSTALL`, `ALTER ROLE ... PASSWORD '<verifier>'` for `AGENT` with a verifier), the grants, the confirmed agent policies, `attach`, and `basalt_meta.record_setup`. Any failure leaves the database as it was.
7. **Passkey.** When no passkey registered on the portal is active, or with `--add-passkey`: init prints and opens `https://portal.basaltvault.app/passkeys/register#1.<request>`, reads the pasted `basalt-passkey.1.` code, verifies it and stores it with the admin credential, as `basalt init` does.
8. Ends with `Done. Tell <agent> to check its status.`, exit `0`.

### On the engine

- **Serving while an `INSTALL` setup is pending.** An agent whose `engine.json` has a pending `INSTALL` `setup` is served degraded: `status` works, and every other tool answers `UNAVAILABLE` reason `SETUP_PENDING` (`SETUP_EXPIRED` after `expiresAt`) with the [steps](#next-steps-per-code), the pending `code` filled in. A pending `AGENT` or `UPGRADE` setup does not change serving; `status` reports `SETUP_CHANGE_PENDING`. An expired `AGENT` or `UPGRADE` setup is dropped from `engine.json`, and the problem that called for it comes back with its steps.
- **Finishing.** On `status`, on every call while degraded, and at each heartbeat, the engine logs in with the agent's credential (the `.pending` one first, when there is one) and looks for the pending `setupId` in `basalt_meta.agent_setups`. Found: it moves a `.pending` credential over the credential file, clears `setup` from `engine.json`, and serves normally; `setup.state` is `DONE`. Logging in proves the role exists with the bot's password: only the bot knows it, and the verifier came from the bot. Guard version, grants and passkeys are then `status`'s usual checks (`GUARD_OUTDATED`, `PERMISSION_DENIED` on use, `NO_PASSKEY`).
- **The shim** reads `operatedBy` and `setup` from the engine config when the engine is down; when it cannot read the file it assumes `PERSON` and no pending setup.
- **Fingerprint in messages.** While a setup is pending, `status` returns `setup.fingerprint`, and every `personMessage` that hands the person the setup code names the fingerprint and asks them to check that `basalt init --setup-code` shows the same.

### Controls

What stops a setup code being used against the person (design section 10):

- **Another agent's role.** `INSTALL` never touches an existing role (`ROLE_EXISTS`, and `CREATE ROLE` in Postgres); a code that sets an existing role's password says so in the summary, naming the agent and role.
- **Old or forged-time codes.** Expiry, a `setupId` in the future and an `expiresAt` too far ahead are refused by the person's clock and by the database's (5 minutes of skew); single use and order are enforced by `record_setup`.
- **A substitute code** posted in the chat by someone else, with their own verifier: the fingerprint shown on the person's computer must match the one their agent reports (`status`, `personMessage`).
- **Wrong database**: target mismatch is refused (CO-17). **Wrong prefix**: refused (`PREFIX_MISMATCH`).
- **The admin credential** is used only on the person's computer (CO-9); the SQL comes from the person's own `basalt` binary, never from the code.

## Approvals

M2. The flow and the reasons are in [`docs/redesign/plans/2026-11-11-m2-approvals.md`](docs/redesign/plans/2026-11-11-m2-approvals.md); this section fixes the bytes. JSON Schemas for every payload are in [`api/mcp/approval/`](api/mcp/approval/).

- An approval or revert counts only with a valid P-256 passkey signature (WebAuthn ES256), verified inside Postgres. Pages and relays (the engine, the CLI, the agent's chat, Telegram) carry signed data and are not trusted.
- **Pages.** Static files under `web/`. Hosted (not live yet) on the console `https://console.basaltvault.app` with passkey RP ID `basaltvault.app` (fixed for good: registered passkeys depend on it) and origin `https://console.basaltvault.app`. Until hosting exists the default everywhere is the engine's local pages, `http://localhost:8787` with RP ID `localhost` (owner decisions, Decided Nov 12). Both have the same paths ([Page links](#page-links)). The clientDataJSON origin check stays strict: a passkey signs only on the origin it was registered on. The pages have no backend, load no third-party code, and send nothing over the network: input comes in the URL fragment, output is a code the person copies. From M4.1 the engine also serves them on loopback with a same-origin relay ([Local pages](#local-pages)); that listener follows the listener rules in [AGENTS.md](AGENTS.md) and the `websec` hardening; custom HTTP headers use the lowercase **`basalt-`** prefix.
- **Expiry.** 24 hours after the hold. No answer means blocked.
- **Engine.** On `BS002` the engine checks the write is repeatable (`NOT_REPEATABLE` otherwise), previews it, holds it, and answers `APPROVAL_REQUIRED` with the link. The engine config (`engine.json`) may set `pagesUrl` (the pages base URL, default `http://localhost:8787`; the older key `approvalPage` is still read, its origin only), `pagesAddr` (see [Local pages](#local-pages)) and `notify.telegram: { botTokenFile, chatId }`; the token file must be mode 0600 and the token is never logged. Telegram only delivers the link, and always the long link: the short link works only on the engine's machine, and the phone flow is parked (M4.1). The button's long link is not subject to the [link budget](#the-link-budget) (planned, M3.5): it is a button, not text a client can wrap.
- **Waiting write (M4.1).** `write` takes `waitForApproval` (integer seconds, 0 to 110). When the write is held, or the call names an `approvalId` whose approval is not signed yet, the engine keeps the call open up to that long, checking about once a second. As soon as the approval is signed (by the page's relay, `basalt approve` or the `approval` argument) it applies the held write exactly as a repeat with `approvalId` would, and returns `APPLIED` in the same call. On timeout it returns `APPROVAL_REQUIRED` with the same `approval` body, and nothing is applied; its message tells the agent not to wait again but to end its turn, telling the person the write waits for their approval (link, expiry) and that it applies the write when they say they approved (a later `write` with `approvalId` applies at once). One wait per turn: a review can take longer than any wait, and MCP cannot start a client turn when the person approves. Default: **0 on a new write**, so the agent gets the link at once and can hand it over; **90 when `approvalId` is given**. The intended loop: the agent shows `personMessage`, then, in the same turn, repeats the write once with `approvalId` (also after a `list_pending` that handed over a link), and the call returns `APPLIED` once the person signs, with no "I approved it" from the person. Bound: Claude Code moves an MCP call still running after 2 minutes to a background task (`CLAUDE_CODE_MCP_AUTO_BACKGROUND_MS`, default 120000), and its hard tool timeout (`MCP_TOOL_TIMEOUT`) is about 28 hours, so 110 seconds keeps a wait in the foreground. A client with a 60 second request timeout should pass a smaller value.

### What an approval binds (decision M2-1)

Bound: the statement, its parameters, and for every affected row, cascades included: table, operation, cascade flag, primary key, full old row, and the new values of the columns the statement assigns (`UPDATE … SET` targets; the `INSERT` column list, or every column when it is omitted). Not bound: defaults, identity and sequence values, and values set by the app's triggers. A write that would be held and contains a value that changes between transactions is refused with `STATEMENT_REFUSED` reason `NOT_REPEATABLE`.

**Preview line.** One per affected row: the `jsonb` text Postgres returns for

```json
{"op": "UPDATE", "key": {"id": 7}, "old": {"id": 7, "status": "open"}, "set": {"status": "merged"}, "table": "public.leads", "cascaded": false}
```

`key` and `old` are `null` for an `INSERT`; `set` is `null` for a `DELETE` and for cascaded rows. A row of a table the agent role cannot `SELECT` is redacted to `{"op", "table", "rowHash", "cascaded", "redacted": true}` with `rowHash` = lowercase hex of `sha256(jsonb_build_array(key, old, set)::text)`. Lines are ordered by their text `COLLATE "C"` (byte order). Clients hash and parse the text as given and never re-serialise it.

**Binding text.** The `jsonb` text Postgres returns for

```json
{"kind": "APPROVE", "rows": 15, "agent": "bot", "runId": "…", "intent": "…", "params": ["merged"], "taskId": "…", "database": "app", "rowsHash": "<hex>", "expiresAt": "2026-11-12T06:02:11.123456Z", "statement": "…", "approvalId": "…", "assignedColumns": ["status"]}
```

`rowsHash` = lowercase hex of `sha256(utf8(lines joined by "\n"))`. `expiresAt` is RFC 3339 UTC with microseconds. Keys appear in `jsonb` order (shorter first, then bytewise); clients parse the text and never rebuild it. `kind` is `APPROVE` (M3 adds `REVERT`). **Challenge** = `sha256(utf8(binding text))`, in `clientDataJSON.challenge` as base64url without padding.

### Codes

All base64url is RFC 4648 §5 without padding. Byte fields inside JSON are base64url strings.

| Payload | Carried as | JSON |
|---|---|---|
| Approval request | URL `<base>/approvals/<approvalId>#2.<b64url(deflate-raw(json))>` ([Format 2](#format-2-the-compact-request)) | `[shapes, texts]`: the binding text, then the preview lines in order |
| Approval request, format 1 (read only) | URL `<base>/approvals/<approvalId>#1.<b64url(deflate-raw(json))>` | `{ "approvalId", "binding", "lines", "credentialIds" }`: `binding` the binding text, `lines` the preview lines in order, `credentialIds` the registered passkeys (may be empty). The pages still read it; the engine no longer writes it. The engine's local pages serve this JSON at `GET /api/v1/approvals/{approvalId}` |
| Approval response | Text `basalt-approval.1.<b64url(json)>` | `{ "approvalId", "credentialId", "authenticatorData", "clientDataJson", "signature" }` from `navigator.credentials.get` (`signature` DER) |
| Passkey registration request | URL `<base>/passkeys/register#1.<b64url(json)>` | `{ "challenge", "userId", "userName", "displayName" }`: 32 and 16 random bytes; names are labels for the passkey picker |
| Passkey registration response | Text `basalt-passkey.1.<b64url(json)>` | `{ "credentialId", "clientDataJson", "authenticatorData", "publicKey", "publicKeyAlgorithm" }`: `publicKey` the SubjectPublicKeyInfo DER from `getPublicKey()`, algorithm `-7` (ES256) only |

### Format 2: the compact request

Owner decisions VC-7 and VC-29; the layout details are VC-31 (provisional). The engine writes approval and revert links in format 2; the pages read format 2 and format 1. Schema: [`compact-request.schema.json`](api/mcp/links/compact-request.schema.json). Shared vectors, which the contract test, the Go codec and the pages all run: [`compact-request.json`](api/mcp/links/compact-request.json).

`#2.<b64url(deflate-raw(json))>`, where the JSON is `[shapes, texts]`:

- **`texts`**: the binding text first, then the lines in order: the preview lines of an approval, or the revert lines (a large plan's sample) of a revert. At least 2 texts, at most 51 for an approval and 1001 for a revert. There is no separate id and no `credentialIds`: the id is the binding's `approvalId` or `revertId`, and the passkeys are discoverable.
- **A text** is a JSON string, the text as it is, or `[shape, value, ...]`: the index of a shape in `shapes` and one value per slot of that shape.
- **`shapes`**: the key layouts the texts share, each listed once and used by at least one text, never more than there are texts. A shape is 1 to 64 entries in text order. An entry is `"key"`, which takes one slot, or `["key", ["column", ...]]` for a key whose value is an object (`key`, `old`, `set`, `now`), which takes one slot per column (at most 1600), in text order.
- **A value** is a string, `true`, `false`, `null`, an integer of magnitude at most 2^53 − 1 that is not `-0`, an array of values (nested at most 32 deep), or `{"raw": "<text>"}`: the value's `jsonb` text as it is, for anything else (other numbers, nested objects). Numbers are read as JavaScript's `JSON.parse` reads them, so `1.0` is the integer 1.

**Rebuild.** A text `[shape, value, ...]` is `{`, then its entries joined by `, `, then `}`. An entry is `"key": value`, or for an object entry `"key": {`, then `"column": value` for each column joined by `, `, then `}`. An array is `[`, its values joined by `, `, then `]`; an integer is written in decimal; `{"raw": text}` is `text`. Keys, columns and strings are quoted as Postgres's `escape_json` quotes them: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, any other character below U+0020 as `\u00xx` (lowercase hex), everything else as it is. That is `jsonb`'s own text layout, so the texts rebuild to the binding text and the lines byte for byte. The engine checks each text rebuilds exactly and sends any text that does not as a string.

**Limits.** The page first repairs the fragment ([The pages repair what they can](#the-pages-repair-what-they-can): line breaks, spaces and the other characters a client adds are dropped), then decodes it. It refuses the repaired fragment unless: its payload is at most 1 MiB of base64url characters and nothing else (a decoder given an unrepaired fragment, as the Go codec is, refuses a line break rather than skipping it); it inflates to at most 1 MiB of UTF-8, with nothing after the end of the deflate stream (the page finds that end itself, without relying on the browser's decompressor); that is one JSON value the schema allows, with nothing after it; and the rebuilt texts total at most 1 MiB. Then it checks the rebuilt request exactly as a format 1 request: the binding's id against the id in the page's path, which the approval and revert pages require (a page whose path has no id refuses to run: a format 2 request has no id of its own), the kind, the number of lines, and `rowsHash` (or `sampleHash`). A wrong rebuild fails closed: the lines no longer hash to the binding's `rowsHash`, and a binding text that differs from the one Postgres built has a different challenge, which Postgres refuses.

A page first repairs the fragment and, when it still does not decode, offers to read the link from the pasted message ([Showing links](#showing-links), planned M3.5). A page whose fragment does not decode as base64url, deflate-raw or JSON says the link looks cut short and to open it with `basalt approve --open` (or `basalt revert ... --open`), which builds the full link itself. The approval page checks `sha256(lines joined by "\n")` equals the binding's `rowsHash` and refuses to ask for a signature otherwise. Registration asks for `userVerification: "required"`, `residentKey: "required"`, `attestation: "none"`, ES256 only. `basalt init` verifies the registration in Go: type `webauthn.create`, challenge, origin, `rpIdHash`, the UP, UV and AT flags, the attested credential id equals `credentialId`, and a P-256 key.

### Checks in Postgres

`submit_approval` accepts an assertion only if: `type` is `webauthn.get`; the challenge is the approval's binding; `origin` and `rpIdHash` match the passkey's stored RP ID and origin; UP and UV are set; the signature counter increased (0 is accepted while the stored count is 0); the ES256 signature over `authenticatorData ‖ sha256(clientDataJSON)` is valid; the approval is not expired and not yet approved. Applying with `basalt.approval_id` commits only if the approval is approved, unused, unexpired, of this agent and run, and the statement, parameters, row count and `rowsHash` recomputed at commit match. Failures are `BS005`.

## Revert

M3. The flow and the reasons are in [`docs/redesign/plans/2026-11-11-m3-revert.md`](docs/redesign/plans/2026-11-11-m3-revert.md); decisions M3-1 to M3-14 are in the owner decisions. This section fixes the rules and the bytes. JSON Schemas for every payload are in [`api/mcp/revert/`](api/mcp/revert/).

- **Scopes:** `CHANGE` (one change, a revert's own change included), `RUN`, `TASK` (every agent's changes with that task id). `APPLIED` and `REVERTED` changes that wrote rows count (a reverted one shows its rows as `ALREADY_REVERTED`).
- **A revert can be reverted** (owner decision AE-14). The ledger is append-only and a revert is itself a recorded write, so reverting a revert's change brings the reverted values back (a redo). People still win and the person still signs. An agent may request it for a revert of its own change or run (`request_revert` with the revert's `changeId`).
- **A revert is a new change.** It restores old values and never edits or deletes ledger rows. It is recorded as one change record with `op: REVERT`, `actor.kind: PERSON` and `revertId` (its `agent` is the role that relayed it), one `ROW_CHANGE` per restored row (detail `revertOf`), and a `REVERTED` ledger row with the credential id, the binding hash and every skipped row (table, key or row hash, reason; no values). Each covered change gets `revertedBy`; its status becomes `REVERTED` only when none of its rows was skipped. Every agent whose changes a revert covered sees the revert's change record.
- **Only a person.** A revert runs only inside `apply_revert`, after it verifies a passkey assertion over the revert binding with the same checks as `submit_approval`. Agents may preview and prepare (from `request_revert` the agent prepares one for the person and hands them the link); they cannot sign. No MCP tool applies a revert without the person's signature: `request_revert` may deliver the person's signed code, which `apply_revert` verifies (N12-R8).
- **Row limits do not apply** to a revert, and no line cap does: a revert of up to 1000 lines is applied in one call; a larger one is a plan applied in batches (see [Large plans](#large-plans)). The intent comes from the person (`--intent`, or through `request_revert` the agent's wording of the person's reason, which the page shows before the person signs).
- **Expiry.** A prepared revert must be signed (and, up to 1000 lines, applied) within 1 hour. A signed large plan must be finished within 24 hours of the signature.
- **Window.** A row whose old values were pruned (30 days) is skipped as `VALUES_PRUNED`.

### What is restored

Per row, BasaltDB takes the first and the last in-scope ledger row, following primary-key changes, and restores the row to its state before the first in-scope change: an inserted row is deleted, an updated row gets its old values back (key included), a deleted row is re-inserted, and a row inserted and deleted in scope gets no line. Cascaded rows (deleted or set to null by an FK cascade) are restored like any other row. Generated columns are not written; identity `ALWAYS` columns are re-inserted with `OVERRIDING SYSTEM VALUE`; columns added after the change keep their current value or default.

### Conflicts (people win)

A row is restored only if nobody wrote it after the last in-scope change. Otherwise it is skipped, reported, and never overwritten; the other rows are still restored.

| Reason | When |
|---|---|
| `CHANGED_AFTER` | The row's `xmin` is not the version the last in-scope change left, or its values differ from that change's new row, or someone wrote it between two in-scope changes. Covers people, the app, other agents and later changes outside the scope |
| `ROW_GONE` | The row the revert would update or delete no longer exists, or the guard cannot see it |
| `KEY_TAKEN` | The revert would re-insert a row, or move a key back, and a row with that key exists |
| `ALREADY_REVERTED` | The row was last written by a revert of this change |
| `VALUES_PRUNED` | The old values are past the 30-day window |
| `SCHEMA_CHANGED` | The table, a column of the old row, or the primary key changed |
| `CASCADE` | The inverse write would cascade into a row that is not part of the revert |
| `CONSTRAINT` | The inverse write fails a constraint on trial; the line carries `sqlState` |

### Lines, binding and codes

**Revert line.** One per row, the `jsonb` text Postgres returns for

```json
{"op": "UPDATE", "key": {"id": 7}, "now": {"id": 7, "status": "merged"}, "set": {"id": 7, "status": "open"}, "table": "public.leads", "action": "RESTORE", "cascaded": false, "conflict": null, "sqlState": null, "changeIds": ["…"]}
```

`op` is the inverse write (`DELETE`, `UPDATE`, `INSERT`); `now` the row as it is now (`null` if absent); `set` the values written (`null` for `DELETE`); `action` `RESTORE` or `SKIP`; `conflict` a reason above on `SKIP` lines. A row of a table the preparing role cannot `SELECT` is redacted to `{"op", "table", "action", "rowHash", "cascaded", "conflict", "redacted": true, "changeIds"}` with `rowHash` = lowercase hex of `sha256(jsonb_build_array(key, now, set)::text)`. Lines are ordered by their text `COLLATE "C"`; clients never re-serialise them.

**Binding text.** The `jsonb` text Postgres returns for

```json
{"kind": "REVERT", "rows": 11, "scope": "RUN", "agents": ["bot"], "intent": "…", "scopeId": "…", "skipped": 1, "database": "app", "revertId": "…", "rowsHash": "<hex>", "expiresAt": "2026-11-11T07:02:11.123456Z", "requestedBy": "basalt_agent_bot"}
```

`rowsHash` = lowercase hex of `sha256(utf8(lines joined by "\n"))` over every line, `RESTORE` and `SKIP`, so the person signs both what is restored and what is left alone. **Challenge** = `sha256(utf8(binding text))`, as for approvals. A large plan's binding also has `"batched": true` and `"sampleHash"` (see [Large plans](#large-plans)); a one-call revert's binding has neither key.

| Payload | Carried as | JSON |
|---|---|---|
| Revert request | URL `<base>/reverts/<revertId>#2.<b64url(deflate-raw(json))>` ([Format 2](#format-2-the-compact-request)) | `[shapes, texts]`: the binding text, then the revert lines in order |
| Revert request, format 1 (read only) | URL `<base>/reverts/<revertId>#1.<b64url(deflate-raw(json))>` | `{ "revertId", "binding", "lines", "credentialIds" }`; the JSON the local pages serve at `GET /api/v1/reverts/{revertId}` |
| Revert response | Text `basalt-revert.1.<b64url(json)>` | `{ "revertId", "credentialId", "authenticatorData", "clientDataJson", "signature" }` |

The revert page checks `rowsHash` (or, for a large plan, `sampleHash`), refuses a binding whose `kind` is not `REVERT`, and shows restored rows (current and restored values) and skipped rows (reason) before asking for the passkey.

**Lines on tables with row-level security** (N12-8). On a table where RLS applies to the preparing role (RLS enabled, and the role neither has the owner's privileges nor `BYPASSRLS`), a line keeps its values only when it is a `RESTORE` line, not cascaded, and every change it names was made by the preparing role; any other line there is redacted as above.

### Large plans

N12. A revert with more than 1000 lines is a **batched plan**:

- `prepare_revert` stores every line in the plan, numbered `1..N` in execution order (the order the trial's writes succeeded, then the `SKIP` lines), and builds one binding over all of them: `rowsHash` over every line in signed order, as above, plus `batched: true` and `sampleHash`.
- **Sample:** the first 1000 lines with `SKIP` lines first, each group in signed order. `sampleHash` = lowercase hex `sha256(utf8(sample joined by "\n"))`. `prepare_revert` returns the sample as `lines`, and the revert request carries it; the page checks `sampleHash`, says how many of the plan's lines it shows and that the signature covers all of them.
- **Signature:** `apply_revert` with the person's code verifies it, opens the revert's change record, marks the `SKIP` lines skipped and records `REVERT_SIGNED`; it writes no row of the person's tables. The plan can then be applied for 24 hours, only by the role that prepared it.
- **Batches:** `apply_revert_batch` (MCP tool above) applies up to 200 pending lines of the plan. Each line runs at most once; a line whose row changed after the plan was built is skipped (people win). Every batch is one transaction with its `ROW_CHANGE` rows under the revert's change and a `REVERT_BATCH` ledger row; a failed batch leaves nothing, so the agent resumes from the pending lines.
- **Finish:** when no line is pending, the plan is `APPLIED`, a `REVERTED` ledger row is appended, and each covered change becomes `REVERTED` only if every line naming it was restored.

### Checks in Postgres

`apply_revert` runs the revert only if the assertion passes every `submit_approval` check with the challenge taken from this revert's binding, and the revert is neither expired nor applied. It then locks the rows, recomputes the lines for the preparing role, and refuses with `REVERT_INVALID` unless their `rowsHash` equals the signed one: a row changed after the preview fails the whole revert and nothing is written. Writes run as `<prefix>_guard` with all constraints immediate; a failure the trial did not predict aborts the revert. Failures are `BS005`. For a large plan `apply_revert` only records the signature; `apply_revert_batch` checks the caller, the signature state, the expiry and every line number, then re-checks each line against the signed text with its row locked.

## Page links

Owner decisions, Decided Nov 12. Every link is built from one pages base URL (`pagesUrl` in `engine.json`; one Go constant `links.HostedConsole` and one JS constant `HOSTED_CONSOLE` for the hosted console): the engine's local pages `http://localhost:8787` by default until hosting exists, or `https://console.basaltvault.app`. The paths are RESTful and the same on both:

| Page | Path |
|---|---|
| Approve a held write | `/approvals/<approvalId>` (long link: `#2.<request>` appended) |
| Sign a revert | `/reverts/<revertId>` (long link: `#2.<request>` appended) |
| Register a passkey | `/passkeys/register#1.<request>` |
| Check which passkeys a device has (M4.1) | `/passkeys/check#1.<request>` |
| Forget a removed passkey (M4.1) | `/passkeys/forget#1.<request>` |
| A run (reserved, later) | `/runs/<runId>` |

## Local pages

M4.1. The engine serves the approval and revert pages itself, so a held write reaches the person as a short link that works out of the box, and the page relays the signature without a pasted code. The signed data does not change: the page fetches the same request the long link carries, checks it the same way (binding, `rowsHash` or `sampleHash`), and the person signs the same binding; Postgres verifies the signature as before. The long-fragment links stay supported (hosted page, phone).

- **Listener.** `pagesAddr` in `engine.json`: a loopback `host:port`. Default: when the pages base URL is local (`http://localhost:<port>`, the default `http://localhost:8787`), `127.0.0.1:<port>`; for the hosted console, `off`. `"off"` disables it. A non-loopback address is refused when the config is loaded: this listener has no TLS or plaintext opt-in. If the port cannot be bound when the engine starts (another process holds it), the engine refuses to start, naming the address and how to find the process (`lsof -nP -iTCP:<port> -sTCP:LISTEN`); it never falls back to the long link silently. To run without the pages, set `pagesAddr` to `"off"`. The listener applies the `websec` Host check (loopback names only), Origin check and security headers.
- **Origin.** The page origin is the pages base URL (scheme, host, port), so the passkey's RP ID and origin are the ones it was registered with. Short links: `<base>/approvals/<approvalId>#s=<secret>` and `<base>/reverts/<revertId>#s=<secret>` (see [Link secrets](#link-secrets)).
- **Assets.** The files under `web/` are embedded in the binary (`go:embed`); to try an edit to a page, rebuild the binary and restart the engine.

| Method and path | What |
|---|---|
| `GET /healthz` | `200 ok`; the CLI's probe |
| `GET /approvals/{approvalId}`, `GET /reverts/{revertId}` | The approval or revert page. A fragment `#1.<request>` is the long link: the page reads the request from it and checks its id equals the path's. A fragment `#s=<secret>` is the short link: the page reads the request from the engine, sending the secret in the `basalt-link-secret` header |
| `GET /passkeys/register` | The registration page (`basalt init`'s link) |
| `GET /passkeys/check`, `GET /passkeys/forget` | The passkey management page (M4.1, [Passkey management](#passkey-management)); it reads its request from the fragment and refuses one whose mode is not its path's |
| `GET /lib/*.js`, `GET /style.css` | The pages' scripts and style; nothing else under `web/` is served |
| `GET /api/v1/approvals/{approvalId}` | The approval request, the JSON the long link carries: [`approval-request.schema.json`](api/mcp/approval/approval-request.schema.json). Needs the link's secret |
| `POST /api/v1/approvals/{approvalId}/approve` | Relay. Body: [`approval-response.schema.json`](api/mcp/approval/approval-response.schema.json), its `approvalId` equal to the path's. The engine calls `submit_approval` with the credential of the agent that holds the write. `200 { "approvalId", "status": "APPROVED" }`. Needs the link's secret |
| `GET /api/v1/reverts/{revertId}` | The revert request: [`revert-request.schema.json`](api/mcp/revert/revert-request.schema.json). Needs the link's secret |
| `POST /api/v1/reverts/{revertId}/apply` | Relay. Body: [`revert-response.schema.json`](api/mcp/revert/revert-response.schema.json). The engine calls `apply_revert` with the credential of the agent whose role prepared it. `200` with the result `basalt revert --apply --json` prints. Needs the link's secret |
| `POST /api/v1/approvals/{approvalId}/links`, `POST /api/v1/reverts/{revertId}/links` | Issue a short link for the CLI (`basalt approve --show`/`--open`, `basalt revert`). Body `{ "proof" }`, see [Link secrets](#link-secrets). `200 { "url" }` with a new secret; the item's earlier link stops working |

- **Which agent.** The engine looks the id up with each configured agent's credential (the ledger views show a role only its own approvals and reverts) and acts with the one that finds it. When none does: `404`. The secret is checked before the lookup, so a missing or wrong secret is answered the same as an unknown id.
- **Errors.** JSON `{ "code", "message" }` with a code from [Error codes](#error-codes): `NOT_FOUND` 404; `APPROVAL_EXPIRED` or `REVERT_EXPIRED` 410; `APPROVAL_INVALID` or `REVERT_INVALID` 409 (already used, already signed, or refused by Postgres, with its detail); `INVALID_ARGUMENT` 400 (a bad id or body, or ids that differ); 415 for a body that is not `application/json`; 413 over 16 KiB; 403 for a missing or foreign `Origin`. Planned ([Next steps](#next-steps)): the body also carries `personMessage` and the `PERSON` steps of the code's entry, which the page shows; a link without its secret or replaced is `NOT_FOUND` reason `LINK`.
- **CSRF.** A `POST` must carry an `Origin` equal to the page origin and `Content-Type: application/json`. The listener sends no CORS headers, so another site's page can neither read a preview nor make a JSON post. The relay only carries a signature: Postgres refuses anything the person's passkey did not sign.
- **Who can read a preview.** Only a holder of the short link (its secret), or of the long link, which carries the preview itself. The id alone is not enough: ids appear in tool results, logs and the CLI.
- **The page.** It shows the same review as the long link. After the passkey signs, it posts the response and shows "Approved. The agent will continue." (approval) or the revert result. If the relay fails, it shows the error and the code to paste into `basalt approve` or `basalt revert --apply`.

### Link secrets

Owner decisions, Decided Nov 12: short links carry a per-link secret.

- **The secret.** 16 random bytes (128 bits), base64url without padding (22 characters), in the fragment: `<base>/approvals/<approvalId>#s=<secret>`. The fragment is never sent in an HTTP request, so the secret stays out of server and proxy logs and `Referer`; the page reads it from `location.hash` and sends it to the same-origin API in the `basalt-link-secret` header. A custom header also makes any cross-origin request need a CORS preflight, which this listener never grants.
- **Storage.** The engine keeps only `sha256(secret)` per held item, with the item's expiry (an approval after 24 hours, a revert after its hour), per agent in `<stateDir>/<agent>.links.json`: mode `0600`, owned by the engine's OS user, written atomically on every change and pruned of expired items. Short links survive an engine restart. It compares in constant time. A file it cannot read is logged and replaced: those links stop working and are issued again as below.
- **One live link per item.** Issuing a link for an item revokes its earlier one. Links are issued by: `write` when it holds a write (`approvalUrl`); `revert_plan` while the plan is `PENDING`; `request_revert` when it prepares a revert, and in its wait form only with `reissueLink: true`; `list_pending` only when called with `reissueLink: true` (then every item it returns gets a new link and the old one stops working; the agent hands the person the new one); the CLI through `POST …/links`, for `basalt revert` (a freshly prepared revert has no link yet) and for `basalt approve --show`/`--open` only with `--reissue`. Without `reissueLink`, `list_pending` touches no link: `approvalUrl` is the long link and `personMessage` points back to the link already given. A waiting `write` that times out issues none and returns the hold's own answer, with the link it issued.
- **Issuing for the CLI.** `POST /api/v1/approvals/{approvalId}/links` (and `/reverts/{revertId}/links`) with `{ "proof": "<hex>" }`, where `proof` = lowercase hex of `sha256(utf8("basalt-link.1\n" + binding text))`. Only a holder of the binding text can issue: a role that can read the item in `basalt_meta` (the CLI with the agent credential) or a holder of the long link, both of whom can already see the whole preview. The proof is not derivable from a signed response (whose challenge is `sha256(binding text)`). No `Origin` or a page-origin `Origin`, `Content-Type: application/json`; a wrong proof is answered as an unknown id.
- **Refusals.** A missing or wrong secret, or a link revoked by a newer one, gets `404 NOT_FOUND` with the same body as an unknown id, on both the request and the relay. The page then says the link is incomplete or replaced and how to get a new one (`list_pending`, `basalt approve --open`).
- **Not affected.** The long-fragment links (`#2.<request>`, or `#1.` before it; the hosted form and Telegram's button) carry the preview themselves and need no secret. The passkey pages, `/passkeys/register#1.<request>`, `/passkeys/check#1.<request>` and `/passkeys/forget#1.<request>`, are static: their whole request travels in the fragment, so the link is already the bearer of everything the page shows, and the engine has no data or relay endpoint for them to gate. They carry no `#s=` secret. A passkey page that ever reads from or posts to the engine gets a short link with a secret and gates its routes as above.
- **Over the Vault (M3.5).** On the portal the same short link opens an end-to-end encrypted session through the Vault: the engine also keeps the link's `linkToken` and `psk`, derived from the secret, and the secret travels only inside the session ([Vault channel](#vault-channel)).
- **Telegram.** The message text also carries the short secret link when the engine serves the pages (it works on the engine's machine only); the button keeps the long link.

### Handing a held action to the person

Every result that names a held action gives the agent what to show the person, so the person needs nothing else: `APPROVAL_REQUIRED` (`write`) and `list_pending` items carry `headline`, `approvalUrl`, `approveCommand` and `personMessage` (above). `revert_plan` for a plan not yet signed (`status` `PENDING`) carries `revertUrl` (the short link when the pages are served, else the long link) and `personMessage`; so does `request_revert` when it prepares a revert, or reissues its link. An agent that lost a link calls `list_pending` again (for a revert, `request_revert` with `revertId` and `reissueLink: true`).

## Showing links

Planned (M3.5, Vault channel Phase 0, owner decision VC-7; design [`docs/redesign/specs/2026-11-12-vault-channel.md`](docs/redesign/specs/2026-11-12-vault-channel.md), section 3). Long links rarely fail on a hard length limit. They fail because chat and terminal clients format them: they hard-wrap the line, stop link detection at a line break, take a trailing `.` or `)` into the URL, or read `_` and `*` as emphasis. These rules keep a link whole from the engine to the person's browser. They apply to every link the engine, the CLI or a page hands over: approval, revert and passkey pages, short or long.

Terms: a **short link** carries `#s=<secret>` ([Link secrets](#link-secrets)); a **long link** carries the whole request, `#1.<request>` or `#2.<request>` ([Codes](#codes)). Format `2.` is the compact request encoding (design section 3.2, item 1), laid out in [Format 2](#format-2-the-compact-request) (owner decision VC-29). The pages read both `1.` and `2.`; the engine emits `2.`.

### The link budget

- **`linkBudget`** in `engine.json`: the longest long link, in characters of the whole URL (base, path and fragment; every link is ASCII), the engine hands an agent as the way to open a page. A positive integer with no other minimum; default **1800** (owner decision VC-30). A value that is not a positive integer is refused when the config is loaded.
- **Short links are never measured.** They are about 110 characters plus the base, so they are always the first choice when one exists.
- **What the engine hands over** for a held write or a revert, in this order:
  1. A short link, when one exists: the engine's [local pages](#local-pages), or the portal's short link over the Vault (Phase 1a).
  2. Else the long link, when it is at most `linkBudget` characters.
  3. Else the long link is **over budget** and is not the main path. The fallback is the request file or pasted text of the chat-only operator design (#182, section 8.3, options B and C), which gets its own contract change. Until it lands, the engine still hands over the long link, because nothing else opens the page, but `personMessage` first says the link is long and may arrive cut or broken, gives the `basalt` command when the result has one (`approveCommand`), and then the link. This is a deliberate, interim deviation from the design (section 3.2, item 2, which says the long link is not handed over above the budget), owner decision VC-28; it ends when the fallback's contract lands.
- **Fields stay as they are.** `approvalUrl`, `revertUrl` and a step's `url` carry whichever link the engine handed over (short, long, or over budget); no field is added for the budget. Revert links almost always go over: a revert carries up to 1000 lines.
- **Only MCP results are budgeted.** The CLI prints the link it has (with `--open` it opens it instead), and the pages show what they are given.
- **Telegram.** The notification is not budgeted either: its button keeps the long link whatever its length (Telegram limits only the message text), and its text follows the hand-over order above.

### Links in `personMessage`

Every `personMessage` follows these rules. They replace "one plain line" in [Next steps](#next-steps).

- **Lines.** Plain text in lines separated by `\n` (never `\r`).
- **Each URL is a paragraph of its own.** Its line holds the URL and nothing else: no label, no leading or trailing space, and nothing after it (no `.`, `,`, `;`, `:`, `)`, `>`, quote or backtick). The line before it and the line after it, when there is one, are empty. So the URL ends at the end of its line in plain text, and stands alone in Markdown.
- **No Markdown.** The engine never writes `[label](url)`, `<url>`, a code span or emphasis around a URL, and never escapes characters in it. A client that renders Markdown uses `links` (below).
- **Length.** At most 500 characters, not counting URL lines (the URL and its line break). URLs are bounded by the link budget, not by this limit. JSON Schema cannot express this, so the schemas carry no `maxLength` for `personMessage`; an engine test checks every message the engine builds (with the engine change that applies the budget).
- **`links`.** Next to every `personMessage`, and present exactly when that `personMessage` holds a URL: an array of `{ "label", "url" }` ([`link.schema.json`](api/mcp/links/link.schema.json)), one entry per URL in the order they appear, each `url` byte for byte the URL in `personMessage`. `url` follows the URL rule of [Terminal hyperlinks](#terminal-hyperlinks): `https`, or `http` for a loopback host, and only RFC 3986 characters. `label` says what opening the link does, in plain text of 1 to 80 characters with no URL, no control character (C0, DEL or C1, U+0080 to U+009F), no line break, no bidirectional control (U+202A to U+202E, U+2066 to U+2069), and none of `[`, `]`, `(`, `)`, `<`, `>`, `` ` ``, `*`, `_` (`Approve the held write`, `Review and sign the revert`). A client that renders Markdown may show `[label](url)`.

For example (`\n` shown as line breaks):

```text
Held for your approval: Update 27 rows in basalt_demo.leads.
Approve it with your passkey here:

http://localhost:8787/approvals/0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b#s=q3Jv8sLk2mT0xYp1aBcD9w

Or run: basalt approve --agent demo_bot --open 0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b
Expires 2026-11-12 07:02 UTC.
```

with `links: [{ "label": "Approve the held write", "url": "http://localhost:8787/approvals/0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b#s=q3Jv8sLk2mT0xYp1aBcD9w" }]`.

A `PERSON` step's `url` is shown under the same rules: on its own line, unchanged.

### What the agent is told

The engine's MCP `initialize` result carries, in its `instructions`, this text unchanged:

> When you show the person a link from Basalt, put it on its own line exactly as Basalt gave it, or as a Markdown link [label](url) with the label from links. Never put a link in a code block or inline code, never split, wrap, shorten, encode or rewrite it, and put nothing after it on its line. Show personMessage verbatim and keep its line breaks.

The tool descriptions say the same where they mention `personMessage`.

### The pages repair what they can

Before decoding, the approval, revert and passkey pages repair the fragment (`location.hash`):

1. Take the text after the first `#`.
2. Remove every `%20`, `%09`, `%0A` and `%0D` (hex digits in either case).
3. Remove every whitespace character (Unicode `White_Space`: spaces, tabs, line breaks, U+00A0, U+2028 and the rest; in JavaScript `/\p{White_Space}/u`, not `\s`, which differs) and every `>`, `*` and `\`.
4. When the text starts with `1.` or `2.`, keep that prefix and the base64url characters (`A` to `Z`, `a` to `z`, `0` to `9`, `-`, `_`) right after it, up to the first other character; drop the rest (a trailing `.`, `)`, quote or text). When it starts with `s=`, keep `s=` and the 22 characters after it when all 22 are base64url. Anything else is left as it is and fails to decode.

`_` and `-` are never removed: they are base64url. Repair never makes a wrong request pass: the page still checks the request's id against the path and `rowsHash` (or `sampleHash`) against the binding, and refuses to sign otherwise.

When the repaired fragment still does not decode, or is missing, the page shows a box, "Paste the whole message from your agent", and reads the link out of the pasted text:

1. Split the text into lines (`\r\n`, `\n`, `\r` or U+2028). In each line remove every `>`, `*` and `\`, then trim leading and trailing `White_Space`.
2. Find the first line holding `#1.`, `#2.` or `#s=`. Take the prefix and the base64url characters right after it on that line.
3. When they reach the end of the line, append each following line while it is not empty and holds only base64url characters; stop at the first line that does not. A short link stops at 22 characters.
4. Decode the result as a repaired fragment (above). The empty line the engine puts after every URL is what ends a wrapped link.

**Only the fragment is taken from the paste.** The page keeps its own origin and path: it uses the pasted text only for the fragment, ignores the scheme, host and path in front of it, never navigates to a pasted URL and never fetches from one. For a long link the decoded request must still carry the id of the page's own path. A short link (`s=`) carries no request and no id: the page sends the pasted secret with its own path's id, and the engine checks the secret against that id, so a secret pasted from another item's link is answered `NOT_FOUND`, as a wrong secret is.

This covers terminal clients that hard-wrap and indent a long link: the person copies the whole block. Shared cases in [`api/mcp/links/link-repair.json`](api/mcp/links/link-repair.json) pin each rule (`fragments`: a fragment and its repair; `pastes`: a pasted message and the fragment read from it, or `null` when there is none); the contract test checks them against these rules, and the pages' tests run them.

### Terminal hyperlinks

The CLI prints every link on its own line, with nothing else on it.

- **The URL rule.** Every link the CLI prints, and every pages base it builds one from, is `https://` followed only by RFC 3986 characters (`A` to `Z`, `a` to `z`, `0` to `9` and `-._~:/?#[]@!$&'()*+,;=%`), or `http://` for a loopback host (`localhost`, `127.0.0.1`, `[::1]`) followed by an optional port and the same characters. [`link.schema.json`](api/mcp/links/link.schema.json) carries the same rule as `url`'s pattern. Every byte of such a URL is between `0x21` and `0x7E`.
- **Bases are checked when read.** `pagesUrl` in `engine.json` and `--pages-url` must follow the URL rule, with no query or fragment. A config that breaks it is refused when it is loaded, and a flag that breaks it is a usage error (exit `2`). Either way the message names the setting and the first bad character's position, never echoes the raw byte, and says what to do: set it to an `https://` URL, or `http://localhost:<port>`, of printable characters.
- **Never a control byte on a terminal (refuse, not escape).** The CLI never writes a byte below `0x20` or between `0x7F` and `0x9F` (as a byte or as the UTF-8 encoding of U+0080 to U+009F) to a terminal as part of a link. A URL that breaks the URL rule anyway (from an older config, or from the database) is not printed: the CLI exits `1` with the same message, naming the item's id and the command to print its link again after the fix. The CLI's tests cover this: a base with `ESC`, `BEL`, `\n`, `0x7F` and U+009B in it is refused at load and at `--pages-url`, and a URL that breaks the rule at print time writes no part of the URL and no control byte to the terminal.
- **Hyperlinks.** When stdout is a terminal (and `TERM` is not `dumb`), the CLI prints the link as an OSC 8 hyperlink whose visible text is the whole URL: `ESC ] 8 ; ; <url> ESC \` `<url>` `ESC ] 8 ; ; ESC \`. The URL rule keeps the URL from ending the escape sequence or starting another. A terminal that supports OSC 8 makes the whole link clickable however it wraps; one that does not shows the plain URL. Otherwise (a pipe, a file, `--json`), the plain URL.

## Vault channel

Planned (M3.5, Vault channel Phase 1a; owner decisions VC-1 to VC-31, provisional details VC-32 to VC-42; design [`docs/redesign/specs/2026-11-12-vault-channel.md`](docs/redesign/specs/2026-11-12-vault-channel.md), sections 4 to 6, 8 and 9). An engine with no inbound port reaches the person's browser through the hosted Vault (`relay.basaltvault.app`, VC-20). The engine dials out, the portal page dials in, and the two run an end-to-end encrypted session keyed by the short link's secret, inside which the page speaks the same pages API the engine serves on loopback. The Vault pairs sockets and forwards opaque bytes.

**The Vault is untrusted.** Neither the engine nor the page depends on it being honest. A Vault that drops, delays, duplicates, reorders, replays, truncates, reflects or alters any message can make a session fail, never make either side accept something. It never holds a key that opens a session (VC-4). The Vault service is closed source (VC-13, VC-18): this section is the whole protocol it must speak, and its internals (hosting, storage, its own rate numbers) are not part of the contract. Schemas, the close-code registry and the vector format: [`api/mcp/vault/`](api/mcp/vault/).

**Scope (VC-1, VC-17).** Link sessions only, for the approval and revert pages. Pairing, box keys in use, envelopes, device codes, the pending list, notifications and accounts are after M4 (their contract is VC2-1's). The direct transport (`DIRECT`, M4.1) runs this same session over the person's own tunnel; its route, the pinned engine address and revocation of an engine in `basalt_meta` are VCT-1's contract ([Direct transport](#direct-transport-reserved)).

**The exception (VC-1).** "No hosted service before M4" has one narrow exception: this rendezvous. It stores no plaintext, no credentials and no ledger, has no accounts, and approvals work when it is down (long links, below).

### Primitives and encodings

- **Algorithms (VC-5).** P-256 (ECDH and ECDSA), SHA-256, HMAC-SHA-256, HKDF-SHA-256 (RFC 5869) and AES-256-GCM: all in WebCrypto and in Go's standard library (`crypto/ecdh`, `crypto/ecdsa`, `crypto/hkdf`, `crypto/hmac`, `crypto/cipher`). No third-party crypto in the engine or the pages, and no primitive of our own: the handshake is a Noise pattern and every other step is a signature, an HKDF or an AEAD call.
- **Public keys.** In a handshake message: the 65-byte uncompressed SEC1 point (`0x04 ‖ X ‖ Y`). As an identity: the 91-byte DER SubjectPublicKeyInfo (`id-ecPublicKey`, `prime256v1`, uncompressed point), base64url without padding (122 characters). Any other encoding (a compressed point, explicit curve parameters, trailing bytes) and any point not on the curve is refused.
- **ECDH output** is the 32-byte x-coordinate (WebCrypto `deriveBits` with 256 bits; Go `ecdh.PrivateKey.ECDH`).
- **Signatures** are ECDSA P-256 with SHA-256, encoded as 64 bytes `r ‖ s` (IEEE P1363, WebCrypto's form; Go converts from ASN.1), base64url without padding (86 characters). A verifier refuses any other length. A high-S signature (`s` above half the group order) is **accepted**: verifiers use plain ECDSA verification (WebCrypto `verify`, Go `ecdsa.Verify`), which accepts both `s` and `n − s`, and nothing uses a signature's bytes as an identifier, so the second form gains nothing.
- **Bytes** in JSON are base64url without padding unless a field says otherwise; in test vectors, lowercase hex.
- **Signing contexts.** The engine's signing key signs only these, each input starting with its context line, so no signature made for one can be used as another (VC-37, provisional). A new context is a contract change.

| Context line | Signed by | Over |
|---|---|---|
| `basalt-vault-engine.1\n` | Engine signing key | The Vault's challenge and the engine's Vault host ([engine socket](#the-engines-socket-to-the-vault)) |
| `basalt-vault-session-sig.1\n` | Engine signing key | The handshake hash `h` after `e, ee` ([Handshake](#handshake)) |
| `basalt-receipt.1\n` | Engine signing key | A receipt's payload bytes ([Receipts](#receipts)) |
| `basalt-engine-box-key.1\n` | Engine signing key | The engine id and the box key's public key |
| `basalt-engine-rotate.1\n` | The previous signing key | The new keys ([Engine keys](#engine-keys), rotation) |

### Engine keys

- **Two keys (VC-5).** A **signing key** (ECDSA P-256) and a **box key** (ECDH P-256, used from Phase 1b; made now so the key file keeps its shape). Neither does the other's job. The box key's public key is signed by the signing key (`basalt-engine-box-key.1\n` + `engineId` + `\n` + the box key's SPKI as its base64url text, as `channel.json` holds it).
- **Engine id** = base64url of the first 16 bytes of `sha256(signing key SPKI DER)`: 22 characters. It is self-certifying (anyone holding the key can check it; nobody can claim another engine's id) and a key fingerprint, not a UUIDv7. **Shown to people** as its first 16 characters in four groups of four, separated by spaces (`AbCd EfGh IjKl MnOp`), next to the agent name: in `status`, `basalt status`, and on every portal page with a session, so the person can compare.
- **When made (VC-36, provisional).** On the engine's first start, whatever `vault` says: receipts need the signing key on every path, the local pages and the CLI included. A missing file is created.
- **Storage.** `<stateDir>/channel.json` ([`channel-key-file.schema.json`](api/mcp/vault/channel-key-file.schema.json)): mode `0600`, owned by the engine's OS user (as `<agent>.links.json` and the credential file), written atomically (a temporary file in the same directory, `fsync`, rename). Private keys are PKCS#8 DER. No key material goes anywhere else: not to logs, `engine.json`, `status`, the ledger or the Vault. No OS keychain (as M51-1).
- **Refused, never replaced (VC-36).** A key file that grants group or other access, is owned by another user, cannot be read, fails its schema, whose `engineId` is not its signing key's or whose `boxKeySig` does not verify is left as it is. The engine then serves MCP and the local pages as usual, does not connect to the Vault, hands over long links instead of portal short links, signs no receipt (the result says why), and `status` reports `vault.state` `KEY_ERROR`. The fix is to correct the file's owner and mode, or `basalt engine rotate-key`. (The links file is replaced instead, because a new link costs nothing; new keys change the engine id the person may have compared, and from M4.1 pinned.)
- **Who can read it.** Whoever can read the agent's credential file: in same-user mode (`GUARD_ONLY`) and with `operatedBy` `AGENT`, the agent. A leaked key lets its holder pose as the engine to the Vault and sign receipts in its name. It reads no session without that session's link secret and approves nothing: only the person's passkey signs, and Postgres verifies it.
- **Rotation (VC-40, provisional).** `basalt engine rotate-key [--config PATH] [--yes]` makes both keys again (a new engine id). When the old file is valid, it signs `basalt-engine-rotate.1\n` + old `engineId` + `\n` + new signing key SPKI + `\n` + new box key SPKI + `\n` + `at` (each SPKI as its base64url text) with the old key and keeps it as `rotatedFrom` (the latest rotation only; the old private key is deleted). Then it revokes every outstanding short link of every agent (their `psk` sat next to the old key), unregisters their tokens, closes open sessions with `ENGINE_SHUTDOWN` and reconnects under the new id. An agent gets new links with `list_pending` and `reissueLink: true`. Rotation is never automatic. A `KEY_ERROR` file is rotated without a statement.
  - `rotatedFrom` proves only that whoever held the old key agreed to the new one. After a leak the thief holds the old key too and can sign a statement of their own, so a Phase 1b device must not trust a new key on `rotatedFrom` alone: it also needs the person's own check (the fingerprint `status` shows) and, from M4.1, the engine key recorded in `basalt_meta` and not revoked.
  - The old key is not dead at the Vault: whoever holds it can still authenticate as the old engine id until the person revokes that key in `basalt_meta` (M4.1). That gives them the old id's routing only: the old id's links were revoked, and no new link uses it.
- **Revocation by the person (M4.1, VC-21).** Recording the engine key in `basalt_meta`, and its revocation, are VCT-1's contract. This contract fixes the engine's side: an engine that finds its key revoked closes every session with `ENGINE_REVOKED`, unregisters its links, leaves the Vault, and reports it in `status`.

### Link secrets in a session

The short link is unchanged ([Link secrets](#link-secrets)): `https://portal.basaltvault.app/approvals/<approvalId>#s=<secret>` and `…/reverts/<revertId>#s=<secret>`. The page tells the transport by its own origin: same-origin `fetch` on the engine's local pages, the Vault on the portal (VC-25: the portal never calls `localhost`). With `s` the 16 bytes the 22-character secret decodes to (VC-9):

- `linkToken` = HKDF-SHA-256(ikm `s`, salt empty, info `basalt-vault-link.1`, 16 bytes), base64url: 22 characters. The Vault's routing key for the link.
- `psk` = HKDF-SHA-256(ikm `s`, salt empty, info `basalt-vault-psk.1`, 32 bytes): the session's pre-shared key.

Neither reveals `s` and neither gives the other. The engine keeps `linkToken` and `psk` per item in `<agent>.links.json` next to `sha256(secret)`, with the same expiry, the same one-live-link rule, and constant-time comparison. The page derives both from `location.hash` and never sends `s` or `psk` to the Vault: the socket path carries `linkToken` only, and the secret itself travels only inside the encrypted session, as `basalt-link-secret`.

### Handshake

`Noise_NNpsk0_P256_AESGCM_SHA256`, from the Noise Protocol Framework (revision 34), with an engine signature in the second payload (VC-32, provisional; design 6.1). The page is the initiator, the engine the responder.

- **Functions.** `DH`: P-256. Noise's `DHLEN` is the length of both a public key and a DH output; here they differ: an `e` token writes, reads and hashes the 65-byte uncompressed point, and `DH` returns the 32-byte x-coordinate (both meet Noise's minimum of 32). `HASH`: SHA-256. `HKDF`: Noise's (HMAC-SHA-256; the same as RFC 5869 with empty info, and implemented with HMAC so a zero-length input key works in WebCrypto). Cipher: AES-256-GCM with Noise's nonce, 4 zero bytes followed by the 64-bit big-endian counter. The protocol name is 31 bytes, so `h` starts as the name padded with zero bytes to 32, and `ck` = `h`. Because the pattern has a `psk` token (Noise section 9.2), every `e` token is followed by `MixKey(e.public_key)` as well as `MixHash(e.public_key)`, on both sides and for both ephemeral keys. A Noise message, which here is everything after a message's 2-byte header (and, in message 1, the 16-byte `linkToken`), is at most 65 535 bytes.
- **Prologue** = UTF-8 of `basalt-vault-prologue.1\n` + transport (`RELAY` or `DIRECT`) + `\n` + `linkToken` as its 22-character base64url text (not the raw bytes), with nothing after it. Each side builds it from what it knows itself (the page from its transport and its link; the engine from the socket the session came on and the token it looked up), so a session moved to another link or transport fails.
- **Message 1, page to engine** (`psk, e`): exactly 99 bytes, `0x01` (version) ‖ `0x01` (type `HELLO`) ‖ `linkToken` (16 raw bytes) ‖ `e` (65 bytes) ‖ `EncryptAndHash` of the empty payload (the 16-byte tag). The payload is always zero bytes: `EncryptAndHash` of it is the tag alone, and the fixed length refuses anything else. `linkToken` travels here as its 16 raw bytes. With `psk0`, that tag is under a key derived from `psk`: the page proves it holds the link before the engine does any public-key work.
- **The engine on message 1**, in order: the version byte (`UNSUPPORTED_VERSION`), then the type and the exact length (`PROTOCOL`); look `linkToken` up (on `RELAY` it must equal `SESSION_OPEN`'s); the [limits](#limits); check the tag (the `e` token hashes and mixes the 65 bytes as they are, so this needs no point arithmetic); only then check `e` is a valid point. A token it does not hold, a link expired or revoked, a different `SESSION_OPEN` token, a failing tag and an invalid point all close with `LINK_REFUSED`, alike, as a wrong secret answers today, so a probe cannot tell a live token from a dead one by the answer.
- **Message 2, engine to page** (`e, ee`): `0x01` ‖ `0x02` (type `WELCOME`) ‖ `e` (65 bytes) ‖ `EncryptAndHash` of the payload, at most 1 024 bytes in all. The payload is UTF-8 JSON, [`handshake-payload.schema.json`](api/mcp/vault/handshake-payload.schema.json): `{ "engineKey": <SPKI, base64url>, "sig": <base64url> }`, where `sig` signs `basalt-vault-session-sig.1\n` followed by the 32 raw bytes of `h` after the `e` and `ee` tokens (before the payload is hashed in).
- **The page on message 2.** Check the version byte (`UNSUPPORTED_VERSION`), the type (`PROTOCOL`) and the size (`TOO_LARGE`), then that `e` is a valid point, decrypt, parse the closed schema, verify `sig` over the same `h` with `engineKey`, and compute the engine id from `engineKey`. On `DIRECT`, compare it with the pinned key (VCT-1). Any failure closes with `HANDSHAKE_FAILED` and shows nothing from the engine.
- **Engine identity on `RELAY` is not pinned (VC-42, provisional).** The link carries no engine id and the page keeps nothing between sessions, so on `RELAY` the page accepts whatever key a holder of the link's `psk` signs with. The engine's identity there is trust on first use, checked only by the person comparing the fingerprint the page shows with the one `status`, `basalt status` or the agent's earlier messages gave. Only someone who holds the link secret (the engine itself, or whoever saw the link) and gets the Vault to route the token to their own engine (a malicious Vault, or the registration race in [The engine's socket to the Vault](#the-engines-socket-to-the-vault)) can present another key. What that gains them: a fake fingerprint on the page, fake receipts in the page, and denial of service (taking the person's signature and not relaying it). Not a forged approval: the page builds the binding from the rows it shows and checks `rowsHash`, and Postgres accepts a signature only over a real pending item's binding, so the most such an engine can obtain is the person's signature over the real item they were shown, which approves only that item. Reading the preview is no gain: the link already lets its holder read it. On `DIRECT` the key is pinned (VCT-1).
- **Split.** `Split()` gives `k1` (page to engine) and `k2` (engine to page), each with its own counter from 0. Both sides erase the ephemeral private keys and `ck`. The final `h` may be logged as the session id; keys never are.

What this gives against the Vault and anyone on the path:

- **Confidentiality and integrity.** Every key depends on `psk` (from the link secret, which the Vault never sees) and on the ephemeral-ephemeral DH. The Vault cannot read or change a session or pretend to be either side.
- **Authentication by the link.** Only holders of `s` (the engine that issued the link, and whoever holds the link) can make message 1's tag or a message 2 the page accepts. The signature binds the session to the engine's identity key, for the fingerprint on the page, receipts and `DIRECT` pinning; on `RELAY` nothing but the person's comparison checks that key (above).
- **Transcript binding.** `h` covers the prologue (version, transport, `linkToken`), both ephemeral keys and both payloads; the signature covers `h`; `Split` derives from the whole chain.
- **Forward secrecy.** A later leak of the link secret, the links file or the engine's key does not open a recorded session.
- **Replay.** A replayed message 1 meets a fresh engine ephemeral key and leads nowhere: the replayer lacks the page's ephemeral private key, so it can neither read message 2 nor send a frame. A replayed message 2 fails against the page's fresh key. Within a session, implicit counters refuse replays ([Frames](#frames)); across sessions, Postgres refuses a used approval or revert ([Replay and expiry](#replay-and-expiry)).

### Frames

After the handshake, every binary WebSocket message either way is one frame: `0x01` (version) ‖ `0x03` (type `FRAME`) ‖ AES-256-GCM ciphertext, made with Noise's `EncryptWithAd` under the direction's key and counter, with the two header bytes as associated data (VC-33, provisional). The nonce is the receiver's own count, never sent, so a frame dropped, repeated, reordered, reflected to its sender or taken from another session does not decrypt: the receiver closes with `FRAME_INVALID` and drops the session. There is no rekey; the limits end a session long before a counter could wrap. A text message, or a binary message with another header, closes with `PROTOCOL` (an unknown version with `UNSUPPORTED_VERSION`). A receiver checks a frame in this order: its size ([limits](#limits)), the version byte, the type, then decrypts and unpads.

**Padding (VC-34, provisional; design 6.2).** The plaintext is `len` (4 bytes, big-endian) ‖ content (`len` bytes) ‖ zero bytes up to `max(1024, the next power of two ≥ 4 + len)` bytes, at most 32 768 (content at most 32 764 bytes per frame, so every Noise message stays under Noise's 65 535-byte limit). A receiver refuses (`FRAME_INVALID`) a plaintext of any other size for its `len`, or with a non-zero padding byte. Sizes on the wire are then 1 024, 2 048, … 32 768 bytes plus 18: one frame leaks a bucket, not a row count. What a whole session still leaks is in [What the Vault sees](#what-the-vault-sees).

**Content** is UTF-8 JSON, one of [`frame-message.schema.json`](api/mcp/vault/frame-message.schema.json):

- `REQUEST`, page to engine: `{ "type", "id", "method", "path", "headers", "body", "more" }`.
- `RESPONSE`, engine to page: `{ "type", "id", "status", "headers", "body", "more" }`.
- `CONTINUE`, either way: `{ "type", "id", "body", "more" }`, the next piece of a body.

`body` is text (the pages API speaks JSON). A body too large for one frame continues in `CONTINUE` frames, appended in order up to the one with `more: false`. A message is acted on only once that frame arrives, so a truncated message is never used: the page times out and shows nothing. `id` is 1 for a session's first request and one more for each next one; a response and its continuations carry the request's `id`. One request is in flight at a time: a `REQUEST` before the previous response ended closes with `PROTOCOL`.

**Requests.**

- **Routes.** Only these are dispatched; any other method or path is answered `404 NOT_FOUND` with the same body as an unknown id:
  - `GET /api/v1/approvals/{approvalId}` and `POST /api/v1/approvals/{approvalId}/approve`;
  - `GET /api/v1/reverts/{revertId}` and `POST /api/v1/reverts/{revertId}/apply`;
  - reserved, each when its own contract lands: the passkey check and forget routes (a passkey page that reads from the engine gets a short link, [Link secrets](#link-secrets)), and after M4 (VC-27) `GET /api/v1/setups/{setupId}` and `POST /api/v1/setups/{setupId}/done`.

  Never the `…/links` issuing routes, `/healthz`, the pages or their scripts.
- **One item per session.** The path's id must be the item of the session's link, and `basalt-link-secret` must be that link's secret (its `sha256` and its `linkToken` both match). Otherwise `404 NOT_FOUND`.
- **Headers**, lowercase. A request carries `basalt-link-secret` and `origin` (`https://portal.basaltvault.app`), and on `POST` `content-type: application/json`. A response carries `content-type`. Any other header in a request is answered `400 INVALID_ARGUMENT`.
- **Dispatch.** The engine hands the request to the same handlers as on loopback, with the same checks, statuses and JSON bodies ([Local pages](#local-pages)): `NOT_FOUND` 404, `APPROVAL_EXPIRED` or `REVERT_EXPIRED` 410, `APPROVAL_INVALID` or `REVERT_INVALID` 409, `INVALID_ARGUMENT` 400, 413 over 16 KiB, 415, 403 for a wrong `origin`. The `approve` and `apply` responses also carry `receipt` ([Receipts](#receipts)).

### Receipts

A statement signed by the engine of what a relayed signature did (VC-22, mitigation 5; built in VC1-17; VC-38, provisional). Token: `basalt-receipt.1.<payload>.<sig>`.

- `payload`: base64url of UTF-8 JSON, [`receipt.schema.json`](api/mcp/vault/receipt.schema.json): `format` (1), `kind` (`APPROVAL` or `REVERT`), `itemId`, `status` (`APPROVED`; `APPLIED` or `APPLYING`), `headline`, `rowsHash` (the signed binding's, from Postgres's record, so the receipt names exactly the rows the passkey signed), `agent`, `engineId`, `at`, and `changeId` when there is one.
- `sig`: over `basalt-receipt.1\n` followed by the payload's decoded bytes. Signing exact bytes means no one needs canonical JSON.
- **Checking one needs an expected engine key from outside the receipt.** On `DIRECT`, the key pinned for that address; otherwise the engine the person already knows: the engine id or fingerprint `status` and `basalt status` report, or an earlier message of the same agent. The verifier checks the signature against that key, then parses the payload, then checks that `engineId` is that key's id and that the payload passes the closed schema; a receipt signed by any other key is refused. A receipt checked only against a key that came with it (the session's own `engineKey`, or a key the Vault or the agent hands over with it) proves only that whoever holds that key signed it, not which engine that is.
- **In the page, a receipt proves nothing beyond the session's own key.** The page can verify it only against the session's `engineKey`, which on `RELAY` is not pinned ([Handshake](#handshake)), and the page's code is what a compromised portal would change. So the page shows it with the fingerprint and asks the person to compare; the check that counts is the one in the chat, against the engine the person knows (VC1-17).
- `headline` is built from Postgres's record of the item, never from what the page sent, so a page that made the person sign another item than the one shown is caught when the receipt names the real one.
- **Where:** the relay responses (`receipt`, on loopback and in a session). In tool results (`write` with `approval`, `request_revert` with `signature`) it comes with VC1-17's own tool-schema change, with a `personMessage` the agent shows as it is.

### The engine's socket to the Vault

`wss://relay.basaltvault.app/v1/engines/<engineId>`, compiled into the binary (as the page origins are, CO-8). `vaultUrl` in `engine.json` overrides it for development and tests only, and only with a `ws://` URL on a loopback address (`127.0.0.1`, `[::1]` or `localhost`); anything else is refused when the config is loaded. The engine connects only when `vault` is `ON` and `pagesUrl` is the portal: a passkey with RP ID `localhost` cannot sign on the portal.

1. **Open**, with the header `basalt-engine-key: <signing key SPKI, base64url>`. The Vault refuses (`AUTH_FAILED`) a key that is not a valid P-256 SPKI or does not hash to the path's `engineId`.
2. **Challenge.** The Vault sends `CHALLENGE` with 32 random bytes: fresh per socket, single use, valid 30 seconds.
3. **Auth.** The engine answers `AUTH` with `version` 1 and `sig` over `basalt-vault-engine.1\n` + challenge (as sent, base64url) + `\n` + host, where host is the engine's own Vault host (`relay.basaltvault.app`, or the override's `host:port`), never one the Vault names. A bad or late answer: `AUTH_FAILED`.
4. **Ready.** The Vault sends `READY`. One live socket per engine id: a newer authenticated socket replaces the older, which is closed with `REPLACED`. After every `READY` the engine registers every live link again (registering is idempotent for the same engine), so a Vault that lost its state recovers.

Control messages are text messages, JSON per [`control-message.schema.json`](api/mcp/vault/control-message.schema.json), at most 4 KiB. Session bytes are binary `ROUTE` messages: `0x01` ‖ `0x10` (type `ROUTE`) ‖ `sid` (16 bytes) ‖ the page's message exactly as received, or the engine's message for the page.

| Message | Direction | Fields | Meaning |
|---|---|---|---|
| `REGISTER_LINK` | engine to Vault | `ref`, `linkToken`, `expiresAt` | Route page sockets for this token to me until `expiresAt` (at most 24 hours and 5 minutes ahead) |
| `UNREGISTER_LINK` | engine to Vault | `ref`, `linkToken` | Stop routing it, and close its page sockets with `LINK_UNKNOWN` |
| `OK` | Vault to engine | `ref` | Request `ref` succeeded |
| `ERROR` | Vault to engine | `ref` (when it answers one), `code` | `LINK_CONFLICT` (another engine registered the token), `LINK_LIMIT` (too many live links), `INVALID_EXPIRY`, `UNKNOWN_SESSION`, `RATE_LIMITED`, `PROTOCOL` |
| `SESSION_OPEN` | Vault to engine | `sid`, `linkToken` | A page connected for the token; its message 1 follows as a `ROUTE` |
| `SESSION_CLOSE` | either way | `sid`, `code` | The session ended (1000, or a [close code](#close-codes)); the Vault closes the page's socket with the same code |

`ref` is a positive integer the engine picks, unique among its requests waiting for an answer; `sid` is 16 random bytes the Vault picks per page socket (base64url in JSON). **No control message is trusted:** a forged `SESSION_OPEN` costs one refused handshake; a forged `OK` gives a link the page cannot reach (the person asks for the link again, which falls back if the Vault keeps failing); a forged `SESSION_CLOSE` or `ERROR` ends a session or a registration. None can open a session, read one or make the engine act on a request.

- **Reconnecting (VC-2).** Exponential backoff from 1 to 60 seconds with full jitter, reset after `READY`. A WebSocket ping every 30 seconds; no pong for 90 seconds closes and redials.
- **Registering a link (VC-15, design 6.5).** Before handing over a portal short link, the engine sends `REGISTER_LINK` and waits up to 5 seconds for `OK`. With no socket, an `ERROR` or no answer, it hands over the long link under the [link budget](#the-link-budget) rules instead, and the short link is not issued. `status` shows the socket's state.
- **A token belongs to one engine (VC-42, provisional).** The Vault binds each registered token to the engine id that registered it on an authenticated socket, and refuses (`LINK_CONFLICT`) a registration of a live token by any other engine id until the token's `expiresAt` or its `UNREGISTER_LINK`. It must keep that binding durably for the token's whole lifetime, across its own restarts and failovers. **Known limit:** if the Vault loses the binding anyway, an engine that also holds the link secret (someone who saw the link) could register the token first while the real engine reconnects. The impact is that of an unpinned `RELAY` identity ([Handshake](#handshake)): a fake fingerprint, fake receipts in the page, or denial of service, never a forged approval. Mitigations: the engine registers every live link at once after each `READY`; on `LINK_CONFLICT` for a link it holds, it revokes that link and logs it, so the item's next link (`list_pending` with `reissueLink: true`) has a new secret whose token nobody else knows; and the person compares the fingerprint.
- **Unregistering.** Reissuing a link unregisters the old token first; a link that expires or is revoked is unregistered then, and its open sessions are closed with `LINK_REFUSED`. The Vault also drops a token at its `expiresAt` by itself.

### The page's socket

`wss://relay.basaltvault.app/v1/links/<linkToken>`, opened by a portal page (the Vault refuses another `Origin` with `PROTOCOL`; a check against other sites' pages, not a security boundary). The Vault closes with `LINK_UNKNOWN` when no engine registered the token or it expired, and with `ENGINE_OFFLINE` when its engine has no socket. Otherwise it sends `SESSION_OPEN` to the engine and forwards every binary message both ways unchanged and in order, as `ROUTE` messages on the engine's side. A text message from the page closes with `PROTOCOL`. When one side ends, the Vault closes the other with the same code.

The page sends nothing but handshake message 1 and frames; it keeps no state between sessions (no storage in Phase 1a) and never holds a key past its session.

### Close codes

WebSocket close codes, with the name as the close reason. Registry: [`close-codes.json`](api/mcp/vault/close-codes.json), checked against this table by the contract test. A code that comes from the Vault only decides what the page shows; nothing else trusts it (VC-39, provisional). What the page shows: link gone (the link expired, was replaced or is incomplete, and how to get a new one, as the loopback `NOT_FOUND` reason `LINK`), engine offline (ask the agent to check `status`, or use the long link), broken (nothing was accepted; open the link again), or try later.

| Code | Name | Sent by | When | The page shows |
|---|---|---|---|---|
| 4000 | `PROTOCOL` | page, engine, Vault | A message out of place or malformed (text for binary, unknown type, content that fails its schema, a second request in flight, a foreign `Origin`) | broken |
| 4001 | `UNSUPPORTED_VERSION` | page, engine, Vault | A version byte or `AUTH` version other than 1 | broken |
| 4002 | `AUTH_FAILED` | Vault | Engine socket: a bad `basalt-engine-key`, or a bad or late `AUTH` | (engine only) |
| 4003 | `REPLACED` | Vault | Engine socket: a newer authenticated socket for the same id | (engine only) |
| 4004 | `LINK_UNKNOWN` | Vault | No engine registered the token, it expired, or it was unregistered | link gone |
| 4005 | `ENGINE_OFFLINE` | Vault | The token's engine has no socket | engine offline |
| 4006 | `LINK_REFUSED` | engine | Message 1 for a link the engine does not hold, expired, revoked, with another token than `SESSION_OPEN`'s, a failing tag, or an invalid ephemeral key, all alike; also open sessions of a link revoked or expired | link gone |
| 4007 | `HANDSHAKE_FAILED` | page | An invalid engine ephemeral key; message 2 that does not decrypt, fails its schema or its signature; on `DIRECT`, an engine key other than the pinned one | broken |
| 4008 | `FRAME_INVALID` | page, engine | A frame that does not decrypt with the next counter, or with non-canonical padding | broken |
| 4009 | `TOO_LARGE` | page, engine, Vault | A message over its [limit](#limits), or a response body over 16 MiB | broken |
| 4010 | `RATE_LIMITED` | engine, Vault | Too many handshakes for a link, requests in a session, or connections at the Vault | try later |
| 4011 | `SESSION_LIMIT` | engine, Vault | Too many open sessions for the link or the engine | try later |
| 4012 | `TIMEOUT` | page, engine, Vault | The handshake took over 10 seconds, the session was idle 5 minutes, or it reached 30 minutes or its link's expiry | try later |
| 4013 | `ENGINE_REVOKED` | engine | The engine's key is revoked in the person's database (M4.1) | engine offline |
| 4014 | `ENGINE_SHUTDOWN` | engine | The engine is stopping, or rotated its keys | engine offline |

A page that ends a session normally closes with 1000. A refusal inside a session that leaves it usable (`404`, `409`, `410`, `413`) is an HTTP status in a `RESPONSE`, not a close.

### Limits

Enforced by the engine and the page (VC-35, provisional). The Vault must carry messages up to these sizes, and may apply lower rates of its own (private numbers), never lower sizes. Rate checks come before any public-key operation.

| Limit | Value | Over it |
|---|---|---|
| Handshake message 1 | exactly 99 bytes | `PROTOCOL` |
| Handshake message 2 | at most 1 024 bytes | `TOO_LARGE` |
| Frame | at most 32 786 bytes (32 768 of padded plaintext, 2 of header, 16 of tag) | `TOO_LARGE` |
| `ROUTE` message on the engine's socket | at most 32 804 bytes (a frame plus 18) | `TOO_LARGE` |
| Control message | at most 4 KiB | `TOO_LARGE` |
| Request body | at most 16 KiB, as on loopback | `413` |
| Response body | at most 16 MiB | `TOO_LARGE` (page) |
| Handshake time | 10 seconds from `SESSION_OPEN` (engine) or from opening the socket (page) | `TIMEOUT` |
| Idle session | 5 minutes without a frame | `TIMEOUT` |
| Session lifetime | 30 minutes, and never past the link's expiry | `TIMEOUT` |
| Requests per session | 64 | `RATE_LIMITED` |
| Open sessions per link | 4 | `SESSION_LIMIT` |
| Open sessions per engine | 64 | `SESSION_LIMIT` |
| Handshakes per link | 20 per 10 minutes | `RATE_LIMITED` |
| Live links the Vault accepts per engine | at least 1 000 | `ERROR` `LINK_LIMIT`; the engine hands over the long link |

### Replay and expiry

- Session keys are fresh per session; counters refuse replays within one ([Handshake](#handshake), [Frames](#frames)).
- An approval is single-use in Postgres, a revert is applied once, and both expire (24 hours; one hour for an unsigned revert). A replayed signature is refused by Postgres (`APPROVAL_INVALID`, `REVERT_INVALID`) whatever carried it (design 6.3).
- A reissued link revokes the old one at the engine (its `psk` deleted, its token unregistered, its sessions closed with `LINK_REFUSED`). An expired link goes the same way, and the Vault drops its token at `expiresAt` on its own.
- A restarted engine keeps its links (the links file) but no session; it registers its links again after `READY`.

### What the Vault sees

**Sees (metadata only, VC-4):** engine ids and their public keys; when each engine is connected and from which IP address; link tokens, when they are registered, used and unregistered, and their expiry; page IP addresses and user agents; how many sessions and frames, their padded sizes and timing; close codes. Padding hides one frame's exact size, not these: how many frames a message took (a large response, such as a big revert, shows as many full frames), which way each went, and the rhythm of a session. From them the Vault can usually tell that a page read an item and then posted a signature (a small request answered after Postgres's time): **that an approval or revert was probably signed, and when**, though not which item, rows or result. **Never sees:** link secrets, `psk`s or session keys; item ids, rows, statements, headlines, signatures, receipts, results; any database credential; any private key. (The portal's static host sees the page path `/approvals/<id>`, an id the contract already treats as not secret.)

**What the Vault must do** (tested against the Go fake Vault, VC1-4, and attacked by a hostile one, VC1-12): forward session bytes unchanged and in order; keep one engine's sessions apart from each other and from other engines'; route a token only to the engine that registered it first, and refuse another engine's registration (`LINK_CONFLICT`); drop tokens at their expiry; accept the sizes above; send fresh single-use challenges; never log session bytes. Retention (VC-24): connection metadata at most 7 days. Nothing in the engine or the page relies on any of these: each is about service and privacy, not about what gets accepted.

### Configuration and status

- **`vault`** in `engine.json`: `ON` or `OFF` (VC-19), set by `basalt init --vault=on|off`: `on` by default with `--operated-by=agent` or when installed through a Vault-driven setup, `off` otherwise; init prints the value it chose and why (`vault: on (default for --operated-by=agent; --vault=off to turn it off)`). `--vault=on` with a local pages origin is a usage error (exit `2`), for the passkey reason above. `vaultUrl`: the development override above.
- **`status`** gains `vault` ([`status.json`](api/mcp/tools/status.json)): `state` (`OFF`, `CONNECTING`, `CONNECTED`, `UNREACHABLE` after 30 seconds without `READY`, `KEY_ERROR`), `engineId` and `fingerprint` whenever the key file loads. `basalt status` prints the same. No state is a problem: approvals work in all of them, through long links when the Vault is not there.
- **Links** follow the [link budget](#the-link-budget)'s order: the portal short link when the Vault registered it, else the long link.

### Direct transport (reserved)

M4.1 (VC-16, VCT-1). The page reaches the engine's own listener through the person's tunnel at the address the person pinned, and runs this same handshake and these frames with transport `DIRECT` in the prologue; message 1 still carries `linkToken`, which tells the engine the link. The page compares `engineKey` with the key pinned for that address. The route (`GET /v1/session`), its Host and Origin rules, the pinned address, the CSP and the engine key in `basalt_meta` are VCT-1's contract. A tunnel that ends TLS sees only ciphertext.

### Test vectors

Shared files under `api/mcp/vault/testdata/` (VC1-2: `link-derivation.json`, `engine-id.json`, `padding.json`, `handshake.json`, `frame.json`, `signature.json`, `receipt.json`), each one kind, in the format of [`vectors.schema.json`](api/mcp/vault/vectors.schema.json): `LINK_DERIVATION`, `ENGINE_ID`, `PADDING`, `HANDSHAKE`, `FRAME`, `SIGNATURE` (every context above) and `RECEIPT`. Each case says what a receiver must do (`ACCEPT`, `REFUSE`, or a close code), so the refusals are pinned too: a tampered tag, a wrong `psk`, an invalid point, a compressed key, a reflected, replayed, reordered or spliced frame, non-zero padding, a signature from another context. Go tests and `node --test` read the same files; a mismatch fails `make ci`. Private keys are fixed 32-byte scalars so the bytes are reproducible (WebCrypto imports one as PKCS#8 without the optional public key and computes it); ECDSA signatures are randomized, so a vector pins one valid signature and a writer under test uses it instead of signing.

The Vault service's own vectors and tests live with it, privately.

## `basalt_meta`

- Everything BasaltDB installs lives in the `basalt_meta` schema and is removed with `DROP SCHEMA basalt_meta CASCADE`.
- The agent role has no direct `INSERT` on `basalt_meta` tables; ledger rows go through validating `SECURITY DEFINER` functions.
- Session settings use the `basalt.` prefix and are set transaction-local with `set_config(name, value, true)` (`SET LOCAL`), never session-level `SET`: `basalt.intent` (required on every agent write), `basalt.run_id`, `basalt.task_id`, `basalt.mode` (`APPLY` default, `PREVIEW`), `basalt.approval_id` (M2).
- Every BasaltDB connection to Postgres (engine and CLI) works through a transaction-mode pooler: it sends unnamed statements in one round trip (pgx `QueryExecModeExec`, `internal/pgdial`), never named prepared statements, unless the connection string sets `default_query_exec_mode`.
- Schema changes to `basalt_meta` are forward-only and versioned; the installed version is recorded in `basalt_meta.schema_version`. From version 13 agent roles may `SELECT` it: the engine reads it when it starts serving an agent and refuses that agent, logging `guard schema vN is older than this build's vM: run basalt init again to upgrade it (same flags as before)`, when the installed version is older than the one its build installs (an agent that cannot read the table has a guard older than version 13). Planned (AE-11): each migration is flagged **breaking** (the default) or **non-breaking**; marking one non-breaking needs a test that runs the engine against a guard without that migration. A missing breaking migration serves the agent degraded (`status` only, every other tool `UNAVAILABLE` `GUARD_OUTDATED` with the `basalt upgrade` steps); missing only non-breaking ones serve normally with `GUARD_UPGRADE_AVAILABLE`. The engine checks again on each call, so `basalt upgrade` needs no restart.
- Roles: `<prefix>_guard` (owner, `NOLOGIN`), `<prefix>_agents` (group, `NOLOGIN`), `<prefix>_agent_<name>` (one `LOGIN` role per agent). Default prefix `basalt`. They are cluster objects: uninstall drops them after the schema.

### Tables and views (versions 1 to 3)

| Object | Purpose |
|---|---|
| `schema_version` | Installed migration versions |
| `guarded_tables` | Tables carrying the guard, with primary-key columns and reason `AGENT_WRITABLE` or `CASCADE_TARGET` |
| `runs` | One row per run: `run_id`, `task_id`, `agent`, `intent`, `started_at` |
| `changes` | The change record: one row per agent action (one top-level statement), `status` `APPLIED` or `REFUSED` in M1 |
| `ledger` | Append-only, hash-chained rows: `ROW_CHANGE` (old and new row, cascades included), `CHANGE` (statement, intent, duration), `REFUSED`, `RUN_STARTED`, `HEARTBEAT`, `DEAD_MAN`, `UNCOVERED_TABLES` (version 2), `PASSKEY_REVOKED` (version 12), `AGENT_SETUP` (version 16), `READ` (version 3: one per read, detail `runId`, `taskId`, `statement`, `tables`, `rows`, `durationMs`, `versions: [{table, key, version}]`), `PRUNED`. A `ROW_CHANGE` detail carries `xmin` (the version the write replaced), `cascaded`, and from version 3 `newXmin` (the version the write left: the writing transaction id, `null` for a delete; revert compares it, M3), `basedOn` (`{version, changeId}`) or `blindWrite` |
| `reads` | Version 3. A run's latest known version of each row it read or wrote: `(run_id, table_oid, row_key)` primary key, `row_version xid`, `change_id`, `at`. Removed with the run (1 year). The guard trigger compares it with `OLD.xmin` |
| `chain_head`, `chain_anchor` | Last appended `(seq, hash)`; where verification starts after retention deletes the oldest rows |
| `agent_guarded_tables` | Version 3. `table_oid`, `table_name`, `pk_cols` of guarded tables the calling agent can `SELECT`; the engine reads it to know which rows of a read it can identify |
| `agent_runs`, `agent_changes`, `agent_ledger`, `agent_guarded_tables` | With `schema_version` (version 13) and `agent_setups` (version 16), the only objects an agent role can `SELECT`. Rows of the calling agent only; `agent_ledger` redacts key and values of tables the agent cannot `SELECT` (`redacted = true`) |

Chain: `hash_n = sha256(hash_{n-1} || canonical_n)` with `canonical_n` the `jsonb` text of the row's `seq`, `at` (epoch microseconds), `agent`, `changeId`, `kind`, `table`, `tableOid`, `op`, `key`, `valuesHash`, `depth` and `detail`, and `valuesHash = sha256(jsonb_build_array(old_row, new_row)::text)`. Retention nulls values after 30 days without breaking the chain and deletes ledger metadata after 1 year, moving the anchor.

### Functions an agent role may call

All `SECURITY DEFINER`, validating, and taking the agent from `session_user`, never from an argument.

| Function | Purpose |
|---|---|
| `start_run(run_id uuid, task_id uuid, intent text)` | Record a run |
| `finish_change(op text, statement text, params jsonb, duration_ms int) returns uuid` | Stamp the change the guard opened in this transaction (and chain a `CHANGE` ledger row with the statement and intent), or record a zero-row change with `op` |
| `record_refusal(run_id uuid, task_id uuid, intent text, op text, statement text, params jsonb, code text, reason text, duration_ms int) returns uuid` | A `REFUSED` change record |
| `record_event(kind text, run_id uuid, detail jsonb) returns bigint` | Engine events: `HEARTBEAT` (every hour; detail `engineVersion`, `chainBrokenAt` when the chain is broken, and planned `operatedBy`, CO-15), `DEAD_MAN` (the engine checks in after more than 7 days of silence; detail `lastHeartbeat`, `silentHours`; D14), `UNCOVERED_TABLES` (detail `tables: [{table, why}]`, written when the set of unguarded tables changes). Version 2 adds the last two |
| `prune() returns jsonb` | Retention (30 days values, 1 year metadata) |
| `verify_chain() returns bigint` | First broken `seq`, or `NULL` when intact. The full check, from the anchor |
| `verify_chain_from(seq bigint, hash bytea) returns (broken_at bigint, seq bigint, hash bytea)` | Version 2. The incremental check: the row at `seq` (or the anchor) must still have `hash`, then every later row is recomputed up to the head. `broken_at` is the first broken `seq`, or `NULL` when intact; `(seq, hash)` is the head it verified, for the caller to keep. A pinned `seq` older than the anchor (retention deleted it) verifies from the anchor. `(0, zero hash)` is a full check |
| `chain_head() returns (seq, hash)`, `check_head(seq, hash) returns boolean` | Head pinning: the engine keeps the last head and checks it on start |
| `record_read(run_id uuid, statement text, params jsonb, tables text[], row_count int, duration_ms int, versions jsonb) returns uuid` | Version 3. A `SELECT` change record, a `READ` ledger row, and for a run the `reads` entries. `versions` is a JSON array (at most 10 000) of `{"tableOid": <oid>, "key": {<pk column>: value}, "version": "<xid>"}`; every table must be guarded and readable by the caller and every key must name exactly its primary-key columns. Called after the read's own read-only transaction |
| `uncovered_tables() returns (table_oid, why)` | Agent-writable tables and cascade targets without the guard |

### Version 4 (M2): approvals

Installed by the migration after M1.5's. Design and reasons in the [M2 plan](docs/redesign/plans/2026-11-11-m2-approvals.md#basalt_meta-additions-specified-here-built-in-phase-b). Applying under `basalt.approval_id` is checked per row (approval of this agent and run, signed, unused, unexpired, no more rows than approved) and at commit (statement, parameters, row count and `rowsHash` of the recomputed lines); a match replaces the held `APPROVAL_PENDING` record with the applied one. `prune()` marks held writes past expiry `APPROVAL_EXPIRED`.

| Object | Purpose |
|---|---|
| `passkeys` | The person's passkeys: credential id, P-256 public key, RP ID, origin, signature counter. Written by `register_passkey` (admin only) |
| `approvals` | Held actions: statement, parameters, assigned columns, preview lines, `rows_hash`, binding text and hash, expiry, approval and use. Values pruned after 30 days |
| `agent_approvals` | The calling agent's approvals (status `PENDING`, `APPROVED`, `APPLIED`, `EXPIRED`) with binding text and lines |
| `agent_passkeys` | Registered passkeys' public data (credential id, label, public key, RP ID, origin, counter), so a relay can fill `credentialIds` and check a code locally before submitting |
| `preview_lines(assigned text[]) returns setof text` | Agent, in a `PREVIEW` transaction: the action's preview lines |
| `hold_action(statement text, params jsonb, assigned text[], lines text[]) returns (approval_id uuid, binding_text text, expires_at timestamptz)` | Agent: store the held action and its `APPROVAL_PENDING` change |
| `submit_approval(approval_id uuid, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea) returns timestamptz` | Any relay: verify the assertion, mark `APPROVED` |
| `register_passkey(credential_id bytea, x bytea, y bytea, rp_id text, origin text, label text)` | Admin: store a passkey (the point must be on P-256) |
| `_verify_assertion(binding bytea, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea)` | Internal, not granted to agents: the WebAuthn checks of `submit_approval` with challenge = `binding`, raising `BS005` `APPROVAL_INVALID` with a detail; bumps the passkey's counter. M3's `apply_revert` reuses it (and re-raises as `REVERT_INVALID`) |

`changes.status` gains `APPROVAL_PENDING` and `APPROVAL_EXPIRED`; ledger kinds `APPROVAL_PENDING` and `APPROVED`.

### Versions 5 to 7 (M3): revert

Version 5 is the read-only plan, version 6 the trial run and prepared reverts, version 7 `apply_revert`. Design and reasons in the [M3 plan](docs/redesign/plans/2026-11-11-m3-revert.md).

| Object | Purpose |
|---|---|
| `ROW_CHANGE` detail | Gains `revertOf` on revert writes (`newXmin` landed in version 3) |
| `reverts` | Prepared reverts: scope, agents, intent, lines, `rows`, `skipped`, `rows_hash`, binding text and hash, 1-hour expiry, applying credential and change. Values pruned after 30 days |
| `revert_running` | Marks the transaction a revert or its trial runs in; written only by the revert functions |
| `agent_reverts` | The calling role's prepared reverts (status `PENDING`, `APPLIED`, `EXPIRED`) with binding text and lines |
| `preview_revert(scope text, scope_id uuid) returns setof text` | Agent: the revert lines, from a trial run that always rolls back. Needs a read-write transaction |
| `prepare_revert(scope text, scope_id uuid, intent text) returns (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])` | Agent, as the CLI's relay: store the revert and its binding; returns the lines for the link (the sample, for a large plan). `NOTHING_TO_REVERT` |
| `apply_revert(revert_id uuid, credential_id bytea, authenticator_data bytea, client_data_json bytea, signature bytea) returns jsonb` | Any relay: verify the person's assertion and run the revert in the same transaction; returns `{changeId, rows, skipped}` |

`changes.op` gains `REVERT`; `changes.status` gains `REVERTED`; `changes` gains `actor_kind` (`AGENT`, `PERSON`), `revert_id`, `credential_id` and `reverted_by`, and `agent_changes` shows the last three; ledger kinds `REVERT_PENDING` and `REVERTED`. `<prefix>_guard` is granted `SELECT`, `INSERT`, `UPDATE`, `DELETE` on guarded tables, used only inside the revert functions. The guard trigger treats writes by `<prefix>_guard` during a revert as revert writes: no intent, no row limits, no `STALE_READ`, and no cascade into rows outside the revert (`BS009`).

### Version 8: row-level security

N12-7 and N12-8; plan: [`docs/redesign/plans/2026-11-12-m3-large-reverts-rls.md`](docs/redesign/plans/2026-11-12-m3-large-reverts-rls.md).

| Object | Purpose |
|---|---|
| Policy `<prefix>_guard` | `AS PERMISSIVE FOR ALL TO <prefix>_guard USING (true) WITH CHECK (true)` on every guarded table with RLS enabled, created by `attach` (every `basalt init`), dropped by `basalt uninstall`. Agent roles keep `NOBYPASSRLS`; they get a policy only as in version 11 |
| `uncovered_tables()` | Also returns guarded tables with RLS enabled and no guard policy, `why` = `RLS_WITHOUT_GUARD_POLICY` |
| Revert lines | Redacted on RLS tables as in [Revert](#lines-binding-and-codes) |

### Version 9: large reverts

N12-1 to N12-6.

| Object | Purpose |
|---|---|
| `reverts` | Gains `batched`, `sample_hash`, `covered` (the changes in scope at prepare), `signed_at`, `apply_by`, `batches` |
| `revert_lines` | A large plan's lines: number, text, the row's ledger chain, `outcome` (`PENDING`, `RESTORED`, `SKIPPED`), `conflict`, `sql_state`, `batch`. Text and chain pruned after 30 days |
| `agent_reverts` | Gains `batched`, `signed_at`, `apply_by`, `restored`, `skipped_now`, `pending`; status gains `APPLYING` |
| `agent_revert_lines` | The calling role's plan lines: `revert_id`, `line_no`, `line`, `outcome`, `conflict`, `sql_state`, `batch` |
| `apply_revert(...)` | For a large plan: verify the assertion and record the signature (`REVERT_SIGNED`); returns `{changeId, rows: 0, skipped, batched: true, pending, applyBy}` |
| `apply_revert_batch(revert_id uuid, lines int[]) returns jsonb` | The role that prepared the plan: apply up to 200 pending lines (see [Large plans](#large-plans)) |

Ledger kinds `REVERT_SIGNED` (detail `revertId`, `scope`, `scopeId`, `intent`, `credentialId`, `binding`, `lines`, `rows`, `skipped`, `applyBy`) and `REVERT_BATCH` (detail `revertId`, `batch`, `lines`, `rows`, `skipped`, `pending`); a large plan's `REVERTED` row carries `rows`, `skipped` (a count) and `batches`.

### Version 11: agent RLS policy

Owner decision "Agent RLS" (Nov 12).

| Object | Purpose |
|---|---|
| Policy `<prefix>_agent_<name>` | `AS PERMISSIVE FOR SELECT TO <role> USING (true)` on a `--read` table, `FOR ALL ... USING (true) WITH CHECK (true)` on a `--write` table. Created by `basalt init` only on agent tables where RLS hid every row from the role and the person confirmed it (or passed `--agent-rls=all-rows`); kept on re-init; dropped by `basalt uninstall` |
| `record_agent_policy(agent name, table regclass, command text) returns bigint` | Admin only (init, after its `CREATE POLICY`): appends ledger kind `AGENT_POLICY_ADDED` for the agent (detail `policy`, `command` `SELECT` or `ALL`, `by`). Refuses a role that is not an agent or a table without that policy |

### Version 12: passkey management

M4.1; see [Passkey management](#passkey-management). It follows version 11, the agent RLS policy.

| Object | Purpose |
|---|---|
| `passkeys` | Gains `user_handle` (the WebAuthn user id the passkey was created with; null for passkeys registered before version 12), `last_used_at`, `revoked_at` and `revoked_by`. Rows are never deleted: a revoked passkey stays for the record |
| `_verify_assertion(...)` | Refuses a revoked passkey (`BS005` `APPROVAL_INVALID`, detail `passkey revoked`; `apply_revert` re-raises it as `REVERT_INVALID`), and sets `last_used_at` when it accepts an assertion |
| `register_passkey(credential_id bytea, x bytea, y bytea, rp_id text, origin text, label text, user_handle bytea)` | Replaces the six-argument form, which is dropped. Admin only. `user_handle` is 1 to 64 bytes or null. Refuses a revoked credential id (`BS008`): a removed passkey is registered again only as a new passkey |
| `revoke_passkey(credential_id bytea, force boolean) returns int` | Admin only, not granted to agents. Marks the passkey revoked and returns how many active passkeys remain. Refuses an unknown or already revoked id (`BS008`) and the last active passkey unless `force` (`BS007` `NOT_ALLOWED`). Appends a `PASSKEY_REVOKED` ledger row: `agent` the admin role, detail `credentialId` (base64url), `label`, `rpId`, `remaining`, `forced` |
| `agent_passkeys` | Active passkeys only (so approval and revert links list only those in `credentialIds`), and gains `created_at` and `last_used_at`. It keeps the public key, which a relay needs to check a code before submitting it |

### Version 14: `list_runs` index

N12-R1. `runs_agent`, an index on `runs (agent, run_id)` for the per-agent keyset of `list_runs`.

### Version 15: PII classification

M5.1; see [PII classification](#pii-classification). The M5.1 plan calls it version 14; 14 went to the `list_runs` index first. Forward-only, removed with `DROP SCHEMA basalt_meta CASCADE`. Breaking, the default (AE-11).

| Object | Shape and purpose |
|---|---|
| `pii_columns` | One row per classified column. `(table_schema text, table_name text, column_name text)` primary key; `data_type text` (as in [Readable columns](#readable-columns-and-the-fingerprint)); `class text` (check: one of the five [classes](#classes)); `entity_type text` (check: one of the five [entity types](#entity-types), not null exactly when `class = 'IDENTIFIER'`); `suggested_class text`, `suggested_entity_type text` (same checks, between themselves; null when nothing was suggested); `reason text` (why it was suggested, names and counts only, never a value); `needs_review boolean not null default false`; `phone_region text` (check: `^[A-Z]{2}$`, null unless `entity_type = 'PHONE'`); `confirmed_at timestamptz`, `confirmed_by text` (`session_user` of the `basalt classify` run that confirmed the class; both null for a row of class `UNCLASSIFIED`). Written only by the admin (`basalt classify`) |
| `pii_catalog` | At most one row: `id boolean primary key default true check (id)`, `fingerprint bytea not null` (32 bytes, [the fingerprint](#readable-columns-and-the-fingerprint) when `basalt classify` last wrote), `classified_at timestamptz not null`, `classified_by text not null`. Written only by the admin |
| `pii_readable_columns() returns table (table_oid oid, attnum smallint, table_schema text, table_name text, column_name text, data_type text)` | `SECURITY INVOKER`, `SET search_path = pg_catalog`: the [readable columns](#readable-columns-and-the-fingerprint). The one definition `basalt classify` and `pii_fingerprint()` use. It reads only `pg_catalog` and calls `has_column_privilege` for the members of `<prefix>_agents`, which any role can already do, so it reveals nothing an agent could not query itself |
| `pii_fingerprint() returns bytea` | `SECURITY INVOKER`, `SET search_path = pg_catalog`, no arguments: the fingerprint of `pii_readable_columns()` now |
| `agent_pii_columns` | View `WITH (security_barrier)`, owned by `<prefix>_guard` so it runs with that role's rights: `table_oid`, `attnum`, `table_schema`, `table_name`, `column_name`, `data_type` (as stored), `class`, `entity_type`, `phone_region`, `needs_review`, for the rows of `pii_columns` whose column exists under those names and that pass `has_column_privilege(session_user, table_oid, attnum, 'SELECT')` inside the view's own `WHERE`, so the filter runs before any function or operator of the caller's query. `table_oid` and `attnum` resolve the names through `pg_attribute`, so the engine maps a result column (pgx `FieldDescription.TableOID`, `TableAttributeNumber`) to its class without a second lookup |
| `agent_pii_catalog` | View `WITH (security_barrier)`, owned by `<prefix>_guard`: `fingerprint`, `classified_at` of `pii_catalog` (no row before the first `basalt classify`), filtered in the view's own `WHERE` to callers for whom `pg_has_role(session_user, '<prefix>_agents', 'USAGE')` holds |
| `pii_unclassified() returns table (table_schema text, table_name text, column_name text, data_type text, why text)` | `SECURITY INVOKER`: the columns the **login role** (`session_user`) may `SELECT`, by the readable-column rules, that need a person: `why` `NEW` (no row in `pii_columns`), `UNCLASSIFIED` (a row of that class) or `TYPE_CHANGED` (a row whose `data_type` differs from the column's type now; its class still applies). It reads classes through `agent_pii_columns`, so an agent needs no other grant. Ordered by schema, table, column (`COLLATE "C"`) |

**Writer.** `<prefix>_guard` owns `basalt_meta` and is `NOLOGIN`. `basalt classify` logs in with the admin connection string, which `basalt init` granted `<prefix>_guard` to, and runs its write transaction under `SET LOCAL ROLE <prefix>_guard` (as the migrations do); it reads the sample as the admin itself, outside that transaction.

**Grants.** `<prefix>_agents` gets `SELECT` on `agent_pii_columns` and `agent_pii_catalog`, and `EXECUTE` on `pii_unclassified()`, `pii_fingerprint()` and `pii_readable_columns()`; nothing else (`EXECUTE` on the functions is revoked from `PUBLIC`). An agent role can neither read nor write `pii_columns` and `pii_catalog`. Every agent-facing view added here is `WITH (security_barrier)` and filters on the login role (`session_user`) in its own `WHERE`, as the earlier `agent_*` views do. Not `current_user`: in a plain view it is the caller, but inside any `SECURITY DEFINER` function owned by `<prefix>_guard` that reads the view it would be `<prefix>_guard`, which may select every column, and after `SET ROLE` it is no longer the agent. `session_user` is the agent's login whatever runs the query, the identity the guard uses everywhere.

**Security tests** (required), run as the agent role:

- `SELECT`, `INSERT`, `UPDATE` and `DELETE` on `pii_columns` and `pii_catalog` are refused (`42501`); `INSERT`, `UPDATE` and `DELETE` on both views are refused.
- `agent_pii_columns` shows no row for a column the role cannot `SELECT` (a column of a table it has no grant on, and a column left out of a column-level grant on a table it can read in part).
- **Leaky function.** The role creates `pg_temp.leak(text, text, text) returns boolean`, cheap (`COST 0.0000001`), that raises a `NOTICE` with its arguments and returns true (`TEMP` is granted to `PUBLIC` by default), and runs `SELECT 1 FROM basalt_meta.agent_pii_columns WHERE pg_temp.leak(table_name, column_name, class)`. No notice names a column the role cannot select. For `agent_pii_catalog`, two runs of `SELECT 1 FROM basalt_meta.agent_pii_catalog WHERE pg_temp.leak(encode(fingerprint, 'hex'), classified_at::text, '')`: as the agent role (a member of `<prefix>_agents`, so the query reaches the filter and passes it) it sees exactly the one row; as a login role that is not a member, granted `SELECT` on the view for the test, it sees no notice and no row.

**Not covered here, open for M5.2.** Some `basalt_meta` agent views carry row values: `agent_changes` (`before`, `after`, `params`), `agent_ledger`, `agent_approvals` and `agent_reverts` (preview and revert lines), and the kept row versions. They are not readable columns of the person's tables, so they get no class here; M5.2 decides whether rule 2 refuses agent SQL on them or treats their values as PII.

### Version 16: setups

Planned, M4 ([Setup from your laptop](#setup-from-your-laptop), CO-13). Version 15 is taken by PII classification (M5.1); the two land in version order. Written only by the admin, inside the transaction of `basalt init --setup-code`.

| Object | Purpose |
|---|---|
| `setups` | One row per setup code that ran: `setup_id uuid` primary key (the code's UUIDv7, so a code runs once), `kind` (`INSTALL`, `AGENT`, `UPGRADE`), `agent_role name` (null for `UPGRADE`), `guard_version int` (the code's `guard.to`), `expires_at`, `used_at` (default `now()`), `used_by` (`session_user`). No agent role may write it |
| `agent_setups` | The calling agent role's rows of `setups` and every `UPGRADE` row: `setup_id`, `kind`, `guard_version`, `used_at`. The engine confirms a pending setup through it |
| `record_setup(setup_id uuid, kind text, agent name, guard_version int, expires_at timestamptz) returns bigint` | Admin only, not granted to agents. Records the setup and appends an `AGENT_SETUP` ledger row; returns its `seq`. `agent` is the agent role (null for `UPGRADE`, required otherwise; a role that is not a member of `<prefix>_agents` is `BS008`). Refuses, raising `BS010` with detail `USED` (the `setup_id` is recorded), `SUPERSEDED` (a later `setup_id` is recorded for the same role; not checked for `UPGRADE`), `EXPIRED` (`now()` at or past `expires_at`), `SETUP_ID_IN_FUTURE` (the UUIDv7 time of `setup_id`, its first 48 bits as milliseconds, more than 5 minutes after `now()`) or `EXPIRY_TOO_FAR` (`expires_at` more than 24 hours and 5 minutes after `now()`, or more than 24 hours after the `setup_id`'s time). The database's clock decides, not the code's |

Ledger kind `AGENT_SETUP`: `agent` the agent role (for `UPGRADE`, the admin role), detail `setupId`, `kind`, `guardVersion`, `by` (`session_user`). The install also gains one input in Go: the agent role's password given as a SCRAM-SHA-256 verifier instead of a generated one (format checked as in the [setup code](#the-setup-code), rendered as a SQL string literal).

### Guard errors

Raised by the guard with SQLSTATE class `BS`. The tool code each maps to is in [Error codes](#error-codes), the only mapping table.

| SQLSTATE | Message | When |
|---|---|---|
| `BS001` | `INTENT_REQUIRED` | Agent write without `basalt.intent` |
| `BS002` | `APPROVAL_REQUIRED` | 11 to 50 rows, or any `DELETE`. without a signed approval (`basalt.approval_id`); the engine then previews and holds it |
| `BS003` | `ROW_LIMIT_EXCEEDED` | Over 50 rows in one action, cascades included |
| `BS004` | `STALE_READ` | An agent `UPDATE` or `DELETE` of a row whose `xmin` differs from the version in `reads` for the run in `basalt.run_id`. Detail names the table, key and both versions. Checked before the row policy |
| `BS005` | `APPROVAL_INVALID`, `APPROVAL_EXPIRED`, `REVERT_INVALID`, `REVERT_EXPIRED` | Bad approval, revert authorisation or signature |
| `BS006` | `PREVIEW_CANNOT_COMMIT` | A preview transaction tried to commit |
| `BS007` | `NOT_ALLOWED` | `TRUNCATE`, unknown `basalt.mode`, a run of another agent |
| `BS008` | `LEDGER_INPUT_INVALID` | A ledger function got invalid input |
| `BS009` | `NOTHING_TO_REVERT`, `REVERT_CASCADE` | M3. A revert that cannot be prepared; `REVERT_CASCADE` is caught inside the revert and becomes a `CASCADE` conflict. `REVERT_TOO_LARGE` is removed in version 9 |
| `BS010` | `SETUP_REFUSED` | Planned, version 16. `record_setup` refused a setup code; detail `USED`, `SUPERSEDED`, `EXPIRED`, `SETUP_ID_IN_FUTURE` or `EXPIRY_TOO_FAR`. Raised to the admin's `basalt init --setup-code` only, never to an agent |

## Passkey management

M4.1. WebAuthn gives the server no signal when a person deletes a passkey from a device or password manager, so Basalt never learns it on its own. Removal is explicit (`basalt passkey remove`, revoked in Postgres), `basalt passkey check` finds passkeys a device can no longer produce, and `basalt log` warns about passkeys unused for 90 days.

- **Revoked means refused.** `_verify_assertion` refuses a revoked passkey, so it can no longer approve a held write, sign a revert or sign a large plan. Revocation is admin only; an agent role can neither register nor revoke a passkey.
- **Page.** `web/passkeys/`, embedded in the binary and served by the engine's local pages and the hosted console at `/passkeys/check` and `/passkeys/forget` ([Page links](#page-links)). Static, under the same rules as the approval pages: no backend, no relay, no third-party code, nothing sent over the network, input in the URL fragment, and for a check a code the person copies. It runs only at the hosted console (RP ID `basaltvault.app`) or `http://localhost:<port>` (RP ID `localhost`), and a link is only built on the origin a passkey was registered with, since only a page on that origin can ask for it or signal about it.
- **Request.** Fragment `#1.<b64url(json)>` (not deflated: it is small), one of:
  - `{ "mode": "CHECK", "challenge", "credentials": [{ "credentialId", "label" }] }`: `challenge` 32 random bytes, base64url; 1 to 100 credentials of the page's origin.
  - `{ "mode": "FORGET", "removed": [{ "credentialId", "label", "userHandle" }], "accepted": ["<credentialId>", …] }`: `userHandle` optional (absent for passkeys registered before version 12); `accepted` the active passkeys of the same RP ID.
- **Check.** The page asks for one passkey at a time (`navigator.credentials.get` with `allowCredentials` holding only that credential, `userVerification: "required"`). An assertion means found on this device; any error (none on this device, prompt cancelled, timed out) means not found, and the page offers to try that one again. The WebAuthn challenge is `sha256(utf8("basalt-passkey-check.1." + challenge))`. Approval and revert challenges are `sha256` of a binding text that Postgres stored and that is a JSON object, so a check signature can never match one: nothing in Postgres accepts it, and only the CLI verifies it, to report the result.
- **Check response.** Text `basalt-passkey-check.1.<b64url(json)>`: `{ "challenge", "found": [{ "credentialId", "authenticatorData", "clientDataJson", "signature" }], "missing": ["<credentialId>", …] }`. The CLI matches `challenge` to the link it printed and checks each found assertion with the same rules as approvals (type `webauthn.get`, challenge, origin, `rpIdHash`, UP and UV, ES256 signature; the counter may lag, since check signatures are never submitted).
- **Forget.** For each removed passkey the page calls `PublicKeyCredential.signalUnknownCredential({ rpId, credentialId })` when the browser has it, and, when it has `PublicKeyCredential.signalAllAcceptedCredentials` and the request carries the passkey's `userHandle`, also `signalAllAcceptedCredentials({ rpId, userId: userHandle, allAcceptedCredentialIds: accepted })`. Both are feature-detected; a browser with neither (or a call that fails) is a no-op, and the page then tells the person to delete the passkey by hand in their password manager. Signals are hints: a password manager may hide or delete the passkey, or ignore them. The page shows what it sent and outputs no code.
- **Unused.** A passkey is unused when no approval or revert was signed with it for 90 days (`last_used_at`, else `created_at`); `basalt log` names it. Nothing is revoked automatically.

## PII classification

M5.1. Design: [M5 design](docs/redesign/specs/2026-11-12-m5-pii-design.md), section 1; plan: [M5.1 plan](docs/redesign/plans/2026-11-12-m5-1-classify-dictionary.md), owner decisions M51-1 to M51-8. Every column an agent can read gets one class, for the whole database and every agent (M51-3). `basalt classify` suggests, the person confirms, `basalt_meta` stores it ([version 15](#version-15-pii-classification)). In M5.1 nothing is tokenized on the wire and nothing is refused: an unclassified column is only warned about (M51-5); refusals start in M5.2.

- **No value is ever printed, logged, written to the ledger or stored in plain form.** The CLI and the engine print counts, column names and reasons; the dictionary holds keyed hashes; `basalt_meta` holds classes, never values.
- Agents can read the classification and never change it. Only the admin writes it, through `basalt classify`.

### Classes

| Class | Meaning |
|---|---|
| `PUBLIC` | Leaves the machine as is |
| `IDENTIFIER` | One person's value, with an entity type: in the dictionary (M5.1) and tokenized on the wire (M5.3) |
| `FREE_TEXT` | Text that may mention people: patterns and the dictionary are applied to it (M5.3) |
| `SECRET` | The engine refuses to read it at all (M5.2) |
| `UNCLASSIFIED` | No person has classified it: warned in M5.1, refused from M5.2. A new or renamed column starts here (M51-4) |

CLI spelling: `public`, `identifier`, `free-text`, `secret`, `unclassified`.

### Entity types

Only for `IDENTIFIER`: every `IDENTIFIER` column has exactly one, and no other class has one.

| Entity type | Holds |
|---|---|
| `EMAIL` | Email addresses |
| `PHONE` | Phone numbers; the column also stores its phone region |
| `PERSON_NAME` | People's names |
| `ADDRESS` | Postal addresses and their parts (street, postcode) |
| `OTHER` | Any other identifier of a person: IBANs, dates of birth, IMEIs, account numbers |

CLI spelling: `email`, `phone`, `person-name`, `address`, `other`.

### Readable columns and the fingerprint

- **Readable columns** are the columns at least one member of `<prefix>_agents` may `SELECT` (`has_column_privilege(member, table, column, 'SELECT')`): ordinary columns (`attnum > 0`, not dropped) of tables, partitioned tables, views, materialized views and foreign tables, outside `pg_catalog`, `information_schema`, `pg_toast`, temporary schemas and `basalt_meta`. Row-level security does not change this: a column is readable when the role may select it, whatever rows it sees.
- **Data type** is `format_type(atttypid, NULL)`, without the type modifier (`character varying`, not `character varying(255)`), so a length change is not a type change.
- **Fingerprint** = `sha256` over the readable columns as lines `schema.table.column:type` (names as stored, unquoted), sorted in byte order (`COLLATE "C"`) and joined by `"\n"`. Stored as `bytea`, shown as lowercase hex. It is the quick "did any readable column change" check; `pii_unclassified()` is the authority. One SQL definition, `pii_fingerprint()`, serves both `basalt classify` and the engine.
- **Renames and type changes** (M51-4). Classes are keyed by `(schema, table, column)` names, so a renamed column (or table) has no class and is `UNCLASSIFIED`; its old row stays until the next `basalt classify` removes it, and no view shows it meanwhile. A type change keeps the class and marks the column for review (`TYPE_CHANGED`) until `basalt classify` records the new type.

### `basalt classify`

```text
basalt classify [--review=changed|all] [--set schema.table.column=class[:entity-type]]...
                [--phone-region=auto|XX] [--yes] [--dry-run] [--json] [--check]
```

- **Credential.** The admin connection string comes from `BASALT_ADMIN_DATABASE_URL` or a hidden prompt, as for `basalt init`; it is used for this run only and never written anywhere. The CLI refuses to run when `basalt_meta` is missing or older than version 15: `basalt: guard schema vN has no PII classification; run basalt init again to upgrade it (same flags as before)`, exit `1`.
- **What it does.** Lists the readable columns, computes a suggestion and its reason for each (name rules, and a sample of up to 1000 non-null values read with the admin connection; values stay in the CLI's memory and are dropped after scoring), shows the review, and writes what is accepted.
- **`--review`** (default `changed`): `changed` shows only columns that are `NEW` (no row), `UNCLASSIFIED` (a row of that class), `TYPE_CHANGED`, flagged `needsReview`, or whose suggestion differs from the confirmed class; `all` shows every readable column. Columns not shown keep their class.
- **The review**, grouped by table: per column its name, data type, current class, suggestion with entity type, reason, and for a `PHONE` suggestion the region and its share (`parsed as ID numbers, 91%`). At a terminal, per table, the person accepts the table, edits a column (input `column=class[:entity-type]`, the `--set` spelling) or skips the table; a skipped table's columns stay `UNCLASSIFIED`. A column flagged `needsReview` is asked about on its own even when its table is accepted. The terminal layout is fixed when `basalt classify` is built, from rendered mockups the owner picks; this contract fixes what the review contains and the `--json` shape.
- **`--set schema.table.column=class[:entity-type]`** (repeatable): sets those columns' classes without the review; nothing else is written. The entity type is required with `identifier` and refused with any other class. A column that is not readable, or a value outside the spellings above, is a usage error (exit `2`).
- **`--phone-region`** (default `auto`): `auto` infers the region per `PHONE` column from its sample (the region where most values are valid numbers, weighted by the `+cc` prefixes seen in the database); `XX`, an ISO 3166-1 alpha-2 code (input case-insensitive, stored upper case), is used for every `PHONE` column of the run instead. The region is stored per column so the engine normalizes that column's values the same way. When the sample holds no value to infer from, the region is null and the engine normalizes only numbers written with `+cc`.
- **`--yes`**: prints the review, then accepts every suggestion shown without asking; a column flagged `needsReview` gets its protected suggestion and stays flagged. Without a terminal, `basalt classify` writes only with `--yes` or `--set`; otherwise it prints the review and exits `1` with `basalt: no terminal to confirm the classes; pass --yes to accept the suggestions or --set to set columns`.
- **`--dry-run`**: computes and prints the review, asks nothing and writes nothing.
- **`--json`**: prints the review as JSON on stdout instead of text ([`classify-review.schema.json`](api/mcp/pii/classify-review.schema.json)) and asks nothing: it writes only with `--yes` or `--set`, and `written` says whether it did.
- **Writing.** One transaction under `SET LOCAL ROLE <prefix>_guard` ([Writer](#version-15-pii-classification)), in plain DML: upserts the accepted columns of `pii_columns` (class, entity type, suggestion, reason, `needs_review`, `phone_region`, `data_type`, `confirmed_at`, `confirmed_by`), stores the suggestion and reason of every column shown but not accepted (class `UNCLASSIFIED`), deletes the rows of columns that no longer exist or are no longer readable, and sets `pii_catalog` to `pii_fingerprint()` and the time. It prints counts: `basalt: classified N columns (P PUBLIC, I IDENTIFIER, F FREE_TEXT, S SECRET); U columns stay UNCLASSIFIED`.
- **`--check`**: writes nothing. For every `IDENTIFIER` column it takes the sample and, in memory, makes each value's token, restores it and tokenizes the restored text again; it prints per column the values sampled and how many do not come back to the same token (`public.customers.full_name: 1000 sampled, 3 do not round-trip`), naming the common-word rule when that is the cause. No value is printed. Exit `0` when it ran, whatever the counts; with `--json` each checked column carries `check`.
- **Output.** No value appears anywhere. Reasons carry names and counts (`NAME:email`, `SAMPLE:EMAIL 912/1000`, `SHAPE:99% distinct, fixed length 12`, `KEY:internal id`), several joined by `; `. Exit codes `0` ok, `1` error, `2` usage.

### `--json` review

[`api/mcp/pii/classify-review.schema.json`](api/mcp/pii/classify-review.schema.json): `{ "fingerprint", "previousFingerprint", "review", "dryRun", "written", "tables": [{ "table", "columns": [...] }] }`, `review` `CHANGED` or `ALL`. Each column: `column`, `dataType`, `status` (below), `class` (the stored class, `UNCLASSIFIED` when there is no row), `entityType`, `suggestedClass`, `suggestedEntityType`, `reason`, `needsReview`, `phoneRegion`, and with `--check` `check: { "sampled", "roundTripFailures", "commonWordRule" }`. `entityType`, `suggestedEntityType`, `phoneRegion` and `previousFingerprint` are absent when they do not apply. Enum values as in [Classes](#classes) and [Entity types](#entity-types). The schema enforces that `entityType` is present exactly when `class` is `IDENTIFIER`, `suggestedEntityType` exactly when `suggestedClass` is `IDENTIFIER`, and `phoneRegion` only when one of them is `PHONE`.

`status`, why a column is shown: the first row that applies.

| Status | When |
|---|---|
| `NEW` | No row in `pii_columns` |
| `UNCLASSIFIED` | A row of class `UNCLASSIFIED` |
| `TYPE_CHANGED` | The stored `data_type` differs from the column's type now |
| `NEEDS_REVIEW` | Flagged `needs_review` |
| `SUGGESTION_DIFFERS` | The suggestion differs from the confirmed class or entity type |
| `UNCHANGED` | None of the above; shown only with `--review=all` |

### Engine, `basalt log` and `basalt init`

- **Engine.** At start and on the hourly upkeep tick the engine calls `pii_unclassified()` as the agent and, when it returns rows, logs `pii: N columns unclassified: schema.table.column, …` (names are not PII). It loads `agent_pii_columns` at start and keeps, with the map, the `pii_fingerprint()` and `agent_pii_catalog` (`fingerprint`, `classified_at`) it read in the same transaction. On each hourly upkeep tick, the same tick that calls `pii_unclassified()`, it reads the three again and reloads the map when any of them differs from the values kept at the last load: `pii_fingerprint()` changes when readable columns are added, dropped, renamed or retyped (so oids and attribute numbers may have moved), and the catalog changes when `basalt classify` ran. It never compares `pii_fingerprint()` with `agent_pii_catalog.fingerprint`: the two differ from the moment a column changes until the next `basalt classify`, which is what `pii_unclassified()` reports. The dictionary (keys, normalizing, the scan, memory) is in the [M5.1 plan](docs/redesign/plans/2026-11-12-m5-1-classify-dictionary.md), sections 5 and 6.
- **Engine files** in `stateDir`: `pii.key` (`k_master`, 32 random bytes, mode `0600`, engine user; created on first start, refused at start when its mode is wider than `0600`; M51-1), the directory `pii/` (mode `0755`, engine user), `pii/dictionary.bin` (mode `0600`, engine user) and `pii/status.json` (mode `0644`, counts and times only, so the person's `basalt log` can read it): `{ "dictionaryValues", "deltaValues", "fingerprintBits", "lastScanAt", "lastScanColumns", "lastScanRows", "updatedAt" }`, `fingerprintBits` `32` or `16`, times RFC 3339 UTC.
- **Engine config.** `engine.json` gains `pii: { "maxMemoryMB": 512, "scanRowsPerSecond": 20000 }` (the defaults).
- **`basalt log`** prints one line on stderr, before its warnings, when the guard is version 15 or later: `PII: N columns classified, M unclassified; dictionary of K values, last scan <time>`. N counts the rows of `agent_pii_columns` with a class other than `UNCLASSIFIED`; M the rows of `pii_unclassified()` with `why` `NEW` or `UNCLASSIFIED`. When `status.json` is missing, cannot be read (permissions, an unreadable `stateDir`) or does not parse, the part after `;` is `dictionary not built yet`. It then warns on stderr `basalt: warning: M columns the agent can read are not classified yet: <names>; run basalt classify` when M > 0, and `basalt: warning: R columns need a classification review (type changed or flagged): <names>; run basalt classify` when any column is `TYPE_CHANGED` or has `needs_review`; at most 10 names each, then `…`. `--json` output is unchanged.
- **`basalt init`**, after installing, prints `basalt: N columns the agent can read are not classified yet; run basalt classify` when N > 0, N counted as `pii_unclassified()` counts for that agent's role (`why` `NEW` or `UNCLASSIFIED`).
