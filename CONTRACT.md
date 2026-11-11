# BasaltDB contracts

Normative contract for the surfaces BasaltDB exposes: **MCP tools** served by the engine (through the per-agent shim), the **`basalt` CLI**, the **approval and revert pages**, and the **`basalt_meta` schema** the guard installs in the person's Postgres. The product is defined in [`docs/redesign/specs/2026-11-11-basalt-foundation-final.md`](docs/redesign/specs/2026-11-11-basalt-foundation-final.md); this file fixes the wire rules. There is no REST API, no OpenAPI/AsyncAPI and no event stream.

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

From M2, an `APPROVAL_REQUIRED` body also carries `approval: { "approvalId", "expiresAt", "rows", "approvalUrl", "approveCommand" }` (see [Approvals](#approvals)). `approveCommand` is `basalt approve --agent NAME [--config PATH] --open <approvalId>` (`--config` only when the engine runs from a non-default config): the person runs it in a terminal and it opens the approval link in their browser. The message tells the agent to give the person that command: the link carries the whole preview, and terminals and chats wrap or cut it. `list_pending` items carry the same `approveCommand`.

| Code | When |
|---|---|
| `INTENT_REQUIRED` | A write without an intent (guard SQLSTATE `BS001`) |
| `STALE_READ` | An `UPDATE` or `DELETE` of a row whose version changed since the run last read or wrote it (`BS004`). A row the run never read is a blind write, not refused |
| `STATEMENT_REFUSED` | DDL, multiple statements, data-changing `WITH`, `COPY`, or a function outside the allowlist (engine policy, or `BS007` from the guard) |
| `ROW_LIMIT_EXCEEDED` | More than 50 rows in one action, cascades included (`BS003`) |
| `QUERY_TIMEOUT` | A `SELECT` hit the row or time limit (time limit: SQLSTATE `57014`) |
| `APPROVAL_REQUIRED` | The action is held; the result carries the approval id and expiry (`BS002`) |
| `APPROVAL_EXPIRED` | The approval was not given within 24 hours (`BS005`) |
| `APPROVAL_INVALID` | The approval does not exist, is used, belongs to another agent, or no longer matches the rows (`BS005`) |
| `REVERT_INVALID` | M3. The revert authorisation does not exist, is already applied, carries a bad signature, or its rows changed since the preview (`BS005`). For a batch of a large plan: the plan is not this agent's, not signed or already finished, or a line is not in the plan, repeated, or already applied |
| `REVERT_EXPIRED` | M3. The revert was not signed within 1 hour of `prepare_revert`, or a signed large plan was not finished within 24 hours of the signature (`BS005`) |
| `NOTHING_TO_REVERT` | M3. Every row in the scope would be skipped, or the scope wrote no rows (`BS009`) |
| `PERMISSION_DENIED` | The agent's role lacks the privilege; the database refused (`42501`) |
| `NOT_FOUND` | The run named in the arguments does not exist for this agent |
| `SQL_ERROR` | Any other error Postgres raised for the agent's statement (syntax, unknown column, constraint); `sqlState` says which |
| `INVALID_ARGUMENT` | Arguments fail schema validation, or an unknown argument was passed |
| `UNAVAILABLE` | The database or the guard cannot be reached |
| `INTERNAL` | A defect in the engine or the guard (`BS006`, `BS008`) |

`STATEMENT_REFUSED` reasons: `PARSE_ERROR`, `MULTIPLE_STATEMENTS`, `WRONG_TOOL` (a write sent to `query` or a read sent to `write`), `DDL_NOT_ALLOWED`, `STATEMENT_NOT_ALLOWED` (`SET`, `DO`, `COPY`, `EXPLAIN`, transaction control and other utility statements), `SELECT_INTO`, `LOCKING_READ`, `MERGE_NOT_ALLOWED`, `DATA_MODIFYING_WITH`, `FUNCTION_NOT_ALLOWED`, and from M2 `NOT_REPEATABLE` (a write that would be held contains a value that changes between transactions; pass it as a parameter). `QUERY_TIMEOUT` reasons: `TIME_LIMIT`, `ROW_LIMIT`.

New codes and reasons go through the contract-first process.

## MCP tools

The first release serves exactly these tools (foundation, "First release", plus the two large-revert tools of owner decision N12-1):

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

`preview_revert` (M3): exactly one of `changeId`, `runId`, `taskId`, plus `limit` and `cursor` (no `sort`: lines come in their signed order). Returns `scope`, `scopeId`, the `rows` and `skipped` totals of the whole preview, the `command` the person runs (`basalt revert --agent <name> --run <id>`), and one page of lines as objects (see [Revert](#revert)). It runs the revert on trial and rolls it back; it never reverts. The cursor names the last line of the page by its hash, so a preview whose rows changed between pages is refused with `INVALID_ARGUMENT` (start again). A scope with nothing to revert is `NOT_FOUND`. A scope of any size can be previewed.

`revert_plan` (large reverts, N12): `revertId`, optional `pending` (only lines not yet applied), `limit` and `cursor` (keyset on the line number; no `sort`: lines come in execution order). Returns the plan's `status` (`PENDING` until the person signs, `APPLYING`, `APPLIED`, `EXPIRED`), `scope`, `scopeId`, totals `lines`, `restored`, `skipped`, `pending`, `expiresAt` (sign by), `applyBy` (after the signature), `maxBatch` (200), and one page of `items`: `{line, outcome, batch, conflict, sqlState, plan}` with `outcome` `PENDING`, `RESTORED` or `SKIPPED` and `plan` the signed revert line as an object. Only the agent that prepared the revert sees it (`NOT_FOUND` otherwise). A revert of up to 1000 lines is applied in one call and has no plan to page (`INVALID_ARGUMENT`).

`apply_revert_batch` (large reverts, N12): `revertId` and `lines`, 1 to 200 unique line numbers from `revert_plan`. Postgres applies those lines only if the person signed the plan, the caller prepared it, it has not expired, and every line is in the plan and still pending; otherwise nothing is written (`REVERT_INVALID`, `REVERT_EXPIRED`). Each line is re-checked with its row locked: a row someone changed after the plan was built is skipped (people win), never overwritten. Returns `revertId`, `batch`, `status`, the plan's totals `restored`, `skipped`, `pending`, and this batch's `items: [{line, outcome, conflict, sqlState}]`. The loop: `revert_plan` with `pending: true` and `limit: 200`, then `apply_revert_batch` with those line numbers, until `pending` is 0. Apply lines in number order: it is the order that worked on trial.

`write` in M2: two optional arguments, `approvalId` (uuid) and `approval` (an approval response code, below; needs `approvalId`). To apply a held write the agent repeats the same `sql`, `params`, `intent` and `runId` and adds `approvalId`; with `approval` the engine first submits the person's signed approval (the agent relays it; it cannot make one). A different statement, parameters or run under the approval is `APPROVAL_INVALID`; an approval not yet signed is `APPROVAL_INVALID` with a message saying so. A held write returns `APPROVAL_REQUIRED` with `approval` in the error body; the held change record has status `APPROVAL_PENDING` until it is applied (the record is then replaced by the `APPLIED` one, which carries `approvalId`) or expires (`APPROVAL_EXPIRED`). The ledger keeps the `APPROVAL_PENDING` and `APPROVED` rows either way.

- **Lists** are cursor-paginated (keyset, no offset): arguments `limit` (default 50, max 200, clamped by the handler) and `cursor` (opaque base64url); result `{ "items": [...], "nextCursor": "..." }`, `nextCursor` absent on the last page. Unknown arguments are rejected with `INVALID_ARGUMENT`, never ignored.
- One named params struct per list tool, embedding `pagination.Params`, passed by value through every layer; the same struct backs the CLI flags.
- Agents cannot approve or sign a revert through MCP. Approve and revert need a passkey signature checked inside Postgres. `apply_revert_batch` only runs lines of a plan the person already signed.

## CLI

`basalt init`, `basalt log --run`, `basalt approve`, `basalt revert` (foundation, "First release"), plus `basalt version`. Machine output with `--json` uses the wire format above. Paged output prints the next cursor on **stderr**. Exit codes: `0` ok, `1` error, `2` usage.

- `basalt init --agent NAME [--write schema.table,…] [--read schema.table,…]`: shows the setup SQL (agent password redacted), asks to confirm unless `--yes`, installs or upgrades `basalt_meta`, creates or rotates the agent role, attaches the guard (with the guard's row-level security policy on tables that have RLS enabled, version 8), registers the passkey, then sets up the engine. At a terminal it asks once `Install the engine as a background service? ... [Y/n]` (`--yes` answers yes, `--no-service` no; without a terminal the answer is no). Yes: one `sudo basalt service install --config ... --user ... --agent NAME --os-user ... --credential-stdin` (the agent's connection string on stdin, never in arguments) creates the engine's OS user, writes the engine config (agent `name`, `osUser`, `credentialFile`) and the `0600` credential file (`<config dir>/agents/NAME.url`) owned by that user in the service's system directories, installs and starts (or restarts) the unit; init then checks the engine answers MCP `initialize` on the agent's socket and prints the `basalt mcp --agent NAME` line. No, or any of `--config`, `--socket-dir`, `--credential-file` given: init writes the config and credential itself (under the person's config directory when the paths are the system defaults) and prints the one `basalt engine --config ...` command. With the `claude` CLI on `PATH`, at a terminal, it offers `claude mcp add basalt-NAME -- basalt mcp --agent NAME` and runs it only on yes. The admin connection string comes from `BASALT_ADMIN_DATABASE_URL` or a hidden prompt and is never written anywhere. `--dry-run` prints the SQL and the engine setup (the sudo command and its steps) and runs nothing.
- `basalt log [--run ID]`: the agent's change records, newest first, read with the agent credential (`--agent NAME` looks it up in the engine config, or `--credential-file`, or `BASALT_DATABASE_URL`). Warnings on stderr: broken ledger chain, unguarded tables, no engine heartbeat for 7 days, and the last `DEAD_MAN` row (the engine came back after more than 7 days of silence). The chain is checked incrementally with `verify_chain_from` from the head this user's `basalt log` last verified (kept under the user cache directory, per database and role); `--full-check` runs `verify_chain()` from the anchor instead.
- Engine config (`engine.json`) also takes `stateDir` (default `/var/lib/basalt` on Linux, the systemd `StateDirectory`; `/Library/Application Support/Basalt/state` on macOS): the engine keeps each agent's last verified chain head there (`<stateDir>/<agent>.head.json`, mode `0600`) and verifies from it on start and every hour.
- `basalt uninstall`: drops the guard's RLS policies, `basalt_meta` and the roles, with the admin connection string given the same way as for init.
- `basalt approve <response-code>` (M2): decodes a `basalt-approval.1.` code, checks it locally against the stored passkey, and submits it with `submit_approval` using the agent credential (looked up as for `basalt log`). `basalt approve --show <approvalId>` prints the approval link for a held action, after a headline on stderr that states its cascaded rows (owner decisions, Decided Nov 12). `basalt approve --open <approvalId>` does the same but opens the link in the default browser (`open` on macOS, `xdg-open` on Linux) instead of printing it; when no browser opens it prints the link on stdout. The link page for `--show` and `--open` is `--page`, else the engine config's `approvalPage` when the agent is named with `--agent`, else `https://basaltvault.app/approve/`. The CLI is only a relay; Postgres checks the signature.
- `basalt revert --change ID | --run ID | --task ID [--intent TEXT] [--dry-run] [--json]` (M3): prepares the revert with `prepare_revert` using the agent credential (looked up as for `basalt log`), prints every line on stdout (restored rows with the columns that change back, then skipped rows with the reason), prints the revert link on stderr, reads the pasted `basalt-revert.1.` code, checks it locally, and calls `apply_revert`. Without a code it exits `1` and nothing is reverted. Prints rows restored and rows skipped with reasons; exit `0` even when some rows were skipped. `--dry-run` prints the preview only (`preview_revert`). `basalt revert --apply <code>` applies a prepared revert later, within its hour. `--intent` defaults to `Revert <scope> <id>`. `--open` opens the revert link in the default browser instead of printing it (printed on stderr when no browser opens). The revert page is `--page`, else `../revert/` next to the engine config's `approvalPage` when the agent is named with `--agent`, else `https://basaltvault.app/revert/`. The CLI is only a relay; Postgres checks the signature and runs the revert. For a large plan (over 1000 lines) it prints the plan size and the lines the link carries instead of every line, and the code signs the plan: the agent then applies it in batches (`apply_revert_batch`), and `basalt revert --status <revertId>` prints its progress (restored, skipped, pending, batches, `applyBy`) and the lines skipped so far.
- `basalt init` (M2) registers the person's passkey: it prints and opens a registration link, reads the pasted `basalt-passkey.1.` code, verifies it, and stores the public key with the admin credential, unless a passkey is registered already. `--skip-passkey` defers it, `--add-passkey` registers another, `--passkey-label` names it, and `--passkey-origin http://localhost:<port>` uses a local development page (RP ID `localhost`).

## Approvals

M2. The flow and the reasons are in [`docs/redesign/plans/2026-11-11-m2-approvals.md`](docs/redesign/plans/2026-11-11-m2-approvals.md); this section fixes the bytes. JSON Schemas for every payload are in [`api/mcp/approval/`](api/mcp/approval/).

- An approval or revert counts only with a valid P-256 passkey signature (WebAuthn ES256), verified inside Postgres. Pages and relays (the engine, the CLI, the agent's chat, Telegram) carry signed data and are not trusted.
- **Pages.** Static files under `web/`, published at `https://basaltvault.app` (`/approve/`, `/register/`). Passkey RP ID `basaltvault.app`, origin `https://basaltvault.app`. Development only: `http://localhost:<port>` with RP ID `localhost`. The pages have no backend, load no third-party code, and send nothing over the network: input comes in the URL fragment, output is a code the person copies. A page served by BasaltDB itself, if ever, follows the listener rules in [AGENTS.md](AGENTS.md) and the `websec` hardening; custom HTTP headers use the lowercase **`basalt-`** prefix.
- **Expiry.** 24 hours after the hold. No answer means blocked.
- **Engine.** On `BS002` the engine checks the write is repeatable (`NOT_REPEATABLE` otherwise), previews it, holds it, and answers `APPROVAL_REQUIRED` with the link. The engine config (`engine.json`) may set `approvalPage` (default `https://basaltvault.app/approve/`) and `notify.telegram: { botTokenFile, chatId }`; the token file must be mode 0600 and the token is never logged. Telegram only delivers the link.

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
| Approval request | URL `https://basaltvault.app/approve/#1.<b64url(deflate-raw(json))>` | `{ "approvalId", "binding", "lines", "credentialIds" }`: `binding` the binding text, `lines` the preview lines in order, `credentialIds` the registered passkeys (may be empty) |
| Approval response | Text `basalt-approval.1.<b64url(json)>` | `{ "approvalId", "credentialId", "authenticatorData", "clientDataJson", "signature" }` from `navigator.credentials.get` (`signature` DER) |
| Passkey registration request | URL `https://basaltvault.app/register/#1.<b64url(json)>` | `{ "challenge", "userId", "userName", "displayName" }`: 32 and 16 random bytes; names are labels for the passkey picker |
| Passkey registration response | Text `basalt-passkey.1.<b64url(json)>` | `{ "credentialId", "clientDataJson", "authenticatorData", "publicKey", "publicKeyAlgorithm" }`: `publicKey` the SubjectPublicKeyInfo DER from `getPublicKey()`, algorithm `-7` (ES256) only |

A page whose fragment does not decode as base64url, deflate-raw or JSON says the link looks cut short and to open it with `basalt approve --open` (or `basalt revert ... --open`), which builds the full link itself. The approval page checks `sha256(lines joined by "\n")` equals the binding's `rowsHash` and refuses to ask for a signature otherwise. Registration asks for `userVerification: "required"`, `residentKey: "required"`, `attestation: "none"`, ES256 only. `basalt init` verifies the registration in Go: type `webauthn.create`, challenge, origin, `rpIdHash`, the UP, UV and AT flags, the attested credential id equals `credentialId`, and a P-256 key.

### Checks in Postgres

`submit_approval` accepts an assertion only if: `type` is `webauthn.get`; the challenge is the approval's binding; `origin` and `rpIdHash` match the passkey's stored RP ID and origin; UP and UV are set; the signature counter increased (0 is accepted while the stored count is 0); the ES256 signature over `authenticatorData ‖ sha256(clientDataJSON)` is valid; the approval is not expired and not yet approved. Applying with `basalt.approval_id` commits only if the approval is approved, unused, unexpired, of this agent and run, and the statement, parameters, row count and `rowsHash` recomputed at commit match. Failures are `BS005`.

## Revert

M3. The flow and the reasons are in [`docs/redesign/plans/2026-11-11-m3-revert.md`](docs/redesign/plans/2026-11-11-m3-revert.md); decisions M3-1 to M3-14 are in the owner decisions. This section fixes the rules and the bytes. JSON Schemas for every payload are in [`api/mcp/revert/`](api/mcp/revert/).

- **Scopes:** `CHANGE` (one change, a revert's own change included), `RUN`, `TASK` (every agent's changes with that task id). `APPLIED` and `REVERTED` changes that wrote rows count (a reverted one shows its rows as `ALREADY_REVERTED`).
- **A revert is a new change.** It restores old values and never edits or deletes ledger rows. It is recorded as one change record with `op: REVERT`, `actor.kind: PERSON` and `revertId` (its `agent` is the role that relayed it), one `ROW_CHANGE` per restored row (detail `revertOf`), and a `REVERTED` ledger row with the credential id, the binding hash and every skipped row (table, key or row hash, reason; no values). Each covered change gets `revertedBy`; its status becomes `REVERTED` only when none of its rows was skipped. Every agent whose changes a revert covered sees the revert's change record.
- **Only a person.** A revert runs only inside `apply_revert`, after it verifies a passkey assertion over the revert binding with the same checks as `submit_approval`. Agents may preview and prepare; they cannot sign. No MCP tool applies a revert.
- **Row limits do not apply** to a revert, and no line cap does: a revert of up to 1000 lines is applied in one call; a larger one is a plan applied in batches (see [Large plans](#large-plans)). The intent comes from the person (`--intent`).
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
| Revert request | URL `https://basaltvault.app/revert/#1.<b64url(deflate-raw(json))>` | `{ "revertId", "binding", "lines", "credentialIds" }` |
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

## `basalt_meta`

- Everything BasaltDB installs lives in the `basalt_meta` schema and is removed with `DROP SCHEMA basalt_meta CASCADE`.
- The agent role has no direct `INSERT` on `basalt_meta` tables; ledger rows go through validating `SECURITY DEFINER` functions.
- Session settings use the `basalt.` prefix and are set transaction-local with `set_config(name, value, true)` (`SET LOCAL`), never session-level `SET`: `basalt.intent` (required on every agent write), `basalt.run_id`, `basalt.task_id`, `basalt.mode` (`APPLY` default, `PREVIEW`), `basalt.approval_id` (M2).
- Every BasaltDB connection to Postgres (engine and CLI) works through a transaction-mode pooler: it sends unnamed statements in one round trip (pgx `QueryExecModeExec`, `internal/pgdial`), never named prepared statements, unless the connection string sets `default_query_exec_mode`.
- Schema changes to `basalt_meta` are forward-only and versioned; the installed version is recorded in `basalt_meta.schema_version`.
- Roles: `<prefix>_guard` (owner, `NOLOGIN`), `<prefix>_agents` (group, `NOLOGIN`), `<prefix>_agent_<name>` (one `LOGIN` role per agent). Default prefix `basalt`. They are cluster objects: uninstall drops them after the schema.

### Tables and views (versions 1 to 3)

| Object | Purpose |
|---|---|
| `schema_version` | Installed migration versions |
| `guarded_tables` | Tables carrying the guard, with primary-key columns and reason `AGENT_WRITABLE` or `CASCADE_TARGET` |
| `runs` | One row per run: `run_id`, `task_id`, `agent`, `intent`, `started_at` |
| `changes` | The change record: one row per agent action (one top-level statement), `status` `APPLIED` or `REFUSED` in M1 |
| `ledger` | Append-only, hash-chained rows: `ROW_CHANGE` (old and new row, cascades included), `CHANGE` (statement, intent, duration), `REFUSED`, `RUN_STARTED`, `HEARTBEAT`, `DEAD_MAN`, `UNCOVERED_TABLES` (version 2), `READ` (version 3: one per read, detail `runId`, `taskId`, `statement`, `tables`, `rows`, `durationMs`, `versions: [{table, key, version}]`), `PRUNED`. A `ROW_CHANGE` detail carries `xmin` (the version the write replaced), `cascaded`, and from version 3 `newXmin` (the version the write left: the writing transaction id, `null` for a delete; revert compares it, M3), `basedOn` (`{version, changeId}`) or `blindWrite` |
| `reads` | Version 3. A run's latest known version of each row it read or wrote: `(run_id, table_oid, row_key)` primary key, `row_version xid`, `change_id`, `at`. Removed with the run (1 year). The guard trigger compares it with `OLD.xmin` |
| `chain_head`, `chain_anchor` | Last appended `(seq, hash)`; where verification starts after retention deletes the oldest rows |
| `agent_guarded_tables` | Version 3. `table_oid`, `table_name`, `pk_cols` of guarded tables the calling agent can `SELECT`; the engine reads it to know which rows of a read it can identify |
| `agent_runs`, `agent_changes`, `agent_ledger`, `agent_guarded_tables` | The only objects an agent role can `SELECT`. Rows of the calling agent only; `agent_ledger` redacts key and values of tables the agent cannot `SELECT` (`redacted = true`) |

Chain: `hash_n = sha256(hash_{n-1} || canonical_n)` with `canonical_n` the `jsonb` text of the row's `seq`, `at` (epoch microseconds), `agent`, `changeId`, `kind`, `table`, `tableOid`, `op`, `key`, `valuesHash`, `depth` and `detail`, and `valuesHash = sha256(jsonb_build_array(old_row, new_row)::text)`. Retention nulls values after 30 days without breaking the chain and deletes ledger metadata after 1 year, moving the anchor.

### Functions an agent role may call

All `SECURITY DEFINER`, validating, and taking the agent from `session_user`, never from an argument.

| Function | Purpose |
|---|---|
| `start_run(run_id uuid, task_id uuid, intent text)` | Record a run |
| `finish_change(op text, statement text, params jsonb, duration_ms int) returns uuid` | Stamp the change the guard opened in this transaction (and chain a `CHANGE` ledger row with the statement and intent), or record a zero-row change with `op` |
| `record_refusal(run_id uuid, task_id uuid, intent text, op text, statement text, params jsonb, code text, reason text, duration_ms int) returns uuid` | A `REFUSED` change record |
| `record_event(kind text, run_id uuid, detail jsonb) returns bigint` | Engine events: `HEARTBEAT` (every hour), `DEAD_MAN` (the engine checks in after more than 7 days of silence; detail `lastHeartbeat`, `silentHours`; D14), `UNCOVERED_TABLES` (detail `tables: [{table, why}]`, written when the set of unguarded tables changes). Version 2 adds the last two |
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
| Policy `<prefix>_guard` | `AS PERMISSIVE FOR ALL TO <prefix>_guard USING (true) WITH CHECK (true)` on every guarded table with RLS enabled, created by `attach` (every `basalt init`), dropped by `basalt uninstall`. Agent roles get no policy and keep `NOBYPASSRLS` |
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
