## Revert

M3. Owner decisions M3-1 to M3-14. This section fixes the rules and the bytes. JSON Schemas for every payload are in [`api/mcp/revert/`](../api/mcp/revert/).

- **Scopes:** `CHANGE` (one change, a revert's own change included), `RUN`, `TASK` (every agent's changes with that task id). `APPLIED` and `REVERTED` changes that wrote rows count (a reverted one shows its rows as `ALREADY_REVERTED`). Planned (RS-1 to RS-3, [Revert scope objects](basalt-meta-revert.md#revert-scope-objects)): what a revert covers is its [scope descriptor](#the-scope-descriptor), a scope narrowed to some agents, runs and tables; an agent role proposes only its own work, and only the person widens it, on the signing page ([Rescope, widen and reject](#rescope-widen-and-reject)).
- **A revert can be reverted** (owner decision AE-14). The ledger is append-only and a revert is itself a recorded write, so reverting a revert's change brings the reverted values back (a redo). People still win and the person still signs. An agent may request it for a revert of its own change or run (`request_revert` with the revert's `changeId`).
- **A revert is a new change.** It restores old values and never edits or deletes ledger rows. It is recorded as one change record with `op: REVERT`, `actor.kind: PERSON` and `revertId` (its `agent` is the role that relayed it), one `ROW_CHANGE` per restored row (detail `revertOf`), and a `REVERTED` ledger row with the credential id, the binding hash and every skipped row (resource, key or row hash, reason; no values). Each covered change gets `revertedBy`; its status becomes `REVERTED` only when none of its rows was skipped. Every agent whose changes a revert covered sees the revert's change record.
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
| `TARGET_GONE` | The row (the target) the revert would update or delete no longer exists, or the guard cannot see it |
| `KEY_TAKEN` | The revert would re-insert a row, or move a key back, and a row with that key exists |
| `ALREADY_REVERTED` | The row was last written by a revert of this change |
| `VALUES_PRUNED` | The old values are past the 30-day window |
| `SCHEMA_CHANGED` | The table, a column of the old row, or the primary key changed |
| `CASCADE` | The inverse write would cascade into a row that is not part of the revert |
| `CONSTRAINT` | The inverse write fails a constraint on trial; the line carries the store's error code in `store.code` |

`SCHEMA_CHANGED` keeps its name in every store: schema means the structure of the data (Basalt says `namespaces` for Postgres's schemas). A store reports only the reasons that apply to it.

### Lines, binding and codes

Every text below follows the [text rules](stores.md#text-rules) and has the shared part, the `shape` and the store part of [What every store writes](stores.md#what-every-store-writes), as an approval's do ([Approvals](approvals.md#what-an-approval-binds-decision-m2-1)).

**Revert line.** One per row:

```json
{"op": "UPDATE", "key": {"id": 7}, "now": {"id": 7, "status": "merged"}, "set": {"id": 7, "status": "open"}, "shape": "RECORD", "store": {"code": null, "kind": "POSTGRES", "verb": "UPDATE"}, "action": "RESTORE", "cascaded": false, "conflict": null, "resource": "public.leads", "changeIds": ["…"]}
```

`op` is the inverse write (`DELETE`, `UPDATE`, `INSERT`), `store.verb` the store's word for it; `resource` what the row belongs to, in the store's form; `now` the row as it is now (`null` if absent); `set` the values written (`null` for `DELETE`); `action` `RESTORE` or `SKIP`; `conflict` a reason above on `SKIP` lines; `store.code` the store's error code for a line it could not restore (`CONSTRAINT`: in Postgres the SQLSTATE of the trial write), else `null`. A row the preparing role cannot read (in Postgres, a table it cannot `SELECT`) is redacted to `{"op", "shape", "store", "action", "rowHash", "cascaded", "conflict", "redacted": true, "resource", "changeIds"}` with `rowHash` the lowercase hex `sha256` of `[key, now, set]` written by the text rules (in Postgres, `jsonb_build_array(key, now, set)::text`). Lines are ordered by their text bytewise (`COLLATE "C"`); clients never re-serialise them. Planned: on the revert page the engine serves, the person can reveal a redacted line's values with their passkey ([Rows hidden from the agent](approvals.md#rows-hidden-from-the-agent)).

**Binding text.**

```json
{"kind": "REVERT", "rows": 11, "store": {"kind": "POSTGRES", "name": "app"}, "intent": "…", "select": {"runs": null, "scope": "RUN", "agents": ["agent:bot"], "scopeId": "…", "resources": null}, "skipped": 1, "widened": false, "revertId": "…", "rowsHash": "<hex>", "expiresAt": "2026-11-11T07:02:11.123456Z", "requestedBy": "agent:bot"}
```

`rowsHash` = lowercase hex of `sha256(utf8(lines joined by "\n"))` over every line, `RESTORE` and `SKIP`, so the person signs both what is restored and what is left alone. **Challenge** = `sha256(utf8(binding text))`, as for approvals. A large plan's binding also has `"batched": true` and `"sampleHash"` (see [Large plans](#large-plans)); a one-call revert's binding has neither key.

The binding carries the scope as [scope descriptors](#the-scope-descriptor) (RS-3, [Revert scope objects](basalt-meta-revert.md#revert-scope-objects); [`revert-binding.schema.json`](../api/mcp/revert/revert-binding.schema.json)). A widened revert:

```json
{"kind": "REVERT", "rows": 14, "store": {"kind": "POSTGRES", "name": "app"}, "intent": "…", "select": {…descriptor…}, "skipped": 1, "widened": true, "proposed": {…descriptor…}, "revertId": "…", "rowsHash": "<hex>", "agentRows": {"agent:bot": 11, "agent:sync": 4}, "expiresAt": "…", "requestedBy": "agent:bot"}
```

- `select`: the scope the person signs. `proposed`: what the agent asked for, **omitted when it equals `select`** (every revert nobody rescoped).
- `widened`: `true` when `select` covers any change not made by `requestedBy` (its `agents` is `null` or names another agent).
- `agentRows`: lines per agent, keyed `agent:<name>`, `RESTORE` and `SKIP`, for the page's headline; present exactly when `widened` is `true`.
- `requestedBy`: the agent that prepared the revert, `agent:<name>` ([Agent names](stores.md#agent-names)).
- `store`: `kind` and `name` (`current_database()` in Postgres), for display. `rows` may be 0 only for a task proposal with no line of the agent's own, which cannot be signed (the page disables signing; `apply_revert` answers `NOTHING_TO_REVERT`).

The challenge is unchanged: `sha256(utf8(binding text))`, so the signature covers the scope.

| Payload | Carried as | JSON |
|---|---|---|
| Revert request | URL `<base>/reverts/<revertId>#2.<b64url(deflate-raw(json))>` ([Format 2](approvals.md#format-2-the-compact-request)) | `[shapes, texts]` or `[shapes, texts, credentialIds]`: the binding text, then the revert lines in order, then the database's active credential ids |
| Revert request JSON | Served by the engine's local pages at `GET /api/v1/reverts/{revertId}`; no link carries it | `{ "revertId", "binding", "lines", "credentialIds" }`, which also carries `rescopeNonce` and (planned) `revealNonce` ([Rows hidden from the agent](approvals.md#rows-hidden-from-the-agent)); format 2 expands to it without either. A format 1 link (`#1.`) is no longer read |
| Revert response | Posted by the page to its relay as JSON, never shown to paste | `{ "revertId", "credentialId", "authenticatorData", "clientDataJson", "signature" }` |

The revert page checks `rowsHash` (or, for a large plan, `sampleHash`), refuses a binding whose `kind` is not `REVERT`, and shows restored rows (current and restored values) and skipped rows (reason) before asking for the passkey.

**Lines on tables with row-level security** (N12-8, Postgres). On a table where RLS applies to the preparing role (RLS enabled, and the role neither has the owner's privileges nor `BYPASSRLS`), a line keeps its values only when it is a `RESTORE` line, not cascaded, and every change it names was made by the preparing role; any other line there is redacted as above, and the person can reveal it like any redacted line.

### Large plans

N12. A revert with more than 1000 lines is a **batched plan**:

- `prepare_revert` stores every line in the plan, numbered `1..N` in execution order (the order the trial's writes succeeded, then the `SKIP` lines), and builds one binding over all of them: `rowsHash` over every line in signed order, as above, plus `batched: true` and `sampleHash`.
- **Sample** (N12-4, amended by RSS-1): 1000 lines that keep room for both kinds. It takes up to 500 `SKIP` lines and up to 500 `RESTORE` lines; when one kind has fewer, the other fills the rest, up to 1000 in all: `skips = min(skipped, max(500, 1000 - rows))`, `restores = min(rows, 1000 - skips)`, with `skipped` and `rows` the binding's. The sample lists the first `skips` `SKIP` lines, then the first `restores` `RESTORE` lines, each kind in signed order. So 1500 `SKIP` and 50 `RESTORE` lines give 950 and 50; 2000 and 2000 give 500 and 500; 10 and 3000 give 10 and 990. `sampleHash` = lowercase hex `sha256(utf8(sample joined by "\n"))`. `prepare_revert` returns the sample as `lines`, and the revert request carries it. The page (and `revert.Request.Check` in Go) checks `sampleHash` and that the sample splits as the binding's `skipped` and `rows` give, then says how many of the plan's lines it shows and that the signature covers all of them.
- **What the page counts.** Every count the page shows comes from signed data: the totals from the binding's `rows` and `skipped`, the shown counts from the sample lines, which hash to `sampleHash`. Hidden rows are `rows` less the `RESTORE` lines shown and `skipped` less the `SKIP` lines shown. The request carries no other count, and the page shows no per-table or per-column count of hidden rows: nothing signed gives them.
- **Signature:** `apply_revert` with the person's code verifies it, opens the revert's change record, marks the `SKIP` lines skipped and records `REVERT_SIGNED`; it writes no row of the person's tables. The plan can then be applied for 24 hours, only by the role that prepared it.
- **Batches:** `apply_revert_batch` (MCP tool above) applies up to 200 pending lines of the plan. Each line runs at most once; a line whose row changed after the plan was built is skipped (people win). Every batch is one transaction with its `ROW_CHANGE` rows under the revert's change and a `REVERT_BATCH` ledger row; a failed batch leaves nothing, so the agent resumes from the pending lines.
- **Finish:** when no line is pending, the plan is `APPLIED`, a `REVERTED` ledger row is appended, and each covered change becomes `REVERTED` only if every line naming it was restored.

### Checks in Postgres

`apply_revert` runs the revert only if the assertion passes every `submit_approval` check with the challenge taken from this revert's binding, and the revert is neither expired nor applied. It then locks the rows, recomputes the lines for the preparing role, and refuses with `REVERT_INVALID` unless their `rowsHash` equals the signed one: a row changed after the preview fails the whole revert and nothing is written. Writes run as `<prefix>_guard` with all constraints immediate; a failure the trial did not predict aborts the revert. Failures are `BS005`. For a large plan `apply_revert` only records the signature; `apply_revert_batch` checks the caller, the signature state, the expiry and every line number, then re-checks each line against the signed text with its row locked.

`apply_revert` and `apply_revert_batch` lock the revert row (`FOR UPDATE`) before any check, so a rescope and a signature cannot interleave; `apply_revert` recomputes the lines from the stored scope descriptor and refuses with `REVERT_INVALID` when the binding's `select` is not the stored one, and refuses a `REJECTED` revert. With `rescope_revert` and `reset_revert`: a rescope or reset after the signature is refused, and a rescope before it changes the binding, so an earlier signature fails. A `REJECTED` revert cannot be rescoped or reset. `reject_revert` marks a pending, unsigned revert `REJECTED`.

### The scope descriptor

RS-1, RS-3, RS-4 ([`revert-select.schema.json`](../api/mcp/revert/revert-select.schema.json)). One JSON object, stored with the revert (`reverts.selection`) and carried in the binding as `select` and `proposed`:

```json
{"runs": null, "scope": "TASK", "agents": ["agent:bot", "agent:sync"], "scopeId": "0193…", "resources": ["public.invoices", "public.leads"]}
```

- **`scope`, `scopeId`**: `CHANGE`, `RUN` or `TASK` and its id. A person's widen may turn a `RUN` proposal into the run's `TASK` when the run has a task id.
- **`agents`**: the agents whose changes are in the selection, each `agent:<name>` ([Agent names](stores.md#agent-names)); the guard maps them to their roles. An agent's proposal has exactly one, itself. A person's widen may send `null`: every agent with changes in the scope.
- **`runs`**: `null` for every run of the selected agents in the scope; otherwise sorted run ids, each in the scope and of a selected agent. Only for `TASK`. At most 20.
- **`resources`**: `null` for every resource; otherwise sorted resource names in the store's form (in Postgres `schema.table` names, each a guarded table) written in the scope by a selected agent. At most 20. It filters lines, not changes: a change that wrote two tables can be half selected, and the trial run (M3-7) reports what that breaks (`CONSTRAINT`, `CASCADE`, `KEY_TAKEN`) before the person signs.
- **`store`** (RS-4): reserved for multi-store work, absent today. Postgres refuses a descriptor that carries it (`INVALID_ARGUMENT`). It is not the binding's `store`, which says which store wrote the binding, for display.
- **Normalized in Postgres.** Every key present, lists sorted by their text `COLLATE "C"` and deduplicated, `null` for all, kept as the `jsonb` text Postgres returns, so the same choice always gives the same text. The widen proof signs that text.
- **Own work.** A descriptor is inside an agent role's own work when `agents` is exactly `[that agent]` (`agent:<name>` of that role), its change or run is the role's own or the role ran in its task, and `runs` and `resources` lie inside that work.

**Link budget (VC-28, VC-30).** A proposal's descriptor adds about 100 characters before compression; a list of 20 run ids about 760. A rescope never travels on a long link (it needs the page talking to the engine). An agent's filtered proposal may make a long link go over budget, which follows the existing over-budget rule.

### Rescope, widen and reject

RS-2, RS-5; plan sections "Person side" and "Links after a widen". The Postgres side (`rescope_revert`, `reset_revert`, the redaction for the requesting agent) is under [Revert scope objects](basalt-meta-revert.md#revert-scope-objects); the engine serves `POST …/scope`, the link rotation and `LINK_RESET` on loopback and in Vault sessions; `reject_revert` is there too, and the engine serves `POST …/reject` on loopback and in Vault sessions, which the page's Reject button posts with its note. The person agrees (signs the proposal as it is), rescopes it, or rejects it, on the revert page served by the engine (loopback, or the [Vault channel](vault-channel.md#vault-channel) session). A long link with no engine shows the scope read only and says widening needs the page from the engine. Rescoping and rejecting go through [`POST …/scope` and `POST …/reject`](local-pages.md#local-pages); the engine calls `rescope_revert` and `reject_revert` with the credential of the role that prepared the revert.

| Select sent to `POST …/scope` | Needs | Checked in |
|---|---|---|
| Inside the agent's own work (narrow the proposal, drop the agent's own filters, or go back to the proposal), on a revert not yet widened | The link secret | Engine (the link), Postgres (own work) |
| Wider than the agent's own work | A **widen proof** and the **new link secret** it names | Postgres (`rescope_revert`) |
| Anything after a widen: inside the widest select the person proved (narrow, or back to the agent's own work) | The **scope token** of that proven call, which the engine adds (or a new widen proof) | Postgres (`rescope_revert`) |

- **Widen proof.** A WebAuthn assertion by the person's passkey ([`revert-scope-request.schema.json`](../api/mcp/revert/revert-scope-request.schema.json), `proof`) with challenge `sha256(utf8("basalt-rescope.1\n" + revertId + "\n" + nonce + "\n" + hex(sha256(rescopeKey)) + "\n" + normalized select))`, where `nonce` is the revert's `rescopeNonce` (base64url, as the revert request carries it), `rescopeKey = HKDF-SHA-256(ikm = the 16 decoded bytes of newSecret, salt = empty, info = "basalt-rescope-key.1", length = 32)`, and hex is lowercase. The prefix keeps a widen proof from ever verifying as an approval or a revert signature (their challenges hash a JSON binding).
- **`newSecret`.** The link secret the revert has after the widen: 16 random bytes the page makes (`crypto.getRandomValues`), sent only to the engine (over loopback, or inside the end-to-end encrypted session), never shown. The engine derives `rescopeKey` and passes Postgres only that key, never the secret; `rescope_revert` refuses unless `sha256(rescopeKey)` is the hash the proof signed. A proof pasted into the chat is worthless without the secret.
- **Nonce.** 16 random bytes per revert (`reverts.rescope_nonce`), carried in the revert request the engine serves (it reads it with the requesting role's `revert_nonce`, [Revert scope objects](basalt-meta-revert.md#revert-scope-objects)), and in the `409` the engine answers for a widened revert whose lines it no longer holds. Every proven widen consumes it and sets a new one; `reset_revert` sets a new one. A proof is good for one widen: synced passkeys report a signature counter of 0, so the counter cannot stop a replay.
- **Checks.** `rescope_revert` verifies the proof with the same checks as `submit_approval` (`_verify_assertion`: a registered, unrevoked passkey, RP ID and origin, the counter where the authenticator keeps one) and records the credential id in the `REVERT_RESCOPED` ledger row, which holds hashes only (`sha256(rescopeKey)`, old and new `rowsHash`), never a key or secret. Any proof or token failure is `REVERT_INVALID` detail `WIDEN_REFUSED`, nothing changes, and nothing is returned.
- **Check order** (so a select cannot be used to probe other agents' work). `rescope_revert` checks, in this order, and stops at the first failure:
  1. **Shape only**, from the descriptor alone: the schema (every key, types, `runs` only with `TASK`), the reserved `store` key, at most 20 runs and 20 tables. These read nothing but the request: `INVALID_ARGUMENT` (`BS011` detail `SHAPE`, `STORE_RESERVED` or `FILTER_CAP`), 400 on the pages API.
  2. **Own work.** Is the select provably inside the requesting role's own work (`agents` exactly `[requestedBy]`, the change or run its own or a task it ran in, every listed run its own run in the scope, every listed table one it wrote in the scope)? This test only answers yes or no; it raises nothing itself.
  3. **Proof or token**, for every select that is not provably own work, and for every select at all once the revert has a ceiling (below): a valid widen proof with its key, or the scope token with the select inside the ceiling. Every failure, whatever it is (no proof, a bad proof, a used nonce, a wrong key, no token, a wrong token, a select outside the ceiling, and a select naming another agent's run or table, an unknown run or table, or an agent with no changes), is `REVERT_INVALID` detail `WIDEN_REFUSED` with one fixed message, 409 on the pages API. So an agent that sends `{"agents": [itself], "scope": "TASK", "runs": [X]}` learns nothing about `X`: another agent's run and a run that does not exist read alike.
  4. **Scope membership**, only for a select that passed 3 or was own work: each listed agent, run and table must lie in the scope (`BS011` detail `FILTER` or `DESCRIPTOR`, `INVALID_ARGUMENT`, 400). Only the person, proven in 3, or the requesting role about its own work, reaches this step.
- **After a widen the token is required.** Once a revert has a ceiling (`reverts.ceiling IS NOT NULL`), `rescope_revert` (any select, own work included) and `reject_revert` refuse a call without the scope token (`REVERT_INVALID` `WIDEN_REFUSED`), or without a new valid proof for `rescope_revert`. Checking `session_user` is not enough there: the requesting agent role can call both functions directly with its own credential. The agent role's only way back is `reset_revert` (its `reissueLink`), which needs no token (owner, Q8), drops the person's scope and is recorded as such; after it the revert has no ceiling, so the agent role can then also call `reject_revert` without a token.
- **Scope token.** A proven widen returns a fresh 128-bit token; Postgres stores only its hash (`reverts.scope_token_hash`) and the proven select as the ceiling (`reverts.ceiling`). The engine keeps the token in memory with the rotated link and adds it to later narrowing calls that carry that link's secret. A narrowing select must lie inside the ceiling; no new prompt. A new proven widen replaces token and ceiling; a reset clears them.
- **What a proven call returns.** Only a call with a valid proof and key, or with the token, gets the full lines (every agent's values, `set` included) and the **catalog**: the agents with changes in the scope, their runs (id, agent, start, change count), the resources written (row counts) and `changeAgents`, the agent (`agent:<name>`) of every change in the scope by change id ([`revert-scope-response.schema.json`](../api/mcp/revert/revert-scope-response.schema.json)). No other function returns the catalog and no view an agent role reads holds it. The engine keeps those lines and the catalog in memory only, keyed by the rotated link, until the revert expires; after an engine restart `GET` with the rotated link returns the redacted view and the page asks the person to widen again. Nothing with other agents' values is written to `stateDir`.
- **The agent of each row** (owner decision Q-11). A line names its `changeIds`, not their agents. `changeAgents` maps each change in the ceiling to the agent that made it (`agent:<name>`), so it covers every change id the lines of any select inside the ceiling name. It is part of the catalog, so it has the catalog's gate and no other: only a call with a valid widen proof and key, or with the scope token of one, gets it. An own-work rescope (no proof, no ceiling), a refused call, `GET /api/v1/reverts/{revertId}`, the long link, every MCP tool and every `basalt_meta` view get no map, so the requesting agent never learns which other agents changed which rows. The page tags each row (a "Changed by" cell) with the agents its `changeIds` map to (short names, as the headline), amber when any of them is not `requestedBy`; a row whose change ids are not all in the map gets no tag rather than a guessed one. Without a catalog (before a widen) or without `changeAgents` the page tags rows only when the select names exactly one agent, as before.
- **Every rescope** rebuilds the lines in Postgres (with the trial run), replaces the binding, lines, totals, `rowsHash` and expiry, keeps `proposed`, and restarts the one-hour expiry; the revert keeps its `revertId`. A rescope that runs longer than 100 seconds (N12-R9) is `QUERY_TIMEOUT` reason `TIME_LIMIT` (504 on the pages API), nothing changes, and the page says: "Changing the scope took longer than 100 seconds and was stopped. Nothing changed. Choose fewer agents, runs or tables, or try again." A widened revert costs two passkey prompts (the proof, then the signature); signing as proposed, or narrowing, costs one. When the scope has 0 lines to restore the page disables signing and says there is nothing to revert in this scope.
- **Reset.** `reissueLink: true` (from `request_revert`, `revert_plan` or `list_pending`) on a widened revert resets it to the agent's proposal through `reset_revert` (own lines, new binding, ceiling and token cleared, new nonce, `REVERT_RESET` in the ledger) and issues a link for that. The page holding the person's rotated link then gets `NOT_FOUND` reason `LINK_RESET` ([Link secrets](local-pages.md#link-secrets)) and says: "The agent reset this revert to its own work. Ask it for the new link, and widen again if you still want to include other agents."
- **Reject.** The page's Reject (optional note up to 500 characters, which the page says the agent will read; in the decision panel on a wide screen, in the bottom bar with a note sheet on a phone) posts `POST …/reject` under the current link secret. `reject_revert` marks the revert `REJECTED`, appends `REVERT_REJECTED` with the note and the path it came by, and the engine revokes the link; the agent's wait returns `REJECTED` at once. No passkey: rejecting can only stop a revert. Before a widen the path is `LINK_OR_AGENT`: the call carried no token, so Postgres cannot tell the person on the link from the agent holding the link, or the agent role calling `reject_revert` itself. After a widen `reject_revert` requires the scope token, which only the engine holds, and adds it only for a request carrying the rotated secret; the path is then `SCOPE_TOKEN`. This does not make a widened revert's reject the person's alone: the agent role can still call `reset_revert` (no token, owner Q8), which drops the person's scope and ceiling, and then `reject_revert` with no token. The ledger then shows `REVERT_RESET` followed by `REVERT_REJECTED` with `via` `LINK_OR_AGENT`, and the page holding the person's rotated link reads `NOT_FOUND` reason `LINK_RESET`. So `SCOPE_TOKEN` proves the person rejected; `LINK_OR_AGENT` never proves who did. Whether a widened revert's end should be the person's alone is an open owner decision. After an engine restart the token is gone (it lives in memory): the person widens again to reject, or lets the revert expire. From a long link with no engine the page says "Close this page to decline; nothing happens unless you sign"; the revert expires in an hour.
- **Nothing to paste.** The page never shows the revert signature or a widen proof as a code: both go only between the page and the engine (owner, Q14).

**What the requesting agent can read** (RS-5). Every line naming a change not made by the requesting role is redacted in every view that role reads, whatever its grants (the signed lines themselves do not change):

| Where | Not widened | After a widen |
|---|---|---|
| `request_revert` wait form | As today, plus `select`; `REJECTED` | Status, totals, `widened`, a large plan's `progress`; no scope, `select`, lines or link |
| `GET /api/v1/reverts/{revertId}` with the agent's link | The request | `404 NOT_FOUND`: the link was rotated |
| `agent_reverts` | As today, plus `selection` | Status, totals, `widened`, expiry and progress; `binding_text`, `selection`, `lines` `NULL` |
| `agent_revert_lines`, `revert_plan` | As today | Line number, `outcome`, `conflict`, `sql_state`, `batch` for every line; `line` text only where every change it names is the caller's |
| `list_pending` | The headline from the binding | "Revert widened by the person: N rows to restore." and no scope or link (LP-3) |
