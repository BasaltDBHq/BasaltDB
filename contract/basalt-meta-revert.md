> Part of **`basalt_meta`**. The section starts in [basalt-meta.md](basalt-meta.md).

### Revert objects

#### Versions 5 to 7 (M3): revert

Version 5 is the read-only plan, version 6 the trial run and prepared reverts, version 7 `apply_revert`.

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

#### Version 9: large reverts

N12-1 to N12-6.

| Object | Purpose |
|---|---|
| `reverts` | Gains `batched`, `sample_hash`, `covered` (the changes in scope at prepare), `signed_at`, `apply_by`, `batches` |
| `revert_lines` | A large plan's lines: number, text, the row's ledger chain, `outcome` (`PENDING`, `RESTORED`, `SKIPPED`), `conflict`, `sql_state`, `batch`. Text and chain pruned after 30 days |
| `agent_reverts` | Gains `batched`, `signed_at`, `apply_by`, `restored`, `skipped_now`, `pending`; status gains `APPLYING` |
| `agent_revert_lines` | The calling role's plan lines: `revert_id`, `line_no`, `line`, `outcome`, `conflict`, `sql_state`, `batch` |
| `apply_revert(...)` | For a large plan: verify the assertion and record the signature (`REVERT_SIGNED`); returns `{changeId, rows: 0, skipped, batched: true, pending, applyBy}` |
| `apply_revert_batch(revert_id uuid, lines int[]) returns jsonb` | The role that prepared the plan: apply up to 200 pending lines (see [Large plans](revert.md#large-plans)) |

Ledger kinds `REVERT_SIGNED` (detail `revertId`, `scope`, `scopeId`, `intent`, `credentialId`, `binding`, `lines`, `rows`, `skipped`, `applyBy`) and `REVERT_BATCH` (detail `revertId`, `batch`, `lines`, `rows`, `skipped`, `pending`); a large plan's `REVERTED` row carries `rows`, `skipped` (a count) and `batches`.

#### Version 17: a large plan's sample keeps restored rows

RSS-1 (amending N12-4). Up to version 16 a batched plan's sample was the first 1000 lines with `SKIP` lines first, so a plan with 1000 or more `SKIP` lines showed no `RESTORE` line.

| Object | Purpose |
|---|---|
| `_revert_sample(lines text[], max int) returns text[]` | Internal. The sample of [Large plans](revert.md#large-plans): up to `max / 2` lines of each kind, the other kind filling the rest, `SKIP` lines first, each kind in signed order. The same as `revert.Sample` in Go |
| `prepare_revert` | Replaced: the same as version 9's, with the sample from `_revert_sample` |

### Revert scope objects

#### Version 20: revert scope

Owner decisions RS-1 to RS-7. Version 20 is the `reverts` columns, `agent_reverts`, `preview_revert`, `prepare_revert`, `apply_revert` and `apply_revert_batch` rows below and the migration. `rescope_revert`, `reset_revert`, the `agent_revert_lines` redaction and their ledger kinds are [version 21](#version-21-widen-proof-rescope-and-reset); `reject_revert` is [version 23](#version-23-reject-a-revert). Version 19 is [the PII fingerprint by oid](basalt-meta.md#version-19-the-pii-fingerprint-names-columns-by-oid), already on master. If another change takes 20 first, this one takes the next free number. **Breaking** (AE-11): the engine calls functions with new signatures. Rules in [Revert](revert.md#revert): [The scope descriptor](revert.md#the-scope-descriptor) and [Rescope, widen and reject](revert.md#rescope-widen-and-reject).

| Object | Purpose |
|---|---|
| `reverts` | `selection jsonb NOT NULL` becomes the one source of the scope; `scope`, `scope_id` and `agents` become generated columns (`GENERATED ALWAYS AS (…) STORED`, the agents array through an `IMMUTABLE` helper), so they cannot disagree with it and existing indexes and views keep working. New: `proposed jsonb NOT NULL`; `widened boolean NOT NULL GENERATED ALWAYS AS (_widened(selection, requested_by)) STORED` (true when `selection->'agents'` is `null` or names a role other than `requested_by`); `ceiling jsonb` (the widest proven select); `scope_token_hash bytea`; `rescope_nonce bytea NOT NULL` (16 random bytes); `rescoped int NOT NULL DEFAULT 0`; `rejected_at timestamptz`, `reject_note text`; `CHECK ((ceiling IS NULL) = (scope_token_hash IS NULL))`. "Inside the requester's own work" needs the ledger, so the functions that write `selection` test it, not a `CHECK` |
| `agent_reverts` | Status gains `REJECTED`; gains `selection`, `widened`, `rejected_at`, `reject_note`. For a widened revert `binding_text`, `selection` and `lines` are `NULL` |
| `preview_revert(p_select jsonb) returns setof text` | Replaces `(scope text, scope_id uuid)`. For an agent role, own work only: `agents` exactly `[session_user]`, the change or run its own or a task it ran in, `runs` and `tables` inside that work, at most 20 each, no `store`. Normalizes the descriptor, then plans as before |
| `prepare_revert(p_select jsonb, p_intent text)` | Replaces `(scope text, scope_id uuid, intent text)`, same result columns. Own work only, as `preview_revert`. Stores `selection = proposed = p_select` (normalized) and a fresh nonce, and builds the binding from the stored row. For a `TASK` the caller ran in, an own proposal with no lines is stored instead of `NOTHING_TO_REVERT` (it cannot be signed until widened); the MCP tools never store one, they answer `NOTHING_TO_REVERT` |
| `apply_revert`, `apply_revert_batch` | Lock the revert row before checking; recompute or check lines from the stored `selection`; `apply_revert` refuses (`REVERT_INVALID`) a binding whose `select` is not the stored `selection`, and a `REJECTED` revert |


**Migration.** Every existing revert gets `selection` from its `scope`, `scope_id` and `agents` (`runs` and `tables` `null`), `proposed = selection` and a nonce; then the old columns become the generated ones and the views that use them are recreated. Reverts from the M3-14 era whose `agents` name other roles come out `widened`. Every `PENDING` revert with no signature gets `expires_at = now()` (its old binding has no `select`); when there was any, a `MIGRATION` ledger row notes the count (detail `version: 20`, `revertsExpired`). Like every migration from version 16, it is idempotent. A large plan signed before the upgrade (`APPLYING`, within its 24 hours) keeps its numbered lines and old binding and finishes as signed: `apply_revert_batch` checks each line against its stored signed text, not the binding's `select`. An engine on an older guard answers `UNAVAILABLE` `GUARD_OUTDATED`; the upgrade is `basalt upgrade` or an `UPGRADE` setup code.

#### Version 21: widen proof, rescope and reset

Owner decisions RS-2 and RS-5. Rules in [Rescope, widen and reject](revert.md#rescope-widen-and-reject). Version 20 already adds the `reverts` columns these use (`proposed`, `ceiling`, `scope_token_hash`, `rescope_nonce`, `rescoped`). **Breaking** (AE-11), the default. Like every migration from version 16, it is idempotent.

| Object | Purpose |
|---|---|
| `rescope_revert(p_revert_id uuid, p_select jsonb, p_proof jsonb, p_rescope_key bytea, p_token bytea) returns jsonb` | New. Shape first (`BS011` `SHAPE`, `STORE_RESERVED`, `FILTER_CAP`, from `p_select` alone). Then locks the revert row (`FOR UPDATE`); only a `PENDING`, unsigned, unexpired revert prepared by `session_user` (another role's revert reads like an unknown id: `REVERT_INVALID` "no such revert"). Then, in the [check order](revert.md#rescope-widen-and-reject): with `p_proof` (`{credentialId, authenticatorData, clientDataJson, signature}`, base64url), the proof must verify (`_verify_assertion`; any error while checking it counts as a bad proof) over the widen challenge with the current `rescope_nonce` and `p_rescope_key` (32 bytes); the nonce is then replaced, the select becomes the ceiling and a new scope token is returned (only `sha256` of it is stored). Without a proof: own work while the revert has no ceiling; once it has one, `p_token` whose `sha256` is `scope_token_hash` and a select inside the ceiling (the same scope; `agents`, `runs`, `tables` each a subset of the ceiling's, any when the ceiling's is `null`). Every failure there is `BS005` `REVERT_INVALID` detail `WIDEN_REFUSED` with one fixed hint. Then scope membership: the scope is the proposal's, or the run or task the proposal's change or run belongs to, and each listed agent other than the requester has a change in it (`BS011` `DESCRIPTOR`); each listed run is a run of the task by a selected agent and each listed table was written in the scope by them (`BS011` `FILTER`). Rebuilds the lines as `prepare_revert` does (a `TASK` with no line is stored empty; any other scope with nothing to restore is `NOTHING_TO_REVERT`); replaces `selection`, lines, totals, `rows_hash`, binding and expiry (one hour from now); keeps `proposed`; `rescoped + 1`; appends `REVERT_RESCOPED`. Returns `{revertId, binding, expiresAt, lines, rescopeNonce}` (`lines` is a large plan's sample), plus `catalog` ([`revert-scope-response.schema.json`](../api/mcp/revert/revert-scope-response.schema.json), computed from the ceiling) for a proven or token-bearing call and `scopeToken` (16 bytes, base64url) for a proven one |
| `reset_revert(p_revert_id uuid) returns jsonb` | New, for the agent's `reissueLink`. Locks the row; only a `PENDING`, unsigned, unexpired revert prepared by `session_user`. Back to `proposed`: lines rebuilt, ceiling and token cleared, new nonce, new binding and expiry; appends `REVERT_RESET`. Needs no token: it only ever narrows to the agent's own proposal (owner, Q8). Returns `{revertId, binding, expiresAt, lines, rescopeNonce}` |
| `preview_revert`, `prepare_revert` | The change of a widened revert (its `op: REVERT` change, recorded under the relaying role) is not the role's own: `BS011` `NOT_OWN_CHANGE`, the same text as an unknown change, so an agent cannot preview or request an undo that would show it the rows and old values the person added (RS-5). Undoing a revert of the agent's own work is unchanged (AE-14) |
| `agent_revert_lines` | For a widened revert, `line` is `NULL` unless every change the line names (its `changeIds`) is the requesting role's. Line numbers, `outcome`, `conflict`, `sql_state` and `batch` stay, so the agent can still apply a signed plan's batches |
| `agent_ledger` | Redacts what a widened revert names of other agents' work. A row whose detail names a `revertId` (`REVERT_PENDING`, `REVERT_SIGNED`, `REVERT_BATCH`, `REVERTED`, `REVERT_RESCOPED`, `REVERT_RESET`) shows `detail` as `{revertId, widened: true, via}` only (`via` when the row has one) when that revert is widened now, or when the row's `select`, `oldSelect` or `droppedSelect` covers changes not made by the row's agent: their `skipped` lists copy the skipped lines' tables and keys, and the selects name other roles and runs. A `ROW_CHANGE` written by the change of a widened revert, for a row whose reverted changes (`revertOf`) are not all the row's agent's, shows no `table_name`, `row_key`, `old_row` or `new_row`, `detail` `{widened: true}`, and `redacted = true` |
| `changes` | Index `changes_task_agent (task_id, agent, change_id)`: an agent's task proposal is looked up by task and agent, so its cost does not grow with other agents' changes in the task |

All new functions are `SECURITY DEFINER` with `SET search_path = pg_catalog`, owned by `<prefix>_guard`; `EXECUTE` on `rescope_revert` and `reset_revert` is granted to `<prefix>_agents` only, and no function in `basalt_meta` is executable by `PUBLIC`. The link secret never reaches Postgres: `rescope_revert` takes only the key the engine derives from it, and records only its `sha256`.

Ledger kinds `REVERT_RESCOPED` (detail `revertId`, `oldSelect`, `select`, `oldRowsHash`, `rowsHash`, `via` the path Postgres checked: `OWN_WORK` (no proof or token: the person on the link, the agent holding it, or the agent role directly, which Postgres cannot tell apart), `PROOF` (with `credentialId` as lowercase hex and `rescopeKeyHash` = hex `sha256(rescopeKey)`) or `SCOPE_TOKEN`; never a key, secret or token) and `REVERT_RESET` (`revertId`, `droppedSelect`, `oldRowsHash`, `rowsHash`; always the requesting role).

#### Version 22: the rescope nonce

Owner decision RS-2. The engine serves the revert's `rescopeNonce` on `GET /api/v1/reverts/{revertId}` at any time, an engine restart included, so the page can always ask the person for a widen proof. **Breaking** (AE-11), the default: the engine calls the new function. Idempotent.

| Object | Purpose |
|---|---|
| `revert_nonce(p_revert_id uuid) returns bytea` | New. The `rescope_nonce` of a revert prepared by `session_user`; another role's revert or an unknown id is `REVERT_INVALID` "no such revert", alike. `SECURITY DEFINER`, `SET search_path = pg_catalog`, `EXECUTE` for `<prefix>_agents` only, none for `PUBLIC`. The nonce is worthless without the person's passkey and the page's new link secret, and the role could already read it from an own-work `rescope_revert` |

#### Version 23: reject a revert

Owner decisions RS-2 and Q8 ("agent can propose, human can agree, rescope, or reject"). Rules in [Rescope, widen and reject](revert.md#rescope-widen-and-reject). Version 20 already adds the `reverts` columns (`rejected_at`, `reject_note` with its 500-character check) and `REJECTED` in `agent_reverts`; `apply_revert`, `rescope_revert` and `reset_revert` already refuse a `REJECTED` revert. **Breaking** (AE-11), the default: the engine calls the new function. Idempotent.

| Object | Purpose |
|---|---|
| `reject_revert(p_revert_id uuid, p_note text, p_token bytea) returns jsonb` | New. The note first, from `p_note` alone: `NULL` or `''` for none, at most 500 characters (`BS008` `LEDGER_INPUT_INVALID` otherwise). Then locks the revert row (`FOR UPDATE`); only a `PENDING`, unsigned, unexpired revert prepared by `session_user` (another role's revert reads like an unknown id: `REVERT_INVALID` "no such revert"; an applied, signed or rejected one is `REVERT_INVALID`, an expired one `REVERT_EXPIRED`). Then the token: while the revert has no ceiling, `p_token` must be `NULL`; once it has one, `p_token` must be its scope token. Every token failure is `REVERT_INVALID` detail `WIDEN_REFUSED` with the one fixed hint of `rescope_revert`. Sets `rejected_at` and `reject_note`, appends `REVERT_REJECTED`. Returns `{revertId, status: "REJECTED", rejectedAt}`. `SECURITY DEFINER`, `SET search_path = pg_catalog`, `EXECUTE` for `<prefix>_agents` only, none for `PUBLIC` |

Ledger kind `REVERT_REJECTED` (detail `revertId`, `note` when there is one, `via`: `LINK_OR_AGENT` without a token, `SCOPE_TOKEN` with one; never the token). For a widened revert `agent_ledger` shows the requesting role only `{revertId, widened: true, via}`, as for every revert row (version 21); the note reaches the agent through `agent_reverts.reject_note` and the wait form.

#### Version 32: the agent of each change in the catalog

Owner decision Q-11. Rules in [Rescope, widen and reject](revert.md#rescope-widen-and-reject), "The agent of each row". The revert page could tag rows with their agent only when the select named one agent, because a line names its `changeIds` and not their agents. The catalog a proven call returns now also maps each change to its agent. **Non-breaking** (AE-11): on an older guard the catalog has no `changeAgents`, the page falls back to tagging single-agent selects only, and nothing else changes; the engine test that serves an agent on a guard without it covers the flag. Idempotent.

| Object | Purpose |
|---|---|
| `_revert_catalog` | Replaced, same signature, `SECURITY DEFINER`, `STABLE`, owner and grants as version 21's (no `EXECUTE` for `<prefix>_agents` or `PUBLIC`), `SET search_path = pg_catalog, pg_temp`. The same `agents`, `runs` and `tables`, plus `changeAgents`: a `jsonb` object from each change id in `_revert_scope(p_sel)` (lowercase canonical UUID text) to its `changes.agent`, `{}` when the scope has no change. `rescope_revert` still calls it only for a `PROOF` or `SCOPE_TOKEN` call, with the ceiling, and returns it only in `catalog` |
| `rescope_revert`, `reset_revert`, `agent_reverts`, `agent_revert_lines` | Unchanged: an `OWN_WORK` rescope and `reset_revert` return no catalog, and no view or other function returns the catalog or the map |

### Reveal objects

#### Version 29: reveal hidden revert rows

Installed; the engine's reveal route is planned. Owner decisions HR-1 and HR-3. Rules in [Rows hidden from the agent](approvals.md#rows-hidden-from-the-agent). **Breaking** (AE-11), the default: the engine calls the new functions. Idempotent.

| Object | Purpose |
|---|---|
| `approvals`, `reverts` | Gain `reveal_nonce bytea NOT NULL DEFAULT basalt_meta._revert_nonce()`: 16 random bytes, so every approval `hold_action` stores and every revert `prepare_revert` stores gets one without either function changing; the migration gives every existing row one. The approvals' nonce is used from [version 30](#version-30-reveal-hidden-approval-rows) |
| `agent_approvals`, `agent_reverts` | Unchanged: neither shows `reveal_nonce` |
| `reveal_nonce(p_kind text, p_id uuid) returns bytea` | New. `p_kind` `APPROVE` or `REVERT` (anything else `BS008` `LEDGER_INPUT_INVALID`). The `reveal_nonce` of an approval held by, or a revert prepared by, `session_user`; another role's item or an unknown id is `APPROVAL_INVALID` "no such approval" or `REVERT_INVALID` "no such revert", alike. The nonce is worthless without the person's passkey |
| `reveal_revert_rows(p_revert_id uuid, p_proof jsonb, p_reveal_key bytea) returns jsonb` | New. Locks the revert row (`FOR UPDATE`, so it serializes with `apply_revert`, `rescope_revert`, `reset_revert` and `reject_revert`); only a revert prepared by `session_user` (otherwise `REVERT_INVALID` "no such revert"), `PENDING`, unsigned and not rejected (`REVERT_INVALID`), and unexpired (`REVERT_EXPIRED`). Then the proof: `p_proof` (`{credentialId, authenticatorData, clientDataJson, signature}`, base64url) must verify through `_verify_assertion` over the [reveal challenge](approvals.md#rows-hidden-from-the-agent) with kind `REVERT`, the current `reveal_nonce`, `sha256(p_reveal_key)` (32 bytes) and the binding's `rowsHash`; every failure, a missing proof or key and any error while checking it included, is `BS005` `REVERT_INVALID` detail `REVEAL_REFUSED` with one fixed hint, and changes nothing. Then it replaces `reveal_nonce`, rebuilds every redacted line the revert request carries (all lines, or a large plan's sample) through `_reveal_revert_line`, appends `ROWS_REVEALED` and returns `{rows}` (the [answer](approvals.md#rows-hidden-from-the-agent)). When a rebuilt line no longer hashes to its `rowHash` it returns `{rowsChanged: true}` and no row, and the ledger row says so; it does not raise, so the new nonce commits. The engine answers that `409 REVERT_INVALID` reason `ROWS_CHANGED` |
| `_reveal_proven`, `_reveal_refused`, `_reveal_row` | New, internal, not granted to agents: the reveal proof and key check (any error while checking is a bad proof), the one `REVEAL_REFUSED` error (`_reveal_refused` is a plain raiser, not `SECURITY DEFINER`, like `_widen_refused`), and a row's text with its `SECRET` columns null and named, which [version 30](#version-30-reveal-hidden-approval-rows) reuses |
| `_reveal_revert_line` | New, internal, not granted to agents: the full text of a revert line as `_revert_line` builds it, without `_line_visible`'s redaction, every `SECRET` column (`pii_columns`) `null`, and the names of those columns. Rebuilds a large plan's line from `revert_lines.chain` and the live row |

All new functions are `SECURITY DEFINER` with `SET search_path = pg_catalog, pg_temp`, owned by `<prefix>_guard`; `EXECUTE` on `reveal_nonce` and `reveal_revert_rows` is granted to `<prefix>_agents` only, and none to `PUBLIC`. The reveal secret never reaches Postgres: it takes only the key the engine derives, and records nothing of it.

Ledger kind `ROWS_REVEALED` (detail `kind` `APPROVE` or `REVERT`, `id`, `credentialId` as lowercase hex, `rows` the number of redacted lines the proof asked for, and `rowsChanged: true` on a revert whose rows changed; hashes and counts only, never a value or key). `agent_ledger` shows it as it is.

#### Version 30: reveal hidden approval rows

Installed; the engine's reveal route is planned. Owner decisions HR-1 to HR-3. Rules in [Rows hidden from the agent](approvals.md#rows-hidden-from-the-agent). **Breaking** (AE-11), the default. Idempotent.

| Object | Purpose |
|---|---|
| `approvals` | Gains `reveal_ticket_hash bytea` and `reveal_until timestamptz`, both `NULL` until a reveal opens. `agent_approvals` shows neither |
| `open_reveal(p_approval_id uuid, p_proof jsonb, p_reveal_key bytea) returns bytea` | New. Locks the approval row (`FOR UPDATE`); only an approval held by `session_user` (otherwise `APPROVAL_INVALID` "no such approval"), not approved and not used (`APPROVAL_INVALID`), and unexpired (`APPROVAL_EXPIRED`). The proof and key as in `reveal_revert_rows`, with kind `APPROVE` (`BS005` `APPROVAL_INVALID` detail `REVEAL_REFUSED`, one fixed hint). Then it replaces `reveal_nonce`, appends `ROWS_REVEALED` (`rows` the number of redacted lines held), stores `sha256` of a fresh 16-byte ticket in `reveal_ticket_hash` with `reveal_until = clock_timestamp() + 2 minutes` (replacing any earlier ticket), and returns the ticket. It never returns a value |
| `reveal_approval_rows(p_approval_id uuid, p_ticket bytea) returns jsonb` | New. Only inside a `PREVIEW` transaction (`basalt.mode`) that has run the held statement and recorded it with `finish_change`, as an apply does; it reads that preview's change as `preview_lines` does. Locked the approval row (`FOR UPDATE`) until [version 31](#version-31-the-approval-reveal-reads-the-approval-unlocked), which reads it without a lock; the approval checks of `open_reveal`. Then `sha256(p_ticket)` must equal `reveal_ticket_hash` and `clock_timestamp()` be before `reveal_until`. Then, as `_commit_approval` checks an apply, the preview change's recorded `statement`, `params` and run are the approval's (the change belongs to `session_user`, the approval's agent). `finish_change` in a preview stamps the change and appends a `CHANGE` ledger row, both rolled back with the preview. Every mode, statement, parameter, run or ticket failure is `BS005` `APPROVAL_INVALID` detail `REVEAL_REFUSED`, the same hint as `open_reveal`. Then it builds this preview's lines twice: as `_lines` does (redacted for `session_user`), which must equal the held `approvals.lines` exactly, or `BS005` `APPROVAL_INVALID` detail `ROWS_CHANGED`; and through `_reveal_lines`. Returns the [answer](approvals.md#rows-hidden-from-the-agent) for every redacted held line. The preview rolls back, so nothing it did, the row locks included, outlasts the call's transaction |
| `_reveal_lines`, `_reveal_approval_lock` | New, internal, not granted to agents: the rows of a change as `_lines` builds its lines, without the table-privilege redaction (table, `rowHash`, and the row through `_reveal_row`); and the caller's own approval, locked, while it can still be signed |

All new functions are `SECURITY DEFINER` with `SET search_path = pg_catalog, pg_temp`, owned by `<prefix>_guard`; `EXECUTE` on `open_reveal` and `reveal_approval_rows` is granted to `<prefix>_agents` only, and none to `PUBLIC`. The ticket exists only as the return value of `open_reveal`, in the engine's memory for one request, and as a bind parameter; Postgres stores only its `sha256`. `reveal_approval_rows` runs after the agent's own statement in the same transaction, so, like every function here, it names every relation fully and keeps `pg_temp` last in `search_path`.

#### Version 31: the approval reveal reads the approval unlocked

Version 30's `reveal_approval_rows` locked the approval row (`FOR UPDATE`) after the re-run preview had run the held statement, whose `ROW_CHANGE` ledger rows take `chain_head`. `submit_approval` takes the same locks in the other order: the approval row, then `chain_head` in `_append`. A reveal racing the person's signature could hold `chain_head` and wait for the approval row while the signature held the approval row and waited for `chain_head`, and Postgres broke the deadlock (`40P01`). **Breaking** (AE-11), the default. Idempotent.

| Object | Purpose |
|---|---|
| `reveal_approval_rows` | Replaced, same signature, `SECURITY DEFINER`, owner and grants as version 30's, `SET search_path = pg_catalog, pg_temp`. Reads the caller's approval without a lock and keeps every version 30 check, in the same order: `PREVIEW` mode; an approval held by `session_user` (otherwise "no such approval"), not used, not approved, unexpired; the ticket and its window; the preview change's recorded `statement`, `params` and run; the preview's lines equal to the held lines (`ROWS_CHANGED`). Nothing in this transaction needs the lock: `open_reveal`, which still locks the row, has already replaced the nonce and stored the ticket, and the preview rolls back without writing to the approval. A reveal that reads the row before a racing signature commits returns the values of the write the person is signing; one that reads it after gets `APPROVAL_INVALID` "approval already approved", as an apply racing a reveal gets the approval's normal answer |
| `open_reveal`, `_reveal_approval_lock` | Unchanged: `open_reveal` still locks the approval row (`FOR UPDATE`), and takes `chain_head` after it, in `submit_approval`'s order |
