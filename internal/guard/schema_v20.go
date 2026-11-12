package guard

// Version 20: revert scope, the core (owner decisions RS-1 to RS-4; plan
// docs/redesign/plans/2026-11-12-revert-scope-person-chooses.md, task 2;
// CONTRACT.md, basalt_meta "Version 20" and Revert "The scope descriptor").
//
// What a revert covers is now its scope descriptor (reverts.selection): a
// CHANGE, RUN or TASK narrowed to some agents, runs and tables. scope,
// scope_id and agents become columns generated from it, so they cannot
// disagree with it. preview_revert and prepare_revert take the descriptor
// and accept, from an agent role, only its own work: agents exactly
// [session_user], its own change or run or a task it ran in, and runs and
// tables inside that work. The binding carries the descriptor as select
// (and proposed when a later rescope changes it), and apply_revert refuses
// a binding whose select is not the stored one and recomputes the lines
// from the stored selection.
//
// Unsigned PENDING reverts are expired: their bindings have no select.
// Signed large plans keep running: apply_revert_batch checks each line
// against its stored signed text, never the binding's select.
//
// Breaking (AE-11): preview_revert and prepare_revert change signatures.
// Rescope, reset and reject come in later versions of this plan.

const v20Descriptor = `
-- 16 random bytes for a revert's rescope nonce, from pg_strong_random
-- (gen_random_uuid): two v4 uuids carry 244 random bits, hashed down.
CREATE OR REPLACE FUNCTION basalt_meta._revert_nonce() RETURNS bytea
LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT substring(sha256(uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid())) FROM 1 FOR 16)
$$;

-- The agents of a descriptor as roles, NULL when it selects every agent.
-- IMMUTABLE: reverts.agents is generated from it.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_agents(p_sel jsonb) RETURNS name[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT CASE WHEN jsonb_typeof(p_sel -> 'agents') = 'array'
                THEN ARRAY(SELECT a::name FROM jsonb_array_elements_text(p_sel -> 'agents') a) END
$$;

-- True when a descriptor covers changes not made by p_role: its agents is
-- null (every agent) or names another role. IMMUTABLE: reverts.widened is
-- generated from it.
CREATE OR REPLACE FUNCTION basalt_meta._widened(p_sel jsonb, p_role name) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(p_sel -> 'agents') IS DISTINCT FROM 'array'
        OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_sel -> 'agents') a WHERE a <> p_role::text)
$$;

-- A scope descriptor refused (BS011): DETAIL is the reason the engine maps
-- (SHAPE, STORE_RESERVED, FILTER_CAP, NOT_OWN_CHANGE, NOT_OWN_RUN,
-- NOT_OWN_TASK, FILTER), HINT what to change.
CREATE OR REPLACE FUNCTION basalt_meta._scope_refused(p_detail text, p_hint text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS011', MESSAGE = 'SCOPE_REFUSED', DETAIL = p_detail, HINT = p_hint;
END $$;

-- A JSON list of the descriptor (agents, runs or tables) sorted by its text
-- COLLATE "C" and deduplicated, or JSON null.
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_list(p_list jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT CASE WHEN jsonb_typeof(p_list) = 'array'
                THEN (SELECT to_jsonb(array_agg(s.e ORDER BY s.e COLLATE "C"))
                        FROM (SELECT DISTINCT e FROM jsonb_array_elements_text(p_list) e) s)
                ELSE 'null'::jsonb END
$$;

-- The descriptor checked for shape and normalized (CONTRACT.md, The scope
-- descriptor): every key present, lists sorted and deduplicated, null for
-- all, ids in canonical form. Reads nothing but its argument, so a refusal
-- here says nothing about any data: SHAPE, STORE_RESERVED (RS-4) or
-- FILTER_CAP (at most 20 runs and 20 tables).
CREATE OR REPLACE FUNCTION basalt_meta._revert_select_norm(p jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    c_max_filter constant int  := 20; -- runs and tables in a descriptor (owner, Q10)
    c_max_name   constant int  := 63; -- NAMEDATALEN - 1
    c_uuid       constant text := '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
    c_table      constant text := '^[^.\s]+\.[^.\s]+$';
    v_key  text;
    v_list text;
BEGIN
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'the scope descriptor is a JSON object');
    END IF;
    IF p ? 'store' THEN
        PERFORM basalt_meta._scope_refused('STORE_RESERVED', 'store is reserved for multi-database work; leave it out');
    END IF;
    SELECT k INTO v_key FROM jsonb_object_keys(p) k
     WHERE k NOT IN ('scope', 'scopeId', 'agents', 'runs', 'tables') ORDER BY k LIMIT 1;
    IF FOUND THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'the scope descriptor has only scope, scopeId, agents, runs and tables');
    END IF;
    FOREACH v_key IN ARRAY ARRAY['scope', 'scopeId', 'agents', 'runs', 'tables'] LOOP
        IF NOT p ? v_key THEN
            PERFORM basalt_meta._scope_refused('SHAPE', format('%s is required (null for all)', v_key));
        END IF;
    END LOOP;
    IF jsonb_typeof(p -> 'scope') IS DISTINCT FROM 'string' OR p ->> 'scope' NOT IN ('CHANGE', 'RUN', 'TASK') THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'scope is CHANGE, RUN or TASK');
    END IF;
    IF jsonb_typeof(p -> 'scopeId') IS DISTINCT FROM 'string' OR p ->> 'scopeId' !~ c_uuid THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'scopeId is a uuid');
    END IF;
    FOREACH v_list IN ARRAY ARRAY['agents', 'runs', 'tables'] LOOP
        CONTINUE WHEN jsonb_typeof(p -> v_list) = 'null';
        IF jsonb_typeof(p -> v_list) IS DISTINCT FROM 'array' OR jsonb_array_length(p -> v_list) = 0 THEN
            PERFORM basalt_meta._scope_refused('SHAPE', format('%s is null (all) or a list of at least one', v_list));
        END IF;
        IF v_list <> 'agents' AND jsonb_array_length(p -> v_list) > c_max_filter THEN
            PERFORM basalt_meta._scope_refused('FILTER_CAP', format('%s has at most %s entries; leave it null for all', v_list, c_max_filter));
        END IF;
        IF EXISTS (SELECT 1 FROM jsonb_array_elements(p -> v_list) e
                    WHERE jsonb_typeof(e) IS DISTINCT FROM 'string'
                       OR CASE v_list WHEN 'agents' THEN length(e #>> '{}') NOT BETWEEN 1 AND c_max_name
                                      WHEN 'runs' THEN (e #>> '{}') !~ c_uuid
                                      ELSE (e #>> '{}') !~ c_table END) THEN
            PERFORM basalt_meta._scope_refused('SHAPE', CASE v_list WHEN 'agents' THEN 'agents are role names'
                                                                     WHEN 'runs' THEN 'runs are run ids'
                                                                     ELSE 'tables are schema.table names' END);
        END IF;
    END LOOP;
    IF jsonb_typeof(p -> 'runs') = 'array' AND p ->> 'scope' <> 'TASK' THEN
        PERFORM basalt_meta._scope_refused('SHAPE', 'runs is only for a TASK scope: a change or a run is one run already');
    END IF;
    RETURN jsonb_build_object(
        'scope', p ->> 'scope',
        'scopeId', ((p ->> 'scopeId')::uuid)::text,
        'agents', basalt_meta._revert_select_list(p -> 'agents'),
        'runs', CASE WHEN jsonb_typeof(p -> 'runs') = 'array'
                     THEN basalt_meta._revert_select_list(
                              (SELECT jsonb_agg(((e)::uuid)::text) FROM jsonb_array_elements_text(p -> 'runs') e))
                     ELSE 'null'::jsonb END,
        'tables', basalt_meta._revert_select_list(p -> 'tables'));
END $$;

-- The changes a descriptor covers: applied (or already reverted) writes,
-- reverts included, of the scope, by its agents (every agent when null), in
-- its runs (every run when null). Version 5's _revert_scope with the
-- agents and runs filters.
CREATE OR REPLACE FUNCTION basalt_meta._revert_scope(p_sel jsonb) RETURNS TABLE (change_id uuid, agent name)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT c.change_id, c.agent FROM basalt_meta.changes c
     WHERE c.mode = 'APPLY' AND c.status IN ('APPLIED', 'REVERTED')
       AND c.op IN ('INSERT', 'UPDATE', 'DELETE', 'REVERT')
       AND CASE p_sel ->> 'scope' WHEN 'CHANGE' THEN c.change_id = (p_sel ->> 'scopeId')::uuid
                                  WHEN 'RUN' THEN c.run_id = (p_sel ->> 'scopeId')::uuid
                                  ELSE c.task_id = (p_sel ->> 'scopeId')::uuid END
       AND (jsonb_typeof(p_sel -> 'agents') IS DISTINCT FROM 'array' OR (p_sel -> 'agents') ? c.agent::text)
       AND (jsonb_typeof(p_sel -> 'runs') IS DISTINCT FROM 'array' OR (p_sel -> 'runs') ? c.run_id::text)
$$;

-- The ledger rows a descriptor covers: the row changes of its changes, on
-- its tables (every table when null). A table filter filters rows, not
-- changes: a change that wrote two tables can be half selected.
CREATE OR REPLACE FUNCTION basalt_meta._revert_rows(p_sel jsonb) RETURNS SETOF basalt_meta.ledger
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT x.* FROM basalt_meta.ledger x
     WHERE x.kind = 'ROW_CHANGE'
       AND x.change_id IN (SELECT s.change_id FROM basalt_meta._revert_scope(p_sel) s)
       AND (jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array' OR (p_sel -> 'tables') ? x.table_name)
$$;

-- The changes a revert of the descriptor covers: those of _revert_scope
-- with a row change on its tables (all of them without a table filter).
-- They get the revert in reverted_by.
CREATE OR REPLACE FUNCTION basalt_meta._revert_covered(p_sel jsonb) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT s.change_id FROM basalt_meta._revert_scope(p_sel) s
     WHERE jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array'
        OR EXISTS (SELECT 1 FROM basalt_meta.ledger x
                    WHERE x.kind = 'ROW_CHANGE' AND x.change_id = s.change_id AND (p_sel -> 'tables') ? x.table_name)
$$;

-- True when a revert of the descriptor covers every row change of change
-- p_change (no table filter leaves one out), so the change may become
-- REVERTED.
CREATE OR REPLACE FUNCTION basalt_meta._revert_whole(p_sel jsonb, p_change uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT jsonb_typeof(p_sel -> 'tables') IS DISTINCT FROM 'array'
        OR NOT EXISTS (SELECT 1 FROM basalt_meta.ledger x
                        WHERE x.kind = 'ROW_CHANGE' AND x.change_id = p_change
                          AND NOT (p_sel -> 'tables') ? x.table_name)
$$;

-- The descriptor p as an agent role's own proposal (RS-1): normalized,
-- agents exactly [session_user], its own change or run or a task it ran in
-- (any of its runs with that task id), and every listed run and table
-- inside that work. Refusals name only what the caller sent, with one
-- fixed text per kind, so another agent's change, run or table reads like
-- one that does not exist.
CREATE OR REPLACE FUNCTION basalt_meta._revert_own_select(p jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_sel     jsonb := basalt_meta._revert_select_norm(p);
    v_role    name := session_user;
    v_id      uuid := (v_sel ->> 'scopeId')::uuid;
    v_own     jsonb;
    v_refused text[];
BEGIN
    IF v_sel -> 'agents' IS DISTINCT FROM jsonb_build_array(v_role::text) THEN
        PERFORM basalt_meta._scope_refused('FILTER', 'agents is exactly your own role: an agent proposes only its own work');
    END IF;
    CASE v_sel ->> 'scope'
    WHEN 'CHANGE' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.changes c WHERE c.change_id = v_id AND c.agent = v_role) THEN
            PERFORM basalt_meta._scope_refused('NOT_OWN_CHANGE', format('change %s is not one of your changes', v_id));
        END IF;
    WHEN 'RUN' THEN
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.run_id = v_id AND r.agent = v_role) THEN
            PERFORM basalt_meta._scope_refused('NOT_OWN_RUN', format('run %s is not one of your runs', v_id));
        END IF;
    ELSE
        IF NOT EXISTS (SELECT 1 FROM basalt_meta.runs r WHERE r.task_id = v_id AND r.agent = v_role) THEN
            PERFORM basalt_meta._scope_refused('NOT_OWN_TASK', format('you have no run in task %s', v_id));
        END IF;
    END CASE;
    v_own := v_sel || jsonb_build_object('runs', NULL, 'tables', NULL);
    v_refused := ARRAY(
        SELECT format('run %s is not one of your runs in task %s', u.run, v_id)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(v_sel -> 'runs') = 'array' THEN v_sel -> 'runs' ELSE '[]' END) u(run)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.runs r
                            WHERE r.run_id = u.run::uuid AND r.task_id = v_id AND r.agent = v_role)
        UNION ALL
        SELECT format('%s has no change of yours in this scope', u.tbl)
          FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(v_sel -> 'tables') = 'array' THEN v_sel -> 'tables' ELSE '[]' END) u(tbl)
         WHERE NOT EXISTS (SELECT 1 FROM basalt_meta._revert_rows(v_own) x WHERE x.table_name = u.tbl));
    IF cardinality(v_refused) > 0 THEN
        PERFORM basalt_meta._scope_refused('FILTER', array_to_string(v_refused, '; '));
    END IF;
    RETURN v_sel;
END $$;
`

const v20Tables = `
-- Idempotent, as every migration from version 16: running it again on a
-- guard that has it changes nothing.
ALTER TABLE basalt_meta.reverts
    ADD COLUMN IF NOT EXISTS selection        jsonb,
    ADD COLUMN IF NOT EXISTS proposed         jsonb,
    ADD COLUMN IF NOT EXISTS ceiling          jsonb,
    ADD COLUMN IF NOT EXISTS scope_token_hash bytea,
    ADD COLUMN IF NOT EXISTS rescope_nonce    bytea,
    ADD COLUMN IF NOT EXISTS rescoped         int NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rejected_at      timestamptz,
    ADD COLUMN IF NOT EXISTS reject_note      text;

-- Once, while scope is still a plain column: the backfill and the expiry.
DO $$
DECLARE
    v_expired bigint;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = 'basalt_meta.reverts'::regclass AND a.attname = 'scope'
                      AND NOT a.attisdropped AND a.attgenerated = '') THEN
        RETURN;
    END IF;
    -- Every revert gets the scope it had, every run and table of its
    -- agents. Reverts from the M3-14 era whose agents name other roles
    -- come out widened.
    UPDATE basalt_meta.reverts r
       SET selection = jsonb_build_object(
               'scope', r.scope, 'scopeId', r.scope_id::text,
               'agents', basalt_meta._revert_select_list(to_jsonb(r.agents::text[])),
               'runs', NULL, 'tables', NULL),
           rescope_nonce = basalt_meta._revert_nonce();
    UPDATE basalt_meta.reverts r SET proposed = r.selection;
    -- Unsigned reverts expire: their bindings have no select, so they
    -- could no longer be signed and applied. A signed large plan keeps its
    -- lines and finishes as signed.
    UPDATE basalt_meta.reverts r SET expires_at = now()
     WHERE r.applied_at IS NULL AND r.signed_at IS NULL AND r.expires_at > now();
    GET DIAGNOSTICS v_expired = ROW_COUNT;
    IF v_expired > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'MIGRATION', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('version', 20, 'revertsExpired', v_expired));
    END IF;
END $$;

ALTER TABLE basalt_meta.reverts
    ALTER COLUMN selection SET NOT NULL,
    ALTER COLUMN proposed SET NOT NULL,
    ALTER COLUMN rescope_nonce SET NOT NULL;

-- Every agent whose changes a revert covered sees the revert's change
-- record (version 7), now from the selection; a selection of every agent
-- (agents null) shows it to the agents of the changes it covered.
CREATE OR REPLACE VIEW basalt_meta.agent_changes WITH (security_barrier = true) AS
    SELECT c.change_id, c.at, c.agent, c.run_id, c.task_id, c.intent, c.op, c.table_name, c.statement,
           c.params, c.rows, c.cascaded_rows, c.duration_ms, c.status, c.code, c.reason, c.approval_id,
           c.actor_kind, c.revert_id, c.reverted_by
      FROM basalt_meta.changes c
     WHERE c.status <> 'PREVIEW'
       AND (c.agent = session_user
            OR (c.op = 'REVERT' AND EXISTS (
                SELECT 1 FROM basalt_meta.reverts r
                 WHERE r.revert_id = c.revert_id
                   AND (r.selection -> 'agents' ? session_user::text
                        OR (jsonb_typeof(r.selection -> 'agents') = 'null'
                            AND EXISTS (SELECT 1 FROM basalt_meta.changes x
                                         WHERE x.change_id = ANY (r.covered) AND x.agent = session_user))))));

DROP VIEW IF EXISTS basalt_meta.agent_reverts;
-- scope, scope_id and agents become generated from selection, so they
-- cannot disagree with it (once).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = 'basalt_meta.reverts'::regclass AND a.attname = 'scope'
                      AND NOT a.attisdropped AND a.attgenerated = '') THEN
        RETURN;
    END IF;
    ALTER TABLE basalt_meta.reverts DROP COLUMN scope, DROP COLUMN scope_id, DROP COLUMN agents;
    ALTER TABLE basalt_meta.reverts
        ADD COLUMN scope text GENERATED ALWAYS AS (selection ->> 'scope') STORED
            CONSTRAINT reverts_scope CHECK (scope IN ('CHANGE', 'RUN', 'TASK')),
        ADD COLUMN scope_id uuid GENERATED ALWAYS AS ((selection ->> 'scopeId')::uuid) STORED,
        ADD COLUMN agents name[] GENERATED ALWAYS AS (basalt_meta._revert_select_agents(selection)) STORED,
        ADD COLUMN widened boolean NOT NULL GENERATED ALWAYS AS (basalt_meta._widened(selection, requested_by)) STORED,
        ADD CONSTRAINT reverts_ceiling_token CHECK ((ceiling IS NULL) = (scope_token_hash IS NULL)),
        ADD CONSTRAINT reverts_reject_note CHECK (char_length(reject_note) <= 500);
END $$;

-- The reverts the calling role prepared (version 9), with REJECTED, the
-- selection and widened. A revert widened beyond the role's own work shows
-- the role no binding, selection, agents or lines (RS-5).
CREATE VIEW basalt_meta.agent_reverts WITH (security_barrier = true) AS
    SELECT r.revert_id, r.scope, r.scope_id, CASE WHEN r.widened THEN NULL ELSE r.agents END AS agents,
           r.intent, r.rows, r.skipped,
           CASE WHEN r.applied_at IS NOT NULL THEN 'APPLIED'
                WHEN r.rejected_at IS NOT NULL THEN 'REJECTED'
                WHEN r.signed_at IS NOT NULL AND r.apply_by > pg_catalog.now() THEN 'APPLYING'
                WHEN r.signed_at IS NOT NULL THEN 'EXPIRED'
                WHEN r.expires_at <= pg_catalog.now() THEN 'EXPIRED'
                ELSE 'PENDING' END AS status,
           r.created_at, r.expires_at, r.applied_at, r.change_id,
           CASE WHEN r.widened THEN NULL ELSE r.binding_text END AS binding_text,
           CASE WHEN r.widened THEN NULL ELSE r.lines END AS lines,
           r.batched, r.signed_at, r.apply_by, r.batches, p.restored, p.skipped AS skipped_now, p.pending,
           CASE WHEN r.widened THEN NULL ELSE r.selection END AS selection,
           r.widened, r.rejected_at, r.reject_note
      FROM basalt_meta.reverts r
      -- Inline, not _revert_progress: a view runs functions as its caller.
      LEFT JOIN LATERAL (SELECT count(l.line_no) FILTER (WHERE l.outcome = 'RESTORED')::int AS restored,
                                count(l.line_no) FILTER (WHERE l.outcome = 'SKIPPED')::int AS skipped,
                                count(l.line_no) FILTER (WHERE l.outcome = 'PENDING')::int AS pending
                           FROM basalt_meta.revert_lines l WHERE l.revert_id = r.revert_id) p ON r.batched
     WHERE r.requested_by = session_user;

GRANT SELECT ON basalt_meta.agent_reverts TO {{agents}};
`

const v20Chains = `
-- Versions 5 and 9's chain functions over a descriptor instead of
-- (scope, id): the same walk over _revert_rows.
CREATE OR REPLACE FUNCTION basalt_meta._revert_chains_walk(p_sel jsonb) RETURNS SETOF basalt_meta.revert_chain
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_chains basalt_meta.revert_chain[] := '{}';
    v_map    jsonb := '{}';
    v_slot   text;
    v_key    jsonb;
    i        int;
    c        basalt_meta.revert_chain;
    l        basalt_meta.ledger;
BEGIN
    FOR l IN SELECT x.* FROM basalt_meta._revert_rows(p_sel) x ORDER BY x.seq LOOP
        v_slot := l.table_oid::text || ':' || l.row_key::text;
        i := (v_map ->> v_slot)::int;
        IF i IS NULL THEN
            c := basalt_meta._revert_chain_start(l);
            v_chains := v_chains || c;
            i := cardinality(v_chains);
        ELSE
            c := basalt_meta._revert_chain_next(v_chains[i], l);
        END IF;
        c := basalt_meta._revert_chain_step(c, l);
        v_key := l.row_key;
        IF l.op <> 'DELETE' AND l.new_row IS NOT NULL THEN
            v_key := basalt_meta._row_key(l.table_oid::regclass, l.new_row);
        END IF;
        c.cur_key := v_key;
        v_chains[i] := c;
        v_map := (v_map - v_slot) || jsonb_build_object(l.table_oid::text || ':' || v_key::text, i);
    END LOOP;
    RETURN QUERY SELECT x.* FROM unnest(v_chains) x;
END $$;

CREATE OR REPLACE FUNCTION basalt_meta._revert_chains(p_sel jsonb) RETURNS SETOF basalt_meta.revert_chain
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c      basalt_meta.revert_chain;
    l      basalt_meta.ledger;
    v_open boolean := false;
BEGIN
    IF EXISTS (SELECT 1 FROM basalt_meta._revert_rows(p_sel) x
                WHERE x.op = 'UPDATE' AND x.new_row IS NOT NULL
                  AND basalt_meta._row_key(x.table_oid::regclass, x.new_row) IS DISTINCT FROM x.row_key) THEN
        RETURN QUERY SELECT * FROM basalt_meta._revert_chains_walk(p_sel);
        RETURN;
    END IF;
    FOR l IN SELECT x.* FROM basalt_meta._revert_rows(p_sel) x ORDER BY x.table_oid, x.row_key, x.seq LOOP
        IF v_open AND c.table_oid = l.table_oid AND c.orig_key = l.row_key THEN
            c := basalt_meta._revert_chain_next(c, l);
        ELSE
            IF v_open THEN
                RETURN NEXT c;
            END IF;
            c := basalt_meta._revert_chain_start(l);
            v_open := true;
        END IF;
        c := basalt_meta._revert_chain_step(c, l);
    END LOOP;
    IF v_open THEN
        RETURN NEXT c;
    END IF;
END $$;

-- The chains that need a line, in ledger order of their first row.
-- NOTHING_TO_REVERT when none, unless p_empty_ok (a task proposal the
-- person may widen).
CREATE OR REPLACE FUNCTION basalt_meta._revert_chain_list(p_sel jsonb, p_empty_ok boolean) RETURNS basalt_meta.revert_chain[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_chains basalt_meta.revert_chain[];
BEGIN
    v_chains := ARRAY(SELECT x FROM basalt_meta._revert_chains(p_sel) x
                       WHERE NOT (x.first_op = 'INSERT' AND x.last_op = 'DELETE')
                       ORDER BY x.first_seq);
    IF cardinality(v_chains) = 0 AND NOT p_empty_ok THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('%s %s changed no rows that a revert could restore', p_sel ->> 'scope', p_sel ->> 'scopeId');
    END IF;
    RETURN v_chains;
END $$;

CREATE OR REPLACE FUNCTION basalt_meta._revert_items(p_sel jsonb, p_lock boolean) RETURNS basalt_meta.revert_item[]
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT ARRAY(SELECT basalt_meta._revert_item(x, p_lock)
                   FROM unnest(basalt_meta._revert_chain_list(p_sel, false)) x)
$$;

-- Lines per agent role among items, RESTORE and SKIP: a line counts for
-- every agent with a change in it. The binding's agentRows.
CREATE OR REPLACE FUNCTION basalt_meta._revert_agent_rows(p_items basalt_meta.revert_item[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT coalesce(jsonb_object_agg(a.agent, a.n), '{}'::jsonb)
      FROM (SELECT c.agent, count(DISTINCT x.first_seq)::int AS n
              FROM unnest(p_items) x
             CROSS JOIN LATERAL unnest(x.change_ids) u(cid)
              JOIN basalt_meta.changes c ON c.change_id = u.cid
             GROUP BY c.agent) a
$$;

-- The binding text the person signs (CONTRACT.md, Revert): the scope as
-- select, proposed only when a rescope changed it, widened, and agentRows
-- only when widened; batched and sampleHash for a large plan.
CREATE OR REPLACE FUNCTION basalt_meta._revert_binding(
    p_id uuid, p_select jsonb, p_proposed jsonb, p_requested_by name, p_intent text, p_rows int, p_skipped int,
    p_rows_hash bytea, p_expires timestamptz, p_sample_hash bytea, p_agent_rows jsonb
) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT (jsonb_build_object(
        'kind', 'REVERT', 'revertId', p_id, 'database', current_database(), 'select', p_select,
        'widened', basalt_meta._widened(p_select, p_requested_by), 'intent', p_intent, 'rows', p_rows,
        'skipped', p_skipped, 'rowsHash', encode(p_rows_hash, 'hex'),
        'expiresAt', to_char(p_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', p_requested_by)
        || CASE WHEN p_proposed IS DISTINCT FROM p_select THEN jsonb_build_object('proposed', p_proposed)
                ELSE '{}'::jsonb END
        || CASE WHEN basalt_meta._widened(p_select, p_requested_by) THEN jsonb_build_object('agentRows', p_agent_rows)
                ELSE '{}'::jsonb END
        || CASE WHEN p_sample_hash IS NOT NULL
                THEN jsonb_build_object('batched', true, 'sampleHash', encode(p_sample_hash, 'hex'))
                ELSE '{}'::jsonb END)::text
$$;
`

const v20Prepare = `
-- Agent (MCP preview_revert, basalt revert --dry-run): what reverting the
-- agent's own proposal p_select would do, from a trial run that always
-- rolls back. Needs a read-write transaction; it leaves nothing behind.
CREATE OR REPLACE FUNCTION basalt_meta.preview_revert(p_select jsonb) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_sel jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    v_sel := basalt_meta._revert_own_select(p_select);
    RETURN QUERY SELECT u.line
      FROM unnest(basalt_meta._revert_trial(basalt_meta._revert_items(v_sel, false), session_user))
           WITH ORDINALITY u(line, n)
     ORDER BY u.n;
END $$;

-- Agent, as the CLI's relay and for request_revert: store the agent's own
-- proposal p_select for the person to sign (version 17 with the scope
-- descriptor). selection = proposed = the normalized descriptor, a fresh
-- rescope nonce, and the binding built from them. A TASK the caller ran in
-- with no line of its own is stored as an empty proposal the person may
-- widen on the page (it cannot be signed as it is); every other scope with
-- nothing to restore is NOTHING_TO_REVERT.
CREATE OR REPLACE FUNCTION basalt_meta.prepare_revert(p_select jsonb, p_intent text)
RETURNS TABLE (revert_id uuid, binding_text text, expires_at timestamptz, lines text[])
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
#variable_conflict use_column
DECLARE
    c_ttl       constant interval := interval '1 hour';
    c_max_lines constant int := 1000; -- one-call revert and lines in a link (M3-9, N12-4, RSS-1)
    v_id        uuid := basalt_meta._uuidv7();
    v_expires   timestamptz := now() + c_ttl;
    v_sel       jsonb;
    v_chains    basalt_meta.revert_chain[];
    v_items     basalt_meta.revert_item[];
    v_lines     text[];
    v_sample    text[];
    v_rows      int;
    v_covered   uuid[];
    v_hash      bytea;
    v_sample_h  bytea;
    v_batched   boolean;
    v_text      text;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    v_sel := basalt_meta._revert_own_select(p_select);
    v_chains := basalt_meta._revert_chain_list(v_sel, v_sel ->> 'scope' = 'TASK');
    v_items := basalt_meta._revert_trial_items(ARRAY(SELECT basalt_meta._revert_item(x, false) FROM unnest(v_chains) x));
    v_lines := basalt_meta._revert_text(v_items, session_user);
    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    IF v_rows = 0 AND cardinality(v_lines) > 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('every row of %s %s would be skipped', v_sel ->> 'scope', v_sel ->> 'scopeId');
    END IF;
    SELECT array_agg(s ORDER BY s) INTO v_covered FROM basalt_meta._revert_covered(v_sel) s;
    v_hash := sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8'));
    v_batched := cardinality(v_lines) > c_max_lines;
    v_sample := v_lines;
    IF v_batched THEN
        v_sample := basalt_meta._revert_sample(v_lines, c_max_lines);
        v_sample_h := sha256(convert_to(array_to_string(v_sample, E'\n'), 'UTF8'));
    END IF;
    v_text := basalt_meta._revert_binding(v_id, v_sel, v_sel, session_user, p_intent, v_rows,
                                          cardinality(v_lines) - v_rows, v_hash, v_expires, v_sample_h,
                                          basalt_meta._revert_agent_rows(v_items));
    INSERT INTO basalt_meta.reverts (revert_id, selection, proposed, rescope_nonce, requested_by, intent, lines, rows,
                                     skipped, rows_hash, binding_text, binding, expires_at, batched, sample_hash, covered)
    VALUES (v_id, v_sel, v_sel, basalt_meta._revert_nonce(), session_user, p_intent, v_sample, v_rows,
            cardinality(v_lines) - v_rows, v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_expires, v_batched,
            v_sample_h, v_covered);
    IF v_batched THEN
        -- Execution order: the writes that landed on trial in the order they
        -- landed, then the lines the trial skipped.
        INSERT INTO basalt_meta.revert_lines (revert_id, line_no, line, chain)
        SELECT v_id, row_number() OVER (ORDER BY it.step NULLS LAST, it.first_seq),
               basalt_meta._revert_line(it, session_user), ch
          FROM unnest(v_items) it JOIN unnest(v_chains) ch ON ch.first_seq = it.first_seq;
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', v_id, 'scope', v_sel ->> 'scope', 'scopeId', v_sel ->> 'scopeId',
                           'select', v_sel, 'intent', p_intent, 'rows', v_rows,
                           'skipped', cardinality(v_lines) - v_rows,
                           'rowsHash', encode(v_hash, 'hex'), 'expiresAt', v_expires)
        || CASE WHEN v_batched THEN jsonb_build_object('batched', true) ELSE '{}'::jsonb END);
    revert_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    lines := v_sample;
    RETURN NEXT;
END $$;
`

const v20Apply = `
-- Any relay (version 9): verify the person's assertion over a prepared
-- revert and run it in the same call; for a batched plan, record the
-- signature only. The revert row is locked before any check, so a rescope
-- and a signature cannot interleave. The binding must carry the stored
-- selection as its select, and the lines are recomputed from that
-- selection, never from the binding.
CREATE OR REPLACE FUNCTION basalt_meta.apply_revert(
    p_revert_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r         basalt_meta.reverts;
    v_change  uuid := basalt_meta._uuidv7();
    v_items   basalt_meta.revert_item[];
    v_lines   text[];
    v_rows    int;
    v_skipped jsonb;
    v_detail  text;
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO r FROM basalt_meta.reverts x WHERE x.revert_id = p_revert_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    IF r.applied_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already applied');
    END IF;
    IF r.rejected_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('the person rejected this revert; nothing was reverted');
    END IF;
    IF r.signed_at IS NOT NULL THEN
        PERFORM basalt_meta._revert_invalid('revert already signed; the agent applies it in batches');
    END IF;
    IF r.expires_at <= now() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_EXPIRED',
            DETAIL = format('revert %s expired at %s; prepare it again', r.revert_id, r.expires_at);
    END IF;
    IF (r.binding_text::jsonb -> 'select') IS DISTINCT FROM r.selection THEN
        PERFORM basalt_meta._revert_invalid('the binding does not carry this revert''s scope; prepare the revert again');
    END IF;
    IF r.rows = 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS009', MESSAGE = 'NOTHING_TO_REVERT',
            DETAIL = format('%s %s has no row to restore in this scope', r.scope, r.scope_id);
    END IF;
    BEGIN
        PERFORM basalt_meta._verify_assertion(r.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    EXCEPTION WHEN SQLSTATE 'BS005' THEN
        GET STACKED DIAGNOSTICS v_detail = PG_EXCEPTION_DETAIL;
        PERFORM basalt_meta._revert_invalid(v_detail);
    END;
    IF r.batched THEN
        RETURN basalt_meta._revert_sign(r, p_credential_id);
    END IF;

    PERFORM set_config('lock_timeout', '5s', true);
    INSERT INTO basalt_meta.changes (change_id, tx, stmt_ts, agent, intent, op, rows, mode, status,
                                     actor_kind, revert_id, credential_id)
    VALUES (v_change, pg_current_xact_id(), statement_timestamp(), session_user, r.intent, 'REVERT', 0, 'APPLY',
            'APPLIED', 'PERSON', r.revert_id, p_credential_id);
    INSERT INTO basalt_meta.revert_running (tx, agent, change_id) VALUES (pg_current_xact_id(), session_user, v_change);
    v_items := basalt_meta._revert_execute(basalt_meta._revert_items(r.selection, true));
    v_lines := basalt_meta._revert_text(v_items, r.requested_by);
    DELETE FROM basalt_meta.revert_running x WHERE x.tx = pg_current_xact_id();
    IF sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8')) <> r.rows_hash THEN
        PERFORM basalt_meta._revert_invalid('rows changed since the preview; nothing was reverted, prepare the revert again');
    END IF;

    SELECT count(x.table_oid)::int INTO v_rows FROM unnest(v_items) x WHERE x.conflict IS NULL;
    UPDATE basalt_meta.changes x SET rows = v_rows WHERE x.change_id = v_change;
    -- A change is REVERTED when none of its rows was skipped and no table
    -- filter left one of its rows out; otherwise it stays APPLIED and names
    -- the revert (M3-8).
    UPDATE basalt_meta.changes c
       SET reverted_by = coalesce(c.reverted_by, '{}'::uuid[]) || v_change,
           status = CASE WHEN EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NOT NULL AND c.change_id = ANY (x.change_ids))
                              OR NOT basalt_meta._revert_whole(r.selection, c.change_id)
                         THEN c.status ELSE 'REVERTED' END
     WHERE c.change_id IN (SELECT s FROM basalt_meta._revert_covered(r.selection) s)
       AND (EXISTS (SELECT 1 FROM unnest(v_items) x WHERE x.conflict IS NULL AND c.change_id = ANY (x.change_ids))
            OR NOT EXISTS (SELECT 1 FROM unnest(v_items) x WHERE c.change_id = ANY (x.change_ids)));
    UPDATE basalt_meta.reverts x SET applied_at = now(), credential_id = p_credential_id, change_id = v_change
     WHERE x.revert_id = r.revert_id;

    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
               'table', l -> 'table', 'key', l -> 'key', 'rowHash', l -> 'rowHash',
               'conflict', l -> 'conflict', 'sqlState', l -> 'sqlState')) ORDER BY n), '[]'::jsonb)
      INTO v_skipped
      FROM unnest(v_lines) WITH ORDINALITY u(t, n) CROSS JOIN LATERAL (SELECT u.t::jsonb AS l) j
     WHERE l ->> 'action' = 'SKIP';
    PERFORM basalt_meta._append(session_user, v_change, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'select', r.selection,
                           'intent', r.intent, 'credentialId', encode(p_credential_id, 'hex'),
                           'binding', encode(r.binding, 'hex'), 'rows', v_rows, 'skipped', v_skipped));
    RETURN jsonb_build_object('changeId', v_change, 'rows', v_rows, 'skipped', cardinality(v_lines) - v_rows);
END $$;

-- The last batch of a plan (version 9): as there, and a covered change
-- becomes REVERTED only when no table filter left one of its rows out.
CREATE OR REPLACE FUNCTION basalt_meta._revert_finish(r basalt_meta.reverts, p_batches int) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_progress record;
BEGIN
    SELECT * INTO v_progress FROM basalt_meta._revert_progress(r.revert_id);
    UPDATE basalt_meta.reverts x SET applied_at = now() WHERE x.revert_id = r.revert_id;
    WITH per AS (
        SELECT u.cid, bool_and(l.outcome = 'RESTORED') AS all_restored, bool_or(l.outcome = 'RESTORED') AS any_restored
          FROM basalt_meta.revert_lines l CROSS JOIN LATERAL unnest((l.chain).change_ids) u(cid)
         WHERE l.revert_id = r.revert_id
         GROUP BY u.cid
    ), covered AS (
        SELECT c.cid, p.all_restored, p.any_restored FROM unnest(r.covered) c(cid) LEFT JOIN per p ON p.cid = c.cid
    )
    UPDATE basalt_meta.changes c
       SET reverted_by = CASE WHEN r.change_id = ANY (coalesce(c.reverted_by, '{}'::uuid[])) THEN c.reverted_by
                              ELSE coalesce(c.reverted_by, '{}'::uuid[]) || r.change_id END,
           status = CASE WHEN coalesce(v.all_restored, true) AND basalt_meta._revert_whole(r.selection, c.change_id)
                         THEN 'REVERTED' ELSE c.status END
      FROM covered v
     WHERE c.change_id = v.cid AND (v.any_restored OR v.all_restored IS NULL);
    PERFORM basalt_meta._append(session_user, r.change_id, 'REVERTED', NULL, 'REVERT', NULL, NULL, NULL, NULL,
        jsonb_build_object('revertId', r.revert_id, 'scope', r.scope, 'scopeId', r.scope_id, 'intent', r.intent,
                           'rows', v_progress.restored, 'skipped', v_progress.skipped, 'batches', p_batches));
END $$;

-- The (scope, id) forms are replaced by the descriptor forms above.
DROP FUNCTION IF EXISTS basalt_meta.preview_revert(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta.prepare_revert(text, uuid, text);
DROP FUNCTION IF EXISTS basalt_meta._revert_items(text, uuid, boolean);
DROP FUNCTION IF EXISTS basalt_meta._revert_chain_list(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta._revert_chains(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta._revert_chains_walk(text, uuid);
DROP FUNCTION IF EXISTS basalt_meta._revert_scope(text, uuid);

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.preview_revert(jsonb) TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.prepare_revert(jsonb, text) TO {{agents}};
`
