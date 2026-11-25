-- Version 10: store-neutral texts (CONTRACT.md, Stores, What every store
-- writes). This file: the agent names the guard writes into texts, and
-- the ledger's store-neutral fields. Breaking and clean state: rows and
-- texts written before stay as they are and are never read in the new form.

-- Each agent's name, recorded with its role when basalt init sets the agent
-- up (planAgent), so a text names it agent:<name> and never strips a prefix
-- it does not know. Never deleted: a change keeps its agent's name after
-- the role is removed. No grants: agents read their own name through
-- agent_name().
CREATE TABLE IF NOT EXISTS basalt_meta.agent_names (
    role        name        PRIMARY KEY,
    name        text        NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9_]*$' AND octet_length(name) <= 63),
    recorded_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON basalt_meta.agent_names FROM PUBLIC;

-- The agents set up before this version: each member of {{agents}} named
-- by this install's own rule, <prefix>_agent_<name>. A role that does not
-- follow it gets no name and its texts are refused until basalt init sets
-- it up again.
INSERT INTO basalt_meta.agent_names (role, name)
SELECT r.rolname, substr(r.rolname, octet_length(left('{{agents}}', -1)) + 2)
  FROM pg_catalog.pg_roles r
 WHERE r.rolname <> '{{agents}}'
   AND pg_catalog.pg_has_role(r.oid, '{{agents}}', 'MEMBER')
   AND starts_with(r.rolname::text, left('{{agents}}', -1) || '_')
   AND substr(r.rolname, octet_length(left('{{agents}}', -1)) + 2) ~ '^[a-z][a-z0-9_]*$'
ON CONFLICT DO NOTHING;

-- agent:<name> of agent role p_role (CONTRACT.md, Stores, Agent names).
-- A role with no recorded name is refused, never shown by its login.
CREATE OR REPLACE FUNCTION basalt_meta._agent_text(p_role name) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_name text;
BEGIN
    SELECT n.name INTO v_name FROM basalt_meta.agent_names n WHERE n.role = p_role;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'UNKNOWN_AGENT',
            HINT = 'this agent has no name on record; run basalt init for it again';
    END IF;
    RETURN 'agent:' || v_name;
END $$;

-- The role of agent:<name> p_agent, from the record. Anything else, an
-- unknown name included, comes back as given: no role is named that, so it
-- matches no role and no change.
CREATE OR REPLACE FUNCTION basalt_meta._agent_role(p_agent text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce((SELECT n.role::text FROM basalt_meta.agent_names n
                      WHERE starts_with(p_agent, 'agent:') AND n.name = substr(p_agent, 7)), p_agent)
$$;

-- Agent: its own agent:<name>, for the descriptors of its own work.
CREATE OR REPLACE FUNCTION basalt_meta.agent_name() RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    RETURN basalt_meta._agent_text(session_user);
END $$;

-- The ledger's store-neutral fields (CONTRACT.md, basalt_meta, Ledger
-- fields): verb, the store's word for op, beside op and table_name (the
-- resource). chain_form says which canonical form hashed the row: 1 for
-- every row written before this version, 2 from it on (_append).
ALTER TABLE basalt_meta.ledger ADD COLUMN IF NOT EXISTS verb text;
ALTER TABLE basalt_meta.ledger ADD COLUMN IF NOT EXISTS chain_form smallint NOT NULL DEFAULT 1;

-- canonical_n of the chain (CONTRACT.md, basalt_meta, Ledger fields): from
-- this version on it names resource, op and verb. A row written before it
-- (chain_form 1) keeps the form it was hashed in, so the chain an install
-- had still verifies; its stored fields are not read in the new form.
CREATE OR REPLACE FUNCTION basalt_meta._canonical(l basalt_meta.ledger) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT convert_to(CASE WHEN l.chain_form = 2 THEN jsonb_build_object(
        'seq', l.seq, 'at', (extract(epoch FROM l.at) * 1000000)::bigint, 'agent', l.agent,
        'changeId', l.change_id, 'kind', l.kind, 'resource', l.table_name, 'tableOid', l.table_oid::bigint,
        'op', l.op, 'verb', l.verb, 'key', l.row_key, 'valuesHash', encode(l.values_hash, 'hex'),
        'depth', l.depth, 'detail', l.detail
    ) ELSE jsonb_build_object(
        'seq', l.seq, 'at', (extract(epoch FROM l.at) * 1000000)::bigint, 'agent', l.agent,
        'changeId', l.change_id, 'kind', l.kind, 'table', l.table_name, 'tableOid', l.table_oid::bigint,
        'op', l.op, 'key', l.row_key, 'valuesHash', encode(l.values_hash, 'hex'),
        'depth', l.depth, 'detail', l.detail
    ) END::text, 'UTF8')
$$;

-- Every ledger row, in the store-neutral form: op is Basalt's (READ for a
-- read) and verb the store's word for it, derived here from op since every
-- caller passes Basalt's op: INSERT, UPDATE and DELETE are Postgres's own
-- commands, a read is SELECT. OTHER (DDL) and REVERT have no verb the
-- guard can know, and kinds with no op have none.
CREATE OR REPLACE FUNCTION basalt_meta._append(
    p_agent name, p_change_id uuid, p_kind text, p_table regclass, p_op text,
    p_key jsonb, p_old jsonb, p_new jsonb, p_depth int, p_detail jsonb
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h basalt_meta.chain_head;
    l basalt_meta.ledger;
BEGIN
    -- The head row lock is held to commit, so chain order equals commit
    -- order and a rolled-back append leaves no gap.
    SELECT * INTO h FROM basalt_meta.chain_head WHERE id FOR UPDATE;
    l.seq := h.seq + 1;
    l.at := clock_timestamp();
    l.agent := p_agent;
    l.change_id := p_change_id;
    l.kind := p_kind;
    l.table_name := p_table::text;
    l.table_oid := p_table::oid;
    l.op := p_op;
    l.verb := CASE WHEN p_op IN ('INSERT', 'UPDATE', 'DELETE') THEN p_op WHEN p_op = 'READ' THEN 'SELECT' END;
    l.row_key := p_key;
    l.old_row := p_old;
    l.new_row := p_new;
    l.values_hash := basalt_meta._values_hash(p_old, p_new);
    l.values_pruned := false;
    l.depth := p_depth;
    l.detail := p_detail;
    l.prev_hash := h.hash;
    l.chain_form := 2;
    l.hash := sha256(h.hash || basalt_meta._canonical(l));
    INSERT INTO basalt_meta.ledger VALUES (l.*);
    UPDATE basalt_meta.chain_head SET seq = l.seq, hash = l.hash WHERE id;
    RETURN l.seq;
END $$;

-- One read the engine ran: a READ change record (the store's verb SELECT), a READ ledger row with
-- the versions it saw, and for a run the run's known version of each row.
-- Called in its own transaction after the read-only one.
CREATE OR REPLACE FUNCTION basalt_meta.record_read(
    p_run_id uuid, p_statement text, p_params jsonb, p_tables text[], p_row_count int, p_duration_ms int,
    p_versions jsonb
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_versions constant int := 10000;
    c_max_tables   constant int := 100;
    v_versions jsonb := coalesce(p_versions, '[]'::jsonb);
    v_task     uuid;
    v_intent   text;
    v_id       uuid;
    v_seen     jsonb;
    e          jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, true);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    IF p_params IS NOT NULL AND jsonb_typeof(p_params) <> 'array' THEN
        PERFORM basalt_meta._invalid('params must be a JSON array');
    END IF;
    IF p_row_count IS NULL OR p_row_count < 0 OR (p_duration_ms IS NOT NULL AND p_duration_ms < 0) THEN
        PERFORM basalt_meta._invalid('row count and duration must be zero or more');
    END IF;
    IF coalesce(cardinality(p_tables), 0) > c_max_tables
       OR EXISTS (SELECT 1 FROM unnest(p_tables) t WHERE coalesce(t, '') = '' OR octet_length(t) > 1000) THEN
        PERFORM basalt_meta._invalid(format('tables: at most %s names', c_max_tables));
    END IF;
    IF jsonb_typeof(v_versions) <> 'array' OR jsonb_array_length(v_versions) > c_max_versions THEN
        PERFORM basalt_meta._invalid(format('versions must be a JSON array of at most %s entries', c_max_versions));
    END IF;
    FOR e IN SELECT x FROM jsonb_array_elements(v_versions) x LOOP
        PERFORM basalt_meta._check_version(e);
    END LOOP;
    v_task := basalt_meta._run_task(p_run_id, NULL);
    SELECT r.intent INTO v_intent FROM basalt_meta.runs r WHERE r.run_id = p_run_id;

    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name, statement, params,
                                     rows, duration_ms, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, v_intent, 'READ',
            p_tables[1], p_statement, p_params, p_row_count, p_duration_ms, 'APPLIED')
    RETURNING change_id INTO v_id;

    IF p_run_id IS NOT NULL THEN
        -- DISTINCT ON: a self-join returns the same row twice.
        INSERT INTO basalt_meta.reads AS r (run_id, table_oid, row_key, row_version, change_id)
        SELECT DISTINCT ON ((x ->> 'tableOid')::oid, x -> 'key')
               p_run_id, (x ->> 'tableOid')::oid, x -> 'key', (x ->> 'version')::xid, v_id
          FROM jsonb_array_elements(v_versions) x
        ON CONFLICT (run_id, table_oid, row_key) DO UPDATE
           SET row_version = excluded.row_version, change_id = excluded.change_id, at = excluded.at;
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
               'resource', (x ->> 'tableOid')::oid::regclass::text, 'key', x -> 'key',
               'version', 'xmin:' || (x ->> 'version')) ORDER BY n), '[]'::jsonb)
      INTO v_seen
      FROM jsonb_array_elements(v_versions) WITH ORDINALITY v(x, n);
    PERFORM basalt_meta._append(session_user, v_id, 'READ', NULL, 'READ', NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'statement', p_statement,
                           'resources', to_jsonb(coalesce(p_tables, '{}'::text[])), 'rows', p_row_count,
                           'durationMs', p_duration_ms, 'versions', v_seen));
    RETURN v_id;
END $$;

-- A refused action: the engine refused it, or the guard raised and the
-- transaction rolled back. Written in a new transaction.
CREATE OR REPLACE FUNCTION basalt_meta.record_refusal(
    p_run_id uuid, p_task_id uuid, p_intent text, p_op text, p_statement text, p_params jsonb,
    p_code text, p_reason text, p_duration_ms int
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_task uuid;
    v_id   uuid;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, false);
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, false);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    PERFORM basalt_meta._check_text('reason', p_reason, 2000, false);
    IF p_op IS NULL OR p_op NOT IN ('READ', 'INSERT', 'UPDATE', 'DELETE', 'OTHER') THEN
        PERFORM basalt_meta._invalid('op must be READ, INSERT, UPDATE, DELETE or OTHER');
    END IF;
    IF p_code IS NULL OR p_code !~ '^[A-Z][A-Z_]{0,63}$' THEN
        PERFORM basalt_meta._invalid('code must be SCREAMING_SNAKE_CASE');
    END IF;
    IF p_duration_ms IS NOT NULL AND p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    v_task := basalt_meta._run_task(p_run_id, p_task_id);
    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, statement, params,
                                     duration_ms, status, code, reason)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, nullif(p_intent, ''),
            p_op, p_statement, p_params, p_duration_ms, 'REFUSED', p_code, p_reason)
    RETURNING change_id INTO v_id;
    PERFORM basalt_meta._append(session_user, v_id, 'REFUSED', NULL, p_op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'intent', p_intent, 'statement', p_statement,
                           'code', p_code, 'reason', p_reason));
    RETURN v_id;
END $$;

-- Called by the engine after the agent's statement, before COMMIT. Stamps
-- the change the guard opened in this transaction, or records a zero-row
-- change, and chains a CHANGE row carrying the statement and intent.
CREATE OR REPLACE FUNCTION basalt_meta.finish_change(p_op text, p_statement text, p_params jsonb, p_duration_ms int)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_intent text := nullif(current_setting('basalt.intent', true), '');
    v_run    uuid := basalt_meta._setting_uuid('basalt.run_id');
    v_task   uuid;
    c        basalt_meta.changes;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, true);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    IF p_params IS NOT NULL AND jsonb_typeof(p_params) <> 'array' THEN
        PERFORM basalt_meta._invalid('params must be a JSON array');
    END IF;
    IF p_duration_ms IS NULL OR p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    IF v_intent IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS001', MESSAGE = 'INTENT_REQUIRED',
            DETAIL = format('finish_change by %s without basalt.intent', session_user);
    END IF;
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));

    SELECT * INTO c FROM basalt_meta.changes x
     WHERE x.tx = pg_current_xact_id_if_assigned() AND x.agent = session_user AND x.statement IS NULL
     ORDER BY x.stmt_ts DESC LIMIT 1;
    IF FOUND THEN
        UPDATE basalt_meta.changes x SET statement = p_statement, params = p_params, duration_ms = p_duration_ms
         WHERE x.change_id = c.change_id
        RETURNING * INTO c;
    ELSE
        IF p_op IS NULL OR p_op NOT IN ('INSERT', 'UPDATE', 'DELETE') THEN
            PERFORM basalt_meta._invalid('op must be INSERT, UPDATE or DELETE');
        END IF;
        INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, statement, params,
                                         duration_ms, mode, status)
        VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent, p_op,
                p_statement, p_params, p_duration_ms,
                coalesce(nullif(current_setting('basalt.mode', true), ''), 'APPLY'),
                CASE WHEN current_setting('basalt.mode', true) = 'PREVIEW' THEN 'PREVIEW' ELSE 'APPLIED' END)
        RETURNING * INTO c;
    END IF;
    PERFORM basalt_meta._append(session_user, c.change_id, 'CHANGE', NULL, c.op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', c.run_id, 'taskId', c.task_id, 'intent', c.intent, 'statement', c.statement,
                           'resource', c.table_name, 'rows', c.rows, 'cascadedRows', c.cascaded_rows,
                           'durationMs', c.duration_ms, 'status', c.status));
    RETURN c.change_id;
END $$;

-- Deferred to commit: a preview never commits, and the policy is checked
-- again over the whole action. SET CONSTRAINTS ... IMMEDIATE only moves the
-- check earlier, where it sees a partial action and fails closed. Reads
-- are change records too; the write policy does not apply to them. Held
-- and expired records are not actions that ran; an applied action under an
-- approval must match it. A revert is authorized by the person's signature
-- and bypasses the row limits (D6), and marking a change reverted is not a
-- new action.
CREATE OR REPLACE FUNCTION basalt_meta._at_commit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c basalt_meta.changes;
BEGIN
    SELECT * INTO c FROM basalt_meta.changes WHERE change_id = NEW.change_id;
    IF NOT FOUND OR c.status NOT IN ('APPLIED', 'PREVIEW') OR c.op IN ('READ', 'REVERT') OR c.reverted_by IS NOT NULL THEN
        RETURN NULL;
    END IF;
    IF c.mode = 'PREVIEW' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS006', MESSAGE = 'PREVIEW_CANNOT_COMMIT';
    END IF;
    IF c.approval_id IS NOT NULL THEN
        PERFORM basalt_meta._commit_approval(c);
    END IF;
    PERFORM basalt_meta._check_policy(c);
    RETURN NULL;
END $$;

-- The calling agent's ledger rows, row keys and values of tables it cannot
-- SELECT redacted, and redacted where a row names other agents' work
-- through a revert (RS-5). Two cases:
--   * a revert row (any kind whose detail names a revertId) of a revert
--     that is widened now, or whose select, oldSelect or droppedSelect
--     covered other agents' changes when it was written: REVERT_SIGNED,
--     REVERT_BATCH and REVERTED copy the skipped lines' tables and keys, and
--     REVERT_RESCOPED and REVERT_RESET the selects. It shows only
--     {revertId, widened, via};
--   * a ROW_CHANGE the change of a widened revert wrote for a row whose
--     reverted changes (revertOf) are not all the row's agent's: no table,
--     key, values or detail, and redacted.
-- Ids from details are cast to uuid only when they look like one, so the
-- lookups use the primary keys and one malformed value cannot fail the view.
CREATE OR REPLACE VIEW basalt_meta.agent_ledger WITH (security_barrier = true) AS
    SELECT l.seq, l.at, l.agent, l.change_id, l.kind,
           CASE WHEN NOT w.hide_row THEN l.table_name END AS table_name, l.op,
           CASE WHEN v.visible AND NOT w.hide_row THEN l.row_key END AS row_key,
           CASE WHEN v.visible AND NOT w.hide_row THEN l.old_row END AS old_row,
           CASE WHEN v.visible AND NOT w.hide_row THEN l.new_row END AS new_row,
           l.values_pruned, l.depth,
           CASE WHEN w.hide_revert
                THEN pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                         'revertId', l.detail -> 'revertId', 'widened', true, 'via', l.detail -> 'via'))
                WHEN w.hide_row THEN pg_catalog.jsonb_build_object('widened', true)
                ELSE l.detail END AS detail,
           NOT v.visible OR w.hide_row AS redacted,
           l.verb
      FROM basalt_meta.ledger l
      CROSS JOIN LATERAL (
          SELECT l.table_oid IS NULL
              OR coalesce(has_table_privilege(session_user, l.table_oid, 'SELECT'), false) AS visible
      ) v
      CROSS JOIN LATERAL (
          SELECT l.kind <> 'ROW_CHANGE' AND pg_catalog.jsonb_typeof(l.detail -> 'revertId') = 'string' AND (
                     EXISTS (SELECT 1 FROM basalt_meta.reverts r
                              WHERE r.widened
                                AND r.revert_id = CASE WHEN l.detail ->> 'revertId' ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
                                                     THEN (l.detail ->> 'revertId')::uuid END)
                     OR EXISTS (
                     SELECT 1 FROM (VALUES (l.detail -> 'select'), (l.detail -> 'oldSelect'), (l.detail -> 'droppedSelect')) s(sel)
                      WHERE pg_catalog.jsonb_typeof(s.sel) = 'object'
                        AND (pg_catalog.jsonb_typeof(s.sel -> 'agents') IS DISTINCT FROM 'array'
                             OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements_text(s.sel -> 'agents') a
                                         WHERE a <> l.agent::text)))) AS hide_revert,
                 l.kind = 'ROW_CHANGE' AND pg_catalog.jsonb_typeof(l.detail -> 'revertOf') = 'array'
                 AND EXISTS (SELECT 1 FROM basalt_meta.changes c JOIN basalt_meta.reverts r ON r.revert_id = c.revert_id
                              WHERE c.change_id = l.change_id AND c.op = 'REVERT' AND r.widened)
                 AND EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements_text(l.detail -> 'revertOf') u(cid)
                              WHERE NOT EXISTS (SELECT 1 FROM basalt_meta.changes o
                                                 WHERE o.change_id = CASE WHEN u.cid ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$' THEN u.cid::uuid END
                                                   AND o.agent = l.agent)) AS hide_row
      ) w
     WHERE l.agent = session_user;

REVOKE ALL ON FUNCTION basalt_meta._agent_text(name), basalt_meta._agent_role(text), basalt_meta.agent_name() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.agent_name() TO {{agents}};
