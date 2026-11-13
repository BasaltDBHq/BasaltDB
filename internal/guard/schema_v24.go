package guard

// Version 24: no basalt_meta function can be fooled by the caller's
// temporary tables (CONTRACT.md, basalt_meta "Version 24"). Postgres
// searches the session's temporary schema for relations and types before
// pg_catalog unless search_path names it, so with search_path = pg_catalog
// alone an agent role that created a temporary table pg_roles saying it is
// a superuser, readable by PUBLIC, made guard_row skip its writes: no
// intent, no approval, no ledger row. Two changes, either enough alone:
//
//   - the functions that named a catalog relation unqualified are replaced
//     with every catalog relation written pg_catalog.<name>, the same as
//     their latest version otherwise (attributes restated, since CREATE OR
//     REPLACE resets what it does not name; owner and grants are kept);
//   - every function in basalt_meta gets search_path = pg_catalog, pg_temp,
//     pg_temp last, so an unqualified relation or type never resolves to a
//     temporary one ahead of the catalog's.
//
// Idempotent: replacing a function and setting search_path again change
// nothing on a guard that already has them.
const v24Functions = `
-- Session (version 10).
CREATE OR REPLACE FUNCTION basalt_meta._require_agent() RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT pg_has_role(session_user, '{{agents}}', 'USAGE')
       OR (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('%s is not an agent role', session_user);
    END IF;
END $$;

-- The trigger functions (guard_row version 6, guard_truncate version 1).
CREATE OR REPLACE FUNCTION basalt_meta.guard_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    IF basalt_meta._revert_running() THEN
        PERFORM basalt_meta._guard_revert_row(
            TG_RELID::regclass, TG_OP, pg_trigger_depth(),
            CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
            CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
            CASE WHEN TG_OP <> 'INSERT' THEN OLD.xmin END,
            CASE WHEN TG_OP <> 'DELETE' THEN NEW.xmin END);
        RETURN NULL;
    END IF;
    PERFORM basalt_meta._guard_agent_row(
        TG_RELID::regclass, TG_OP, pg_trigger_depth(),
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.xmin END,
        CASE WHEN TG_OP <> 'DELETE' THEN NEW.xmin END);
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION basalt_meta.guard_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'TRUNCATE by an agent';
END $$;

-- Coverage (version 10).
CREATE OR REPLACE FUNCTION basalt_meta._agent_writable() RETURNS SETOF oid
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.oid FROM pg_catalog.pg_class c
     WHERE c.relkind IN ('r', 'p')
       AND c.relnamespace NOT IN ('pg_catalog'::regnamespace, 'information_schema'::regnamespace, 'basalt_meta'::regnamespace)
       AND (has_table_privilege('{{agents}}', c.oid, 'INSERT, UPDATE, DELETE')
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                        WHERE m.roleid = '{{agents}}'::regrole
                          AND pg_has_role(m.member, m.roleid, 'USAGE')
                          AND has_table_privilege(m.member, c.oid, 'INSERT, UPDATE, DELETE')))
$$;

-- Cascade targets (version 1).
CREATE OR REPLACE FUNCTION basalt_meta.cascade_targets() RETURNS TABLE (table_oid regclass, via text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH RECURSIVE reach(oid, via) AS (
        SELECT con.conrelid, con.confrelid::regclass::text || ' -> ' || con.conrelid::regclass::text
          FROM pg_catalog.pg_constraint con
         WHERE con.contype = 'f' AND con.confrelid IN (SELECT basalt_meta._agent_writable())
           AND (con.confdeltype IN ('c', 'n', 'd') OR con.confupdtype IN ('c', 'n', 'd'))
        UNION
        SELECT con.conrelid, r.via || ' -> ' || con.conrelid::regclass::text
          FROM pg_catalog.pg_constraint con JOIN reach r ON con.confrelid = r.oid
         WHERE con.contype = 'f' AND (con.confdeltype IN ('c', 'n', 'd') OR con.confupdtype IN ('c', 'n', 'd'))
           AND position(con.conrelid::regclass::text IN r.via) = 0
    )
    SELECT DISTINCT ON (oid) oid::regclass, via FROM reach ORDER BY oid, via
$$;

-- Attach (version 10).
CREATE OR REPLACE FUNCTION basalt_meta.attach(p_table regclass, p_reason text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_pk text[];
BEGIN
    SELECT array_agg(a.attname::text ORDER BY k.ord) INTO v_pk
      FROM pg_catalog.pg_index i
      CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
      JOIN pg_catalog.pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
     WHERE i.indrelid = p_table AND i.indisprimary;
    IF v_pk IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('table %s has no primary key; the guard keys ledger rows by it', p_table),
            HINT = 'add a primary key, or revoke the agent''s write privileges on it';
    END IF;
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard AFTER INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'USAGE'))
        EXECUTE FUNCTION basalt_meta.guard_row()$t$, p_table);
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard_truncate BEFORE TRUNCATE ON %s
        FOR EACH STATEMENT WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'USAGE'))
        EXECUTE FUNCTION basalt_meta.guard_truncate()$t$, p_table);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO {{guard}}',
        (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE c.oid = p_table));
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO {{guard}}', p_table);
    IF (SELECT c.relrowsecurity FROM pg_catalog.pg_class c WHERE c.oid = p_table) THEN
        EXECUTE format('DROP POLICY IF EXISTS {{guard}} ON %s', p_table);
        EXECUTE format('CREATE POLICY {{guard}} ON %s AS PERMISSIVE FOR ALL TO {{guard}} USING (true) WITH CHECK (true)', p_table);
    END IF;
    INSERT INTO basalt_meta.guarded_tables VALUES (p_table, v_pk, p_reason)
    ON CONFLICT (table_oid) DO UPDATE
       SET pk_cols = excluded.pk_cols, reason = least(basalt_meta.guarded_tables.reason, excluded.reason);
END $$;

-- Attach all (version 10).
CREATE OR REPLACE FUNCTION basalt_meta.attach_all() RETURNS SETOF regclass
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t regclass;
    r text;
BEGIN
    FOR t, r IN SELECT g.table_oid, g.reason FROM basalt_meta.guarded_tables g
                  JOIN pg_catalog.pg_class c ON c.oid = g.table_oid ORDER BY 1 LOOP
        PERFORM basalt_meta.attach(t, r);
        RETURN NEXT t;
    END LOOP;
    FOR t IN SELECT w::regclass FROM basalt_meta._agent_writable() w ORDER BY 1 LOOP
        PERFORM basalt_meta.attach(t, 'AGENT_WRITABLE');
        RETURN NEXT t;
    END LOOP;
    FOR t IN SELECT ct.table_oid FROM basalt_meta.cascade_targets() ct ORDER BY 1 LOOP
        PERFORM basalt_meta.attach(t, 'CASCADE_TARGET');
        RETURN NEXT t;
    END LOOP;
END $$;

-- Coverage report (version 8).
CREATE OR REPLACE FUNCTION basalt_meta.uncovered_tables() RETURNS TABLE (table_oid regclass, why text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT w::regclass, 'AGENT_WRITABLE' FROM basalt_meta._agent_writable() w
     WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = w AND t.tgname = 'basalt_guard')
    UNION ALL
    SELECT ct.table_oid, 'CASCADE_TARGET via ' || ct.via FROM basalt_meta.cascade_targets() ct
     WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger g WHERE g.tgrelid = ct.table_oid AND g.tgname = 'basalt_guard')
    UNION ALL
    SELECT g.table_oid, 'RLS_WITHOUT_GUARD_POLICY' FROM basalt_meta.guarded_tables g
      JOIN pg_catalog.pg_class c ON c.oid = g.table_oid
     WHERE c.relrowsecurity
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p
                        WHERE p.polrelid = g.table_oid AND p.polname = '{{guard}}'
                          AND '{{guard}}'::regrole = ANY (p.polroles))
$$;

-- Whether row-level security filters p_role's access to p_table (version 8).
CREATE OR REPLACE FUNCTION basalt_meta._rls_applies(p_role name, p_table oid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(bool_and(c.relrowsecurity
                             AND NOT r.rolsuper AND NOT r.rolbypassrls
                             AND (c.relforcerowsecurity OR NOT pg_has_role(r.oid, c.relowner, 'USAGE'))), false)
      FROM pg_catalog.pg_class c CROSS JOIN pg_catalog.pg_roles r
     WHERE c.oid = p_table AND r.rolname = p_role
$$;

-- The inverse of one chain and its static conflict (version 9).
CREATE OR REPLACE FUNCTION basalt_meta._revert_item(c basalt_meta.revert_chain, p_lock boolean) RETURNS basalt_meta.revert_item
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    it     basalt_meta.revert_item;
    v_pk   text[];
    v_gen  text[];
    v_now  jsonb;
    v_xmin text;
    v_left jsonb;
    v_last basalt_meta.ledger;
    v_take jsonb;
BEGIN
    it.table_oid := c.table_oid;
    it.table_name := c.table_name;
    it.cascaded := c.cascaded;
    it.change_ids := c.change_ids;
    it.first_seq := c.first_seq;
    it.last_seq := c.last_seq;
    it.op := CASE WHEN c.first_op = 'INSERT' THEN 'DELETE' WHEN c.last_op = 'DELETE' THEN 'INSERT' ELSE 'UPDATE' END;
    it.key := CASE it.op WHEN 'INSERT' THEN c.orig_key ELSE c.cur_key END;
    it.set := CASE WHEN it.op = 'DELETE' THEN NULL ELSE c.old_row END;

    IF c.pruned THEN
        it.conflict := 'VALUES_PRUNED';
        RETURN it;
    END IF;
    SELECT g.pk_cols INTO v_pk FROM basalt_meta.guarded_tables g WHERE g.table_oid = c.table_oid::regclass;
    IF v_pk IS NULL
       OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(it.key) k)
          IS DISTINCT FROM (SELECT array_agg(k ORDER BY k) FROM unnest(v_pk) k)
       OR EXISTS (SELECT 1 FROM jsonb_object_keys(coalesce(c.old_row, '{}'::jsonb)) k
                   WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                                      WHERE a.attrelid = c.table_oid AND a.attname = k AND a.attnum > 0
                                        AND NOT a.attisdropped)) THEN
        it.conflict := 'SCHEMA_CHANGED';
        RETURN it;
    END IF;
    SELECT coalesce(array_agg(a.attname::text), '{}') INTO v_gen
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = c.table_oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated <> '';
    it.set := it.set - v_gen; -- generated columns are recomputed, never written (M3-13)

    SELECT f.row_now, f.row_xmin INTO v_now, v_xmin FROM basalt_meta._revert_fetch(c.table_oid, it.key, p_lock) f;
    it.now := v_now;

    v_last := basalt_meta._revert_last(c.table_oid, ARRAY[c.orig_key, c.cur_key], c.last_seq);
    IF v_last.seq IS NOT NULL AND v_last.detail ? 'revertOf'
       AND (v_last.detail -> 'revertOf') ?| c.change_ids::text[] THEN
        it.conflict := 'ALREADY_REVERTED';
        RETURN it;
    END IF;
    IF c.broken THEN
        it.conflict := 'CHANGED_AFTER';
        RETURN it;
    END IF;

    IF it.op = 'INSERT' THEN
        IF v_now IS NOT NULL THEN
            it.conflict := 'KEY_TAKEN';
        END IF;
        RETURN it;
    END IF;
    IF v_now IS NULL THEN
        it.conflict := 'ROW_GONE';
        RETURN it;
    END IF;
    -- The row as the agent left it: same version and same values (columns
    -- added since are not compared).
    SELECT jsonb_object_agg(k, v_now -> k) INTO v_left FROM jsonb_object_keys(c.new_row) k;
    IF (c.new_xmin IS NOT NULL AND v_xmin IS DISTINCT FROM c.new_xmin) OR v_left IS DISTINCT FROM c.new_row THEN
        it.conflict := 'CHANGED_AFTER';
        RETURN it;
    END IF;
    IF it.op = 'UPDATE' AND c.orig_key <> c.cur_key THEN
        SELECT f.row_now INTO v_take FROM basalt_meta._revert_fetch(c.table_oid, c.orig_key, p_lock) f;
        IF v_take IS NOT NULL THEN
            it.conflict := 'KEY_TAKEN';
        END IF;
    END IF;
    RETURN it;
END $$;

-- Admin only (version 11): record an agent RLS policy the person confirmed.
CREATE OR REPLACE FUNCTION basalt_meta.record_agent_policy(p_agent name, p_table regclass, p_command text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_command IS NULL OR p_command NOT IN ('SELECT', 'ALL') THEN
        PERFORM basalt_meta._invalid(format('command %s', p_command));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = p_agent)
       OR NOT pg_has_role(p_agent, '{{agents}}', 'USAGE') THEN
        PERFORM basalt_meta._invalid(format('%s is not an agent role', p_agent));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy p
                    WHERE p.polrelid = p_table AND p.polname = p_agent
                      AND p_agent::regrole = ANY (p.polroles)) THEN
        PERFORM basalt_meta._invalid(format('no policy %s on %s', p_agent, p_table));
    END IF;
    RETURN basalt_meta._append(p_agent, NULL, 'AGENT_POLICY_ADDED', p_table, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('policy', p_agent, 'command', p_command, 'by', session_user));
END $$;

-- The PII readable columns (version 15).
CREATE OR REPLACE FUNCTION basalt_meta.pii_readable_columns()
RETURNS TABLE (table_oid oid, attnum smallint, table_schema text, table_name text, column_name text, data_type text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
    SELECT c.oid, a.attnum, n.nspname::text, c.relname::text, a.attname::text,
           format_type(a.atttypid, NULL) -- no type modifier: a length change is not a type change
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND a.attnum > 0 AND NOT a.attisdropped
       AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'basalt_meta')
       AND n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname NOT LIKE 'pg\_toast\_temp\_%'
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                    WHERE m.roleid = '{{agents}}'::regrole
                      AND pg_has_role(m.member, m.roleid, 'USAGE')
                      AND has_column_privilege(m.member, c.oid, a.attnum, 'SELECT'))
$$;

-- Admin only (version 18): record a setup code.
CREATE OR REPLACE FUNCTION basalt_meta.record_setup(
    p_setup_id uuid, p_kind text, p_agent name, p_guard_version int, p_expires_at timestamptz
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_skew       constant interval := interval '5 minutes';
    c_lifetime   constant interval := interval '24 hours';
    c_hex_ms_len constant int      := 12; -- the first 48 bits of a UUIDv7, in hex
    c_version    constant int      := 15; -- 1-based position of the version digit in uuid text
    v_hex      text := replace(p_setup_id::text, '-', '');
    v_id_at    timestamptz;
    v_used_at  timestamptz;
    v_now      timestamptz;
    v_actor    name;
BEGIN
    IF p_setup_id IS NULL OR substr(p_setup_id::text, c_version, 1) <> '7' THEN
        PERFORM basalt_meta._invalid('setup id must be a UUIDv7');
    END IF;
    IF p_kind IS NULL OR p_kind NOT IN ('INSTALL', 'AGENT', 'UPGRADE') THEN
        PERFORM basalt_meta._invalid('kind must be INSTALL, AGENT or UPGRADE');
    END IF;
    IF p_guard_version IS NULL OR p_guard_version < 1 THEN
        PERFORM basalt_meta._invalid('guard version is required');
    END IF;
    IF p_expires_at IS NULL THEN
        PERFORM basalt_meta._invalid('expires_at is required');
    END IF;
    IF p_kind = 'UPGRADE' AND p_agent IS NOT NULL THEN
        PERFORM basalt_meta._invalid('an UPGRADE setup names no agent');
    END IF;
    -- pg_has_role on the oid of a role that exists: a missing name would
    -- raise instead of answering.
    IF p_kind <> 'UPGRADE' AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
        WHERE r.rolname = p_agent AND r.rolname <> '{{agents}}'
          AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole
          AND pg_has_role(r.oid, '{{agents}}', 'USAGE')) THEN
        PERFORM basalt_meta._invalid(format('%s is not an agent role', coalesce(p_agent::text, 'null')));
    END IF;

    -- One setup at a time, so USED and SUPERSEDED see every committed row.
    PERFORM pg_advisory_xact_lock(hashtext('basalt_meta setups'));
    SELECT s.used_at INTO v_used_at FROM basalt_meta.setups s WHERE s.setup_id = p_setup_id;
    IF FOUND THEN
        PERFORM basalt_meta._setup_refused('USED', format('this setup code was already used on %s',
            to_char(v_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS "UTC"')));
    END IF;
    IF p_kind <> 'UPGRADE' THEN
        SELECT s.used_at INTO v_used_at FROM basalt_meta.setups s
         WHERE s.agent_role = p_agent AND s.setup_id > p_setup_id
         ORDER BY s.setup_id DESC LIMIT 1;
        IF FOUND THEN
            PERFORM basalt_meta._setup_refused('SUPERSEDED', format('a newer setup for %s already ran on %s',
                p_agent, to_char(v_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS "UTC"')));
        END IF;
    END IF;
    -- The time now, not the transaction's start: the person may have
    -- waited inside the transaction, and the lock above may have waited.
    v_now := clock_timestamp();
    IF v_now >= p_expires_at THEN
        PERFORM basalt_meta._setup_refused('EXPIRED', 'this setup code expired');
    END IF;
    v_id_at := to_timestamp((('x' || lpad(substr(v_hex, 1, c_hex_ms_len), 16, '0'))::bit(64)::bigint) / 1000.0);
    IF v_id_at > v_now + c_skew THEN
        PERFORM basalt_meta._setup_refused('SETUP_ID_IN_FUTURE', 'the setup id claims a time in the future');
    END IF;
    IF p_expires_at > v_now + c_lifetime + c_skew OR p_expires_at > v_id_at + c_lifetime THEN
        PERFORM basalt_meta._setup_refused('EXPIRY_TOO_FAR', 'the setup code expires too far in the future');
    END IF;

    INSERT INTO basalt_meta.setups (setup_id, kind, agent_role, guard_version, expires_at)
    VALUES (p_setup_id, p_kind, p_agent, p_guard_version, p_expires_at);
    v_actor := coalesce(p_agent, session_user);
    RETURN basalt_meta._append(v_actor, NULL, 'AGENT_SETUP', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('setupId', p_setup_id, 'kind', p_kind, 'guardVersion', p_guard_version, 'by', session_user));
END $$;
`

// v24SearchPath sets search_path = pg_catalog, pg_temp on every function
// in basalt_meta that does not have it yet, the ones replaced above
// included. A loop over pg_proc rather than a list, so no function is
// missed; TestEveryGuardFunctionPutsPgTempLast holds later versions to it.
const v24SearchPath = `
DO $$
DECLARE
    f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = 'basalt_meta'::pg_catalog.regnamespace AND p.prokind = 'f'
                AND p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
              ORDER BY 1 LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %s SET search_path = pg_catalog, pg_temp', f);
    END LOOP;
END $$;
`
