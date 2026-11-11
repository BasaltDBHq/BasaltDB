package guard

// Version 8 (M3 follow-up, decisions N12-7 and N12-8): reverts on tables
// with row-level security.

const v8RLS = `
-- Attach (version 5) plus the guard's RLS policy: on a table with RLS
-- enabled the guard role needs a policy to see and write the rows a revert
-- restores. It names only the guard role, which no one can log in as or
-- become, so agents' own RLS is unchanged. Re-created on every attach, so
-- re-init repairs it.
CREATE OR REPLACE FUNCTION basalt_meta.attach(p_table regclass, p_reason text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    v_pk text[];
BEGIN
    SELECT array_agg(a.attname::text ORDER BY k.ord) INTO v_pk
      FROM pg_index i
      CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
     WHERE i.indrelid = p_table AND i.indisprimary;
    IF v_pk IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('table %s has no primary key; the guard keys ledger rows by it', p_table),
            HINT = 'add a primary key, or revoke the agent''s write privileges on it';
    END IF;
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard AFTER INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_row()$t$, p_table);
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard_truncate BEFORE TRUNCATE ON %s
        FOR EACH STATEMENT WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_truncate()$t$, p_table);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO {{guard}}',
        (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = p_table));
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %s TO {{guard}}', p_table);
    IF (SELECT c.relrowsecurity FROM pg_class c WHERE c.oid = p_table) THEN
        EXECUTE format('DROP POLICY IF EXISTS {{guard}} ON %s', p_table);
        EXECUTE format('CREATE POLICY {{guard}} ON %s AS PERMISSIVE FOR ALL TO {{guard}} USING (true) WITH CHECK (true)', p_table);
    END IF;
    INSERT INTO basalt_meta.guarded_tables VALUES (p_table, v_pk, p_reason)
    ON CONFLICT (table_oid) DO UPDATE
       SET pk_cols = excluded.pk_cols, reason = least(basalt_meta.guarded_tables.reason, excluded.reason);
END $$;

-- Coverage (version 1) plus guarded tables that turned RLS on after the
-- last init: until the next init the guard cannot see their rows.
CREATE OR REPLACE FUNCTION basalt_meta.uncovered_tables() RETURNS TABLE (table_oid regclass, why text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT w::regclass, 'AGENT_WRITABLE' FROM basalt_meta._agent_writable() w
     WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = w AND t.tgname = 'basalt_guard')
    UNION ALL
    SELECT ct.table_oid, 'CASCADE_TARGET via ' || ct.via FROM basalt_meta.cascade_targets() ct
     WHERE NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = ct.table_oid AND g.tgname = 'basalt_guard')
    UNION ALL
    SELECT g.table_oid, 'RLS_WITHOUT_GUARD_POLICY' FROM basalt_meta.guarded_tables g
      JOIN pg_class c ON c.oid = g.table_oid
     WHERE c.relrowsecurity
       AND NOT EXISTS (SELECT 1 FROM pg_policy p
                        WHERE p.polrelid = g.table_oid AND p.polname = '{{guard}}'
                          AND '{{guard}}'::regrole = ANY (p.polroles))
$$;

-- Whether row-level security filters p_role's access to p_table: RLS is
-- on, and the role neither has the owner's privileges (unless forced) nor
-- BYPASSRLS, nor is a superuser. Mirrors Postgres' check_enable_rls.
CREATE FUNCTION basalt_meta._rls_applies(p_role name, p_table oid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT coalesce(bool_and(c.relrowsecurity
                             AND NOT r.rolsuper AND NOT r.rolbypassrls
                             AND (c.relforcerowsecurity OR NOT pg_has_role(r.oid, c.relowner, 'USAGE'))), false)
      FROM pg_class c CROSS JOIN pg_roles r
     WHERE c.oid = p_table AND r.rolname = p_role
$$;

-- Whether p_role may see a line's values (decision N12-8): it can SELECT
-- the table, and where RLS filters it, only its own RESTORE lines: the
-- values the role wrote and replaced, never a row someone else changed,
-- a cascaded row or another agent's row, which its policies may hide.
CREATE FUNCTION basalt_meta._line_visible(it basalt_meta.revert_item, p_role name) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT coalesce(has_table_privilege(p_role, it.table_oid, 'SELECT'), false)
       AND (NOT basalt_meta._rls_applies(p_role, it.table_oid)
            OR (it.conflict IS NULL AND NOT it.cascaded
                AND NOT EXISTS (SELECT 1 FROM basalt_meta.changes c
                                 WHERE c.change_id = ANY (it.change_ids) AND c.agent <> p_role)))
$$;

-- One revert line (version 5), redacted unless _line_visible.
CREATE OR REPLACE FUNCTION basalt_meta._revert_line(it basalt_meta.revert_item, p_role name) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT CASE WHEN basalt_meta._line_visible(it, p_role)
        THEN jsonb_build_object('op', it.op, 'key', it.key, 'now', it.now, 'set', it.set, 'table', it.table_name,
                                'action', CASE WHEN it.conflict IS NULL THEN 'RESTORE' ELSE 'SKIP' END,
                                'cascaded', it.cascaded, 'conflict', it.conflict, 'sqlState', it.sql_state,
                                'changeIds', to_jsonb(it.change_ids))::text
        ELSE jsonb_build_object('op', it.op, 'table', it.table_name,
                                'action', CASE WHEN it.conflict IS NULL THEN 'RESTORE' ELSE 'SKIP' END,
                                'rowHash', encode(sha256(convert_to(jsonb_build_array(it.key, it.now, it.set)::text, 'UTF8')), 'hex'),
                                'cascaded', it.cascaded, 'conflict', it.conflict, 'redacted', true,
                                'changeIds', to_jsonb(it.change_ids))::text
    END
$$;

REVOKE ALL ON FUNCTION basalt_meta._rls_applies(name, oid), basalt_meta._line_visible(basalt_meta.revert_item, name) FROM PUBLIC;
`
