-- Version 10 (M4): an agent is a role that inherits the agents
-- group, not any member of it. From Postgres 16, CREATE ROLE by a role
-- with CREATEROLE that is not a superuser (Supabase's postgres) also
-- grants the creator ADMIN on the new role, with INHERIT and SET off.
-- pg_has_role(..., 'MEMBER') counts that membership, so the admin who ran
-- basalt init was treated as an agent: its own writes to guarded tables
-- were refused (INTENT_REQUIRED) and every table it can write counted as
-- agent-writable. 'USAGE' counts only memberships that pass privileges
-- on, which every agent role has (GRANT {{agents}} TO <agent>, INHERIT),
-- on every supported Postgres version.

-- Session (version 1), with USAGE: callers of the agent functions must be
-- agent roles, never superusers (superusers are members of every role).
CREATE OR REPLACE FUNCTION basalt_meta._require_agent() RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
BEGIN
    IF NOT pg_has_role(session_user, '{{agents}}', 'USAGE')
       OR (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('%s is not an agent role', session_user);
    END IF;
END $$;

-- Coverage (version 1), counting only members that inherit the group.
CREATE OR REPLACE FUNCTION basalt_meta._agent_writable() RETURNS SETOF oid
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT c.oid FROM pg_class c
     WHERE c.relkind IN ('r', 'p')
       AND c.relnamespace NOT IN ('pg_catalog'::regnamespace, 'information_schema'::regnamespace, 'basalt_meta'::regnamespace)
       AND (has_table_privilege('{{agents}}', c.oid, 'INSERT, UPDATE, DELETE')
            OR EXISTS (SELECT 1 FROM pg_auth_members m
                        WHERE m.roleid = '{{agents}}'::regrole
                          AND pg_has_role(m.member, m.roleid, 'USAGE')
                          AND has_table_privilege(m.member, c.oid, 'INSERT, UPDATE, DELETE')))
$$;

-- Attach (version 8), with USAGE in the triggers' WHEN clause.
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
        FOR EACH ROW WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'USAGE'))
        EXECUTE FUNCTION basalt_meta.guard_row()$t$, p_table);
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard_truncate BEFORE TRUNCATE ON %s
        FOR EACH STATEMENT WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'USAGE'))
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

-- Attach all (version 1), re-attaching every table guarded before first,
-- so its triggers carry the current WHEN clause.
CREATE OR REPLACE FUNCTION basalt_meta.attach_all() RETURNS SETOF regclass
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    t regclass;
    r text;
BEGIN
    FOR t, r IN SELECT g.table_oid, g.reason FROM basalt_meta.guarded_tables g
                  JOIN pg_class c ON c.oid = g.table_oid ORDER BY 1 LOOP
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
