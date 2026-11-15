-- Coverage: the tables agents can write, attach, attach_all, cascade
-- targets and uncovered_tables.

-- Tables any agent role (a member of the agents group) can write.
CREATE FUNCTION basalt_meta._agent_writable() RETURNS SETOF oid
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT c.oid FROM pg_class c
     WHERE c.relkind IN ('r', 'p')
       AND c.relnamespace NOT IN ('pg_catalog'::regnamespace, 'information_schema'::regnamespace, 'basalt_meta'::regnamespace)
       AND (has_table_privilege('{{agents}}', c.oid, 'INSERT, UPDATE, DELETE')
            OR EXISTS (SELECT 1 FROM pg_auth_members m
                        WHERE m.roleid = '{{agents}}'::regrole
                          AND has_table_privilege(m.member, c.oid, 'INSERT, UPDATE, DELETE')))
$$;

-- Tables reachable by an FK action (CASCADE, SET NULL, SET DEFAULT on
-- delete or update) from any agent-writable table, transitively (D5).
CREATE FUNCTION basalt_meta.cascade_targets() RETURNS TABLE (table_oid regclass, via text)
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    WITH RECURSIVE reach(oid, via) AS (
        SELECT con.conrelid, con.confrelid::regclass::text || ' -> ' || con.conrelid::regclass::text
          FROM pg_constraint con
         WHERE con.contype = 'f' AND con.confrelid IN (SELECT basalt_meta._agent_writable())
           AND (con.confdeltype IN ('c', 'n', 'd') OR con.confupdtype IN ('c', 'n', 'd'))
        UNION
        SELECT con.conrelid, r.via || ' -> ' || con.conrelid::regclass::text
          FROM pg_constraint con JOIN reach r ON con.confrelid = r.oid
         WHERE con.contype = 'f' AND (con.confdeltype IN ('c', 'n', 'd') OR con.confupdtype IN ('c', 'n', 'd'))
           AND position(con.conrelid::regclass::text IN r.via) = 0
    )
    SELECT DISTINCT ON (oid) oid::regclass, via FROM reach ORDER BY oid, via
$$;

-- Attach the guard to one table. Run by the admin (it needs to own the
-- table); idempotent.
CREATE FUNCTION basalt_meta.attach(p_table regclass, p_reason text) RETURNS void
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
    -- WHEN filters before the AFTER event is queued, so writes by people
    -- and the app pay one pg_has_role call and nothing else.
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard AFTER INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_row()$t$, p_table);
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard_truncate BEFORE TRUNCATE ON %s
        FOR EACH STATEMENT WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_truncate()$t$, p_table);
    INSERT INTO basalt_meta.guarded_tables VALUES (p_table, v_pk, p_reason)
    ON CONFLICT (table_oid) DO UPDATE
       SET pk_cols = excluded.pk_cols, reason = least(basalt_meta.guarded_tables.reason, excluded.reason);
END $$;

-- Attach the guard to every agent-writable table and every cascade target.
CREATE FUNCTION basalt_meta.attach_all() RETURNS SETOF regclass
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    t regclass;
BEGIN
    FOR t IN SELECT w::regclass FROM basalt_meta._agent_writable() w ORDER BY 1 LOOP
        PERFORM basalt_meta.attach(t, 'AGENT_WRITABLE');
        RETURN NEXT t;
    END LOOP;
    FOR t IN SELECT ct.table_oid FROM basalt_meta.cascade_targets() ct ORDER BY 1 LOOP
        PERFORM basalt_meta.attach(t, 'CASCADE_TARGET');
        RETURN NEXT t;
    END LOOP;
END $$;

-- Coverage: every agent-writable table and every cascade target must carry
-- the guard. basalt init fails and basalt log warns when this has rows.
CREATE FUNCTION basalt_meta.uncovered_tables() RETURNS TABLE (table_oid regclass, why text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT w::regclass, 'AGENT_WRITABLE' FROM basalt_meta._agent_writable() w
     WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = w AND t.tgname = 'basalt_guard')
    UNION ALL
    SELECT ct.table_oid, 'CASCADE_TARGET via ' || ct.via FROM basalt_meta.cascade_targets() ct
     WHERE NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = ct.table_oid AND g.tgname = 'basalt_guard')
$$;
