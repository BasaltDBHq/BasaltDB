-- Version 26: the guard's triggers fire whatever session_replication_role
-- says (CONTRACT.md, basalt_meta "Version 26"). A trigger created the
-- default way is ENABLE: it fires when session_replication_role is origin
-- or local, not replica. An agent role cannot set the parameter itself, and
-- basalt init resets the agent role's own settings, but a database default
-- (ALTER DATABASE ... SET, ALTER ROLE ALL ... SET, postgresql.conf) of
-- replica reaches every new agent session and would skip the guard
-- entirely: no intent, no approval, no ledger row, no commit check.
--
--   - attach makes basalt_guard and basalt_guard_truncate ENABLE ALWAYS
--     each time it runs. It runs as the admin, who owns the tables, after
--     every migration (attach_all), so an upgrade sets the triggers on
--     every table already guarded;
--   - the commit check at_commit on basalt_meta.changes, owned by the
--     guard, is set ENABLE ALWAYS here.
--
-- Idempotent.

-- Attach (version 24): the same, plus ENABLE ALWAYS on both triggers.
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
    -- ALWAYS: fire whatever session_replication_role says. The default,
    -- ENABLE, fires only in origin and local, so a replica default for
    -- the database would skip the guard.
    EXECUTE format('ALTER TABLE %s ENABLE ALWAYS TRIGGER basalt_guard, ENABLE ALWAYS TRIGGER basalt_guard_truncate', p_table);
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

ALTER TABLE basalt_meta.changes ENABLE ALWAYS TRIGGER at_commit;
