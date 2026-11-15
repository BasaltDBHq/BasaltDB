-- The guard: the triggers on the person's tables that record, count, hold
-- or refuse every agent write, the commit check, coverage (attach,
-- attach_all, uncovered_tables) and the guard's row-level security.

-- Default policy (fixed until custom policies): up to 10 rows allowed,
-- 11 to 50 held, over 50 refused, every DELETE held. Rows are counted per
-- action, cascades included.
CREATE FUNCTION basalt_meta._check_policy(c basalt_meta.changes) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_allow_max constant int := 10;
    c_hold_max  constant int := 50;
BEGIN
    IF c.rows > c_hold_max THEN
        RAISE EXCEPTION USING ERRCODE = 'BS003', MESSAGE = 'ROW_LIMIT_EXCEEDED',
            DETAIL = format('more than %s rows in one action (cascades included)', c_hold_max);
    END IF;
    IF c.mode = 'APPLY' AND c.approval_id IS NULL AND (c.has_delete OR c.rows > c_allow_max) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS002', MESSAGE = 'APPROVAL_REQUIRED',
            DETAIL = format('%s rows, delete=%s', c.rows, c.has_delete);
    END IF;
END $$;

-- The trigger function. People and the app never reach it: the trigger's
-- WHEN clause filters on pg_has_role first. Superusers are members of every
-- role, so they pass WHEN and return here unguarded.
--
-- The SET clauses pin the session settings to_jsonb prints row images by
-- (TimeZone for timestamptz, IntervalStyle for interval,
-- extra_float_digits for float4 and float8, lc_monetary for money,
-- bytea_output for bytea), to the values the engine and basalt revert pin
-- in every transaction they open (PinSession). A write that skips the
-- engine, the agent's credential used directly as in psql, then stores the
-- same images, held lines and rowsHash as the engine would, and a revert
-- from the engine does not skip its rows as CHANGED_AFTER. Postgres
-- restores the session's values when the function returns, so the agent's
-- own SQL in the same transaction is unchanged. Restate them in any CREATE
-- OR REPLACE of guard_row (it resets what it does not name);
-- TestGuardPinsTheSessionSettings checks it.
CREATE OR REPLACE FUNCTION basalt_meta.guard_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    SET TimeZone = 'UTC'
    SET DateStyle = 'ISO, MDY'
    SET IntervalStyle = 'postgres'
    SET extra_float_digits = 1
    SET lc_monetary = 'C'
    SET bytea_output = 'hex' AS $$
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

-- TRUNCATE by an agent role on a guarded table. It builds no row image, so
-- it pins no session setting.
CREATE OR REPLACE FUNCTION basalt_meta.guard_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'TRUNCATE by an agent';
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
    IF NOT FOUND OR c.status NOT IN ('APPLIED', 'PREVIEW') OR c.op IN ('SELECT', 'REVERT') OR c.reverted_by IS NOT NULL THEN
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

-- Tables any agent role (a member of the agents group that inherits it)
-- can write.
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

-- Tables reachable by an FK action (CASCADE, SET NULL, SET DEFAULT on
-- delete or update) from any agent-writable table, transitively (D5).
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

-- Attach the guard to one table. Run by the admin (it needs to own the
-- table); idempotent. The triggers are ENABLE ALWAYS, so they fire under
-- any session_replication_role, and their WHEN clause checks USAGE of the
-- agents group.
--
-- The guard role reads and writes guarded tables, only inside the revert
-- functions; attach grants it, and basalt init re-attaches every table. On
-- a table with RLS enabled the guard role needs a policy to see and write
-- the rows a revert restores. It names only the guard role, which no one
-- can log in as or become, so agents' own RLS is unchanged. Re-created on
-- every attach, so re-init repairs it.
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

-- Attach the guard to every agent-writable table and every cascade target,
-- re-attaching every table guarded before first, so its triggers carry the
-- current WHEN clause.
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

-- Coverage: every agent-writable table and every cascade target must carry
-- the guard, and a guarded table that turned RLS on after the last init is
-- listed too (until the next init the guard cannot see its rows). basalt
-- init fails and basalt log warns when this has rows.
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

-- Whether row-level security filters p_role's access to p_table: RLS is
-- on, and the role neither has the owner's privileges (unless forced) nor
-- BYPASSRLS, nor is a superuser. Mirrors Postgres' check_enable_rls.
CREATE OR REPLACE FUNCTION basalt_meta._rls_applies(p_role name, p_table oid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(bool_and(c.relrowsecurity
                             AND NOT r.rolsuper AND NOT r.rolbypassrls
                             AND (c.relforcerowsecurity OR NOT pg_has_role(r.oid, c.relowner, 'USAGE'))), false)
      FROM pg_catalog.pg_class c CROSS JOIN pg_catalog.pg_roles r
     WHERE c.oid = p_table AND r.rolname = p_role
$$;

-- Admin only (basalt init, right after its CREATE POLICY): record that the
-- person let p_agent see every row of p_table. Not granted to agents.
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

-- The commit check of every change record, ENABLE ALWAYS like the guard's
-- triggers on the person's tables, so it fires under any
-- session_replication_role.
CREATE CONSTRAINT TRIGGER at_commit AFTER INSERT OR UPDATE ON basalt_meta.changes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION basalt_meta._at_commit();

ALTER TABLE basalt_meta.changes ENABLE ALWAYS TRIGGER at_commit;
