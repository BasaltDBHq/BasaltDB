-- Version 3 (M1.5): recorded reads and STALE_READ. The engine records each
-- read with record_read, including the version (xmin) of every row it can
-- identify; the guard trigger compares a run's known version of a row
-- with OLD.xmin before an UPDATE or DELETE lands. Same rules as schema.go:
-- forward-only, schema-qualified, role names only through Names.render.

-- A run's latest known version of each row it read or wrote (owner
-- decisions #7 and #15). Removed with the run by retention (1 year).
CREATE TABLE basalt_meta.reads (
    run_id      uuid        NOT NULL REFERENCES basalt_meta.runs ON DELETE CASCADE,
    table_oid   oid         NOT NULL,
    row_key     jsonb       NOT NULL,
    row_version xid         NOT NULL,
    change_id   uuid,
    at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (run_id, table_oid, row_key)
);

-- Guarded tables the calling agent can SELECT: the tables whose rows the
-- engine can identify in a read (by primary key and xmin).
CREATE VIEW basalt_meta.agent_guarded_tables WITH (security_barrier = true) AS
    SELECT g.table_oid::oid AS table_oid,
           pg_catalog.format('%I.%I', n.nspname, c.relname) AS table_name, -- qualified whatever the search_path
           g.pk_cols
      FROM basalt_meta.guarded_tables g
      JOIN pg_catalog.pg_class c ON c.oid = g.table_oid
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
     WHERE coalesce(pg_catalog.has_table_privilege(session_user, g.table_oid, 'SELECT'), false);

-- One version entry of record_read: an object naming a guarded table the
-- caller can read, a key with exactly its primary-key columns, and an xid.
CREATE FUNCTION basalt_meta._check_version(p_v jsonb) RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_u32_max constant bigint := 4294967295; -- oid and xid are unsigned 32-bit
    v_pk      text[];
BEGIN
    IF jsonb_typeof(p_v) IS DISTINCT FROM 'object'
       OR coalesce(p_v ->> 'tableOid', '') !~ '^[0-9]{1,10}$'
       OR coalesce(p_v ->> 'version', '') !~ '^[0-9]{1,10}$'
       OR jsonb_typeof(p_v -> 'key') IS DISTINCT FROM 'object' THEN
        PERFORM basalt_meta._invalid('each version needs tableOid, key (an object) and version (an xid)');
    END IF;
    IF (p_v ->> 'tableOid')::bigint > c_u32_max OR (p_v ->> 'version')::bigint > c_u32_max THEN
        PERFORM basalt_meta._invalid('tableOid and version must fit 32 bits');
    END IF;
    SELECT g.pk_cols INTO v_pk FROM basalt_meta.guarded_tables g WHERE g.table_oid = (p_v ->> 'tableOid')::oid;
    IF NOT FOUND OR NOT coalesce(has_table_privilege(session_user, (p_v ->> 'tableOid')::oid, 'SELECT'), false) THEN
        PERFORM basalt_meta._invalid(format('table %s is not a guarded table %s can read', p_v ->> 'tableOid', session_user));
    END IF;
    IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(p_v -> 'key') k)
       IS DISTINCT FROM (SELECT array_agg(k ORDER BY k) FROM unnest(v_pk) k) THEN
        PERFORM basalt_meta._invalid(format('key must name exactly the primary-key columns %s', v_pk));
    END IF;
END $$;

-- One read the engine ran: a SELECT change record, a READ ledger row with
-- the versions it saw, and for a run the run's known version of each row.
-- Called in its own transaction after the read-only one.
CREATE FUNCTION basalt_meta.record_read(
    p_run_id uuid, p_statement text, p_params jsonb, p_tables text[], p_row_count int, p_duration_ms int,
    p_versions jsonb
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
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
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, v_intent, 'SELECT',
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
               'table', (x ->> 'tableOid')::oid::regclass::text, 'key', x -> 'key',
               'version', 'xmin:' || (x ->> 'version')) ORDER BY n), '[]'::jsonb)
      INTO v_seen
      FROM jsonb_array_elements(v_versions) WITH ORDINALITY v(x, n);
    PERFORM basalt_meta._append(session_user, v_id, 'READ', NULL, 'SELECT', NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'statement', p_statement,
                           'tables', to_jsonb(coalesce(p_tables, '{}'::text[])), 'rows', p_row_count,
                           'durationMs', p_duration_ms, 'versions', v_seen));
    RETURN v_id;
END $$;
