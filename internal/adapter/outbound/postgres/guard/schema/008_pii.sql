-- PII classification: the columns agents can read, the catalog's
-- fingerprint, the unclassified columns, and the two agent views of the
-- classes (here, not with the other views: pii_unclassified reads one).

-- The readable columns: ordinary columns of tables, partitioned tables,
-- views, materialized views and foreign tables outside the system and
-- temporary schemas and basalt_meta that a member of {{agents}} (one that
-- inherits the group) may SELECT, with USAGE on the schema. Only
-- pg_catalog and privilege checks any role may run, so it reveals nothing
-- an agent could not query itself.
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
                      AND has_schema_privilege(m.member, n.oid, 'USAGE')
                      AND has_column_privilege(m.member, c.oid, a.attnum, 'SELECT'))
$$;

-- sha256 of the readable columns as lines
-- format('%I.%I.%I:%s:%s:%s', schema, table, column, type, table_oid, attnum),
-- in byte order, joined by a line break.
CREATE OR REPLACE FUNCTION basalt_meta.pii_fingerprint() RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
    SELECT sha256(convert_to(coalesce(string_agg(l.line, E'\n' ORDER BY l.line COLLATE "C"), ''), 'UTF8'))
      FROM (SELECT format('%I.%I.%I:%s:%s:%s', r.table_schema, r.table_name, r.column_name,
                          r.data_type, r.table_oid, r.attnum) AS line
              FROM basalt_meta.pii_readable_columns() r) l
$$;

-- The classes of the columns the login role may SELECT. Names resolve
-- through pg_attribute, so a renamed column's old row shows nowhere, and
-- table_oid and attnum match pgx's FieldDescription.
CREATE OR REPLACE VIEW basalt_meta.agent_pii_columns WITH (security_barrier = true) AS
    SELECT c.oid AS table_oid, a.attnum, p.table_schema, p.table_name, p.column_name, p.data_type,
           p.class, p.entity_type, p.phone_region, p.needs_review
      FROM basalt_meta.pii_columns p
      JOIN pg_catalog.pg_namespace n ON n.nspname::text = p.table_schema
      JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname::text = p.table_name
      JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attname::text = p.column_name
                                    AND a.attnum > 0 AND NOT a.attisdropped
     WHERE coalesce(pg_catalog.has_column_privilege(session_user, c.oid, a.attnum, 'SELECT'), false);

CREATE OR REPLACE VIEW basalt_meta.agent_pii_catalog WITH (security_barrier = true) AS
    SELECT k.fingerprint, k.classified_at
      FROM basalt_meta.pii_catalog k
     WHERE pg_catalog.pg_has_role(session_user, '{{agents}}', 'USAGE');

-- The columns the login role may reach (SELECT on the column, USAGE on its
-- schema) that need a person: no row (NEW), a row of class UNCLASSIFIED, or
-- a type that changed since basalt classify recorded it (TYPE_CHANGED; the
-- class still applies).
CREATE OR REPLACE FUNCTION basalt_meta.pii_unclassified()
RETURNS TABLE (table_schema text, table_name text, column_name text, data_type text, why text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.table_schema, r.table_name, r.column_name, r.data_type,
           CASE WHEN p.class IS NULL THEN 'NEW'
                WHEN p.class = 'UNCLASSIFIED' THEN 'UNCLASSIFIED'
                ELSE 'TYPE_CHANGED' END
      FROM basalt_meta.pii_readable_columns() r
      LEFT JOIN basalt_meta.agent_pii_columns p ON p.table_oid = r.table_oid AND p.attnum = r.attnum
     WHERE coalesce(has_schema_privilege(session_user, r.table_schema, 'USAGE'), false)
       AND coalesce(has_column_privilege(session_user, r.table_oid, r.attnum, 'SELECT'), false)
       AND (p.class IS NULL OR p.class = 'UNCLASSIFIED' OR p.data_type IS DISTINCT FROM r.data_type)
     ORDER BY r.table_schema COLLATE "C", r.table_name COLLATE "C", r.column_name COLLATE "C"
$$;
