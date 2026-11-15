-- PII classification: pii_readable_columns and pii_fingerprint.

-- The readable columns: ordinary columns of tables, partitioned tables,
-- views, materialized views and foreign tables outside the system and
-- temporary schemas and basalt_meta that a member of {{agents}} (one that
-- inherits the group) may SELECT. Only pg_catalog and privilege checks
-- any role may run, so it reveals nothing an agent could not query itself.
CREATE OR REPLACE FUNCTION basalt_meta.pii_readable_columns()
RETURNS TABLE (table_oid oid, attnum smallint, table_schema text, table_name text, column_name text, data_type text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
    SELECT c.oid, a.attnum, n.nspname::text, c.relname::text, a.attname::text,
           format_type(a.atttypid, NULL) -- no type modifier: a length change is not a type change
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = c.oid
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND a.attnum > 0 AND NOT a.attisdropped
       AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast', 'basalt_meta')
       AND n.nspname NOT LIKE 'pg\_temp\_%' AND n.nspname NOT LIKE 'pg\_toast\_temp\_%'
       AND EXISTS (SELECT 1 FROM pg_auth_members m
                    WHERE m.roleid = '{{agents}}'::regrole
                      AND pg_has_role(m.member, m.roleid, 'USAGE')
                      AND has_column_privilege(m.member, c.oid, a.attnum, 'SELECT'))
$$;

-- sha256 of the readable columns as lines schema.table.column:type, in
-- byte order, joined by a line break.
CREATE OR REPLACE FUNCTION basalt_meta.pii_fingerprint() RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
    SELECT sha256(convert_to(coalesce(string_agg(l.line, E'\n' ORDER BY l.line COLLATE "C"), ''), 'UTF8'))
      FROM (SELECT r.table_schema || '.' || r.table_name || '.' || r.column_name || ':' || r.data_type AS line
              FROM basalt_meta.pii_readable_columns() r) l
$$;
