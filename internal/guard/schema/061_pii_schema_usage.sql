-- Version 27 (EV-14): a PII column counts only when the role may reach it,
-- with USAGE on its schema as well as SELECT on the column (CONTRACT.md,
-- basalt_meta "Version 27"). Up to version 26 a column the agent had SELECT
-- on, in a schema without USAGE, was listed by pii_readable_columns and
-- pii_unclassified, though the agent, and basalt classify scanning as it,
-- got "permission denied for schema" reading it.
--
-- pii_fingerprint is built from pii_readable_columns, so it follows without
-- being replaced. The fingerprint stored in pii_catalog is never compared
-- with the live one, so the change needs no rewrite of it. CREATE OR
-- REPLACE keeps the owner and the grants; attributes are restated.
--
-- Idempotent.

-- The PII readable columns (version 24), the same with USAGE on the schema
-- required of the member that may select the column.
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

-- The columns the login role may reach that need a person (version 15),
-- the same with USAGE on the schema required of session_user.
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
