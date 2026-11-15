-- The PII views: agent_pii_catalog, agent_pii_columns and
-- pii_unclassified.

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

-- The columns the login role may SELECT that need a person: no row (NEW),
-- a row of class UNCLASSIFIED, or a type that changed since basalt
-- classify recorded it (TYPE_CHANGED; the class still applies).
CREATE OR REPLACE FUNCTION basalt_meta.pii_unclassified()
RETURNS TABLE (table_schema text, table_name text, column_name text, data_type text, why text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
    SELECT r.table_schema, r.table_name, r.column_name, r.data_type,
           CASE WHEN p.class IS NULL THEN 'NEW'
                WHEN p.class = 'UNCLASSIFIED' THEN 'UNCLASSIFIED'
                ELSE 'TYPE_CHANGED' END
      FROM basalt_meta.pii_readable_columns() r
      LEFT JOIN basalt_meta.agent_pii_columns p ON p.table_oid = r.table_oid AND p.attnum = r.attnum
     WHERE coalesce(has_column_privilege(session_user, r.table_oid, r.attnum, 'SELECT'), false)
       AND (p.class IS NULL OR p.class = 'UNCLASSIFIED' OR p.data_type IS DISTINCT FROM r.data_type)
     ORDER BY r.table_schema COLLATE "C", r.table_name COLLATE "C", r.column_name COLLATE "C"
$$;

REVOKE ALL ON basalt_meta.agent_pii_columns, basalt_meta.agent_pii_catalog FROM PUBLIC;
REVOKE ALL ON FUNCTION
    basalt_meta.pii_readable_columns(),
    basalt_meta.pii_fingerprint(),
    basalt_meta.pii_unclassified()
FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_pii_columns, basalt_meta.agent_pii_catalog TO {{agents}};
GRANT EXECUTE ON FUNCTION
    basalt_meta.pii_readable_columns(),
    basalt_meta.pii_fingerprint(),
    basalt_meta.pii_unclassified()
TO {{agents}};
