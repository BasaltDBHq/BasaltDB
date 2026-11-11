package guard

// Version 15 (M5.1): PII classification (CONTRACT.md, basalt_meta
// "Version 15" and "PII classification"). One class per column an agent can
// read, written only by basalt classify under SET LOCAL ROLE {{guard}}
// (WriteClassification); agents read it through two security_barrier views
// that filter on session_user in their own WHERE, so a function of the
// caller's query never sees a row the filter drops. The step is
// idempotent: re-running it keeps the rows.

const v15Tables = `
CREATE TABLE IF NOT EXISTS basalt_meta.pii_columns (
    table_schema          text    NOT NULL,
    table_name            text    NOT NULL,
    column_name           text    NOT NULL,
    data_type             text    NOT NULL,
    class                 text    NOT NULL
        CHECK (class IN ('PUBLIC', 'IDENTIFIER', 'FREE_TEXT', 'SECRET', 'UNCLASSIFIED')),
    entity_type           text
        CHECK (entity_type IN ('EMAIL', 'PHONE', 'PERSON_NAME', 'ADDRESS', 'OTHER')),
    suggested_class       text
        CHECK (suggested_class IN ('PUBLIC', 'IDENTIFIER', 'FREE_TEXT', 'SECRET', 'UNCLASSIFIED')),
    suggested_entity_type text
        CHECK (suggested_entity_type IN ('EMAIL', 'PHONE', 'PERSON_NAME', 'ADDRESS', 'OTHER')),
    reason                text,
    needs_review          boolean NOT NULL DEFAULT false,
    phone_region          text    CHECK (phone_region ~ '^[A-Z]{2}$'),
    confirmed_at          timestamptz,
    confirmed_by          text,
    PRIMARY KEY (table_schema, table_name, column_name),
    CONSTRAINT pii_columns_entity_type CHECK ((entity_type IS NOT NULL) = (class = 'IDENTIFIER')),
    CONSTRAINT pii_columns_suggested_entity_type
        CHECK ((suggested_entity_type IS NOT NULL) = coalesce(suggested_class = 'IDENTIFIER', false)),
    CONSTRAINT pii_columns_phone_region CHECK (phone_region IS NULL OR entity_type = 'PHONE'),
    -- Confirmed exactly when a person gave the column a class.
    CONSTRAINT pii_columns_confirmed CHECK (CASE WHEN class = 'UNCLASSIFIED'
        THEN confirmed_at IS NULL AND confirmed_by IS NULL
        ELSE confirmed_at IS NOT NULL AND confirmed_by IS NOT NULL END)
);

-- At most one row: the fingerprint when basalt classify last wrote.
CREATE TABLE IF NOT EXISTS basalt_meta.pii_catalog (
    id            boolean     PRIMARY KEY DEFAULT true CHECK (id),
    fingerprint   bytea       NOT NULL CHECK (octet_length(fingerprint) = 32), -- sha256
    classified_at timestamptz NOT NULL,
    classified_by text        NOT NULL
);
REVOKE ALL ON basalt_meta.pii_columns, basalt_meta.pii_catalog FROM PUBLIC;
`

const v15Functions = `
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
`

const v15Views = `
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
`
