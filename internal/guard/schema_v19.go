package guard

// Version 19 (M5.1 follow-up): pii_fingerprint names each column by table
// oid and attribute number and quotes its names (CONTRACT.md, basalt_meta
// "Version 19"). Up to version 18 a line was schema.table.column:type,
// unquoted and without the oid, so a table dropped and created again with the
// same columns kept the fingerprint, and the engine's map, keyed by oid and
// attnum, kept the dead oid; and a table x.y in schema s collided with a
// table y in a schema named s.x. The stored fingerprint (pii_catalog) is
// never compared with the live one, so the new format needs no rewrite of
// it: the next basalt classify stores the new form. CREATE OR REPLACE keeps
// the owner and the grants; they are restated so the step reads whole.
const v19PIIFingerprint = `
-- sha256 of the readable columns as lines
-- format('%I.%I.%I:%s:%s:%s', schema, table, column, type, table_oid, attnum),
-- in byte order, joined by a line break.
CREATE OR REPLACE FUNCTION basalt_meta.pii_fingerprint() RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
    SELECT sha256(convert_to(coalesce(string_agg(l.line, E'\n' ORDER BY l.line COLLATE "C"), ''), 'UTF8'))
      FROM (SELECT format('%I.%I.%I:%s:%s:%s', r.table_schema, r.table_name, r.column_name,
                          r.data_type, r.table_oid, r.attnum) AS line
              FROM basalt_meta.pii_readable_columns() r) l
$$;

REVOKE ALL ON FUNCTION basalt_meta.pii_fingerprint() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.pii_fingerprint() TO {{agents}};
`
