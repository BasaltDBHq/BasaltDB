-- v28SearchPath is version 24's loop over every routine kind that takes a
-- SET clause: functions and procedures. Aggregates and window functions
-- cannot have one; basalt_meta has none.

DO $$
DECLARE
    f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = 'basalt_meta'::pg_catalog.regnamespace AND p.prokind IN ('f', 'p')
                AND p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
              ORDER BY 1 LOOP
        EXECUTE pg_catalog.format('ALTER ROUTINE %s SET search_path = pg_catalog, pg_temp', f);
    END LOOP;
END $$;
