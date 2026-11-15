-- v24SearchPath sets search_path = pg_catalog, pg_temp on every function
-- in basalt_meta that does not have it yet, the ones replaced above
-- included. A loop over pg_proc rather than a list, so no function is
-- missed; TestEveryGuardFunctionPutsPgTempLast holds later versions to it.

DO $$
DECLARE
    f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
              WHERE p.pronamespace = 'basalt_meta'::pg_catalog.regnamespace AND p.prokind = 'f'
                AND p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']
              ORDER BY 1 LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %s SET search_path = pg_catalog, pg_temp', f);
    END LOOP;
END $$;
