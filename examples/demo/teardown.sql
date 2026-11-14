-- BasaltDB M4 teardown. Run `basalt uninstall` first (it drops basalt_meta,
-- the guard's triggers and policies, and the basalt_* roles), then paste
-- this into the SQL editor or psql. It drops only what examples/demo/seed.sql
-- and the demo created.

DROP SCHEMA IF EXISTS basalt_demo CASCADE;

-- Expect zero rows from both: nothing of BasaltDB or the demo is left.
SELECT nspname FROM pg_namespace WHERE nspname IN ('basalt_meta', 'basalt_demo');
SELECT rolname FROM pg_roles WHERE rolname LIKE 'basalt\_%';
