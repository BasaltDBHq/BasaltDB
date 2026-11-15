-- Version 13: agents may read the installed version, so the engine can
-- refuse to serve an agent whose guard is older than its build (a
-- basalt_meta that predates a column the engine reads fails mid-call
-- otherwise). The table holds version numbers and timestamps only.

GRANT SELECT ON basalt_meta.schema_version TO {{agents}};
