-- Version 35: bytea_output joins the settings the guard pins, and the
-- revert functions that read and write the person's rows pin them too
-- (CONTRACT.md, basalt_meta "Version 35").
--
--   - guard_row gets SET bytea_output = 'hex' next to version 34's five:
--     to_jsonb prints a bytea column by the session's bytea_output, so a
--     write that skipped the engine with 'escape' stored \000\377A where
--     the engine stores \x00ff41, and a revert from the engine skipped it.
--   - _revert_fetch (the row now, for every conflict check and line) and
--     _revert_write (the restore, which parses the stored image back with
--     jsonb_populate_record) get all six. Through the engine and basalt
--     revert their transaction is already pinned (PinSession); a person
--     calling preview_revert, prepare_revert or apply_revert by hand in
--     another session got the row now in that session's form and every
--     line skipped CHANGED_AFTER.
--
-- ALTER FUNCTION keeps each body, owner, grants and search_path; Postgres
-- restores the caller's values when the function returns, so nothing
-- outside them changes. A later CREATE OR REPLACE of any of the three must
-- restate the clauses; TestGuardPinsTheSessionSettings checks it.
-- Non-breaking: on an older guard every call through the engine is pinned
-- by the engine. Idempotent.

ALTER FUNCTION basalt_meta.guard_row() SET bytea_output = 'hex';
ALTER FUNCTION basalt_meta._revert_fetch(oid, jsonb, boolean)
    SET TimeZone = 'UTC'
    SET DateStyle = 'ISO, MDY'
    SET IntervalStyle = 'postgres'
    SET extra_float_digits = 1
    SET lc_monetary = 'C'
    SET bytea_output = 'hex';
ALTER FUNCTION basalt_meta._revert_write(basalt_meta.revert_item)
    SET TimeZone = 'UTC'
    SET DateStyle = 'ISO, MDY'
    SET IntervalStyle = 'postgres'
    SET extra_float_digits = 1
    SET lc_monetary = 'C'
    SET bytea_output = 'hex';
