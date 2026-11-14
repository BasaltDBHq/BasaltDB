package guard

// Version 34: the guard's row trigger stores row images in fixed session
// settings (CONTRACT.md, basalt_meta "Version 34"). guard_row builds the
// old and new images with to_jsonb, which prints timestamptz in the
// session's TimeZone, interval in its IntervalStyle, float4 and float8 by
// its extra_float_digits and money by its lc_monetary. The engine and
// basalt revert pin those in every transaction they open (PinSession), but
// a write that skips the engine, the agent's credential used directly as
// in psql, ran the trigger in its own session's settings, so its images,
// held lines and rowsHash differed from the engine's and a revert from the
// engine skipped its rows as CHANGED_AFTER.
//
// A SET clause on guard_row pins the same values PinSession sets, for the
// trigger only: Postgres restores the session's values when the function
// returns, so the agent's own SQL in the same transaction is unchanged.
// ALTER FUNCTION keeps the body, owner, grants and search_path. A later
// CREATE OR REPLACE of guard_row must restate these SET clauses (it resets
// what it does not name); TestGuardPinsTheSessionSettings checks it.
//
// guard_truncate and _at_commit build no row image and are not changed.
// Non-breaking: on an older guard a write through the engine is pinned by
// the engine already; only writes that skip it keep their own settings.
// Idempotent.
const v34PinnedTrigger = `
ALTER FUNCTION basalt_meta.guard_row()
    SET TimeZone = 'UTC'
    SET DateStyle = 'ISO, MDY'
    SET IntervalStyle = 'postgres'
    SET extra_float_digits = 1
    SET lc_monetary = 'C';
`
