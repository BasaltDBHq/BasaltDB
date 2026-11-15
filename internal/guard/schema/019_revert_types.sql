-- Version 5 (M3, part 1): the revert plan, read-only. From the ledger rows
-- of a scope (one change, one run, one task) the guard builds one chain per
-- row, following key changes, and from each chain the inverse write and
-- the people-win conflicts (CONTRACT.md, Revert; decisions M3-3, M3-4).
-- Nothing here writes the person's tables; version 6 runs the plan on
-- trial and version 7 applies it. Same rules as schema.go: forward-only,
-- schema-qualified, role names only through Names.render.

-- One row as the scope changed it: the first and last in-scope ledger rows,
-- the key it had before (orig_key) and has now (cur_key), the values to
-- restore (old_row of the first) and the values and version the agent left
-- (new_row and new_xmin of the last). broken: someone wrote the row between
-- two in-scope changes.
CREATE TYPE basalt_meta.revert_chain AS (
    table_oid  oid,
    table_name text,
    first_seq  bigint,
    last_seq   bigint,
    first_op   text,
    last_op    text,
    orig_key   jsonb,
    cur_key    jsonb,
    old_row    jsonb,
    new_row    jsonb,
    new_xmin   text,
    cascaded   boolean,
    pruned     boolean,
    broken     boolean,
    change_ids uuid[]
);

-- One line of a revert: the inverse write (op on key, writing set), the
-- row as it is now, and the conflict that skips it (NULL to restore).
CREATE TYPE basalt_meta.revert_item AS (
    table_oid  oid,
    table_name text,
    op         text,
    key        jsonb,
    now        jsonb,
    set        jsonb,
    conflict   text,
    sql_state  text,
    cascaded   boolean,
    change_ids uuid[],
    first_seq  bigint,
    last_seq   bigint
);

-- The latest ledger row of a row, for ALREADY_REVERTED.
CREATE INDEX ledger_table_key ON basalt_meta.ledger (table_oid, row_key, seq) WHERE kind = 'ROW_CHANGE';
CREATE INDEX changes_task ON basalt_meta.changes (task_id, change_id);
