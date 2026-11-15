-- Version 9 (M3 follow-up, decisions N12-1 to N12-6): reverts of any size.
-- Up to 1000 lines a revert is prepared, signed and applied in one call as
-- in M3. A larger one is a batched plan: every line is stored, the person
-- signs one binding over all of them, and the role that prepared it applies
-- the plan in batches that are checked here against the signed lines.

-- The order a trial write succeeded in (deletes, updates, re-inserts, FK
-- retries): a batched plan's lines are numbered in it, so applying them
-- in number order lands parents before children across batches.
ALTER TYPE basalt_meta.revert_item ADD ATTRIBUTE step int;

ALTER TABLE basalt_meta.reverts
    ADD COLUMN batched     boolean NOT NULL DEFAULT false,
    ADD COLUMN sample_hash bytea,
    ADD COLUMN covered     uuid[],
    ADD COLUMN signed_at   timestamptz,
    ADD COLUMN apply_by    timestamptz,
    ADD COLUMN batches     int     NOT NULL DEFAULT 0;

-- A batched plan's lines: the signed text (redacted for the preparing
-- role, as every line), the row's ledger chain to re-check it at apply
-- time, and what happened to it. line and chain are values, pruned after
-- 30 days.
CREATE TABLE basalt_meta.revert_lines (
    revert_id uuid NOT NULL REFERENCES basalt_meta.reverts ON DELETE CASCADE,
    line_no   int  NOT NULL,
    line      text,
    chain     basalt_meta.revert_chain,
    outcome   text NOT NULL DEFAULT 'PENDING'
              CONSTRAINT revert_lines_outcome CHECK (outcome IN ('PENDING', 'RESTORED', 'SKIPPED')),
    conflict  text,
    sql_state text,
    batch     int,
    PRIMARY KEY (revert_id, line_no)
);
CREATE INDEX revert_lines_pending ON basalt_meta.revert_lines (revert_id, line_no) WHERE outcome = 'PENDING';
REVOKE ALL ON basalt_meta.revert_lines FROM PUBLIC;
