-- Version 7 (M3, part 3): apply a revert. apply_revert verifies the
-- person's passkey assertion over the revert binding with the approval
-- verifier (D6), then runs the plan for real in the same transaction, and
-- refuses everything unless the lines it produced are the lines the person
-- signed (decisions M3-2, M3-6). The revert is one change record (op
-- REVERT, actor PERSON) with a ROW_CHANGE per restored row and a REVERTED
-- ledger row (M3-8). Same rules as schema.go: forward-only,
-- schema-qualified, role names only through Names.render.

ALTER TABLE basalt_meta.changes
    ADD COLUMN actor_kind    text   NOT NULL DEFAULT 'AGENT' CONSTRAINT changes_actor_kind CHECK (actor_kind IN ('AGENT', 'PERSON')),
    ADD COLUMN revert_id     uuid,
    ADD COLUMN credential_id bytea,
    ADD COLUMN reverted_by   uuid[];
ALTER TABLE basalt_meta.changes DROP CONSTRAINT changes_status;
ALTER TABLE basalt_meta.changes ADD CONSTRAINT changes_status
    CHECK (status IN ('APPLIED', 'PREVIEW', 'REFUSED', 'APPROVAL_PENDING', 'APPROVAL_EXPIRED', 'REVERTED'));
