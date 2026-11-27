-- Version 14: schema_version records which BasaltDB release wrote each
-- version. Every install and update writes the release of the binary that
-- ran it (a version string, at most 64 characters) on the rows it adds, so
-- a guard too old to update can name the release that set it up. Rows
-- written before this version have none. Non-breaking: no engine reads it
-- while it serves an agent. Idempotent.

ALTER TABLE basalt_meta.schema_version
    ADD COLUMN IF NOT EXISTS release text
    CONSTRAINT schema_version_release_shape CHECK (release ~ '^[0-9A-Za-z.+-]{1,64}$');
