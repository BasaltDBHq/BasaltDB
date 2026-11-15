-- Version 36 (owner decision of 14 Nov 2026 on reinstalls): reinstalls on
-- the record (CONTRACT.md, basalt_meta "Version 36"). A guard install is the
-- oid of its basalt_meta schema; installs keeps one row per install, written
-- by the install transaction. A witness (an engine, or basalt log) whose
-- chain pin was verified on another install reports it with
-- record_pin_set_aside before it sets the pin aside, so a reinstall is never
-- silent, and pin_on_chain tells it whether its pinned entry is still on the
-- current chain (a pg_dump and pg_restore). agent_reinstalls is what every
-- agent role reads to show the notice. Non-breaking: on an older guard an
-- engine keeps its pin and reports a broken chain, as before. Idempotent.

CREATE TABLE IF NOT EXISTS basalt_meta.installs (
    install      oid         PRIMARY KEY,
    installed_at timestamptz NOT NULL,
    installed_by name        NOT NULL,
    vault_user   text
);
REVOKE ALL ON basalt_meta.installs FROM PUBLIC;
{{record_install_row}}
