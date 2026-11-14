package guard

// Version 36 (owner decision of 14 Nov 2026 on reinstalls): reinstalls on
// the record (CONTRACT.md, basalt_meta "Version 36"). A guard install is the
// oid of its basalt_meta schema; installs keeps one row per install, written
// by the install transaction. A witness (an engine, or basalt log) whose
// chain pin was verified on another install reports it with
// record_pin_set_aside before it sets the pin aside, so a reinstall is never
// silent, and pin_on_chain tells it whether its pinned entry is still on the
// current chain (a pg_dump and pg_restore). agent_reinstalls is what every
// agent role reads to show the notice. Non-breaking: on an older guard an
// engine keeps its pin and reports a broken chain, as before. Idempotent.
const v36Tables = `
CREATE TABLE IF NOT EXISTS basalt_meta.installs (
    install      oid         PRIMARY KEY,
    installed_at timestamptz NOT NULL,
    installed_by name        NOT NULL,
    vault_user   text
);
REVOKE ALL ON basalt_meta.installs FROM PUBLIC;
` + recordInstallRow

// recordInstallRow writes the current install's row: on an upgrade to
// version 36 (the time of the upgrade), and on every install after it, when
// nothing changes for an install that has one (installed_at kept).
// basalt.vault_user is the Vault user the install ran for, set by the
// Vault's install path; null otherwise.
const recordInstallRow = `
INSERT INTO basalt_meta.installs (install, installed_at, installed_by, vault_user)
SELECT n.oid, pg_catalog.clock_timestamp(), session_user,
       NULLIF(pg_catalog.current_setting('basalt.vault_user', true), '')
  FROM pg_catalog.pg_namespace n
 WHERE n.nspname = 'basalt_meta'
ON CONFLICT (install) DO NOTHING;
`

// recordInstall is recordInstallRow as its own init step, after the
// migrations: it runs as the owner, which alone may write installs.
const recordInstall = `
SET LOCAL ROLE {{guard}};
SET LOCAL search_path = pg_catalog, pg_temp;
` + recordInstallRow + `
RESET search_path;
RESET ROLE;`

const v36Functions = `
-- An agent reports that the chain head it pinned (p_seq, p_hash) was
-- verified on another install (p_install), before it sets that pin aside.
-- Appends PIN_SET_ASIDE with the install's row copied in, so the row stands
-- on its own; the install fields are absent when installs has no row for
-- the current install (basalt_meta was recreated or restored outside the
-- install). Returns false, appending nothing, for a report this role
-- already made. The chain head's row lock serializes the check with the
-- append.
CREATE OR REPLACE FUNCTION basalt_meta.record_pin_set_aside(p_seq bigint, p_hash bytea, p_install oid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_hash_len constant int := 32;
    v_install  oid;
    v_row      basalt_meta.installs;
    v_detail   jsonb;
BEGIN
    IF p_seq IS NULL OR p_seq < 0 OR p_hash IS NULL OR pg_catalog.octet_length(p_hash) <> c_hash_len
       OR p_install IS NULL THEN
        PERFORM basalt_meta._invalid('PIN_SHAPE');
    END IF;
    SELECT n.oid INTO v_install FROM pg_catalog.pg_namespace n WHERE n.nspname = 'basalt_meta';
    IF p_install = v_install THEN
        PERFORM basalt_meta._invalid('PIN_SAME_INSTALL');
    END IF;
    PERFORM 1 FROM basalt_meta.chain_head h WHERE h.id FOR UPDATE;
    IF EXISTS (SELECT 1 FROM basalt_meta.ledger l
                WHERE l.agent = session_user AND l.kind = 'PIN_SET_ASIDE'
                  AND l.detail->>'pinnedInstall' = p_install::text
                  AND l.detail->>'pinnedSeq' = p_seq::text
                  AND l.detail->>'pinnedHash' = pg_catalog.encode(p_hash, 'hex')) THEN
        RETURN false;
    END IF;
    v_detail := pg_catalog.jsonb_build_object('pinnedSeq', p_seq, 'pinnedHash', pg_catalog.encode(p_hash, 'hex'),
        'pinnedInstall', p_install::bigint, 'install', v_install::bigint);
    SELECT * INTO v_row FROM basalt_meta.installs i WHERE i.install = v_install;
    IF FOUND THEN
        v_detail := v_detail || pg_catalog.jsonb_build_object(
            'installedAt', pg_catalog.to_char(v_row.installed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'installedBy', v_row.installed_by);
        IF v_row.vault_user IS NOT NULL THEN
            v_detail := v_detail || pg_catalog.jsonb_build_object('vaultUser', v_row.vault_user);
        END IF;
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'PIN_SET_ASIDE', NULL, NULL, NULL, NULL, NULL, NULL, v_detail);
    RETURN true;
END $$;

-- Whether a pinned head is still on the current chain: the row at p_seq,
-- after the anchor, exists, holds p_hash and recomputes to it, or p_seq is
-- the anchor's seq and the anchor's hash is p_hash. False for a pin before
-- the anchor, which verify_chain_from and check_head accept as verifying
-- from it. Agents cannot read chain_anchor or other agents' rows: this is
-- how a witness tells "my pinned entry is still here" from "the anchor
-- moved past it". Reads only; returns no row data.
CREATE OR REPLACE FUNCTION basalt_meta.pin_on_chain(p_seq bigint, p_hash bytea) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a basalt_meta.chain_anchor;
    l basalt_meta.ledger;
BEGIN
    IF p_seq IS NULL OR p_hash IS NULL THEN
        RETURN false;
    END IF;
    SELECT * INTO a FROM basalt_meta.chain_anchor x WHERE x.id;
    IF p_seq = a.seq THEN
        RETURN a.hash = p_hash;
    END IF;
    IF p_seq < a.seq THEN
        RETURN false;
    END IF;
    SELECT * INTO l FROM basalt_meta.ledger x WHERE x.seq = p_seq;
    RETURN FOUND AND l.hash = p_hash AND l.hash = pg_catalog.sha256(l.prev_hash || basalt_meta._canonical(l));
END $$;
`

const v36Views = `
-- Every PIN_SET_ASIDE row of every agent: a reinstall concerns the whole
-- database, so every engine shows it. Chain heads, role names and the
-- Vault user's name, which the notice shows; no secrets.
CREATE OR REPLACE VIEW basalt_meta.agent_reinstalls WITH (security_barrier = true) AS
    SELECT l.at, l.agent,
           (l.detail->>'pinnedSeq')::bigint AS pinned_seq,
           pg_catalog.decode(l.detail->>'pinnedHash', 'hex') AS pinned_hash,
           (l.detail->>'pinnedInstall')::oid AS pinned_install,
           (l.detail->>'install')::oid AS install,
           (l.detail->>'installedAt')::timestamptz AS installed_at,
           (l.detail->>'installedBy') AS installed_by,
           (l.detail->>'vaultUser') AS vault_user
      FROM basalt_meta.ledger l
     WHERE l.kind = 'PIN_SET_ASIDE';
REVOKE ALL ON basalt_meta.agent_reinstalls FROM PUBLIC;
REVOKE ALL ON FUNCTION
    basalt_meta.record_pin_set_aside(bigint, bytea, oid),
    basalt_meta.pin_on_chain(bigint, bytea)
FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_reinstalls TO {{agents}};
GRANT EXECUTE ON FUNCTION
    basalt_meta.record_pin_set_aside(bigint, bytea, oid),
    basalt_meta.pin_on_chain(bigint, bytea)
TO {{agents}};
`
