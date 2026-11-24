-- Version 2: a guard install is identified by a random id that the install
-- writes, not by the oid of the basalt_meta schema. That oid repeats: two
-- clusters made the same way (a Postgres container removed and started
-- again from the same image, then basalt init) give basalt_meta the same
-- oid, so a witness's pin of the old ledger was checked against the new
-- one and reported a broken chain.

-- installs becomes this install's one row with a random id. An upgraded
-- install keeps the time, user and Vault user its oid row recorded; with no
-- row for the current oid (basalt_meta restored outside the install) the
-- upgrade writes a new one, as basalt init does.
ALTER TABLE basalt_meta.installs RENAME TO installs_by_oid;

CREATE TABLE basalt_meta.installs (
    id           boolean     PRIMARY KEY DEFAULT true CHECK (id),
    install      uuid        NOT NULL,
    installed_at timestamptz NOT NULL,
    installed_by name        NOT NULL,
    vault_user   text
);

INSERT INTO basalt_meta.installs (id, install, installed_at, installed_by, vault_user)
SELECT true, pg_catalog.gen_random_uuid(), o.installed_at, o.installed_by, o.vault_user
  FROM basalt_meta.installs_by_oid o
  JOIN pg_catalog.pg_namespace n ON n.oid = o.install
 WHERE n.nspname = 'basalt_meta';

{{record_install_row}}
DROP TABLE basalt_meta.installs_by_oid;

-- This install's id, for an agent role to pin chain heads with. Null when
-- installs has no row: basalt_meta was recreated outside the install, or the
-- row deleted, until basalt init writes a new one.
CREATE OR REPLACE FUNCTION basalt_meta.install_id() RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT i.install FROM basalt_meta.installs i WHERE i.id;
$$;

-- record_pin_set_aside takes the install id the pin was verified on.
DROP FUNCTION basalt_meta.record_pin_set_aside(bigint, bytea, oid);

-- An agent reports that the chain head it pinned (p_seq, p_hash) was
-- verified on another install (p_install), before it sets that pin aside.
-- Appends PIN_SET_ASIDE with the install's row copied in, so the row stands
-- on its own. Refuses when installs has no row (NO_INSTALL): there is no
-- install to set the pin aside on. Returns false, appending nothing, for a
-- report this role already made. The chain head's row lock serializes the
-- check with the append.
CREATE FUNCTION basalt_meta.record_pin_set_aside(p_seq bigint, p_hash bytea, p_install uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_hash_len constant int := 32;
    v_row      basalt_meta.installs;
    v_detail   jsonb;
BEGIN
    IF p_seq IS NULL OR p_seq < 0 OR p_hash IS NULL OR pg_catalog.octet_length(p_hash) <> c_hash_len
       OR p_install IS NULL THEN
        PERFORM basalt_meta._invalid('PIN_SHAPE');
    END IF;
    SELECT * INTO v_row FROM basalt_meta.installs i WHERE i.id;
    IF NOT FOUND THEN
        PERFORM basalt_meta._invalid('NO_INSTALL');
    END IF;
    IF p_install = v_row.install THEN
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
        'pinnedInstall', p_install::text, 'install', v_row.install::text,
        'installedAt', pg_catalog.to_char(v_row.installed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'installedBy', v_row.installed_by);
    IF v_row.vault_user IS NOT NULL THEN
        v_detail := v_detail || pg_catalog.jsonb_build_object('vaultUser', v_row.vault_user);
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'PIN_SET_ASIDE', NULL, NULL, NULL, NULL, NULL, NULL, v_detail);
    RETURN true;
END $$;

DROP VIEW basalt_meta.agent_reinstalls;

-- Every PIN_SET_ASIDE row of every agent: a reinstall concerns the whole
-- database, so every engine shows it. Chain heads, role names and the
-- Vault user's name, which the notice shows; no secrets. Install ids are
-- uuids. Ledger rows are never rewritten, so a report recorded before
-- version 2 keeps its oids; it shows under a uuid made from the oid (zeros,
-- then the oid in its last 12 hex digits), which no random id is, so the
-- earlier reports of one install still group together.
CREATE VIEW basalt_meta.agent_reinstalls WITH (security_barrier = true) AS
    SELECT l.at, l.agent,
           (l.detail->>'pinnedSeq')::bigint AS pinned_seq,
           pg_catalog.decode(l.detail->>'pinnedHash', 'hex') AS pinned_hash,
           CASE WHEN l.detail->>'pinnedInstall' ~ '^[0-9]+$'
                THEN ('00000000-0000-0000-0000-' || pg_catalog.lpad(pg_catalog.to_hex((l.detail->>'pinnedInstall')::bigint), 12, '0'))::uuid
                ELSE (l.detail->>'pinnedInstall')::uuid END AS pinned_install,
           CASE WHEN l.detail->>'install' ~ '^[0-9]+$'
                THEN ('00000000-0000-0000-0000-' || pg_catalog.lpad(pg_catalog.to_hex((l.detail->>'install')::bigint), 12, '0'))::uuid
                ELSE (l.detail->>'install')::uuid END AS install,
           (l.detail->>'installedAt')::timestamptz AS installed_at,
           (l.detail->>'installedBy') AS installed_by,
           (l.detail->>'vaultUser') AS vault_user
      FROM basalt_meta.ledger l
     WHERE l.kind = 'PIN_SET_ASIDE';

GRANT SELECT ON basalt_meta.agent_reinstalls TO {{agents}};
GRANT EXECUTE ON FUNCTION basalt_meta.install_id(), basalt_meta.record_pin_set_aside(bigint, bytea, uuid) TO {{agents}};
