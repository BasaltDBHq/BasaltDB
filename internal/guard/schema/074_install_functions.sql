-- Reinstalls: record_pin_set_aside and pin_on_chain.

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
