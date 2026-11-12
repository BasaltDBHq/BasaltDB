package guard

// Version 22 (RS-2): the requesting role reads its revert's rescope nonce
// (CONTRACT.md, basalt_meta "Version 22"), so the engine can serve it to
// the revert page for a widen proof at any time, an engine restart
// included. The nonce is worthless without the person's passkey and the
// page's new link secret; the role could already learn it from an own-work
// rescope.
const v22RevertNonce = `
CREATE OR REPLACE FUNCTION basalt_meta.revert_nonce(p_revert_id uuid) RETURNS bytea
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_nonce bytea;
BEGIN
    SELECT r.rescope_nonce INTO v_nonce FROM basalt_meta.reverts r
     WHERE r.revert_id = p_revert_id AND r.requested_by = session_user;
    IF NOT FOUND THEN
        PERFORM basalt_meta._revert_invalid('no such revert');
    END IF;
    RETURN v_nonce;
END $$;

REVOKE ALL ON FUNCTION basalt_meta.revert_nonce(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.revert_nonce(uuid) TO {{agents}};
`
