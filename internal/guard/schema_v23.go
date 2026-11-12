package guard

// Version 23 (RS-2, Q8): the person rejects a pending revert on the revert
// page (CONTRACT.md, basalt_meta "Version 23"; Revert, Rescope, widen and
// reject). No passkey: rejecting can only stop a revert. The engine calls
// reject_revert with the credential of the role that prepared the revert.
// Before a widen nothing tells the person on the link from the agent holding
// it, so the ledger records LINK_OR_AGENT; once the revert has a ceiling the
// call needs the scope token, which only the engine holds for the rotated
// link, and the ledger records SCOPE_TOKEN.
const v23RejectRevert = `
-- Agent, for the engine's reject route: mark the caller's own pending,
-- unsigned, unexpired revert REJECTED. In this order, stopping at the first
-- failure:
--   1. the note, from p_note alone: at most 500 characters (BS008);
--   2. the revert, locked: another role's revert reads like an unknown id,
--      and an applied, signed, rejected or expired one is refused
--      (_revert_lock_pending);
--   3. the scope token: required once the revert has a ceiling, refused
--      on a revert never widened; every failure is REVERT_INVALID
--      WIDEN_REFUSED.
-- Then REJECTED is set and REVERT_REJECTED appended with the note and the
-- path (via). The token is never recorded.
CREATE OR REPLACE FUNCTION basalt_meta.reject_revert(p_revert_id uuid, p_note text, p_token bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    r      basalt_meta.reverts;
    v_note text := nullif(p_note, '');
    v_via  text := 'LINK_OR_AGENT';
    v_at   timestamptz := now();
BEGIN
    PERFORM basalt_meta._require_agent();
    IF char_length(v_note) > 500 THEN
        RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID',
            DETAIL = 'a reject note is at most 500 characters';
    END IF;
    r := basalt_meta._revert_lock_pending(p_revert_id);
    CASE
    WHEN r.ceiling IS NULL AND p_token IS NULL THEN
        v_via := 'LINK_OR_AGENT';
    WHEN r.ceiling IS NOT NULL AND p_token IS NOT NULL AND sha256(p_token) = r.scope_token_hash THEN
        v_via := 'SCOPE_TOKEN';
    ELSE
        PERFORM basalt_meta._widen_refused();
    END CASE;
    UPDATE basalt_meta.reverts x SET rejected_at = v_at, reject_note = v_note WHERE x.revert_id = r.revert_id;
    PERFORM basalt_meta._append(session_user, NULL, 'REVERT_REJECTED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_strip_nulls(jsonb_build_object('revertId', r.revert_id, 'note', v_note, 'via', v_via)));
    RETURN jsonb_build_object('revertId', r.revert_id, 'status', 'REJECTED', 'rejectedAt', v_at);
END $$;

REVOKE ALL ON FUNCTION basalt_meta.reject_revert(uuid, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.reject_revert(uuid, text, bytea) TO {{agents}};
`
