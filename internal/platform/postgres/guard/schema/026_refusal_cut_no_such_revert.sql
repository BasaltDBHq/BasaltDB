-- Version 13: a refusal is always recorded, and a missing revert or
-- approval has a code. record_refusal cuts an intent, statement or reason
-- over its limit and marks the cut with '...', and replaces params over
-- 64 KiB with {"cut": true, "bytes": <size>}, instead of raising, so an
-- over-long text can no longer keep a refusal out of the ledger, as an
-- over-long name cannot (version 12). REVERT_INVALID for a revert the
-- calling role did not prepare, or none, carries the code NO_SUCH_REVERT
-- as its detail and APPROVAL_INVALID for an approval it does not hold, or
-- none, NO_SUCH_APPROVAL, each with the sentence as its hint, as the codes
-- of version 11 do, so the engine reads the code, never the sentence.

-- p_value cut to at most p_max bytes, '...' included, without splitting a
-- character; p_value itself when it fits, NULL for NULL. The limit is in
-- bytes and left() counts characters, so the cut drops characters until
-- the rest fits: a character is one to four bytes in any server encoding.
CREATE OR REPLACE FUNCTION basalt_meta._cut_text(p_value text, p_max int) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_marker constant text := '...';
    v_keep   int := p_max - octet_length(c_marker);
    v        text;
BEGIN
    IF p_value IS NULL OR octet_length(p_value) <= p_max THEN
        RETURN p_value;
    END IF;
    v := left(p_value, v_keep);
    WHILE octet_length(v) > v_keep LOOP
        v := left(v, char_length(v) - (octet_length(v) - v_keep + 3) / 4);
    END LOOP;
    RETURN v || c_marker;
END $$;

-- REVERT_INVALID with detail p_detail. A revert the calling role did not
-- prepare, or none, is raised with the code NO_SUCH_REVERT as its detail
-- and the sentence as its hint (_revert_refused); every other detail stays
-- the sentence. Every function that refuses a missing revert calls this one
-- with that sentence, so they all answer with the code.
CREATE OR REPLACE FUNCTION basalt_meta._revert_invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_detail = 'no such revert' THEN
        PERFORM basalt_meta._revert_refused('NO_SUCH_REVERT', p_detail);
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'REVERT_INVALID', DETAIL = p_detail;
END $$;

-- APPROVAL_INVALID with detail p_detail. An approval the calling role
-- does not hold, or none, is raised with the code NO_SUCH_APPROVAL as its
-- detail and the sentence as its hint; every other detail stays the
-- sentence. Every function that refuses a missing approval calls this one
-- with that sentence, so they all answer with the code.
CREATE OR REPLACE FUNCTION basalt_meta._approval_invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF p_detail = 'no such approval' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = 'NO_SUCH_APPROVAL', HINT = p_detail;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = p_detail;
END $$;

-- A refused action: the engine refused it, or the guard raised and the
-- transaction rolled back. Written in a new transaction. p_resources are
-- the resources the statement names, a write's target first, empty or NULL
-- when it did not parse. The first 100 that are neither empty nor over 1000
-- bytes are kept, in order; the rest are left out. An intent or reason
-- over 2000 bytes and a statement over 64 KiB are cut with '...'
-- (_cut_text), on the change record and in the ledger row alike, and
-- params over 64 KiB are replaced by {"cut": true, "bytes": <size of the
-- params as JSON text>}, so no text, params or name can keep the refusal
-- out of the ledger.
CREATE OR REPLACE FUNCTION basalt_meta.record_refusal(
    p_run_id uuid, p_task_id uuid, p_intent text, p_op text, p_statement text, p_params jsonb,
    p_code text, p_reason text, p_duration_ms int, p_resources text[]
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_resources constant int := 100;
    v_intent    text := basalt_meta._cut_text(p_intent, 2000);
    v_statement text := basalt_meta._cut_text(p_statement, 65536);
    v_reason    text := basalt_meta._cut_text(p_reason, 2000);
    v_params    jsonb := p_params;
    v_task      uuid;
    v_id        uuid;
    v_resources text[];
BEGIN
    PERFORM basalt_meta._require_agent();
    IF octet_length(p_params::text) > 65536 THEN
        v_params := jsonb_build_object('cut', true, 'bytes', octet_length(p_params::text));
    END IF;
    IF p_op IS NULL OR p_op NOT IN ('READ', 'INSERT', 'UPDATE', 'DELETE', 'OTHER') THEN
        PERFORM basalt_meta._invalid('op must be READ, INSERT, UPDATE, DELETE or OTHER');
    END IF;
    IF p_code IS NULL OR p_code !~ '^[A-Z][A-Z_]{0,63}$' THEN
        PERFORM basalt_meta._invalid('code must be SCREAMING_SNAKE_CASE');
    END IF;
    IF p_duration_ms IS NOT NULL AND p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    v_resources := ARRAY(SELECT u.t FROM unnest(p_resources) WITH ORDINALITY AS u(t, i)
                          WHERE coalesce(u.t, '') <> '' AND octet_length(u.t) <= 1000
                          ORDER BY u.i LIMIT c_max_resources);
    v_task := basalt_meta._run_task(p_run_id, p_task_id);
    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name, statement, params,
                                     duration_ms, status, code, reason)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, nullif(v_intent, ''),
            p_op, v_resources[1], v_statement, v_params, p_duration_ms, 'REFUSED', p_code, v_reason)
    RETURNING change_id INTO v_id;
    PERFORM basalt_meta._append(session_user, v_id, 'REFUSED', NULL, p_op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'intent', v_intent, 'statement', v_statement,
                           'resources', to_jsonb(v_resources),
                           'code', p_code, 'reason', v_reason));
    RETURN v_id;
END $$;

REVOKE ALL ON FUNCTION basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int, text[]) TO {{agents}};
