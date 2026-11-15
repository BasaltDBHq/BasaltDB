-- Version 25: approval and revert deadlines are read from the wall clock
-- (CONTRACT.md, basalt_meta "Version 25"). Up to version 24 every expiry
-- check compared with now(), which Postgres fixes when the transaction
-- starts, so an agent that opened a transaction before an approval or a
-- revert expired could still submit, apply and commit it afterwards, as
-- long as it kept the transaction open. Each check now reads
-- clock_timestamp(), after the row lock where there is one, as
-- record_setup does since version 18.
--
-- The functions are replaced with their latest version otherwise
-- unchanged, attributes restated (CREATE OR REPLACE resets what it does
-- not name; owner and grants are kept), except:
--
--   - submit_approval records the same clock reading as approved_at and
--     returns it;
--   - _check_approval is no longer STABLE: it reads the clock.
--
-- Idempotent.

-- Any relay (version 4): the person's passkey assertion over the
-- approval's binding. The relay is untrusted; only a valid signature
-- counts.
CREATE OR REPLACE FUNCTION basalt_meta.submit_approval(
    p_approval_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a    basalt_meta.approvals;
    v_at timestamptz;
BEGIN
    PERFORM basalt_meta._require_agent();
    SELECT * INTO a FROM basalt_meta.approvals x WHERE x.approval_id = p_approval_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.approved_at IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already signed');
    END IF;
    -- The time now, read after the lock: not the transaction's start.
    v_at := clock_timestamp();
    IF a.expires_at <= v_at THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    PERFORM basalt_meta._verify_assertion(a.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    UPDATE basalt_meta.approvals x SET approved_at = v_at, credential_id = p_credential_id
     WHERE x.approval_id = a.approval_id;
    PERFORM basalt_meta._append(a.agent, a.held_change, 'APPROVED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('approvalId', a.approval_id, 'credentialId', encode(p_credential_id, 'hex'),
                           'relayedBy', session_user));
    RETURN v_at;
END $$;

-- Row trigger: an approval named by basalt.approval_id must be this
-- agent's, for this run, signed, unused and unexpired.
CREATE OR REPLACE FUNCTION basalt_meta._check_approval(p_id uuid, p_run uuid) RETURNS basalt_meta.approvals
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a basalt_meta.approvals;
BEGIN
    SELECT * INTO a FROM basalt_meta.approvals x WHERE x.approval_id = p_id;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.agent <> session_user THEN
        PERFORM basalt_meta._approval_invalid('approval is for another agent');
    END IF;
    IF a.run_id IS DISTINCT FROM p_run THEN
        PERFORM basalt_meta._approval_invalid('approval is for another run');
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    IF a.approved_at IS NULL THEN
        PERFORM basalt_meta._approval_invalid('not approved yet: the person has not signed it with their passkey');
    END IF;
    RETURN a;
END $$;

-- At commit: the applied action is the one the person approved. Checked
-- once per change (later deferred events of the same change see it used
-- by this change). The held record is replaced by the applied one.
CREATE OR REPLACE FUNCTION basalt_meta._commit_approval(c basalt_meta.changes) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a       basalt_meta.approvals;
    v_lines text[];
BEGIN
    SELECT * INTO a FROM basalt_meta.approvals x WHERE x.approval_id = c.approval_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('no such approval');
    END IF;
    IF a.used_by_change = c.change_id THEN
        RETURN;
    END IF;
    IF a.used_by_change IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('approval already used');
    END IF;
    IF a.agent <> c.agent OR a.run_id IS DISTINCT FROM c.run_id OR a.approved_at IS NULL THEN
        PERFORM basalt_meta._approval_invalid('approval is not signed for this agent and run');
    END IF;
    IF a.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = format('approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    IF c.statement IS DISTINCT FROM a.statement OR c.params IS DISTINCT FROM a.params THEN
        PERFORM basalt_meta._approval_invalid('the statement or its parameters differ from the approval');
    END IF;
    v_lines := basalt_meta._lines(c.change_id, a.assigned_columns, a.agent);
    IF cardinality(v_lines) <> a.rows
       OR sha256(convert_to(array_to_string(v_lines, E'\n'), 'UTF8')) <> a.rows_hash THEN
        PERFORM basalt_meta._approval_invalid('rows changed since the preview; a fresh preview and approval are needed');
    END IF;
    UPDATE basalt_meta.approvals x SET used_by_change = c.change_id WHERE x.approval_id = a.approval_id;
    DELETE FROM basalt_meta.changes x WHERE x.change_id = a.held_change AND x.status = 'APPROVAL_PENDING';
END $$;
