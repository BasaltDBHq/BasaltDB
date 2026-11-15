-- Version 12 (M4.1): passkey management (CONTRACT.md, Passkey management).
-- WebAuthn never tells the server a passkey was deleted, so the person
-- revokes it here; a revoked passkey signs nothing. Rows are kept.

ALTER TABLE basalt_meta.passkeys
    ADD COLUMN user_handle  bytea CHECK (octet_length(user_handle) BETWEEN 1 AND 64),
    ADD COLUMN last_used_at timestamptz,
    ADD COLUMN revoked_at   timestamptz,
    ADD COLUMN revoked_by   name;

-- The checks of version 4, refusing a revoked passkey and stamping
-- last_used_at on success.
CREATE OR REPLACE FUNCTION basalt_meta._verify_assertion(
    p_binding bytea, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_flag_up       constant int := 1;  -- user present
    c_flag_uv       constant int := 4;  -- user verified (Touch ID, Face ID)
    c_rpid_len      constant int := 32;
    c_counter_at    constant int := 34; -- 1-based offset of the 4-byte counter
    c_counter_len   constant int := 4;
    c_auth_min      constant int := 37;
    c_auth_max      constant int := 1024;
    c_client_max    constant int := 4096;
    c_signature_max constant int := 128;
    pk      basalt_meta.passkeys;
    cd      jsonb;
    flags   int;
    counter bigint;
    sig     record;
BEGIN
    IF p_binding IS NULL OR p_credential_id IS NULL OR p_authenticator_data IS NULL
       OR p_client_data_json IS NULL OR p_signature IS NULL THEN
        PERFORM basalt_meta._approval_invalid('the assertion is missing a field');
    END IF;
    IF octet_length(p_authenticator_data) > c_auth_max OR octet_length(p_client_data_json) > c_client_max
       OR octet_length(p_signature) > c_signature_max THEN
        PERFORM basalt_meta._approval_invalid('the assertion is too large');
    END IF;
    SELECT * INTO pk FROM basalt_meta.passkeys k WHERE k.credential_id = p_credential_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('unknown passkey');
    END IF;
    IF pk.revoked_at IS NOT NULL THEN
        PERFORM basalt_meta._approval_invalid('passkey revoked');
    END IF;
    BEGIN
        cd := convert_from(p_client_data_json, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        cd := NULL;
    END;
    IF jsonb_typeof(cd) IS DISTINCT FROM 'object'
       OR cd ->> 'type' IS DISTINCT FROM 'webauthn.get'
       OR cd ->> 'challenge' IS DISTINCT FROM basalt_meta._b64url(p_binding)
       OR cd ->> 'origin' IS DISTINCT FROM pk.origin THEN
        PERFORM basalt_meta._approval_invalid('client data does not match the request');
    END IF;
    IF octet_length(p_authenticator_data) < c_auth_min
       OR substring(p_authenticator_data FROM 1 FOR c_rpid_len) <> sha256(convert_to(pk.rp_id, 'UTF8')) THEN
        PERFORM basalt_meta._approval_invalid('rpIdHash mismatch');
    END IF;
    flags := get_byte(p_authenticator_data, c_rpid_len);
    IF flags & c_flag_up = 0 OR flags & c_flag_uv = 0 THEN
        PERFORM basalt_meta._approval_invalid('user presence and verification required');
    END IF;
    counter := basalt_meta._num(substring(p_authenticator_data FROM c_counter_at FOR c_counter_len));
    -- Some authenticators never count: 0 is accepted while the stored count is 0.
    IF (counter <> 0 OR pk.sign_count <> 0) AND counter <= pk.sign_count THEN
        PERFORM basalt_meta._approval_invalid('signature counter did not increase (cloned authenticator or replay)');
    END IF;
    sig := basalt_meta._der_sig(p_signature);
    IF NOT basalt_meta._p256_verify(sha256(p_authenticator_data || sha256(p_client_data_json)),
                                    sig.r, sig.s, basalt_meta._num(pk.public_key_x), basalt_meta._num(pk.public_key_y)) THEN
        PERFORM basalt_meta._approval_invalid('bad passkey signature');
    END IF;
    UPDATE basalt_meta.passkeys k SET sign_count = counter, last_used_at = clock_timestamp()
     WHERE k.credential_id = pk.credential_id;
END $$;

-- Admin only (basalt init): store the person's passkey with the WebAuthn
-- user id it was created with. A revoked passkey is never brought back:
-- the person registers a new one.
DROP FUNCTION basalt_meta.register_passkey(bytea, bytea, bytea, text, text, text);
CREATE FUNCTION basalt_meta.register_passkey(
    p_credential_id bytea, p_x bytea, p_y bytea, p_rp_id text, p_origin text, p_label text, p_user_handle bytea
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_handle_max constant int := 64; -- WebAuthn user.id is at most 64 bytes
BEGIN
    IF p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 1 AND 1023 THEN
        PERFORM basalt_meta._invalid('credential id must be 1 to 1023 bytes');
    END IF;
    IF octet_length(p_x) IS DISTINCT FROM 32 OR octet_length(p_y) IS DISTINCT FROM 32
       OR NOT basalt_meta._p256_on_curve(basalt_meta._num(p_x), basalt_meta._num(p_y)) THEN
        PERFORM basalt_meta._invalid('the public key is not a P-256 point');
    END IF;
    IF p_user_handle IS NOT NULL AND octet_length(p_user_handle) NOT BETWEEN 1 AND c_handle_max THEN
        PERFORM basalt_meta._invalid(format('user handle must be 1 to %s bytes', c_handle_max));
    END IF;
    PERFORM basalt_meta._check_text('rp_id', p_rp_id, 253, true);
    PERFORM basalt_meta._check_text('origin', p_origin, 300, true);
    PERFORM basalt_meta._check_text('label', p_label, 200, true);
    IF EXISTS (SELECT 1 FROM basalt_meta.passkeys k WHERE k.credential_id = p_credential_id AND k.revoked_at IS NOT NULL) THEN
        PERFORM basalt_meta._invalid('this passkey was revoked; register a new one');
    END IF;
    INSERT INTO basalt_meta.passkeys (credential_id, public_key_x, public_key_y, rp_id, origin, label, user_handle)
    VALUES (p_credential_id, p_x, p_y, p_rp_id, p_origin, p_label, p_user_handle)
    ON CONFLICT (credential_id) DO UPDATE
       SET public_key_x = excluded.public_key_x, public_key_y = excluded.public_key_y,
           rp_id = excluded.rp_id, origin = excluded.origin, label = excluded.label,
           user_handle = excluded.user_handle, sign_count = 0;
END $$;

-- Admin only: revoke a passkey. Refuses the last active one unless
-- p_force, since nothing held could then be approved or reverted. Returns
-- how many active passkeys remain.
CREATE FUNCTION basalt_meta.revoke_passkey(p_credential_id bytea, p_force boolean) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    pk          basalt_meta.passkeys;
    v_remaining int;
BEGIN
    -- Lock every active passkey, so two revocations cannot both pass the
    -- last-passkey check.
    PERFORM 1 FROM basalt_meta.passkeys k WHERE k.revoked_at IS NULL FOR UPDATE;
    SELECT * INTO pk FROM basalt_meta.passkeys k WHERE k.credential_id = p_credential_id;
    IF NOT FOUND OR pk.revoked_at IS NOT NULL THEN
        PERFORM basalt_meta._invalid('no active passkey with this credential id');
    END IF;
    SELECT count(k.credential_id) INTO v_remaining FROM basalt_meta.passkeys k
     WHERE k.revoked_at IS NULL AND k.credential_id <> p_credential_id;
    IF v_remaining = 0 AND NOT coalesce(p_force, false) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = 'this is the last active passkey: nothing held could be approved or reverted without one',
            HINT = 'pass force to revoke it anyway, then register another with basalt init --add-passkey';
    END IF;
    UPDATE basalt_meta.passkeys k SET revoked_at = clock_timestamp(), revoked_by = session_user
     WHERE k.credential_id = p_credential_id;
    PERFORM basalt_meta._append(session_user, NULL, 'PASSKEY_REVOKED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('credentialId', basalt_meta._b64url(p_credential_id), 'label', pk.label,
                           'rpId', pk.rp_id, 'remaining', v_remaining, 'forced', coalesce(p_force, false)));
    RETURN v_remaining;
END $$;

-- Active passkeys only, so links list only those; with their dates.
CREATE OR REPLACE VIEW basalt_meta.agent_passkeys AS
    SELECT k.credential_id, k.label, k.public_key_x, k.public_key_y, k.rp_id, k.origin, k.sign_count,
           k.created_at, k.last_used_at
      FROM basalt_meta.passkeys k
     WHERE k.revoked_at IS NULL;

REVOKE ALL ON FUNCTION
    basalt_meta.register_passkey(bytea, bytea, bytea, text, text, text, bytea),
    basalt_meta.revoke_passkey(bytea, boolean)
FROM PUBLIC;
