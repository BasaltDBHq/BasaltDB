-- Approvals and passkeys: P-256 and WebAuthn checks done in Postgres, held
-- writes and their preview lines, the person's approval, passkey
-- registration and revocation, and the reveal of a held approval's
-- redacted lines.

-- Big-endian bytes to an integer.
CREATE FUNCTION basalt_meta._num(b bytea) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE r numeric := 0;
BEGIN
    FOR i IN 0 .. length(b) - 1 LOOP
        r := r * 256 + get_byte(b, i);
    END LOOP;
    RETURN r;
END $$;

CREATE FUNCTION basalt_meta._hexnum(h text) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT basalt_meta._num(decode(h, 'hex'))
$$;

-- a mod m in [0, m)
CREATE FUNCTION basalt_meta._mod(a numeric, m numeric) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE WHEN a % m < 0 THEN a % m + m ELSE a % m END
$$;

-- Modular inverse by the extended Euclidean algorithm.
CREATE FUNCTION basalt_meta._inv(a numeric, m numeric) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    t numeric := 0; nt numeric := 1; r numeric := m; nr numeric := basalt_meta._mod(a, m);
    q numeric; tmp numeric;
BEGIN
    WHILE nr <> 0 LOOP
        q := div(r, nr);
        tmp := nt; nt := t - q * nt; t := tmp;
        tmp := nr; nr := r - q * nr; r := tmp;
    END LOOP;
    IF r <> 1 THEN
        RAISE EXCEPTION 'not invertible';
    END IF;
    RETURN basalt_meta._mod(t, m);
END $$;

-- (x, y) is a point of P-256: y^2 = x^3 - 3x + b mod p.
CREATE FUNCTION basalt_meta._p256_on_curve(qx numeric, qy numeric) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p constant numeric := basalt_meta._hexnum('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
    b constant numeric := basalt_meta._hexnum('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
BEGIN
    RETURN qx < p AND qy < p AND basalt_meta._mod(qy * qy - (qx * qx * qx - 3 * qx + b), p) = 0;
END $$;

-- P-256 ECDSA verify: e = the 32-byte hash as an integer, (r, s) the
-- signature, (qx, qy) the public key. Jacobian coordinates with a = -3 and
-- Shamir's trick for u1*G + u2*Q. Verification of public data only, so
-- constant time does not matter.
CREATE FUNCTION basalt_meta._p256_verify(p_hash bytea, r numeric, s numeric, qx numeric, qy numeric) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    p  constant numeric := basalt_meta._hexnum('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
    n  constant numeric := basalt_meta._hexnum('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    gx constant numeric := basalt_meta._hexnum('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
    gy constant numeric := basalt_meta._hexnum('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');
    c_bits constant int := 256;
    e numeric; w numeric; u1 numeric; u2 numeric;
    -- affine table: 1 = G, 2 = Q, 3 = G + Q
    tx numeric[] := ARRAY[0, 0, 0]; ty numeric[] := ARRAY[0, 0, 0]; t3inf boolean := false;
    lam numeric;
    bits1 int[] := '{}'; bits2 int[] := '{}';
    X numeric := 1; Y numeric := 1; Z numeric := 0;   -- point at infinity
    delta numeric; gamma numeric; beta numeric; alpha numeric;
    z1z1 numeric; uu2 numeric; ss2 numeric; h numeric; hh numeric; ii numeric; j numeric; rr numeric; v numeric;
    X3 numeric; Y3 numeric; Z3 numeric; idx int;
BEGIN
    IF r < 1 OR r >= n OR s < 1 OR s >= n OR length(p_hash) <> 32 THEN
        RETURN false;
    END IF;
    IF NOT basalt_meta._p256_on_curve(qx, qy) THEN
        RETURN false;
    END IF;

    e  := basalt_meta._mod(basalt_meta._num(p_hash), n);
    w  := basalt_meta._inv(s, n);
    u1 := basalt_meta._mod(e * w, n);
    u2 := basalt_meta._mod(r * w, n);

    tx[1] := gx; ty[1] := gy; tx[2] := qx; ty[2] := qy;
    IF gx = qx THEN
        IF gy = qy THEN
            lam := basalt_meta._mod((3 * gx * gx - 3) * basalt_meta._inv(2 * gy, p), p);
        ELSE
            t3inf := true;  -- Q = -G
        END IF;
    ELSE
        lam := basalt_meta._mod((qy - gy) * basalt_meta._inv(qx - gx, p), p);
    END IF;
    IF NOT t3inf THEN
        tx[3] := basalt_meta._mod(lam * lam - gx - qx, p);
        ty[3] := basalt_meta._mod(lam * (gx - tx[3]) - gy, p);
    END IF;

    FOR i IN 1 .. c_bits LOOP
        bits1 := (u1 % 2)::int || bits1; u1 := div(u1, 2);
        bits2 := (u2 % 2)::int || bits2; u2 := div(u2, 2);
    END LOOP;

    FOR i IN 1 .. c_bits LOOP
        -- double (dbl-2001-b, a = -3)
        IF Z <> 0 THEN
            IF Y = 0 THEN
                Z := 0;
            ELSE
                delta := Z * Z % p; gamma := Y * Y % p; beta := X * gamma % p;
                alpha := basalt_meta._mod(3 * (X - delta) * (X + delta), p);
                X3 := basalt_meta._mod(alpha * alpha - 8 * beta, p);
                Z3 := basalt_meta._mod((Y + Z) * (Y + Z) - gamma - delta, p);
                Y3 := basalt_meta._mod(alpha * (4 * beta - X3) - 8 * gamma * gamma, p);
                X := X3; Y := Y3; Z := Z3;
            END IF;
        END IF;

        idx := bits1[i] + 2 * bits2[i];
        CONTINUE WHEN idx = 0 OR (idx = 3 AND t3inf);
        IF Z = 0 THEN
            X := tx[idx]; Y := ty[idx]; Z := 1;
            CONTINUE;
        END IF;
        -- mixed add (madd-2007-bl) with an affine table point
        z1z1 := Z * Z % p;
        uu2 := tx[idx] * z1z1 % p;
        ss2 := ty[idx] * Z % p * z1z1 % p;
        h := basalt_meta._mod(uu2 - X, p);
        rr := basalt_meta._mod(2 * (ss2 - Y), p);
        IF h = 0 THEN
            IF rr <> 0 THEN
                Z := 0;  -- P + (-P)
                CONTINUE;
            END IF;
            -- P equals the table point: double it (crafted inputs only)
            delta := Z * Z % p; gamma := Y * Y % p; beta := X * gamma % p;
            alpha := basalt_meta._mod(3 * (X - delta) * (X + delta), p);
            X3 := basalt_meta._mod(alpha * alpha - 8 * beta, p);
            Z3 := basalt_meta._mod((Y + Z) * (Y + Z) - gamma - delta, p);
            Y3 := basalt_meta._mod(alpha * (4 * beta - X3) - 8 * gamma * gamma, p);
            X := X3; Y := Y3; Z := Z3;
            CONTINUE;
        END IF;
        hh := h * h % p; ii := 4 * hh % p; j := h * ii % p; v := X * ii % p;
        X3 := basalt_meta._mod(rr * rr - j - 2 * v, p);
        Y3 := basalt_meta._mod(rr * (v - X3) - 2 * Y * j, p);
        Z3 := basalt_meta._mod((Z + h) * (Z + h) - z1z1 - hh, p);
        X := X3; Y := Y3; Z := Z3;
    END LOOP;

    IF Z = 0 THEN
        RETURN false;
    END IF;
    -- affine x = X / Z^2
    RETURN basalt_meta._mod(X * basalt_meta._inv(Z * Z, p), p) % n = r;
END $$;

-- Raise the one error every bad assertion or approval gets.
CREATE FUNCTION basalt_meta._approval_invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = p_detail;
END $$;

-- DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) to (r, s).
CREATE FUNCTION basalt_meta._der_sig(sig bytea, OUT r numeric, OUT s numeric)
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_seq     constant int := 48;  -- 0x30
    c_int     constant int := 2;   -- 0x02
    c_int_max constant int := 33;  -- 32 bytes plus a sign byte
    c_min     constant int := 8;
    pos int := 2; rl int; sl int;
BEGIN
    IF length(sig) < c_min OR get_byte(sig, 0) <> c_seq OR get_byte(sig, 1) <> length(sig) - 2
       OR get_byte(sig, pos) <> c_int THEN
        PERFORM basalt_meta._approval_invalid('malformed DER signature');
    END IF;
    rl := get_byte(sig, pos + 1);
    IF rl < 1 OR rl > c_int_max OR pos + 2 + rl + 2 > length(sig) THEN
        PERFORM basalt_meta._approval_invalid('malformed DER signature');
    END IF;
    r := basalt_meta._num(substring(sig FROM pos + 3 FOR rl));
    pos := pos + 2 + rl;
    IF get_byte(sig, pos) <> c_int THEN
        PERFORM basalt_meta._approval_invalid('malformed DER signature');
    END IF;
    sl := get_byte(sig, pos + 1);
    IF sl < 1 OR sl > c_int_max OR pos + 2 + sl <> length(sig) THEN
        PERFORM basalt_meta._approval_invalid('malformed DER signature');
    END IF;
    s := basalt_meta._num(substring(sig FROM pos + 3 FOR sl));
END $$;

CREATE FUNCTION basalt_meta._b64url(b bytea) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT rtrim(translate(replace(encode(b, 'base64'), E'\n', ''), '+/', '-_'), '=')
$$;

-- The WebAuthn checks of an assertion over p_binding (the challenge), for
-- approvals and revert authorisations. Raises BS005 APPROVAL_INVALID with
-- a detail, and refuses a revoked passkey; on success bumps the passkey's
-- counter and stamps last_used_at.
CREATE OR REPLACE FUNCTION basalt_meta._verify_assertion(
    p_binding bytea, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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

-- The preview lines of one action (CONTRACT.md, Approvals): one jsonb text
-- per row, cascades included, in COLLATE "C" order. Rows of tables p_role
-- cannot SELECT are redacted to a row hash. The same function builds the
-- lines at preview and at commit, so a match means the same rows.
CREATE FUNCTION basalt_meta._lines(p_change uuid, p_assigned text[], p_role name) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(array_agg(s.line ORDER BY s.line COLLATE "C"), '{}'::text[])
      FROM (
        SELECT CASE WHEN coalesce(has_table_privilege(p_role, l.table_oid, 'SELECT'), false)
                    THEN jsonb_build_object('op', l.op, 'key', x.key, 'old', l.old_row, 'set', x.set,
                                            'table', l.table_name, 'cascaded', x.cascaded)::text
                    ELSE jsonb_build_object('op', l.op, 'table', l.table_name,
                                            'rowHash', encode(sha256(convert_to(jsonb_build_array(x.key, l.old_row, x.set)::text, 'UTF8')), 'hex'),
                                            'cascaded', x.cascaded, 'redacted', true)::text
               END AS line
          FROM basalt_meta.ledger l
          CROSS JOIN LATERAL (SELECT coalesce((l.detail ->> 'cascaded')::boolean, false) AS cascaded) c
          CROSS JOIN LATERAL (
              SELECT CASE WHEN l.op = 'INSERT' THEN NULL ELSE l.row_key END AS key,
                     CASE WHEN l.op = 'DELETE' OR c.cascaded THEN NULL
                          ELSE coalesce((SELECT jsonb_object_agg(k, l.new_row -> k) FROM unnest(p_assigned) k), '{}'::jsonb)
                     END AS set,
                     c.cascaded
          ) x
         WHERE l.change_id = p_change AND l.kind = 'ROW_CHANGE'
      ) s
$$;

CREATE FUNCTION basalt_meta._check_assigned(p_assigned text[]) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_max_columns constant int := 1600;  -- Postgres's column limit
    c_ident_max   constant int := 63;    -- NAMEDATALEN - 1
BEGIN
    IF p_assigned IS NULL OR cardinality(p_assigned) > c_max_columns
       OR EXISTS (SELECT 1 FROM unnest(p_assigned) k WHERE coalesce(k, '') = '' OR octet_length(k) > c_ident_max)
       OR (SELECT count(DISTINCT k) FROM unnest(p_assigned) k) <> cardinality(p_assigned) THEN
        PERFORM basalt_meta._invalid('assigned columns must be distinct column names');
    END IF;
END $$;

-- Agent, in a PREVIEW transaction after the statement: the action's lines,
-- refused whole when they are over the cap.
CREATE OR REPLACE FUNCTION basalt_meta.preview_lines(p_assigned text[]) RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_change uuid;
    v_lines  text[];
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_assigned(p_assigned);
    IF current_setting('basalt.mode', true) IS DISTINCT FROM 'PREVIEW' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'preview_lines needs basalt.mode = PREVIEW';
    END IF;
    SELECT x.change_id INTO v_change FROM basalt_meta.changes x
     WHERE x.tx = pg_current_xact_id_if_assigned() AND x.agent = session_user AND x.mode = 'PREVIEW'
     ORDER BY x.stmt_ts DESC LIMIT 1;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    v_lines := basalt_meta._lines(v_change, p_assigned, session_user);
    PERFORM basalt_meta._check_held_lines(v_lines);
    RETURN QUERY SELECT u.line FROM unnest(v_lines) WITH ORDINALITY u(line, n) ORDER BY u.n;
END $$;

-- Agent: hold a write for the person's approval. Agent, run, task and
-- intent come from session_user and the basalt.* settings; the binding is
-- built here, so the engine cannot choose what the passkey signs beyond the
-- statement, parameters and lines, which the commit check recomputes.
CREATE OR REPLACE FUNCTION basalt_meta.hold_action(p_statement text, p_params jsonb, p_assigned text[], p_lines text[])
RETURNS TABLE (approval_id uuid, binding_text text, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_hold_max constant int := 50;
    c_ttl      constant interval := interval '24 hours';
    v_intent   text := nullif(current_setting('basalt.intent', true), '');
    v_run      uuid := basalt_meta._setting_uuid('basalt.run_id');
    v_rows     int := coalesce(cardinality(p_lines), 0);
    v_id       uuid := basalt_meta._uuidv7();
    v_expires  timestamptz := now() + c_ttl;
    v_task     uuid;
    v_first    jsonb;
    v_hash     bytea;
    v_text     text;
    v_change   uuid;
    v_line     text;
    v_ok       boolean;
BEGIN
    PERFORM basalt_meta._require_agent();
    IF v_intent IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS001', MESSAGE = 'INTENT_REQUIRED',
            DETAIL = format('hold_action by %s without basalt.intent', session_user);
    END IF;
    PERFORM basalt_meta._check_text('basalt.intent', v_intent, 2000, true);
    IF v_run IS NULL THEN
        PERFORM basalt_meta._invalid('basalt.run_id is required: an approval belongs to a run');
    END IF;
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, true);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    IF p_params IS NOT NULL AND jsonb_typeof(p_params) <> 'array' THEN
        PERFORM basalt_meta._invalid('params must be a JSON array');
    END IF;
    PERFORM basalt_meta._check_assigned(p_assigned);
    IF v_rows < 1 OR v_rows > c_hold_max THEN
        PERFORM basalt_meta._invalid(format('a held action has 1 to %s lines', c_hold_max));
    END IF;
    -- Before any line is parsed: the cap bounds the work below too.
    PERFORM basalt_meta._check_held_lines(p_lines);
    FOREACH v_line IN ARRAY p_lines LOOP
        BEGIN
            v_ok := v_line IS NOT NULL
                    AND jsonb_typeof(v_line::jsonb) = 'object' AND v_line::jsonb::text = v_line
                    AND (v_line::jsonb ->> 'op') IN ('INSERT', 'UPDATE', 'DELETE');
        EXCEPTION WHEN OTHERS THEN
            v_ok := false;
        END;
        IF NOT v_ok THEN
            PERFORM basalt_meta._invalid('each line must be the jsonb text of a preview line');
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM generate_subscripts(p_lines, 1) i
                WHERE i > 1 AND (p_lines[i - 1] COLLATE "C") > (p_lines[i] COLLATE "C")) THEN
        PERFORM basalt_meta._invalid('lines must be in COLLATE "C" order');
    END IF;
    SELECT x::jsonb INTO v_first FROM unnest(p_lines) x
     WHERE NOT coalesce((x::jsonb ->> 'cascaded')::boolean, false) LIMIT 1;
    IF v_first IS NULL THEN
        PERFORM basalt_meta._invalid('no line belongs to the statement''s own table');
    END IF;

    v_hash := sha256(convert_to(array_to_string(p_lines, E'\n'), 'UTF8'));
    v_text := jsonb_build_object(
        'kind', 'APPROVE', 'approvalId', v_id, 'database', current_database(), 'agent', session_user,
        'runId', v_run, 'taskId', v_task, 'intent', v_intent, 'statement', p_statement,
        'params', coalesce(p_params, '[]'::jsonb), 'assignedColumns', to_jsonb(p_assigned),
        'rows', v_rows, 'rowsHash', encode(v_hash, 'hex'),
        'expiresAt', to_char(v_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text;

    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name, statement, params,
                                     rows, cascaded_rows, has_delete, mode, approval_id, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent,
            v_first ->> 'op', v_first ->> 'table', p_statement, p_params, v_rows,
            (SELECT count(x) FROM unnest(p_lines) x WHERE coalesce((x::jsonb ->> 'cascaded')::boolean, false)),
            EXISTS (SELECT 1 FROM unnest(p_lines) x WHERE x::jsonb ->> 'op' = 'DELETE'),
            'APPLY', v_id, 'APPROVAL_PENDING')
    RETURNING change_id INTO v_change;

    INSERT INTO basalt_meta.approvals (approval_id, kind, agent, run_id, task_id, intent, statement, params,
                                       assigned_columns, lines, rows, rows_hash, binding_text, binding,
                                       held_change, expires_at)
    VALUES (v_id, 'APPROVE', session_user, v_run, v_task, v_intent, p_statement, p_params, p_assigned, p_lines,
            v_rows, v_hash, v_text, sha256(convert_to(v_text, 'UTF8')), v_change, v_expires);

    PERFORM basalt_meta._append(session_user, v_change, 'APPROVAL_PENDING', NULL, v_first ->> 'op', NULL, NULL, NULL, NULL,
        jsonb_build_object('approvalId', v_id, 'runId', v_run, 'taskId', v_task, 'intent', v_intent,
                           'statement', p_statement, 'rows', v_rows, 'rowsHash', encode(v_hash, 'hex'),
                           'expiresAt', v_expires));
    approval_id := v_id;
    binding_text := v_text;
    expires_at := v_expires;
    RETURN NEXT;
END $$;

-- Any relay (the engine for the agent, basalt approve): the person's
-- passkey assertion over the approval's binding. The relay is untrusted;
-- only a valid signature counts.
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

CREATE FUNCTION basalt_meta.register_passkey(
    p_credential_id bytea, p_x bytea, p_y bytea, p_rp_id text, p_origin text, p_label text, p_user_handle bytea
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
            HINT = 'pass force to revoke it anyway, then register another on the setup page (basalt init)';
    END IF;
    UPDATE basalt_meta.passkeys k SET revoked_at = clock_timestamp(), revoked_by = session_user
     WHERE k.credential_id = p_credential_id;
    PERFORM basalt_meta._append(session_user, NULL, 'PASSKEY_REVOKED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('credentialId', basalt_meta._b64url(p_credential_id), 'label', pk.label,
                           'rpId', pk.rp_id, 'remaining', v_remaining, 'forced', coalesce(p_force, false)));
    RETURN v_remaining;
END $$;

-- The cap on a held write's preview lines: their text summed, in bytes.
CREATE OR REPLACE FUNCTION basalt_meta._check_held_lines(p_lines text[]) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_lines_max constant bigint := 67108864;  -- 64 MiB, guard.MaxHeldLinesBytes
    v_bytes     bigint;
BEGIN
    SELECT coalesce(sum(octet_length(l)), 0) INTO v_bytes FROM unnest(p_lines) l;
    IF v_bytes > c_lines_max THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'HOLD_TOO_LARGE',
            HINT = format('the preview lines are %s bytes; a held write holds at most %s', v_bytes, c_lines_max);
    END IF;
END $$;
