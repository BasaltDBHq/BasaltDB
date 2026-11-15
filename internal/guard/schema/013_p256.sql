-- Version 4 (M2): approvals. A held write is stored with its preview lines
-- and a binding built in Postgres; the person's passkey signs sha256 of the
-- binding text; submit_approval verifies the WebAuthn assertion with a
-- P-256 verifier in plain PL/pgSQL; applying with
-- basalt.approval_id commits only if the statement, parameters and the
-- recomputed lines match (decision M2-1). Same rules as schema.go:
-- forward-only, schema-qualified, role names only through Names.render.

-- Big-endian bytes to an integer.
CREATE FUNCTION basalt_meta._num(b bytea) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
DECLARE r numeric := 0;
BEGIN
    FOR i IN 0 .. length(b) - 1 LOOP
        r := r * 256 + get_byte(b, i);
    END LOOP;
    RETURN r;
END $$;

CREATE FUNCTION basalt_meta._hexnum(h text) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT basalt_meta._num(decode(h, 'hex'))
$$;

-- a mod m in [0, m)
CREATE FUNCTION basalt_meta._mod(a numeric, m numeric) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT CASE WHEN a % m < 0 THEN a % m + m ELSE a % m END
$$;

-- Modular inverse by the extended Euclidean algorithm.
CREATE FUNCTION basalt_meta._inv(a numeric, m numeric) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
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
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
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
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
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
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID', DETAIL = p_detail;
END $$;

-- DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) to (r, s).
CREATE FUNCTION basalt_meta._der_sig(sig bytea, OUT r numeric, OUT s numeric)
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
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
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
    SELECT rtrim(translate(replace(encode(b, 'base64'), E'\n', ''), '+/', '-_'), '=')
$$;
