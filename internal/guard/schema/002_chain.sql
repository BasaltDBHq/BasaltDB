-- The hash chain and retention. hash_n = sha256(hash_{n-1} || canonical_n):
-- _append writes every ledger row, verify_chain and verify_chain_from check
-- it, and prune nulls old values and deletes old rows, moving the anchor.

-- hash_n = sha256(hash_{n-1} || canonical_n). The chain covers a digest of
-- the old and new values, not the values, so retention can null them
-- without breaking it. jsonb text has a canonical key order; at is epoch
-- microseconds so the hash does not depend on TimeZone.
CREATE FUNCTION basalt_meta._values_hash(p_old jsonb, p_new jsonb) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT sha256(convert_to(jsonb_build_array(p_old, p_new)::text, 'UTF8'))
$$;

CREATE FUNCTION basalt_meta._canonical(l basalt_meta.ledger) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT convert_to(jsonb_build_object(
        'seq', l.seq, 'at', (extract(epoch FROM l.at) * 1000000)::bigint, 'agent', l.agent,
        'changeId', l.change_id, 'kind', l.kind, 'table', l.table_name, 'tableOid', l.table_oid::bigint,
        'op', l.op, 'key', l.row_key, 'valuesHash', encode(l.values_hash, 'hex'),
        'depth', l.depth, 'detail', l.detail
    )::text, 'UTF8')
$$;

CREATE FUNCTION basalt_meta._append(
    p_agent name, p_change_id uuid, p_kind text, p_table regclass, p_op text,
    p_key jsonb, p_old jsonb, p_new jsonb, p_depth int, p_detail jsonb
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    h basalt_meta.chain_head;
    l basalt_meta.ledger;
BEGIN
    -- The head row lock is held to commit, so chain order equals commit
    -- order and a rolled-back append leaves no gap.
    SELECT * INTO h FROM basalt_meta.chain_head WHERE id FOR UPDATE;
    l.seq := h.seq + 1;
    l.at := clock_timestamp();
    l.agent := p_agent;
    l.change_id := p_change_id;
    l.kind := p_kind;
    l.table_name := p_table::text;
    l.table_oid := p_table::oid;
    l.op := p_op;
    l.row_key := p_key;
    l.old_row := p_old;
    l.new_row := p_new;
    l.values_hash := basalt_meta._values_hash(p_old, p_new);
    l.values_pruned := false;
    l.depth := p_depth;
    l.detail := p_detail;
    l.prev_hash := h.hash;
    l.hash := sha256(h.hash || basalt_meta._canonical(l));
    INSERT INTO basalt_meta.ledger VALUES (l.*);
    UPDATE basalt_meta.chain_head SET seq = l.seq, hash = l.hash WHERE id;
    RETURN l.seq;
END $$;

CREATE FUNCTION basalt_meta.chain_head() RETURNS TABLE (seq bigint, hash bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT h.seq, h.hash FROM basalt_meta.chain_head h WHERE h.id
$$;

-- Head pinning: the engine keeps the last head it saw and checks it on
-- start. False when the row at that seq now has another hash, or the head
-- went backwards: history was rewritten. True when retention already
-- deleted that seq (nothing left to compare).
CREATE FUNCTION basalt_meta.check_head(p_seq bigint, p_hash bytea) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE
        WHEN p_seq = 0 THEN true
        WHEN p_seq > (SELECT h.seq FROM basalt_meta.chain_head h WHERE h.id) THEN false
        WHEN EXISTS (SELECT 1 FROM basalt_meta.ledger l WHERE l.seq = p_seq)
            THEN (SELECT l.hash = p_hash FROM basalt_meta.ledger l WHERE l.seq = p_seq)
        WHEN p_seq = (SELECT a.seq FROM basalt_meta.chain_anchor a WHERE a.id)
            THEN (SELECT a.hash = p_hash FROM basalt_meta.chain_anchor a WHERE a.id)
        WHEN p_seq < (SELECT a.seq FROM basalt_meta.chain_anchor a WHERE a.id) THEN true
        ELSE false
    END
$$;

-- Retention (D10): old and new values (ledger rows, change params) are
-- kept 30 days; other ledger metadata 1 year. Values are nulled, not
-- deleted, and the chain hashes their digest, so it stays verifiable. The
-- oldest rows are deleted as a prefix and the anchor moves to the last one.
-- A held write past its expiry is APPROVAL_EXPIRED. Approval values, a
-- revert's lines and binding text, and a batched plan's line text and chain
-- are values (30 days); their rows go after 1 year (a plan's lines with
-- their revert).
CREATE OR REPLACE FUNCTION basalt_meta._prune(p_now timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_values_ttl constant interval := interval '30 days';
    c_meta_ttl   constant interval := interval '1 year';
    v_values  bigint := 0;
    v_rows    bigint := 0;
    v_expired bigint := 0;
    v_cut     bigint;
BEGIN
    UPDATE basalt_meta.changes c SET status = 'APPROVAL_EXPIRED'
      FROM basalt_meta.approvals a
     WHERE a.held_change = c.change_id AND c.status = 'APPROVAL_PENDING'
       AND a.used_by_change IS NULL AND a.expires_at <= p_now;
    GET DIAGNOSTICS v_expired = ROW_COUNT;

    UPDATE basalt_meta.ledger SET old_row = NULL, new_row = NULL, values_pruned = true
     WHERE NOT values_pruned AND at < p_now - c_values_ttl AND (old_row IS NOT NULL OR new_row IS NOT NULL);
    GET DIAGNOSTICS v_values = ROW_COUNT;
    UPDATE basalt_meta.changes SET params = NULL WHERE params IS NOT NULL AND at < p_now - c_values_ttl;
    UPDATE basalt_meta.approvals SET params = NULL, lines = NULL, binding_text = NULL, statement = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);
    UPDATE basalt_meta.reverts SET lines = NULL, binding_text = NULL
     WHERE created_at < p_now - c_values_ttl AND (lines IS NOT NULL OR binding_text IS NOT NULL);
    UPDATE basalt_meta.revert_lines l SET line = NULL, chain = NULL
      FROM basalt_meta.reverts r
     WHERE r.revert_id = l.revert_id AND r.created_at < p_now - c_values_ttl AND l.line IS NOT NULL;

    SELECT max(seq) INTO v_cut FROM basalt_meta.ledger WHERE at < p_now - c_meta_ttl;
    IF v_cut IS NOT NULL THEN
        UPDATE basalt_meta.chain_anchor a SET seq = l.seq, hash = l.hash
          FROM basalt_meta.ledger l WHERE a.id AND l.seq = v_cut;
        DELETE FROM basalt_meta.ledger WHERE seq <= v_cut;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        DELETE FROM basalt_meta.changes WHERE at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.runs WHERE started_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.approvals WHERE created_at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.reverts WHERE created_at < p_now - c_meta_ttl;
    END IF;

    IF v_values + v_rows > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'PRUNED', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows));
    END IF;
    RETURN jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows, 'approvalsExpired', v_expired);
END $$;

-- The engine's timer calls this. Agents cannot choose the clock.
CREATE FUNCTION basalt_meta.prune() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    RETURN basalt_meta._prune(now());
END $$;

-- Verify the chain from a head the caller pinned earlier: the pinned row
-- (or the anchor) must still carry that hash and recompute to it, then
-- every later row is recomputed up to the head. Returns the first broken
-- seq (NULL when intact) and the head it verified, for the caller to pin.
-- When broken, the pinned head is returned unchanged. A pin older than the
-- anchor (retention deleted it) verifies from the anchor; (0, zero hash)
-- is the full check. Rows before the pin are not recomputed: verify_chain
-- does that.
CREATE FUNCTION basalt_meta.verify_chain_from(p_seq bigint, p_hash bytea)
RETURNS TABLE (broken_at bigint, seq bigint, hash bytea)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a      basalt_meta.chain_anchor;
    h      basalt_meta.chain_head;
    l      basalt_meta.ledger;
    prev   bytea;
    expect bigint;
BEGIN
    IF p_seq IS NULL OR p_seq < 0 OR p_hash IS NULL THEN
        PERFORM basalt_meta._invalid('seq (zero or more) and hash are required');
    END IF;
    SELECT * INTO a FROM basalt_meta.chain_anchor x WHERE x.id;
    SELECT * INTO h FROM basalt_meta.chain_head x WHERE x.id;
    broken_at := NULL;
    seq := p_seq;
    hash := p_hash;

    CASE
    WHEN p_seq > h.seq THEN
        broken_at := h.seq + 1; -- the head went backwards: rows were removed
        RETURN NEXT;
        RETURN;
    WHEN p_seq < a.seq THEN
        prev := a.hash;
        expect := a.seq + 1;
    WHEN p_seq = a.seq THEN
        IF a.hash <> p_hash THEN
            broken_at := p_seq;
            RETURN NEXT;
            RETURN;
        END IF;
        prev := a.hash;
        expect := a.seq + 1;
    ELSE
        SELECT * INTO l FROM basalt_meta.ledger x WHERE x.seq = p_seq;
        IF NOT FOUND OR l.hash <> p_hash OR l.hash <> sha256(l.prev_hash || basalt_meta._canonical(l)) THEN
            broken_at := p_seq;
            RETURN NEXT;
            RETURN;
        END IF;
        prev := l.hash;
        expect := p_seq + 1;
    END CASE;

    FOR l IN SELECT * FROM basalt_meta.ledger x WHERE x.seq >= expect ORDER BY x.seq LOOP
        IF l.seq <> expect THEN
            broken_at := expect;
            RETURN NEXT;
            RETURN;
        END IF;
        IF l.prev_hash <> prev
           OR l.hash <> sha256(prev || basalt_meta._canonical(l))
           OR (l.values_pruned AND (l.old_row IS NOT NULL OR l.new_row IS NOT NULL))
           OR (NOT l.values_pruned AND l.values_hash <> basalt_meta._values_hash(l.old_row, l.new_row)) THEN
            broken_at := l.seq;
            RETURN NEXT;
            RETURN;
        END IF;
        prev := l.hash;
        expect := expect + 1;
    END LOOP;
    IF h.seq <> expect - 1 OR h.hash <> prev THEN
        broken_at := expect; -- tail deleted or head rewritten
        RETURN NEXT;
        RETURN;
    END IF;
    seq := h.seq;
    hash := h.hash;
    RETURN NEXT;
END $$;

-- The full check is the incremental one from the genesis pin.
CREATE OR REPLACE FUNCTION basalt_meta.verify_chain() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT v.broken_at FROM basalt_meta.verify_chain_from(0, '\x0000000000000000000000000000000000000000000000000000000000000000') v
$$;
