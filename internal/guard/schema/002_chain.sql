-- The hash chain: canonical row text, value digests, appending to the
-- ledger, and verify_chain.

-- hash_n = sha256(hash_{n-1} || canonical_n). The chain covers a digest of
-- the old and new values, not the values, so retention can null them
-- without breaking it. jsonb text has a canonical key order; at is epoch
-- microseconds so the hash does not depend on TimeZone.
CREATE FUNCTION basalt_meta._values_hash(p_old jsonb, p_new jsonb) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT sha256(convert_to(jsonb_build_array(p_old, p_new)::text, 'UTF8'))
$$;

CREATE FUNCTION basalt_meta._canonical(l basalt_meta.ledger) RETURNS bytea
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
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
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
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

-- Recompute the chain from the anchor. Returns the first broken seq (a
-- missing seq when rows were deleted), or NULL when intact.
CREATE FUNCTION basalt_meta.verify_chain() RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    a      basalt_meta.chain_anchor;
    h      basalt_meta.chain_head;
    l      basalt_meta.ledger;
    prev   bytea;
    expect bigint;
BEGIN
    SELECT * INTO a FROM basalt_meta.chain_anchor WHERE id;
    prev := a.hash;
    expect := a.seq + 1;
    FOR l IN SELECT * FROM basalt_meta.ledger ORDER BY seq LOOP
        IF l.seq <> expect THEN
            RETURN expect;
        END IF;
        IF l.prev_hash <> prev
           OR l.hash <> sha256(prev || basalt_meta._canonical(l))
           OR (l.values_pruned AND (l.old_row IS NOT NULL OR l.new_row IS NOT NULL))
           OR (NOT l.values_pruned AND l.values_hash <> basalt_meta._values_hash(l.old_row, l.new_row)) THEN
            RETURN l.seq;
        END IF;
        prev := l.hash;
        expect := expect + 1;
    END LOOP;
    SELECT * INTO h FROM basalt_meta.chain_head WHERE id;
    IF h.seq <> expect - 1 OR h.hash <> prev THEN
        RETURN expect; -- tail deleted or head rewritten
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION basalt_meta.chain_head() RETURNS TABLE (seq bigint, hash bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT h.seq, h.hash FROM basalt_meta.chain_head h WHERE h.id
$$;

-- Head pinning: the engine keeps the last head it saw and checks it on
-- start. False when the row at that seq now has another hash, or the head
-- went backwards: history was rewritten. True when retention already
-- deleted that seq (nothing left to compare).
CREATE FUNCTION basalt_meta.check_head(p_seq bigint, p_hash bytea) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
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
