-- Version 2 (M1 close-out): incremental chain verification and the engine
-- events of the dead-man switch and the coverage check.

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
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
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
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT v.broken_at FROM basalt_meta.verify_chain_from(0, '\x0000000000000000000000000000000000000000000000000000000000000000') v
$$;

GRANT EXECUTE ON FUNCTION basalt_meta.verify_chain_from(bigint, bytea) TO {{agents}};
