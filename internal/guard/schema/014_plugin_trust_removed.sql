-- Version 4: PLUGIN_TRUST_REMOVED. The engine records that a key its
-- trust store does not hold is no longer trusted, in each agent's ledger
-- that records it as added: a key the person removed, or a
-- PLUGIN_TRUST_ADDED the agent wrote itself. The detail is the key id
-- alone, as for PLUGIN_TRUST_ADDED. record_plugin_event is replaced; its
-- owner, grants and every other rule are kept.

CREATE OR REPLACE FUNCTION basalt_meta.record_plugin_event(p_kind text, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_detail_max constant int := 4096;
    c_key_id     constant text := '^[A-Za-z0-9_-]{22}$';
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_kind IS NULL OR p_kind NOT IN ('PLUGIN_ENABLED', 'PLUGIN_DISABLED', 'PLUGIN_CHANGED', 'PLUGIN_TRUST_ADDED', 'PLUGIN_TRUST_REMOVED') THEN
        PERFORM basalt_meta._invalid('kind must be PLUGIN_ENABLED, PLUGIN_DISABLED, PLUGIN_CHANGED, PLUGIN_TRUST_ADDED or PLUGIN_TRUST_REMOVED');
    END IF;
    IF p_detail IS NULL OR pg_catalog.jsonb_typeof(p_detail) <> 'object' THEN
        PERFORM basalt_meta._invalid('detail must be a JSON object');
    END IF;
    IF pg_catalog.octet_length(p_detail::text) > c_detail_max THEN
        PERFORM basalt_meta._invalid('detail is longer than 4096 bytes');
    END IF;
    IF p_kind IN ('PLUGIN_TRUST_ADDED', 'PLUGIN_TRUST_REMOVED') THEN
        IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_detail) k WHERE k <> 'signerKeyId')
           OR pg_catalog.jsonb_typeof(p_detail -> 'signerKeyId') IS DISTINCT FROM 'string'
           OR p_detail ->> 'signerKeyId' !~ c_key_id THEN
            PERFORM basalt_meta._invalid(p_kind || ' detail must be signerKeyId alone, a key id');
        END IF;
    ELSE
        PERFORM basalt_meta._check_plugin_detail(p_detail);
    END IF;
    RETURN basalt_meta._append(session_user, NULL, p_kind, NULL, NULL, NULL, NULL, NULL, NULL, p_detail);
END $$;

REVOKE ALL ON FUNCTION basalt_meta.record_plugin_event(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.record_plugin_event(text, jsonb) TO {{agents}};
