-- Version 3: plugin events. The engine records each plugin entry an agent
-- is served, stops being served or that changes, and each key added to the
-- plugin trust store, in that agent's own ledger, through
-- record_plugin_event. The detail is closed: only the keys and shapes of
-- api/plugin/events.schema.json, at most 4 KiB. It holds no config value
-- and no agent name, so no agent's ledger names another agent.

-- A plugin entry event's detail (PLUGIN_ENABLED, PLUGIN_DISABLED,
-- PLUGIN_CHANGED). Raises BS008 LEDGER_INPUT_INVALID on the first rule it
-- breaks; the message names the rule, never the value given. Patterns are
-- the schema's, written without backslashes so they read the same whatever
-- standard_conforming_strings is.
CREATE OR REPLACE FUNCTION basalt_meta._check_plugin_detail(p_detail jsonb) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_name      constant text := '^[a-z][a-z0-9-]{1,39}$';
    c_instance  constant text := '^[a-z][a-z0-9_]{0,31}$';
    c_version   constant text := '^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$';
    c_sha256    constant text := '^[0-9a-f]{64}$';
    c_key_id    constant text := '^[A-Za-z0-9_-]{22}$';
    c_host_port constant text := '^(([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*|[[][0-9a-f:.]+[]]|[0-9]{1,3}([.][0-9]{1,3}){3}):[0-9]{1,5}$';
    c_ident     constant text := '^[A-Za-z0-9._+-]{1,64}$';
    c_version_max constant int := 64;
    c_host_max    constant int := 260;
    v_endpoint  jsonb := p_detail -> 'endpoint';
    v_isolation jsonb := p_detail -> 'isolation';
    v_model     jsonb := p_detail -> 'model';
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_detail) k
                WHERE k NOT IN ('name', 'instance', 'version', 'manifestSha256', 'signerKeyId', 'hooks', 'roles',
                                'egress', 'endpoint', 'isolation', 'model')) THEN
        PERFORM basalt_meta._invalid('plugin event detail has a key that is not allowed');
    END IF;
    IF pg_catalog.jsonb_typeof(p_detail -> 'name') IS DISTINCT FROM 'string' OR p_detail ->> 'name' !~ c_name THEN
        PERFORM basalt_meta._invalid('plugin event name must be a plugin name');
    END IF;
    IF pg_catalog.jsonb_typeof(p_detail -> 'instance') IS DISTINCT FROM 'string' OR p_detail ->> 'instance' !~ c_instance THEN
        PERFORM basalt_meta._invalid('plugin event instance must be an instance name');
    END IF;
    IF pg_catalog.jsonb_typeof(p_detail -> 'version') IS DISTINCT FROM 'string'
       OR pg_catalog.octet_length(p_detail ->> 'version') > c_version_max OR p_detail ->> 'version' !~ c_version THEN
        PERFORM basalt_meta._invalid('plugin event version must be a semantic version of at most 64 bytes');
    END IF;
    IF pg_catalog.jsonb_typeof(p_detail -> 'manifestSha256') IS DISTINCT FROM 'string' OR p_detail ->> 'manifestSha256' !~ c_sha256 THEN
        PERFORM basalt_meta._invalid('plugin event manifestSha256 must be 64 lowercase hex digits');
    END IF;
    IF pg_catalog.jsonb_typeof(p_detail -> 'signerKeyId') IS DISTINCT FROM 'string' OR p_detail ->> 'signerKeyId' !~ c_key_id THEN
        PERFORM basalt_meta._invalid('plugin event signerKeyId must be a key id');
    END IF;

    -- hooks: one or more of the four hooks, each once.
    IF pg_catalog.jsonb_typeof(p_detail -> 'hooks') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(p_detail -> 'hooks') = 0
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_detail -> 'hooks') h
                   WHERE h NOT IN ('"wire.detect"'::jsonb, '"feed.observe"'::jsonb, '"approval.deliver"'::jsonb, '"classify.suggest"'::jsonb))
       OR (SELECT count(DISTINCT h) FROM pg_catalog.jsonb_array_elements(p_detail -> 'hooks') h)
          <> pg_catalog.jsonb_array_length(p_detail -> 'hooks') THEN
        PERFORM basalt_meta._invalid('plugin event hooks must list one or more hooks, each once');
    END IF;
    -- roles: wire.detect only, VALUE and NAME_CUE, each once.
    IF p_detail ? 'roles' AND (
           NOT (p_detail -> 'hooks') @> '["wire.detect"]'::jsonb
           OR pg_catalog.jsonb_typeof(p_detail -> 'roles') <> 'array'
           OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_detail -> 'roles') r
                       WHERE r NOT IN ('"VALUE"'::jsonb, '"NAME_CUE"'::jsonb))
           OR (SELECT count(DISTINCT r) FROM pg_catalog.jsonb_array_elements(p_detail -> 'roles') r)
              <> pg_catalog.jsonb_array_length(p_detail -> 'roles')) THEN
        PERFORM basalt_meta._invalid('plugin event roles must list VALUE or NAME_CUE, each once, for wire.detect');
    END IF;
    -- egress: host:port entries, each once; empty when none.
    IF pg_catalog.jsonb_typeof(p_detail -> 'egress') IS DISTINCT FROM 'array'
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_detail -> 'egress') e
                   WHERE pg_catalog.jsonb_typeof(e) <> 'string' OR pg_catalog.octet_length(e #>> '{}') > c_host_max
                      OR e #>> '{}' !~ c_host_port)
       OR (SELECT count(DISTINCT e) FROM pg_catalog.jsonb_array_elements(p_detail -> 'egress') e)
          <> pg_catalog.jsonb_array_length(p_detail -> 'egress') THEN
        PERFORM basalt_meta._invalid('plugin event egress must list host:port entries, each once');
    END IF;

    -- endpoint: LOCAL, or REMOTE with its host:port. A local entry records
    -- its isolation; a remote one has none to record.
    IF pg_catalog.jsonb_typeof(v_endpoint) IS DISTINCT FROM 'object'
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(v_endpoint) k WHERE k NOT IN ('kind', 'host')) THEN
        PERFORM basalt_meta._invalid('plugin event endpoint must be an object with kind, and host when REMOTE');
    END IF;
    CASE v_endpoint -> 'kind'
    WHEN '"LOCAL"'::jsonb THEN
        IF v_endpoint ? 'host' THEN
            PERFORM basalt_meta._invalid('plugin event endpoint must be an object with kind, and host when REMOTE');
        END IF;
        IF pg_catalog.jsonb_typeof(v_isolation) IS DISTINCT FROM 'object'
           OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(v_isolation) k WHERE k NOT IN ('files', 'network'))
           OR v_isolation -> 'files' IS NULL OR v_isolation -> 'files' NOT IN ('"OS_USER"'::jsonb, '"NONE"'::jsonb)
           OR v_isolation -> 'network' IS NULL
           OR v_isolation -> 'network' NOT IN ('"ENFORCED"'::jsonb, '"DECLARED"'::jsonb, '"NOT_ENFORCED"'::jsonb) THEN
            PERFORM basalt_meta._invalid('plugin event isolation must give files and network for a LOCAL endpoint');
        END IF;
    WHEN '"REMOTE"'::jsonb THEN
        IF pg_catalog.jsonb_typeof(v_endpoint -> 'host') IS DISTINCT FROM 'string'
           OR pg_catalog.octet_length(v_endpoint ->> 'host') > c_host_max OR v_endpoint ->> 'host' !~ c_host_port THEN
            PERFORM basalt_meta._invalid('plugin event endpoint must be an object with kind, and host when REMOTE');
        END IF;
        IF p_detail ? 'isolation' THEN
            PERFORM basalt_meta._invalid('plugin event isolation is for a LOCAL endpoint only');
        END IF;
    ELSE
        PERFORM basalt_meta._invalid('plugin event endpoint must be an object with kind, and host when REMOTE');
    END CASE;

    -- model: the name and version a plugin reports, short identifiers only.
    IF p_detail ? 'model' AND (
           pg_catalog.jsonb_typeof(v_model) <> 'object'
           OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(v_model) k WHERE k NOT IN ('name', 'version'))
           OR pg_catalog.jsonb_typeof(v_model -> 'name') IS DISTINCT FROM 'string' OR v_model ->> 'name' !~ c_ident
           OR pg_catalog.jsonb_typeof(v_model -> 'version') IS DISTINCT FROM 'string' OR v_model ->> 'version' !~ c_ident) THEN
        PERFORM basalt_meta._invalid('plugin event model must give a name and a version, each a short identifier');
    END IF;
END $$;

-- Appends a plugin event to the calling agent's own ledger and returns its
-- seq. The agent is session_user, never an argument. PLUGIN_TRUST_ADDED
-- carries signerKeyId only; the other kinds carry an entry's detail
-- (_check_plugin_detail). A detail over 4 KiB, or any other kind or key,
-- is refused with BS008 and nothing is written.
CREATE OR REPLACE FUNCTION basalt_meta.record_plugin_event(p_kind text, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_detail_max constant int := 4096;
    c_key_id     constant text := '^[A-Za-z0-9_-]{22}$';
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_kind IS NULL OR p_kind NOT IN ('PLUGIN_ENABLED', 'PLUGIN_DISABLED', 'PLUGIN_CHANGED', 'PLUGIN_TRUST_ADDED') THEN
        PERFORM basalt_meta._invalid('kind must be PLUGIN_ENABLED, PLUGIN_DISABLED, PLUGIN_CHANGED or PLUGIN_TRUST_ADDED');
    END IF;
    IF p_detail IS NULL OR pg_catalog.jsonb_typeof(p_detail) <> 'object' THEN
        PERFORM basalt_meta._invalid('detail must be a JSON object');
    END IF;
    IF pg_catalog.octet_length(p_detail::text) > c_detail_max THEN
        PERFORM basalt_meta._invalid('detail is longer than 4096 bytes');
    END IF;
    IF p_kind = 'PLUGIN_TRUST_ADDED' THEN
        IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_detail) k WHERE k <> 'signerKeyId')
           OR pg_catalog.jsonb_typeof(p_detail -> 'signerKeyId') IS DISTINCT FROM 'string'
           OR p_detail ->> 'signerKeyId' !~ c_key_id THEN
            PERFORM basalt_meta._invalid('PLUGIN_TRUST_ADDED detail must be signerKeyId alone, a key id');
        END IF;
    ELSE
        PERFORM basalt_meta._check_plugin_detail(p_detail);
    END IF;
    RETURN basalt_meta._append(session_user, NULL, p_kind, NULL, NULL, NULL, NULL, NULL, NULL, p_detail);
END $$;

REVOKE ALL ON FUNCTION basalt_meta._check_plugin_detail(jsonb), basalt_meta.record_plugin_event(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.record_plugin_event(text, jsonb) TO {{agents}};
