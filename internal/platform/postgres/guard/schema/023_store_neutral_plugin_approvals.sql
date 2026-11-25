-- Version 10: store-neutral texts. This file: what a person signs for a
-- plugin (CONTRACT.md, Plugins, What a plugin approval binds): the binding
-- names the store, and agents and requestedBy agent:<name>. The table and
-- the view keep the roles, which the engine's check and the ledger compare.

-- The detail open_plugin_approval takes: the binding's keys agents to
-- signerKeyId, without settingsSha256 (CONTRACT.md, What a plugin approval
-- binds). The rules of _check_plugin_detail, then the binding's own: no
-- model, signer required, roles (one or more) exactly with wire.detect,
-- one to 256 agents, every list sorted COLLATE "C" with no repeats, and
-- the detail without agents at most 4096 bytes as text, as a plugin
-- event's. BS008 on the first rule broken, naming the rule only.
CREATE OR REPLACE FUNCTION basalt_meta._check_plugin_approval_detail(p_detail jsonb) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_detail_max constant int := 4096;
    c_agents_max constant int := 256;
    c_agent      constant text := '^agent:[a-z][a-z0-9_]{0,62}$';
    v_agents     jsonb := p_detail -> 'agents';
BEGIN
    IF p_detail IS NULL OR pg_catalog.jsonb_typeof(p_detail) <> 'object' THEN
        PERFORM basalt_meta._invalid('plugin approval detail must be a JSON object');
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_detail) k
                WHERE k NOT IN ('agents', 'name', 'instance', 'version', 'manifestSha256', 'signer', 'signerKeyId',
                                'hooks', 'roles', 'egress', 'endpoint', 'isolation')) THEN
        PERFORM basalt_meta._invalid('plugin approval detail has a key that is not allowed');
    END IF;
    IF pg_catalog.octet_length((p_detail - 'agents')::text) > c_detail_max THEN
        PERFORM basalt_meta._invalid('plugin approval detail without agents is longer than 4096 bytes');
    END IF;
    IF pg_catalog.jsonb_typeof(v_agents) IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(v_agents) NOT BETWEEN 1 AND c_agents_max
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(v_agents) a
                   WHERE pg_catalog.jsonb_typeof(a) <> 'string' OR a #>> '{}' !~ c_agent)
       OR NOT basalt_meta._plugin_sorted(v_agents) THEN
        PERFORM basalt_meta._invalid('plugin approval agents must list 1 to 256 agent:<name> names, sorted COLLATE "C", each once');
    END IF;
    PERFORM basalt_meta._check_plugin_detail(p_detail - 'agents');
    IF NOT p_detail ? 'signer' THEN
        PERFORM basalt_meta._invalid('plugin approval signer is required');
    END IF;
    -- The engine runs every entry that requires approval itself, as its own
    -- child, so it derives files NONE for it: an approval claiming OS_USER
    -- never matches, and the page would show it a calmer level than it has.
    IF p_detail #>> '{isolation,files}' = 'OS_USER' THEN
        PERFORM basalt_meta._invalid('plugin approval isolation files must be NONE: the engine runs an approved plugin itself');
    END IF;
    -- _check_plugin_detail has shown roles is an array when present.
    IF (p_detail -> 'hooks') @> '["wire.detect"]'::jsonb
       <> (p_detail ? 'roles' AND pg_catalog.jsonb_array_length(coalesce(p_detail -> 'roles', '[]'::jsonb)) > 0) THEN
        PERFORM basalt_meta._invalid('plugin approval roles must list one or more roles exactly when hooks has wire.detect');
    END IF;
    IF NOT basalt_meta._plugin_sorted(p_detail -> 'hooks') OR NOT basalt_meta._plugin_sorted(coalesce(p_detail -> 'roles', '[]'::jsonb))
       OR NOT basalt_meta._plugin_sorted(p_detail -> 'egress') THEN
        PERFORM basalt_meta._invalid('plugin approval hooks, roles and egress must be sorted COLLATE "C"');
    END IF;
END $$;

-- The binding of a plugin approval, without change: the validated detail
-- (agents included, agent:<name>) and what Postgres adds: the store and
-- the agent that opened it, agent:<name>. Its jsonb text is the binding
-- text.
CREATE OR REPLACE FUNCTION basalt_meta._plugin_approval_binding(
    p_approval_id uuid, p_expires_at timestamptz, p_requested_by name, p_detail jsonb, p_settings_sha256 text
) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_detail || pg_catalog.jsonb_build_object(
        'kind', 'PLUGIN', 'approvalId', p_approval_id,
        'store', pg_catalog.jsonb_build_object('kind', 'POSTGRES', 'name', pg_catalog.current_database()::text),
        'expiresAt', pg_catalog.to_char(p_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', basalt_meta._agent_text(p_requested_by), 'settingsSha256', p_settings_sha256)
$$;

-- change: what p_binding differs in from the earlier signed approval
-- p_prev, from Postgres's own records. Each key only when that thing
-- differs; {} when nothing does.
CREATE OR REPLACE FUNCTION basalt_meta._plugin_approval_change(p_prev basalt_meta.plugin_approvals, p_binding jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_prev   jsonb := p_prev.detail;
    -- The earlier approval's agents, stored as roles, named as the binding
    -- names them.
    v_agents jsonb := (SELECT pg_catalog.jsonb_agg(basalt_meta._agent_text(a::name)) FROM pg_catalog.unnest(p_prev.agents) a);
    v_out    jsonb := '{}'::jsonb;
    v_list   jsonb;
    k        text;
BEGIN
    IF v_prev -> 'version' IS DISTINCT FROM p_binding -> 'version' THEN
        v_out := v_out || pg_catalog.jsonb_build_object('fromVersion', v_prev -> 'version');
    END IF;
    IF v_prev -> 'manifestSha256' IS DISTINCT FROM p_binding -> 'manifestSha256' THEN
        v_out := v_out || pg_catalog.jsonb_build_object('fromManifestSha256', v_prev -> 'manifestSha256');
    END IF;
    IF v_prev -> 'signer' IS DISTINCT FROM p_binding -> 'signer' THEN
        v_out := v_out || pg_catalog.jsonb_build_object('fromSigner', v_prev -> 'signer');
    END IF;
    IF v_prev -> 'endpoint' IS DISTINCT FROM p_binding -> 'endpoint' THEN
        v_out := v_out || pg_catalog.jsonb_build_object('fromEndpoint', v_prev -> 'endpoint');
    END IF;
    IF v_prev -> 'isolation' IS DISTINCT FROM p_binding -> 'isolation' THEN
        -- JSON null when the earlier entry was REMOTE and had none.
        v_out := v_out || pg_catalog.jsonb_build_object('fromIsolation', coalesce(v_prev -> 'isolation', 'null'::jsonb));
    END IF;
    FOREACH k IN ARRAY ARRAY['hooks', 'roles', 'egress'] LOOP
        v_list := basalt_meta._plugin_list_minus(p_binding -> k, v_prev -> k);
        IF v_list IS NOT NULL THEN
            v_out := v_out || pg_catalog.jsonb_build_object(k || 'Added', v_list);
        END IF;
        v_list := basalt_meta._plugin_list_minus(v_prev -> k, p_binding -> k);
        IF v_list IS NOT NULL THEN
            v_out := v_out || pg_catalog.jsonb_build_object(k || 'Removed', v_list);
        END IF;
    END LOOP;
    v_list := basalt_meta._plugin_list_minus(p_binding -> 'agents', v_agents);
    IF v_list IS NOT NULL THEN
        v_out := v_out || pg_catalog.jsonb_build_object('agentsAdded', v_list);
    END IF;
    v_list := basalt_meta._plugin_list_minus(v_agents, p_binding -> 'agents');
    IF v_list IS NOT NULL THEN
        v_out := v_out || pg_catalog.jsonb_build_object('agentsRemoved', v_list);
    END IF;
    IF v_prev -> 'settingsSha256' IS DISTINCT FROM p_binding -> 'settingsSha256' THEN
        v_out := v_out || '{"settingsChanged": true}'::jsonb;
    END IF;
    RETURN v_out;
END $$;

-- Agent: open a plugin approval for the agents in the detail, all of this
-- database. Cancels the earlier pending approvals of the same (name,
-- instance), refuses a ninth unexpired pending one, builds change, the
-- settings text and the binding text, stores the row and appends
-- PLUGIN_APPROVAL_PENDING to the caller's ledger. Opens are serialised by
-- the table lock, so the cap holds under concurrent calls.
CREATE OR REPLACE FUNCTION basalt_meta.open_plugin_approval(p_detail jsonb, p_settings jsonb)
RETURNS TABLE (approval_id uuid, binding_text text, settings_text text, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
#variable_conflict use_column
DECLARE
    c_ttl         constant interval := interval '24 hours';
    c_pending_max constant int := 8;
    v_settings jsonb;
    v_settings_text text;
    v_id       uuid;
    v_now      timestamptz;
    v_expires  timestamptz;
    v_prev     basalt_meta.plugin_approvals;
    v_binding  jsonb;
    v_text     text;
    v_pending  bigint;
    v_roles    jsonb;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_plugin_approval_detail(p_detail);
    v_settings := basalt_meta._plugin_approval_settings(p_settings, p_detail -> 'endpoint' ->> 'kind');
    -- Each agent's role, from the record; an unknown name stays as given
    -- and is no agent role, so the check refuses it.
    SELECT pg_catalog.jsonb_agg(basalt_meta._agent_role(a) ORDER BY n) INTO v_roles
      FROM pg_catalog.jsonb_array_elements_text(p_detail -> 'agents') WITH ORDINALITY u(a, n);
    PERFORM basalt_meta._check_plugin_approval_agents(v_roles);
    v_settings_text := v_settings::text;

    -- submit_plugin_approval takes ROW EXCLUSIVE first, so the two never
    -- wait on each other in opposite orders.
    LOCK TABLE basalt_meta.plugin_approvals IN SHARE ROW EXCLUSIVE MODE;
    UPDATE basalt_meta.plugin_approvals p SET status = 'CANCELLED'
     WHERE p.name = p_detail ->> 'name' AND p.instance = p_detail ->> 'instance' AND p.status = 'PENDING';
    v_now := pg_catalog.clock_timestamp();
    SELECT pg_catalog.count(p.approval_id) INTO v_pending
      FROM basalt_meta.plugin_approvals p WHERE p.status = 'PENDING' AND p.expires_at > v_now;
    IF v_pending >= c_pending_max THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'TOO_MANY_PENDING',
            HINT = pg_catalog.format('a database holds at most %s pending plugin approvals', c_pending_max);
    END IF;

    v_id := basalt_meta._uuidv7();
    v_expires := v_now + c_ttl;
    v_binding := basalt_meta._plugin_approval_binding(v_id, v_expires, session_user, p_detail,
        pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_settings_text, 'UTF8')), 'hex'));
    SELECT * INTO v_prev FROM basalt_meta.plugin_approvals p
     WHERE p.name = p_detail ->> 'name' AND p.instance = p_detail ->> 'instance' AND p.status = 'APPROVED'
     ORDER BY p.opened_at DESC, p.approval_id DESC LIMIT 1;
    IF v_prev.approval_id IS NOT NULL THEN
        v_binding := v_binding || pg_catalog.jsonb_build_object('change', basalt_meta._plugin_approval_change(v_prev, v_binding));
    END IF;
    v_text := v_binding::text;

    INSERT INTO basalt_meta.plugin_approvals (approval_id, name, instance, opened_by, agents, detail, settings_text,
                                              binding_text, binding, opened_at, expires_at)
    VALUES (v_id, p_detail ->> 'name', p_detail ->> 'instance', session_user,
            ARRAY(SELECT a FROM pg_catalog.jsonb_array_elements_text(v_roles) a),
            v_binding - ARRAY['kind', 'store', 'requestedBy', 'agents', 'change'],
            v_settings_text, v_text, pg_catalog.sha256(pg_catalog.convert_to(v_text, 'UTF8')), v_now, v_expires);
    PERFORM basalt_meta._append(session_user, NULL, 'PLUGIN_APPROVAL_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        v_binding - ARRAY['kind', 'store', 'requestedBy', 'agents', 'change']);

    approval_id := v_id;
    binding_text := v_text;
    settings_text := v_settings_text;
    expires_at := v_expires;
    RETURN NEXT;
END $$;
