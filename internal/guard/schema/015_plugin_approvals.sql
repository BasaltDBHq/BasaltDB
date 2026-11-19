-- Version 5: plugin approvals. A person approves a plugin entry for agents
-- of this database with a passkey. open_plugin_approval validates the
-- caller's detail and settings, builds the binding text here and stores a
-- pending approval; submit_plugin_approval verifies the passkey assertion
-- with _verify_assertion and appends PLUGIN_APPROVED to the ledger of
-- every agent the approval lists. Only that function writes the kind:
-- record_plugin_event refuses it. A PLUGIN_DISABLED written through
-- record_plugin_event ends the caller's signed approvals of that entry in
-- plugin_approval_ends, which outlives the ledger's retention. Ledger
-- details name no agent; the list is in the binding and the table.

CREATE TABLE IF NOT EXISTS basalt_meta.plugin_approvals (
    approval_id   uuid        PRIMARY KEY,
    name          text        NOT NULL,
    instance      text        NOT NULL,
    opened_by     name        NOT NULL,
    agents        text[]      NOT NULL,
    -- The PLUGIN_APPROVAL_PENDING detail: the validated detail without
    -- agents, with approvalId, expiresAt and settingsSha256.
    detail        jsonb       NOT NULL,
    settings_text text        NOT NULL,
    binding_text  text        NOT NULL,
    binding       bytea       NOT NULL,
    opened_at     timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    status        text        NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'CANCELLED')),
    approved_at   timestamptz,
    credential_id bytea,
    CHECK ((status = 'APPROVED') = (approved_at IS NOT NULL AND credential_id IS NOT NULL))
);
-- At most one pending approval per entry: opening a new one cancels it.
CREATE UNIQUE INDEX IF NOT EXISTS plugin_approvals_one_pending
    ON basalt_meta.plugin_approvals (name, instance) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS plugin_approvals_entry
    ON basalt_meta.plugin_approvals (name, instance, opened_at);

-- A signed approval that a PLUGIN_DISABLED ended for one agent role.
CREATE TABLE IF NOT EXISTS basalt_meta.plugin_approval_ends (
    approval_id uuid        NOT NULL REFERENCES basalt_meta.plugin_approvals,
    agent       name        NOT NULL,
    ended_at    timestamptz NOT NULL,
    PRIMARY KEY (approval_id, agent)
);

REVOKE ALL ON basalt_meta.plugin_approvals, basalt_meta.plugin_approval_ends FROM PUBLIC;

-- A plugin entry event's detail (PLUGIN_ENABLED, PLUGIN_DISABLED,
-- PLUGIN_CHANGED), as version 3 with signer: KNOWN or UNKNOWN when given.
-- With UNKNOWN there is no signerKeyId; otherwise signerKeyId is required.
-- Raises BS008 LEDGER_INPUT_INVALID on the first rule it breaks; the
-- message names the rule, never the value given.
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
                WHERE k NOT IN ('name', 'instance', 'version', 'manifestSha256', 'signer', 'signerKeyId', 'hooks', 'roles',
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
    IF p_detail ? 'signer' AND p_detail -> 'signer' NOT IN ('"KNOWN"'::jsonb, '"UNKNOWN"'::jsonb) THEN
        PERFORM basalt_meta._invalid('plugin event signer must be KNOWN or UNKNOWN');
    END IF;
    IF p_detail -> 'signer' = '"UNKNOWN"'::jsonb THEN
        IF p_detail ? 'signerKeyId' THEN
            PERFORM basalt_meta._invalid('plugin event signerKeyId is not allowed with signer UNKNOWN');
        END IF;
    ELSIF pg_catalog.jsonb_typeof(p_detail -> 'signerKeyId') IS DISTINCT FROM 'string' OR p_detail ->> 'signerKeyId' !~ c_key_id THEN
        PERFORM basalt_meta._invalid('plugin event signerKeyId must be a key id');
    END IF;

    -- hooks: one or more of the four hooks, each once.
    IF pg_catalog.jsonb_typeof(p_detail -> 'hooks') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(p_detail -> 'hooks') = 0
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_detail -> 'hooks') h
                   WHERE h NOT IN ('"wire.detect"'::jsonb, '"feed.observe"'::jsonb, '"approval.deliver"'::jsonb, '"classify.suggest"'::jsonb))
       OR (SELECT pg_catalog.count(DISTINCT h) FROM pg_catalog.jsonb_array_elements(p_detail -> 'hooks') h)
          <> pg_catalog.jsonb_array_length(p_detail -> 'hooks') THEN
        PERFORM basalt_meta._invalid('plugin event hooks must list one or more hooks, each once');
    END IF;
    -- roles: wire.detect only, VALUE and NAME_CUE, each once.
    IF p_detail ? 'roles' AND (
           NOT (p_detail -> 'hooks') @> '["wire.detect"]'::jsonb
           OR pg_catalog.jsonb_typeof(p_detail -> 'roles') <> 'array'
           OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_detail -> 'roles') r
                       WHERE r NOT IN ('"VALUE"'::jsonb, '"NAME_CUE"'::jsonb))
           OR (SELECT pg_catalog.count(DISTINCT r) FROM pg_catalog.jsonb_array_elements(p_detail -> 'roles') r)
              <> pg_catalog.jsonb_array_length(p_detail -> 'roles')) THEN
        PERFORM basalt_meta._invalid('plugin event roles must list VALUE or NAME_CUE, each once, for wire.detect');
    END IF;
    -- egress: host:port entries, each once; empty when none.
    IF pg_catalog.jsonb_typeof(p_detail -> 'egress') IS DISTINCT FROM 'array'
       OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(p_detail -> 'egress') e
                   WHERE pg_catalog.jsonb_typeof(e) <> 'string' OR pg_catalog.octet_length(e #>> '{}') > c_host_max
                      OR e #>> '{}' !~ c_host_port)
       OR (SELECT pg_catalog.count(DISTINCT e) FROM pg_catalog.jsonb_array_elements(p_detail -> 'egress') e)
          <> pg_catalog.jsonb_array_length(p_detail -> 'egress') THEN
        PERFORM basalt_meta._invalid('plugin event egress must list host:port entries, each once');
    END IF;

    -- endpoint: LOCAL, or REMOTE with its host:port. A local entry records
    -- its isolation; a remote one has none to record.
    IF (CASE WHEN pg_catalog.jsonb_typeof(v_endpoint) = 'object'
             THEN EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(v_endpoint) k WHERE k NOT IN ('kind', 'host'))
             ELSE true END) THEN
        PERFORM basalt_meta._invalid('plugin event endpoint must be an object with kind, and host when REMOTE');
    END IF;
    CASE v_endpoint -> 'kind'
    WHEN '"LOCAL"'::jsonb THEN
        IF v_endpoint ? 'host' THEN
            PERFORM basalt_meta._invalid('plugin event endpoint must be an object with kind, and host when REMOTE');
        END IF;
        IF (CASE WHEN pg_catalog.jsonb_typeof(v_isolation) = 'object'
                 THEN EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(v_isolation) k WHERE k NOT IN ('files', 'network'))
                 ELSE true END)
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
           (CASE WHEN pg_catalog.jsonb_typeof(v_model) = 'object'
                 THEN EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(v_model) k WHERE k NOT IN ('name', 'version'))
                 ELSE true END)
           OR pg_catalog.jsonb_typeof(v_model -> 'name') IS DISTINCT FROM 'string' OR v_model ->> 'name' !~ c_ident
           OR pg_catalog.jsonb_typeof(v_model -> 'version') IS DISTINCT FROM 'string' OR v_model ->> 'version' !~ c_ident) THEN
        PERFORM basalt_meta._invalid('plugin event model must give a name and a version, each a short identifier');
    END IF;
END $$;

-- True when a JSON array of strings is sorted by its text COLLATE "C"
-- with no repeats.
CREATE OR REPLACE FUNCTION basalt_meta._plugin_sorted(p_list jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT NOT EXISTS (
        SELECT 1
          FROM (SELECT x.e, pg_catalog.lag(x.e) OVER (ORDER BY x.n) AS prev
                  FROM pg_catalog.jsonb_array_elements_text(p_list) WITH ORDINALITY x(e, n)) s
         WHERE s.prev IS NOT NULL AND (s.prev COLLATE "C") >= (s.e COLLATE "C"))
$$;

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
    c_role       constant text := '^[a-z_][a-z0-9_]{0,62}$';
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
                   WHERE pg_catalog.jsonb_typeof(a) <> 'string' OR a #>> '{}' !~ c_role)
       OR NOT basalt_meta._plugin_sorted(v_agents) THEN
        PERFORM basalt_meta._invalid('plugin approval agents must list 1 to 256 role names, sorted COLLATE "C", each once');
    END IF;
    PERFORM basalt_meta._check_plugin_detail(p_detail - 'agents');
    IF NOT p_detail ? 'signer' THEN
        PERFORM basalt_meta._invalid('plugin approval signer is required');
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

-- Every role in agents is an agent role of this database: a member of
-- {{agents}}, not the group itself and not a superuser. BS007 NOT_ALLOWED
-- with detail UNKNOWN_AGENT otherwise; the role is not named.
CREATE OR REPLACE FUNCTION basalt_meta._check_plugin_approval_agents(p_agents jsonb) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1
                 FROM pg_catalog.jsonb_array_elements_text(p_agents) a
                 LEFT JOIN pg_catalog.pg_roles r ON r.rolname = a
                WHERE r.oid IS NULL OR r.rolsuper OR r.rolname = '{{agents}}'
                   OR NOT coalesce(pg_catalog.pg_has_role(r.oid, '{{agents}}', 'USAGE'), false)) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'UNKNOWN_AGENT',
            HINT = 'every role in agents must be an agent role of this database';
    END IF;
END $$;

-- The settings object (CONTRACT.md, What a plugin approval binds): the
-- keys config, auth, timeoutMs and minConfidence, each only when the entry
-- sets it. config is an object as engine.json holds it; auth is
-- credentialFile alone, an absolute path, for a REMOTE endpoint only;
-- timeoutMs a whole number from 50 to 60000; minConfidence from 0 to 1.
-- The two numbers are returned by value, without trailing zeros (0.60 is
-- 0.6, 300.0 is 300); config is returned as given. At most 65536 bytes as
-- text. BS008 on the first rule broken.
CREATE OR REPLACE FUNCTION basalt_meta._plugin_approval_settings(p_settings jsonb, p_endpoint text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_settings_max constant int := 65536;
    c_path_max     constant int := 4096;
    v_out jsonb := p_settings;
    v_n   numeric;
BEGIN
    IF p_settings IS NULL OR pg_catalog.jsonb_typeof(p_settings) <> 'object' THEN
        PERFORM basalt_meta._invalid('plugin settings must be a JSON object');
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_settings) k
                WHERE k NOT IN ('config', 'auth', 'timeoutMs', 'minConfidence')) THEN
        PERFORM basalt_meta._invalid('plugin settings have a key that is not allowed');
    END IF;
    IF pg_catalog.octet_length(p_settings::text) > c_settings_max THEN
        PERFORM basalt_meta._invalid('plugin settings are longer than 65536 bytes');
    END IF;
    IF p_settings ? 'config' AND pg_catalog.jsonb_typeof(p_settings -> 'config') <> 'object' THEN
        PERFORM basalt_meta._invalid('plugin settings config must be a JSON object');
    END IF;
    IF p_settings ? 'auth' AND (
           p_endpoint IS DISTINCT FROM 'REMOTE'
           OR (CASE WHEN pg_catalog.jsonb_typeof(p_settings -> 'auth') = 'object'
                    THEN EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(p_settings -> 'auth') k WHERE k <> 'credentialFile')
                    ELSE true END)
           OR pg_catalog.jsonb_typeof(p_settings -> 'auth' -> 'credentialFile') IS DISTINCT FROM 'string'
           OR pg_catalog.left(p_settings -> 'auth' ->> 'credentialFile', 1) <> '/'
           OR pg_catalog.octet_length(p_settings -> 'auth' ->> 'credentialFile') > c_path_max) THEN
        PERFORM basalt_meta._invalid('plugin settings auth must be credentialFile alone, an absolute path, for a REMOTE endpoint');
    END IF;
    IF p_settings ? 'timeoutMs' THEN
        IF pg_catalog.jsonb_typeof(p_settings -> 'timeoutMs') <> 'number' THEN
            PERFORM basalt_meta._invalid('plugin settings timeoutMs must be a whole number from 50 to 60000');
        END IF;
        v_n := (p_settings ->> 'timeoutMs')::numeric;
        IF v_n <> pg_catalog.trunc(v_n) OR v_n < 50 OR v_n > 60000 THEN
            PERFORM basalt_meta._invalid('plugin settings timeoutMs must be a whole number from 50 to 60000');
        END IF;
        v_out := pg_catalog.jsonb_set(v_out, '{timeoutMs}', pg_catalog.to_jsonb(pg_catalog.trim_scale(v_n)));
    END IF;
    IF p_settings ? 'minConfidence' THEN
        IF pg_catalog.jsonb_typeof(p_settings -> 'minConfidence') <> 'number' THEN
            PERFORM basalt_meta._invalid('plugin settings minConfidence must be a number from 0 to 1');
        END IF;
        v_n := (p_settings ->> 'minConfidence')::numeric;
        IF v_n < 0 OR v_n > 1 THEN
            PERFORM basalt_meta._invalid('plugin settings minConfidence must be a number from 0 to 1');
        END IF;
        v_out := pg_catalog.jsonb_set(v_out, '{minConfidence}', pg_catalog.to_jsonb(pg_catalog.trim_scale(v_n)));
    END IF;
    RETURN v_out;
END $$;

-- The binding of a plugin approval, without change: the validated detail
-- (agents included) and what Postgres adds. Its jsonb text is the binding
-- text.
CREATE OR REPLACE FUNCTION basalt_meta._plugin_approval_binding(
    p_approval_id uuid, p_expires_at timestamptz, p_requested_by name, p_detail jsonb, p_settings_sha256 text
) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT p_detail || pg_catalog.jsonb_build_object(
        'kind', 'PLUGIN', 'approvalId', p_approval_id, 'database', pg_catalog.current_database()::text,
        'expiresAt', pg_catalog.to_char(p_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'requestedBy', p_requested_by::text, 'settingsSha256', p_settings_sha256)
$$;

-- The strings of p_list not in p_other, sorted COLLATE "C"; NULL when none.
CREATE OR REPLACE FUNCTION basalt_meta._plugin_list_minus(p_list jsonb, p_other jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT pg_catalog.jsonb_agg(x.e ORDER BY x.e COLLATE "C")
      FROM pg_catalog.jsonb_array_elements_text(coalesce(p_list, '[]'::jsonb)) x(e)
     WHERE NOT coalesce(p_other, '[]'::jsonb) @> pg_catalog.jsonb_build_array(x.e)
$$;

-- change: what p_binding differs in from the earlier signed approval
-- p_prev, from Postgres's own records. Each key only when that thing
-- differs; {} when nothing does.
CREATE OR REPLACE FUNCTION basalt_meta._plugin_approval_change(p_prev basalt_meta.plugin_approvals, p_binding jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    v_prev   jsonb := p_prev.detail;
    v_agents jsonb := pg_catalog.to_jsonb(p_prev.agents);
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
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_plugin_approval_detail(p_detail);
    v_settings := basalt_meta._plugin_approval_settings(p_settings, p_detail -> 'endpoint' ->> 'kind');
    PERFORM basalt_meta._check_plugin_approval_agents(p_detail -> 'agents');
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
            ARRAY(SELECT a FROM pg_catalog.jsonb_array_elements_text(p_detail -> 'agents') a),
            v_binding - ARRAY['kind', 'database', 'requestedBy', 'agents', 'change'],
            v_settings_text, v_text, pg_catalog.sha256(pg_catalog.convert_to(v_text, 'UTF8')), v_now, v_expires);
    PERFORM basalt_meta._append(session_user, NULL, 'PLUGIN_APPROVAL_PENDING', NULL, NULL, NULL, NULL, NULL, NULL,
        v_binding - ARRAY['kind', 'database', 'requestedBy', 'agents', 'change']);

    approval_id := v_id;
    binding_text := v_text;
    settings_text := v_settings_text;
    expires_at := v_expires;
    RETURN NEXT;
END $$;

-- Any agent role, as a relay: the person's passkey assertion over a
-- pending plugin approval's binding. Postgres verifies it; the relay is
-- untrusted. Appends PLUGIN_APPROVED, which names no agent, to the ledger
-- of every agent the approval lists.
CREATE OR REPLACE FUNCTION basalt_meta.submit_plugin_approval(
    p_approval_id uuid, p_credential_id bytea, p_authenticator_data bytea, p_client_data_json bytea, p_signature bytea
) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    a        basalt_meta.plugin_approvals;
    v_at     timestamptz;
    v_detail jsonb;
    v_agent  text;
BEGIN
    PERFORM basalt_meta._require_agent();
    LOCK TABLE basalt_meta.plugin_approvals IN ROW EXCLUSIVE MODE;
    SELECT * INTO a FROM basalt_meta.plugin_approvals x WHERE x.approval_id = p_approval_id FOR UPDATE;
    IF NOT FOUND THEN
        PERFORM basalt_meta._approval_invalid('NOT_FOUND');
    END IF;
    IF a.status = 'CANCELLED' THEN
        PERFORM basalt_meta._approval_invalid('CANCELLED');
    END IF;
    IF a.status = 'APPROVED' THEN
        PERFORM basalt_meta._approval_invalid('ALREADY_APPROVED');
    END IF;
    -- The time now, read after the lock: not the transaction's start.
    v_at := pg_catalog.clock_timestamp();
    IF a.expires_at <= v_at THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_EXPIRED',
            DETAIL = pg_catalog.format('plugin approval %s expired at %s', a.approval_id, a.expires_at);
    END IF;
    PERFORM basalt_meta._verify_assertion(a.binding, p_credential_id, p_authenticator_data, p_client_data_json, p_signature);
    UPDATE basalt_meta.plugin_approvals x SET status = 'APPROVED', approved_at = v_at, credential_id = p_credential_id
     WHERE x.approval_id = a.approval_id;
    v_detail := (a.detail - 'expiresAt') || pg_catalog.jsonb_build_object(
        'credentialId', basalt_meta._b64url(p_credential_id), 'bindingSha256', pg_catalog.encode(a.binding, 'hex'));
    FOREACH v_agent IN ARRAY a.agents LOOP
        PERFORM basalt_meta._append(v_agent::name, NULL, 'PLUGIN_APPROVED', NULL, NULL, NULL, NULL, NULL, NULL, v_detail);
    END LOOP;
    RETURN v_at;
END $$;

-- Version 4's record_plugin_event with the signer rule (_check_plugin_detail
-- above). It still refuses every kind but its five, PLUGIN_APPROVAL_PENDING
-- and PLUGIN_APPROVED included. A PLUGIN_DISABLED also ends, for the
-- caller, every signed approval of that (name, instance) that names it.
CREATE OR REPLACE FUNCTION basalt_meta.record_plugin_event(p_kind text, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_detail_max constant int := 4096;
    c_key_id     constant text := '^[A-Za-z0-9_-]{22}$';
    v_seq        bigint;
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
    v_seq := basalt_meta._append(session_user, NULL, p_kind, NULL, NULL, NULL, NULL, NULL, NULL, p_detail);
    IF p_kind = 'PLUGIN_DISABLED' THEN
        INSERT INTO basalt_meta.plugin_approval_ends (approval_id, agent, ended_at)
        SELECT p.approval_id, session_user, pg_catalog.clock_timestamp()
          FROM basalt_meta.plugin_approvals p
         WHERE p.name = p_detail ->> 'name' AND p.instance = p_detail ->> 'instance'
           AND p.status = 'APPROVED' AND session_user::text = ANY (p.agents)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN v_seq;
END $$;

-- The plugin approvals that name the calling role or that it opened. The
-- binding and settings texts list other agents, so only the opener sees
-- them; detail names no agent. status is EXPIRED for a pending approval
-- past its expiry; ended_at is the caller's end, if any.
CREATE OR REPLACE VIEW basalt_meta.agent_plugin_approvals WITH (security_barrier = true) AS
    SELECT p.approval_id, p.name, p.instance,
           CASE WHEN p.status = 'PENDING' AND p.expires_at <= pg_catalog.clock_timestamp() THEN 'EXPIRED'
                ELSE p.status END AS status,
           p.opened_at, p.expires_at, p.approved_at,
           (session_user::text = ANY (p.agents)) AS names_caller,
           e.ended_at,
           p.detail,
           CASE WHEN p.opened_by = session_user THEN p.binding_text END AS binding_text,
           CASE WHEN p.opened_by = session_user THEN p.settings_text END AS settings_text
      FROM basalt_meta.plugin_approvals p
      LEFT JOIN basalt_meta.plugin_approval_ends e ON e.approval_id = p.approval_id AND e.agent = session_user
     WHERE session_user::text = ANY (p.agents) OR p.opened_by = session_user;

REVOKE ALL ON basalt_meta.agent_plugin_approvals FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_plugin_approvals TO {{agents}};
REVOKE ALL ON FUNCTION basalt_meta._check_plugin_detail(jsonb), basalt_meta._plugin_sorted(jsonb),
    basalt_meta._check_plugin_approval_detail(jsonb), basalt_meta._check_plugin_approval_agents(jsonb),
    basalt_meta._plugin_approval_settings(jsonb, text),
    basalt_meta._plugin_approval_binding(uuid, timestamptz, name, jsonb, text),
    basalt_meta._plugin_list_minus(jsonb, jsonb), basalt_meta._plugin_approval_change(basalt_meta.plugin_approvals, jsonb),
    basalt_meta.open_plugin_approval(jsonb, jsonb), basalt_meta.submit_plugin_approval(uuid, bytea, bytea, bytea, bytea),
    basalt_meta.record_plugin_event(text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION basalt_meta.open_plugin_approval(jsonb, jsonb),
    basalt_meta.submit_plugin_approval(uuid, bytea, bytea, bytea, bytea),
    basalt_meta.record_plugin_event(text, jsonb) TO {{agents}};
