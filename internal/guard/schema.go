package guard

// The SQL installed in the person's database, in basalt_meta. Every
// migration runs as the guard role (owner of basalt_meta) with
// search_path = pg_catalog, so every object is schema-qualified.
//
// Role names reach this SQL only through Names.render, which replaces the
// {{guard}} and {{agents}} tokens with names that matched identPattern
// (lowercase, so the same token is valid as an identifier and inside a
// string literal). fmt.Sprintf is not used: the PL/pgSQL bodies are full of
// format('%s') calls.
//
// Forward-only: never edit an applied migration; add a new version.

// migration is one forward-only schema version.
type migration struct {
	version int
	sql     string
}

// basalt_meta versions, in order.
const (
	versionGuard         = iota + 1 // M1: guard, ledger, chain, retention
	versionChainFrom                // M1 close-out: verify_chain_from, engine events
	versionReads                    // M1.5: recorded reads and STALE_READ
	versionApprovals                // M2: passkeys, held writes and approvals
	versionRevertPlan               // M3: the revert plan, read-only
	versionRevertTrial              // M3: the trial run and prepared reverts
	versionRevertApply              // M3: apply a signed revert
	versionRLS                      // M3 follow-up: the guard's row-level security policy
	versionRevertBatches            // M3 follow-up: large reverts, signed once and applied in batches
	versionAgentsInherit            // M4: agents are roles that inherit the agents group
	versionAgentPolicy              // M4: ledger row for an agent RLS policy the person confirmed
	versionPasskeys                 // M4.1: passkey revocation and last use
)

// migrations lists every version in order. M2 appends versions.
var migrations = []migration{
	{version: versionGuard, sql: v1Tables + v1Chain + v1Session + v1Guard + v1Coverage + v1Retention + v1Views + v1Grants},
	{version: versionChainFrom, sql: v2ChainFrom + v2Events},
	{version: versionReads, sql: v3Reads + v3Guard},
	{version: versionApprovals, sql: v4P256 + v4Tables + v4Approvals + v4Guard + v4Retention + v4Views},
	{version: versionRevertPlan, sql: v5Types + v5Plan},
	{version: versionRevertTrial, sql: v6Tables + v6Trial},
	{version: versionRevertApply, sql: v7Tables + v7Apply},
	{version: versionRLS, sql: v8RLS},
	{version: versionRevertBatches, sql: v9Tables + v9Chains + v9Execute + v9Prepare + v9Apply + v9Views},
	{version: versionAgentsInherit, sql: v10Agents},
	{version: versionAgentPolicy, sql: v11AgentPolicy},
	{version: versionPasskeys, sql: v12Revocation},
}

// LatestVersion is the basalt_meta version this build installs.
func LatestVersion() int { return migrations[len(migrations)-1].version }

// schemaVersionTable is created before any migration so the installer can
// read the installed version.
const schemaVersionTable = `
CREATE TABLE IF NOT EXISTS basalt_meta.schema_version (
    version    int         PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON basalt_meta.schema_version FROM PUBLIC;
`

const v1Tables = `
-- UUIDv7 (RFC 9562): 48-bit Unix milliseconds over a random v4, version
-- bits set to 0111. Core functions only; Postgres 18's uuidv7() is not
-- available on 15 to 17.
CREATE FUNCTION basalt_meta._uuidv7() RETURNS uuid
LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT encode(set_bit(set_bit(
        overlay(uuid_send(gen_random_uuid())
                PLACING substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
                FROM 1 FOR 6),
        52, 1), 53, 1), 'hex')::uuid
$$;

-- Every table carrying the guard and why (coverage reads this).
CREATE TABLE basalt_meta.guarded_tables (
    table_oid regclass PRIMARY KEY,
    pk_cols   text[]   NOT NULL,
    reason    text     NOT NULL CHECK (reason IN ('AGENT_WRITABLE', 'CASCADE_TARGET'))
);

-- One row per run (run_start). The task id is shared across agents.
CREATE TABLE basalt_meta.runs (
    run_id     uuid        PRIMARY KEY,
    task_id    uuid,
    agent      name        NOT NULL,
    intent     text        NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX runs_started_at ON basalt_meta.runs (started_at);

-- The change record: one row per agent action, which is one top-level
-- statement in one transaction, keyed by (tx, stmt_ts) while it is written.
CREATE TABLE basalt_meta.changes (
    change_id     uuid        PRIMARY KEY DEFAULT basalt_meta._uuidv7(),
    tx            xid8        NOT NULL,
    stmt_ts       timestamptz NOT NULL,
    at            timestamptz NOT NULL DEFAULT clock_timestamp(),
    agent         name        NOT NULL,
    run_id        uuid,
    task_id       uuid,
    intent        text,
    op            text,
    table_name    text,
    statement     text,
    params        jsonb,
    rows          int         NOT NULL DEFAULT 0,
    cascaded_rows int         NOT NULL DEFAULT 0,
    has_delete    boolean     NOT NULL DEFAULT false,
    mode          text        NOT NULL DEFAULT 'APPLY' CONSTRAINT changes_mode CHECK (mode IN ('APPLY', 'PREVIEW')),
    approval_id   uuid,
    duration_ms   int,
    status        text        NOT NULL CONSTRAINT changes_status CHECK (status IN ('APPLIED', 'PREVIEW', 'REFUSED')),
    code          text,
    reason        text,
    UNIQUE (tx, stmt_ts)
);
CREATE INDEX changes_agent ON basalt_meta.changes (agent, change_id);
CREATE INDEX changes_run ON basalt_meta.changes (run_id, change_id);
CREATE INDEX changes_at ON basalt_meta.changes (at);

-- Append-only, hash-chained ledger. Rows are written only by _append.
CREATE TABLE basalt_meta.ledger (
    seq           bigint      PRIMARY KEY,
    at            timestamptz NOT NULL,
    agent         name        NOT NULL,
    change_id     uuid,
    kind          text        NOT NULL,
    table_name    text,
    table_oid     oid,
    op            text,
    row_key       jsonb,
    old_row       jsonb,
    new_row       jsonb,
    values_hash   bytea       NOT NULL,
    values_pruned boolean     NOT NULL DEFAULT false,
    depth         int,
    detail        jsonb,
    prev_hash     bytea       NOT NULL,
    hash          bytea       NOT NULL
);
CREATE INDEX ledger_change ON basalt_meta.ledger (change_id);
CREATE INDEX ledger_agent_kind ON basalt_meta.ledger (agent, kind, seq);
CREATE INDEX ledger_at ON basalt_meta.ledger (at);

-- Last appended (seq, hash). Its row lock serializes appends until commit.
CREATE TABLE basalt_meta.chain_head (
    id   boolean PRIMARY KEY DEFAULT true CHECK (id),
    seq  bigint  NOT NULL,
    hash bytea   NOT NULL
);
INSERT INTO basalt_meta.chain_head VALUES (true, 0, '\x0000000000000000000000000000000000000000000000000000000000000000');

-- Where verification starts: (0, zero hash) until retention deletes the
-- oldest rows, then the last deleted row's (seq, hash).
CREATE TABLE basalt_meta.chain_anchor (
    id   boolean PRIMARY KEY DEFAULT true CHECK (id),
    seq  bigint  NOT NULL,
    hash bytea   NOT NULL
);
INSERT INTO basalt_meta.chain_anchor VALUES (true, 0, '\x0000000000000000000000000000000000000000000000000000000000000000');
`

const v1Chain = `
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
`

const v1Session = `
-- Callers of the agent functions must be agent roles, never superusers
-- (superusers are members of every role).
CREATE FUNCTION basalt_meta._require_agent() RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
BEGIN
    IF NOT pg_has_role(session_user, '{{agents}}', 'MEMBER')
       OR (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('%s is not an agent role', session_user);
    END IF;
END $$;

CREATE FUNCTION basalt_meta._invalid(p_detail text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'BS008', MESSAGE = 'LEDGER_INPUT_INVALID', DETAIL = p_detail;
END $$;

-- Text inputs: intents up to 2000 bytes, statements and JSON up to 64 KiB.
CREATE FUNCTION basalt_meta._check_text(p_name text, p_value text, p_max int, p_required boolean) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
BEGIN
    IF p_required AND coalesce(p_value, '') = '' THEN
        PERFORM basalt_meta._invalid(format('%s is required', p_name));
    END IF;
    IF octet_length(coalesce(p_value, '')) > p_max THEN
        PERFORM basalt_meta._invalid(format('%s is longer than %s bytes', p_name, p_max));
    END IF;
END $$;

-- A uuid session variable, or NULL when unset.
CREATE FUNCTION basalt_meta._setting_uuid(p_name text) RETURNS uuid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $$
DECLARE
    v text := nullif(current_setting(p_name, true), '');
BEGIN
    IF v IS NULL THEN
        RETURN NULL;
    END IF;
    IF v !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        PERFORM basalt_meta._invalid(format('%s must be a uuid', p_name));
    END IF;
    RETURN v::uuid;
END $$;

-- The run an agent names must be its own; its task id wins over the
-- argument so one run cannot claim another task.
CREATE FUNCTION basalt_meta._run_task(p_run uuid, p_task uuid) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_task uuid;
BEGIN
    IF p_run IS NULL THEN
        RETURN p_task;
    END IF;
    SELECT r.task_id INTO v_task FROM basalt_meta.runs r WHERE r.run_id = p_run AND r.agent = session_user;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('run %s is not a run of %s', p_run, session_user);
    END IF;
    RETURN coalesce(v_task, p_task);
END $$;

CREATE FUNCTION basalt_meta.start_run(p_run_id uuid, p_task_id uuid, p_intent text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_run_id IS NULL THEN
        PERFORM basalt_meta._invalid('run id is required');
    END IF;
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, true);
    INSERT INTO basalt_meta.runs (run_id, task_id, agent, intent) VALUES (p_run_id, p_task_id, session_user, p_intent)
    ON CONFLICT (run_id) DO NOTHING;
    IF NOT FOUND THEN
        PERFORM basalt_meta._invalid(format('run %s already exists', p_run_id));
    END IF;
    PERFORM basalt_meta._append(session_user, NULL, 'RUN_STARTED', NULL, NULL, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', p_task_id, 'intent', p_intent));
END $$;

-- Called by the engine after the agent's statement, before COMMIT. Stamps
-- the change the guard opened in this transaction, or records a zero-row
-- change, and chains a CHANGE row carrying the statement and intent.
CREATE FUNCTION basalt_meta.finish_change(p_op text, p_statement text, p_params jsonb, p_duration_ms int)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_intent text := nullif(current_setting('basalt.intent', true), '');
    v_run    uuid := basalt_meta._setting_uuid('basalt.run_id');
    v_task   uuid;
    c        basalt_meta.changes;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, true);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    IF p_params IS NOT NULL AND jsonb_typeof(p_params) <> 'array' THEN
        PERFORM basalt_meta._invalid('params must be a JSON array');
    END IF;
    IF p_duration_ms IS NULL OR p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    IF v_intent IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS001', MESSAGE = 'INTENT_REQUIRED',
            DETAIL = format('finish_change by %s without basalt.intent', session_user);
    END IF;
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));

    SELECT * INTO c FROM basalt_meta.changes x
     WHERE x.tx = pg_current_xact_id_if_assigned() AND x.agent = session_user AND x.statement IS NULL
     ORDER BY x.stmt_ts DESC LIMIT 1;
    IF FOUND THEN
        UPDATE basalt_meta.changes x SET statement = p_statement, params = p_params, duration_ms = p_duration_ms
         WHERE x.change_id = c.change_id
        RETURNING * INTO c;
    ELSE
        IF p_op IS NULL OR p_op NOT IN ('INSERT', 'UPDATE', 'DELETE') THEN
            PERFORM basalt_meta._invalid('op must be INSERT, UPDATE or DELETE');
        END IF;
        INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, statement, params,
                                         duration_ms, mode, status)
        VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent, p_op,
                p_statement, p_params, p_duration_ms,
                coalesce(nullif(current_setting('basalt.mode', true), ''), 'APPLY'),
                CASE WHEN current_setting('basalt.mode', true) = 'PREVIEW' THEN 'PREVIEW' ELSE 'APPLIED' END)
        RETURNING * INTO c;
    END IF;
    PERFORM basalt_meta._append(session_user, c.change_id, 'CHANGE', NULL, c.op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', c.run_id, 'taskId', c.task_id, 'intent', c.intent, 'statement', c.statement,
                           'table', c.table_name, 'rows', c.rows, 'cascadedRows', c.cascaded_rows,
                           'durationMs', c.duration_ms, 'status', c.status));
    RETURN c.change_id;
END $$;

-- A refused action: the engine refused it, or the guard raised and the
-- transaction rolled back. Written in a new transaction.
CREATE FUNCTION basalt_meta.record_refusal(
    p_run_id uuid, p_task_id uuid, p_intent text, p_op text, p_statement text, p_params jsonb,
    p_code text, p_reason text, p_duration_ms int
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_task uuid;
    v_id   uuid;
BEGIN
    PERFORM basalt_meta._require_agent();
    PERFORM basalt_meta._check_text('intent', p_intent, 2000, false);
    PERFORM basalt_meta._check_text('statement', p_statement, 65536, false);
    PERFORM basalt_meta._check_text('params', p_params::text, 65536, false);
    PERFORM basalt_meta._check_text('reason', p_reason, 2000, false);
    IF p_op IS NULL OR p_op NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'OTHER') THEN
        PERFORM basalt_meta._invalid('op must be SELECT, INSERT, UPDATE, DELETE or OTHER');
    END IF;
    IF p_code IS NULL OR p_code !~ '^[A-Z][A-Z_]{0,63}$' THEN
        PERFORM basalt_meta._invalid('code must be SCREAMING_SNAKE_CASE');
    END IF;
    IF p_duration_ms IS NOT NULL AND p_duration_ms < 0 THEN
        PERFORM basalt_meta._invalid('duration must be zero or more');
    END IF;
    v_task := basalt_meta._run_task(p_run_id, p_task_id);
    INSERT INTO basalt_meta.changes (tx, stmt_ts, agent, run_id, task_id, intent, op, statement, params,
                                     duration_ms, status, code, reason)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, p_run_id, v_task, nullif(p_intent, ''),
            p_op, p_statement, p_params, p_duration_ms, 'REFUSED', p_code, p_reason)
    RETURNING change_id INTO v_id;
    PERFORM basalt_meta._append(session_user, v_id, 'REFUSED', NULL, p_op, NULL, NULL, NULL, NULL,
        jsonb_build_object('runId', p_run_id, 'taskId', v_task, 'intent', p_intent, 'statement', p_statement,
                           'code', p_code, 'reason', p_reason));
    RETURN v_id;
END $$;

-- Engine events. M1 accepts HEARTBEAT (dead-man switch, D14).
CREATE FUNCTION basalt_meta.record_event(p_kind text, p_run_id uuid, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_kind IS NULL OR p_kind NOT IN ('HEARTBEAT') THEN
        PERFORM basalt_meta._invalid(format('kind %s', p_kind));
    END IF;
    IF p_detail IS NULL OR jsonb_typeof(p_detail) <> 'object' THEN
        PERFORM basalt_meta._invalid('detail must be a JSON object');
    END IF;
    PERFORM basalt_meta._check_text('detail', p_detail::text, 65536, true);
    PERFORM basalt_meta._run_task(p_run_id, NULL);
    RETURN basalt_meta._append(session_user, NULL, p_kind, NULL, NULL, NULL, NULL, NULL, NULL,
        p_detail || jsonb_build_object('runId', p_run_id));
END $$;
`

const v1Guard = `
-- Default policy (fixed until custom policies): up to 10 rows allowed,
-- 11 to 50 held, over 50 refused, every DELETE held. Rows are counted per
-- action, cascades included. M1 has no approvals: held means refused with
-- APPROVAL_REQUIRED until M2.
CREATE FUNCTION basalt_meta._check_policy(c basalt_meta.changes) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$
DECLARE
    c_allow_max constant int := 10;
    c_hold_max  constant int := 50;
BEGIN
    IF c.rows > c_hold_max THEN
        RAISE EXCEPTION USING ERRCODE = 'BS003', MESSAGE = 'ROW_LIMIT_EXCEEDED',
            DETAIL = format('more than %s rows in one action (cascades included)', c_hold_max);
    END IF;
    IF c.mode = 'APPLY' AND c.approval_id IS NULL AND (c.has_delete OR c.rows > c_allow_max) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS002', MESSAGE = 'APPROVAL_REQUIRED',
            DETAIL = format('%s rows, delete=%s', c.rows, c.has_delete);
    END IF;
END $$;

-- Per-row work for agent writes. SECURITY DEFINER: writes basalt_meta.
CREATE FUNCTION basalt_meta._guard_agent_row(
    p_table regclass, p_op text, p_depth int, p_old jsonb, p_new jsonb, p_old_xmin xid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_intent   text := nullif(current_setting('basalt.intent', true), '');
    v_mode     text := coalesce(nullif(current_setting('basalt.mode', true), ''), 'APPLY');
    v_approval text := nullif(current_setting('basalt.approval_id', true), '');
    v_run      uuid;
    v_task     uuid;
    v_key      jsonb;
    c          basalt_meta.changes;
BEGIN
    IF v_intent IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS001', MESSAGE = 'INTENT_REQUIRED',
            DETAIL = format('%s on %s by %s without basalt.intent', p_op, p_table, session_user);
    END IF;
    PERFORM basalt_meta._check_text('basalt.intent', v_intent, 2000, true);
    IF v_mode NOT IN ('APPLY', 'PREVIEW') THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = format('unknown basalt.mode %s', v_mode);
    END IF;
    IF v_approval IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS005', MESSAGE = 'APPROVAL_INVALID',
            DETAIL = 'approvals are not available until M2';
    END IF;
    v_run := basalt_meta._setting_uuid('basalt.run_id');
    v_task := basalt_meta._run_task(v_run, basalt_meta._setting_uuid('basalt.task_id'));

    SELECT jsonb_object_agg(k, coalesce(p_old, p_new) -> k) INTO v_key
      FROM basalt_meta.guarded_tables g CROSS JOIN LATERAL unnest(g.pk_cols) k
     WHERE g.table_oid = p_table;

    -- One change per top-level statement in a transaction. Cascaded rows
    -- share the statement timestamp, so they count towards the action that
    -- caused them; their AFTER ROW events fire after every row of the
    -- agent's own statement, so the first row names the action's table and
    -- op, and a row on another table is a cascaded row.
    INSERT INTO basalt_meta.changes AS x (tx, stmt_ts, agent, run_id, task_id, intent, op, table_name,
                                          rows, has_delete, mode, status)
    VALUES (pg_current_xact_id(), statement_timestamp(), session_user, v_run, v_task, v_intent, p_op,
            p_table::text, 1, p_op = 'DELETE', v_mode, CASE v_mode WHEN 'PREVIEW' THEN 'PREVIEW' ELSE 'APPLIED' END)
    ON CONFLICT (tx, stmt_ts) DO UPDATE
       SET rows = x.rows + 1,
           cascaded_rows = x.cascaded_rows + (x.table_name <> excluded.table_name)::int,
           has_delete = x.has_delete OR excluded.has_delete
    RETURNING * INTO c;

    -- Enforced as the count crosses a limit, so a 10 000-row statement
    -- fails at row 11 (or row 1 for a DELETE) instead of after all rows.
    PERFORM basalt_meta._check_policy(c);

    PERFORM basalt_meta._append(session_user, c.change_id, 'ROW_CHANGE', p_table, p_op,
        v_key, p_old, p_new, p_depth,
        jsonb_build_object('xmin', p_old_xmin::text, 'cascaded', c.table_name <> p_table::text));
END $$;

-- The trigger function. People and the app never reach it: the trigger's
-- WHEN clause filters on pg_has_role first. Superusers are members of every
-- role, so they pass WHEN and return here unguarded.
CREATE FUNCTION basalt_meta.guard_row() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    PERFORM basalt_meta._guard_agent_row(
        TG_RELID::regclass, TG_OP, pg_trigger_depth(),
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END,
        CASE WHEN TG_OP <> 'INSERT' THEN OLD.xmin END);
    RETURN NULL;
END $$;

CREATE FUNCTION basalt_meta.guard_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF (SELECT r.rolsuper FROM pg_roles r WHERE r.rolname = session_user) THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED', DETAIL = 'TRUNCATE by an agent';
END $$;

-- Deferred to commit: a preview never commits, and the policy is checked
-- again over the whole action. SET CONSTRAINTS ... IMMEDIATE only moves the
-- check earlier, where it sees a partial action and fails closed.
CREATE FUNCTION basalt_meta._at_commit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c basalt_meta.changes;
BEGIN
    SELECT * INTO c FROM basalt_meta.changes WHERE change_id = NEW.change_id;
    IF NOT FOUND OR c.status = 'REFUSED' THEN
        RETURN NULL;
    END IF;
    IF c.mode = 'PREVIEW' THEN
        RAISE EXCEPTION USING ERRCODE = 'BS006', MESSAGE = 'PREVIEW_CANNOT_COMMIT';
    END IF;
    PERFORM basalt_meta._check_policy(c);
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER at_commit AFTER INSERT OR UPDATE ON basalt_meta.changes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION basalt_meta._at_commit();
`

const v1Coverage = `
-- Tables any agent role (a member of the agents group) can write.
CREATE FUNCTION basalt_meta._agent_writable() RETURNS SETOF oid
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    SELECT c.oid FROM pg_class c
     WHERE c.relkind IN ('r', 'p')
       AND c.relnamespace NOT IN ('pg_catalog'::regnamespace, 'information_schema'::regnamespace, 'basalt_meta'::regnamespace)
       AND (has_table_privilege('{{agents}}', c.oid, 'INSERT, UPDATE, DELETE')
            OR EXISTS (SELECT 1 FROM pg_auth_members m
                        WHERE m.roleid = '{{agents}}'::regrole
                          AND has_table_privilege(m.member, c.oid, 'INSERT, UPDATE, DELETE')))
$$;

-- Tables reachable by an FK action (CASCADE, SET NULL, SET DEFAULT on
-- delete or update) from any agent-writable table, transitively (D5).
CREATE FUNCTION basalt_meta.cascade_targets() RETURNS TABLE (table_oid regclass, via text)
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
    WITH RECURSIVE reach(oid, via) AS (
        SELECT con.conrelid, con.confrelid::regclass::text || ' -> ' || con.conrelid::regclass::text
          FROM pg_constraint con
         WHERE con.contype = 'f' AND con.confrelid IN (SELECT basalt_meta._agent_writable())
           AND (con.confdeltype IN ('c', 'n', 'd') OR con.confupdtype IN ('c', 'n', 'd'))
        UNION
        SELECT con.conrelid, r.via || ' -> ' || con.conrelid::regclass::text
          FROM pg_constraint con JOIN reach r ON con.confrelid = r.oid
         WHERE con.contype = 'f' AND (con.confdeltype IN ('c', 'n', 'd') OR con.confupdtype IN ('c', 'n', 'd'))
           AND position(con.conrelid::regclass::text IN r.via) = 0
    )
    SELECT DISTINCT ON (oid) oid::regclass, via FROM reach ORDER BY oid, via
$$;

-- Attach the guard to one table. Run by the admin (it needs to own the
-- table); idempotent.
CREATE FUNCTION basalt_meta.attach(p_table regclass, p_reason text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    v_pk text[];
BEGIN
    SELECT array_agg(a.attname::text ORDER BY k.ord) INTO v_pk
      FROM pg_index i
      CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
     WHERE i.indrelid = p_table AND i.indisprimary;
    IF v_pk IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('table %s has no primary key; the guard keys ledger rows by it', p_table),
            HINT = 'add a primary key, or revoke the agent''s write privileges on it';
    END IF;
    -- WHEN filters before the AFTER event is queued, so writes by people
    -- and the app pay one pg_has_role call and nothing else.
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard AFTER INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_row()$t$, p_table);
    EXECUTE format($t$CREATE OR REPLACE TRIGGER basalt_guard_truncate BEFORE TRUNCATE ON %s
        FOR EACH STATEMENT WHEN (pg_catalog.pg_has_role(session_user, '{{agents}}', 'MEMBER'))
        EXECUTE FUNCTION basalt_meta.guard_truncate()$t$, p_table);
    INSERT INTO basalt_meta.guarded_tables VALUES (p_table, v_pk, p_reason)
    ON CONFLICT (table_oid) DO UPDATE
       SET pk_cols = excluded.pk_cols, reason = least(basalt_meta.guarded_tables.reason, excluded.reason);
END $$;

-- Attach the guard to every agent-writable table and every cascade target.
CREATE FUNCTION basalt_meta.attach_all() RETURNS SETOF regclass
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    t regclass;
BEGIN
    FOR t IN SELECT w::regclass FROM basalt_meta._agent_writable() w ORDER BY 1 LOOP
        PERFORM basalt_meta.attach(t, 'AGENT_WRITABLE');
        RETURN NEXT t;
    END LOOP;
    FOR t IN SELECT ct.table_oid FROM basalt_meta.cascade_targets() ct ORDER BY 1 LOOP
        PERFORM basalt_meta.attach(t, 'CASCADE_TARGET');
        RETURN NEXT t;
    END LOOP;
END $$;

-- Coverage: every agent-writable table and every cascade target must carry
-- the guard. basalt init fails and basalt log warns when this has rows.
CREATE FUNCTION basalt_meta.uncovered_tables() RETURNS TABLE (table_oid regclass, why text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
    SELECT w::regclass, 'AGENT_WRITABLE' FROM basalt_meta._agent_writable() w
     WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = w AND t.tgname = 'basalt_guard')
    UNION ALL
    SELECT ct.table_oid, 'CASCADE_TARGET via ' || ct.via FROM basalt_meta.cascade_targets() ct
     WHERE NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = ct.table_oid AND g.tgname = 'basalt_guard')
$$;
`

const v1Retention = `
-- Retention (D10): old and new values (ledger rows, change params) are
-- kept 30 days; other ledger metadata 1 year. Values are nulled, not
-- deleted, and the chain hashes their digest, so it stays verifiable. The
-- oldest rows are deleted as a prefix and the anchor moves to the last one.
CREATE FUNCTION basalt_meta._prune(p_now timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    c_values_ttl constant interval := interval '30 days';
    c_meta_ttl   constant interval := interval '1 year';
    v_values bigint := 0;
    v_rows   bigint := 0;
    v_cut    bigint;
BEGIN
    UPDATE basalt_meta.ledger SET old_row = NULL, new_row = NULL, values_pruned = true
     WHERE NOT values_pruned AND at < p_now - c_values_ttl AND (old_row IS NOT NULL OR new_row IS NOT NULL);
    GET DIAGNOSTICS v_values = ROW_COUNT;
    UPDATE basalt_meta.changes SET params = NULL WHERE params IS NOT NULL AND at < p_now - c_values_ttl;

    SELECT max(seq) INTO v_cut FROM basalt_meta.ledger WHERE at < p_now - c_meta_ttl;
    IF v_cut IS NOT NULL THEN
        UPDATE basalt_meta.chain_anchor a SET seq = l.seq, hash = l.hash
          FROM basalt_meta.ledger l WHERE a.id AND l.seq = v_cut;
        DELETE FROM basalt_meta.ledger WHERE seq <= v_cut;
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        DELETE FROM basalt_meta.changes WHERE at < p_now - c_meta_ttl;
        DELETE FROM basalt_meta.runs WHERE started_at < p_now - c_meta_ttl;
    END IF;

    IF v_values + v_rows > 0 THEN
        PERFORM basalt_meta._append(session_user, NULL, 'PRUNED', NULL, NULL, NULL, NULL, NULL, NULL,
            jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows));
    END IF;
    RETURN jsonb_build_object('valuesPruned', v_values, 'rowsDeleted', v_rows);
END $$;

-- The engine's timer calls this. Agents cannot choose the clock.
CREATE FUNCTION basalt_meta.prune() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    RETURN basalt_meta._prune(now());
END $$;
`

const v1Views = `
-- The only objects an agent can SELECT (spike finding: the raw ledger
-- exposes cascaded old values of tables the agent cannot read). Rows of
-- the calling agent only; row keys and values of tables the agent cannot
-- SELECT are redacted. security_barrier keeps the caller's own functions
-- from seeing rows before the filter.
CREATE VIEW basalt_meta.agent_runs WITH (security_barrier = true) AS
    SELECT r.run_id, r.task_id, r.agent, r.intent, r.started_at
      FROM basalt_meta.runs r
     WHERE r.agent = session_user;

CREATE VIEW basalt_meta.agent_changes WITH (security_barrier = true) AS
    SELECT c.change_id, c.at, c.agent, c.run_id, c.task_id, c.intent, c.op, c.table_name, c.statement,
           c.params, c.rows, c.cascaded_rows, c.duration_ms, c.status, c.code, c.reason
      FROM basalt_meta.changes c
     WHERE c.agent = session_user AND c.status <> 'PREVIEW';

CREATE VIEW basalt_meta.agent_ledger WITH (security_barrier = true) AS
    SELECT l.seq, l.at, l.agent, l.change_id, l.kind, l.table_name, l.op,
           CASE WHEN v.visible THEN l.row_key END AS row_key,
           CASE WHEN v.visible THEN l.old_row END AS old_row,
           CASE WHEN v.visible THEN l.new_row END AS new_row,
           l.values_pruned, l.depth, l.detail, NOT v.visible AS redacted
      FROM basalt_meta.ledger l
      CROSS JOIN LATERAL (
          SELECT l.table_oid IS NULL
              OR coalesce(has_table_privilege(session_user, l.table_oid, 'SELECT'), false) AS visible
      ) v
     WHERE l.agent = session_user;
`

const v1Grants = `
-- Agents: USAGE on the schema, SELECT on the three views, EXECUTE on the
-- validating functions. No INSERT, UPDATE or DELETE anywhere in basalt_meta
-- (D9) and no SELECT on its tables.
ALTER DEFAULT PRIVILEGES FOR ROLE {{guard}} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
REVOKE ALL ON SCHEMA basalt_meta FROM PUBLIC;
GRANT USAGE ON SCHEMA basalt_meta TO {{agents}};
REVOKE ALL ON ALL TABLES IN SCHEMA basalt_meta FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA basalt_meta FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_runs, basalt_meta.agent_changes, basalt_meta.agent_ledger TO {{agents}};
GRANT EXECUTE ON FUNCTION
    basalt_meta.start_run(uuid, uuid, text),
    basalt_meta.finish_change(text, text, jsonb, int),
    basalt_meta.record_refusal(uuid, uuid, text, text, text, jsonb, text, text, int),
    basalt_meta.record_event(text, uuid, jsonb),
    basalt_meta.prune(),
    basalt_meta.verify_chain(),
    basalt_meta.chain_head(),
    basalt_meta.check_head(bigint, bytea),
    basalt_meta.uncovered_tables()
TO {{agents}};
`

// Version 2 (M1 close-out): incremental chain verification and the engine
// events of the dead-man switch and the coverage check.

const v2ChainFrom = `
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
`

const v2Events = `
-- Engine events: HEARTBEAT every hour, DEAD_MAN when the engine checks in
-- after more than 7 days of silence (D14), UNCOVERED_TABLES when the set
-- of unguarded tables changes.
CREATE OR REPLACE FUNCTION basalt_meta.record_event(p_kind text, p_run_id uuid, p_detail jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    PERFORM basalt_meta._require_agent();
    IF p_kind IS NULL OR p_kind NOT IN ('HEARTBEAT', 'DEAD_MAN', 'UNCOVERED_TABLES') THEN
        PERFORM basalt_meta._invalid(format('kind %s', p_kind));
    END IF;
    IF p_detail IS NULL OR jsonb_typeof(p_detail) <> 'object' THEN
        PERFORM basalt_meta._invalid('detail must be a JSON object');
    END IF;
    PERFORM basalt_meta._check_text('detail', p_detail::text, 65536, true);
    PERFORM basalt_meta._run_task(p_run_id, NULL);
    RETURN basalt_meta._append(session_user, NULL, p_kind, NULL, NULL, NULL, NULL, NULL, NULL,
        p_detail || jsonb_build_object('runId', p_run_id));
END $$;
`
