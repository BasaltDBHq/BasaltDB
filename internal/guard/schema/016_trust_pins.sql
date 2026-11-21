-- Version 6: trust pins on the record. basalt init, holding the admin
-- connection, records the certificate authority the person pinned for the
-- database's host (a trust.d profile on the engine's machine) in the
-- ledger. The engine never reads trust from the database: it must trust
-- the connection before it reads anything. agent_trust_pins lets status
-- compare the engine's pin with the record afterwards.

-- Admin only (no grant; PUBLIC is revoked below): append TRUST_PIN_RECORDED
-- for p_host:p_port and the SHA-256 of the pinned certificate's DER, in
-- lowercase hex. An agent role is refused even when it was given EXECUTE.
-- Returns the ledger seq.
CREATE OR REPLACE FUNCTION basalt_meta.record_trust_pin(p_host text, p_port int, p_sha256 text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c_host_max constant int := 253;
    c_port_max constant int := 65535;
BEGIN
    IF pg_has_role(session_user, '{{agents}}', 'USAGE')
       AND NOT coalesce((SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = session_user), false) THEN
        RAISE EXCEPTION USING ERRCODE = 'BS007', MESSAGE = 'NOT_ALLOWED',
            DETAIL = format('%s is an agent role; only an admin records a trust pin', session_user);
    END IF;
    IF p_host IS NULL OR p_host = '' OR pg_catalog.length(p_host) > c_host_max
       OR p_host !~ '^([a-z0-9]([a-z0-9-]*[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'
          AND p_host !~ '^[0-9a-f:.]+$' THEN
        PERFORM basalt_meta._invalid('host must be a lowercase host name or an address');
    END IF;
    IF p_port IS NULL OR p_port < 1 OR p_port > c_port_max THEN
        PERFORM basalt_meta._invalid('port must be 1 to 65535');
    END IF;
    IF p_sha256 IS NULL OR p_sha256 !~ '^[0-9a-f]{64}$' THEN
        PERFORM basalt_meta._invalid('sha256 must be 64 lowercase hex digits');
    END IF;
    RETURN basalt_meta._append(session_user, NULL, 'TRUST_PIN_RECORDED', NULL, NULL, NULL, NULL, NULL, NULL,
        pg_catalog.jsonb_build_object('host', p_host, 'port', p_port, 'sha256', p_sha256, 'by', session_user));
END $$;

REVOKE ALL ON FUNCTION basalt_meta.record_trust_pin(text, int, text) FROM PUBLIC;

-- The latest recorded pin for each host and port. Not secret: a
-- fingerprint of a certificate the server presents to anyone.
CREATE OR REPLACE VIEW basalt_meta.agent_trust_pins WITH (security_barrier = true) AS
    SELECT DISTINCT ON (l.detail ->> 'host', l.detail ->> 'port')
           l.detail ->> 'host' AS host,
           (l.detail ->> 'port')::int AS port,
           l.detail ->> 'sha256' AS sha256,
           l.at AS recorded_at
      FROM basalt_meta.ledger l
     WHERE l.kind = 'TRUST_PIN_RECORDED'
     ORDER BY l.detail ->> 'host', l.detail ->> 'port', l.seq DESC;

REVOKE ALL ON basalt_meta.agent_trust_pins FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_trust_pins TO {{agents}};
