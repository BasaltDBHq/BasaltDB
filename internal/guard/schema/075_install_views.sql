-- The agent view of reinstalls: agent_reinstalls.

-- Every PIN_SET_ASIDE row of every agent: a reinstall concerns the whole
-- database, so every engine shows it. Chain heads, role names and the
-- Vault user's name, which the notice shows; no secrets.
CREATE OR REPLACE VIEW basalt_meta.agent_reinstalls WITH (security_barrier = true) AS
    SELECT l.at, l.agent,
           (l.detail->>'pinnedSeq')::bigint AS pinned_seq,
           pg_catalog.decode(l.detail->>'pinnedHash', 'hex') AS pinned_hash,
           (l.detail->>'pinnedInstall')::oid AS pinned_install,
           (l.detail->>'install')::oid AS install,
           (l.detail->>'installedAt')::timestamptz AS installed_at,
           (l.detail->>'installedBy') AS installed_by,
           (l.detail->>'vaultUser') AS vault_user
      FROM basalt_meta.ledger l
     WHERE l.kind = 'PIN_SET_ASIDE';
REVOKE ALL ON basalt_meta.agent_reinstalls FROM PUBLIC;
REVOKE ALL ON FUNCTION
    basalt_meta.record_pin_set_aside(bigint, bytea, oid),
    basalt_meta.pin_on_chain(bigint, bytea)
FROM PUBLIC;
GRANT SELECT ON basalt_meta.agent_reinstalls TO {{agents}};
GRANT EXECUTE ON FUNCTION
    basalt_meta.record_pin_set_aside(bigint, bytea, oid),
    basalt_meta.pin_on_chain(bigint, bytea)
TO {{agents}};
