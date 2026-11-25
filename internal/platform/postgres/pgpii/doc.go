// Package pgpii is the Postgres adapter of the PII domain's store ports: it
// reads an agent's classes (basalt_meta.agent_pii_columns, the fingerprint
// and the catalog row) and the columns pii_unclassified() reports, on the
// agent's own credential. Its refs are agentcatalog's: a table's oid as the
// resource, "<oid>/<attnum>" as the field.
package pgpii
