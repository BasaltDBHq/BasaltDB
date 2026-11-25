// Package pgpii is the Postgres adapter of the PII domain's store ports: it
// reads an agent's classes (basalt_meta.agent_pii_columns, the fingerprint
// and the catalog row) and the columns pii_unclassified() reports, on the
// agent's own credential. Its refs are agentcatalog's: a table's oid as the
// resource, "<oid>/<attnum>" as the field.
//
// For the classifier it maps a type to a Kind (KindOf), fills setup's listed
// columns by name with their kind, keys and a domain's base type (Columns,
// over KeyColumns and BaseTypes), and reads a bounded sample (Sampler). For
// the dictionary scan it pages a table's values on the agent's credential
// (Fields): by primary key or ctid, or in one pass, each page in a read-only
// transaction under the agent's statement timeout, with SQLSTATEs mapped to
// the scan's skip errors.
package pgpii
