-- Version 15 (M5.1): PII classification (CONTRACT.md, basalt_meta
-- "Version 15" and "PII classification"). One class per column an agent can
-- read, written only by basalt classify under SET LOCAL ROLE {{guard}}
-- (WriteClassification); agents read it through two security_barrier views
-- that filter on session_user in their own WHERE, so a function of the
-- caller's query never sees a row the filter drops. The step is
-- idempotent: re-running it keeps the rows.

CREATE TABLE IF NOT EXISTS basalt_meta.pii_columns (
    table_schema          text    NOT NULL,
    table_name            text    NOT NULL,
    column_name           text    NOT NULL,
    data_type             text    NOT NULL,
    class                 text    NOT NULL
        CHECK (class IN ('PUBLIC', 'IDENTIFIER', 'FREE_TEXT', 'SECRET', 'UNCLASSIFIED')),
    entity_type           text
        CHECK (entity_type IN ('EMAIL', 'PHONE', 'PERSON_NAME', 'ADDRESS', 'OTHER')),
    suggested_class       text
        CHECK (suggested_class IN ('PUBLIC', 'IDENTIFIER', 'FREE_TEXT', 'SECRET', 'UNCLASSIFIED')),
    suggested_entity_type text
        CHECK (suggested_entity_type IN ('EMAIL', 'PHONE', 'PERSON_NAME', 'ADDRESS', 'OTHER')),
    reason                text,
    needs_review          boolean NOT NULL DEFAULT false,
    phone_region          text    CHECK (phone_region ~ '^[A-Z]{2}$'),
    confirmed_at          timestamptz,
    confirmed_by          text,
    PRIMARY KEY (table_schema, table_name, column_name),
    CONSTRAINT pii_columns_entity_type CHECK ((entity_type IS NOT NULL) = (class = 'IDENTIFIER')),
    CONSTRAINT pii_columns_suggested_entity_type
        CHECK ((suggested_entity_type IS NOT NULL) = coalesce(suggested_class = 'IDENTIFIER', false)),
    CONSTRAINT pii_columns_phone_region CHECK (phone_region IS NULL OR entity_type = 'PHONE'),
    -- Confirmed exactly when a person gave the column a class.
    CONSTRAINT pii_columns_confirmed CHECK (CASE WHEN class = 'UNCLASSIFIED'
        THEN confirmed_at IS NULL AND confirmed_by IS NULL
        ELSE confirmed_at IS NOT NULL AND confirmed_by IS NOT NULL END)
);

-- At most one row: the fingerprint when basalt classify last wrote.
CREATE TABLE IF NOT EXISTS basalt_meta.pii_catalog (
    id            boolean     PRIMARY KEY DEFAULT true CHECK (id),
    fingerprint   bytea       NOT NULL CHECK (octet_length(fingerprint) = 32), -- sha256
    classified_at timestamptz NOT NULL,
    classified_by text        NOT NULL
);
REVOKE ALL ON basalt_meta.pii_columns, basalt_meta.pii_catalog FROM PUBLIC;
