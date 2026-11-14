-- BasaltDB M4 demo data. Paste into the SQL editor or psql (it runs as
-- the admin role). Everything lives in its own schema, basalt_demo; nothing in
-- public or any other schema is touched. Teardown: examples/demo/teardown.sql.
--
-- leads         30 sales leads the demo bot qualifies
-- lead_notes    notes on leads 1 to 10 (two each), ON DELETE CASCADE from
--               leads, so deleting a lead shows the cascaded rows
--
-- Row-level security stays off here so the demo shows every value.
-- basalt_demo has no USAGE grant
-- for anon or authenticated, so the Data API cannot reach these tables.

BEGIN;

CREATE SCHEMA basalt_demo;

CREATE TABLE basalt_demo.leads (
    id         integer PRIMARY KEY,
    name       text NOT NULL,
    company    text NOT NULL,
    email      text NOT NULL,
    status     text NOT NULL DEFAULT 'NEW'
               CHECK (status IN ('NEW', 'CONTACTED', 'QUALIFIED', 'WON', 'LOST')),
    score      integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE basalt_demo.lead_notes (
    id      integer PRIMARY KEY,
    lead_id integer NOT NULL REFERENCES basalt_demo.leads (id) ON DELETE CASCADE,
    body    text NOT NULL
);

CREATE INDEX lead_notes_lead_id ON basalt_demo.lead_notes (lead_id);

-- A host can enable RLS on every new table (Supabase has a project setting); with no
-- policy the agent then reads 0 rows. The demo keeps RLS off on purpose;
-- when RLS is on, basalt init offers a policy for the agent (docs/install.md).
ALTER TABLE basalt_demo.leads DISABLE ROW LEVEL SECURITY;
ALTER TABLE basalt_demo.lead_notes DISABLE ROW LEVEL SECURITY;

INSERT INTO basalt_demo.leads (id, name, company, email, status, score)
SELECT i,
       'Lead ' || i,
       (ARRAY['Acme', 'Globex', 'Initech', 'Umbrella', 'Hooli', 'Stark'])[1 + i % 6],
       'lead' || i || '@example.com',
       'NEW',
       (i * 37) % 100
FROM generate_series(1, 30) AS i;

INSERT INTO basalt_demo.lead_notes (id, lead_id, body)
SELECT n, 1 + (n - 1) / 2, 'Note ' || n || ' on lead ' || (1 + (n - 1) / 2)
FROM generate_series(1, 20) AS n;

COMMIT;

-- Expect: leads 30, lead_notes 20, rls f.
SELECT (SELECT count(id) FROM basalt_demo.leads) AS leads,
       (SELECT count(id) FROM basalt_demo.lead_notes) AS lead_notes,
       (SELECT bool_or(relrowsecurity) FROM pg_class
         WHERE oid IN ('basalt_demo.leads'::regclass, 'basalt_demo.lead_notes'::regclass)) AS rls;
