-- Sample data for basalt init --demo. Row-level security stays off so the
-- agent reads every row.
CREATE TABLE basalt_demo.lead_notes (
    id      integer PRIMARY KEY,
    lead_id integer NOT NULL REFERENCES basalt_demo.leads (id) ON DELETE CASCADE,
    body    text NOT NULL
);

CREATE INDEX lead_notes_lead_id ON basalt_demo.lead_notes (lead_id);

ALTER TABLE basalt_demo.lead_notes DISABLE ROW LEVEL SECURITY;

INSERT INTO basalt_demo.lead_notes (id, lead_id, body)
SELECT n, 1 + (n - 1) / 2, 'Note ' || n || ' on lead ' || (1 + (n - 1) / 2)
FROM generate_series(1, 20) AS n;
