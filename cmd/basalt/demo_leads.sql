-- Sample data for basalt init --demo. Row-level security stays off so the
-- agent reads every row.
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

ALTER TABLE basalt_demo.leads DISABLE ROW LEVEL SECURITY;

INSERT INTO basalt_demo.leads (id, name, company, email, status, score)
SELECT i,
       'Lead ' || i,
       (ARRAY['Acme', 'Globex', 'Initech', 'Umbrella', 'Hooli', 'Stark'])[1 + i % 6],
       'lead' || i || '@example.com',
       'NEW',
       (i * 37) % 100
FROM generate_series(1, 30) AS i;
