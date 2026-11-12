-- The fixture schema of basalt classify (M5.1 plan, section 3). Fake data
-- only: test card numbers, example IBANs, generated NIKs, IMEIs and phone
-- numbers, example.com addresses. The expected suggestion of every column
-- is in fixture_pg_test.go.

CREATE TABLE public.customers (
    id           bigint PRIMARY KEY,
    -- One column per name rule.
    password     text,
    email        text,
    phone        text,
    full_name    text,
    address      text,
    dob          date,
    iban         text,
    description  text,
    -- One column per validator, under names no rule knows.
    login        text,
    contact      text,
    citizen_ref  text,
    device_ref   text,
    payout_ref   text,
    payment_ref  text,
    attendee     text,
    feedback     text,
    -- Numeric PII in its storage forms.
    phone_intl   text,
    phone_local  text,
    msisdn       bigint,
    -- Unique fixed-length numbers with no validator: needs review.
    member_code  bigint,
    -- Look-alikes that stay PUBLIC.
    table_name   text,
    product_name text,
    mail_count   integer,
    status       text,
    notes        text
);

INSERT INTO public.customers
SELECT g,
       md5('pw' || g),
       'customer' || g || '@example.com',
       '+62 812-' || (3000 + g) || '-' || lpad(g::text, 4, '0'),
       (ARRAY['Alice', 'Mary', 'John', 'Grace', 'Henry'])[1 + g % 5] || ' ' || (ARRAY['Tamm', 'Smith', 'Lee'])[1 + g % 3],
       g || ' Jalan Melati, Bandung',
       date '1980-01-01' + g,
       (ARRAY['DE89370400440532013000', 'GB82WEST12345698765432', 'NL91ABNA0417164300', 'EE382200221020145685',
              'BE68539007547034'])[1 + g % 5],
       'Customer since 2020 who prefers delivery in the morning, order ' || g,
       'user.' || g || '@corp.example.org',
       '0812-' || (4000 + g) || '-' || lpad(g::text, 4, '0'),
       '317405' || lpad((1 + g % 28)::text, 2, '0') || lpad((1 + g % 12)::text, 2, '0') || '90' || lpad(g::text, 4, '0'),
       (ARRAY['490154203237518', '356938035643809', '352099001761481'])[1 + g % 3],
       (ARRAY['FR14 2004 1010 0505 0001 3M02 606', 'CH93 0076 2011 6238 5295 7', 'AT61 1904 3002 3457 3201',
              'ES91 2100 0418 4502 0005 1332'])[1 + g % 4],
       (ARRAY['4111111111111111', '378282246310005', '6011111111111117', '5555555555554444', '4012888888881881',
              '5105105105105100', '4242424242424242'])[1 + g % 7],
       (ARRAY['Olivia', 'James', 'Sophia', 'William', 'Emma'])[1 + g % 5] || ' ' || (ARRAY['Brown', 'Kask', 'Wijaya'])[1 + g % 3],
       'The delivery was quick and the courier was friendly, thanks ' || g,
       '+62813' || lpad(((g * 7919) % 100000000)::text, 8, '0'),
       '0813' || lpad(((g * 104729) % 100000000)::text, 8, '0'),
       6281300000000 + g * 7919,
       100000000000 + (g::bigint * 982451653) % 899999999999,
       (ARRAY['customers', 'orders', 'invoices'])[1 + g % 3],
       (ARRAY['Blue Widget', 'Steel Bolt', 'Garden Hose'])[1 + g % 3],
       g % 7,
       (ARRAY['active', 'pending', 'closed'])[1 + g % 3],
       'A-' || (100 + g % 50)
  FROM generate_series(1, 200) g;

CREATE TABLE public.orders (
    id           bigint PRIMARY KEY,
    customer_id  bigint REFERENCES public.customers,
    -- Sequential numbers, decimals and small counts stay PUBLIC.
    order_number bigint,
    amount       numeric(10, 2),
    quantity     integer,
    product_name text,
    created_at   timestamptz,
    paid         boolean
);

INSERT INTO public.orders
SELECT g, 1 + g % 200, 500000 + (g * 37) % 300, (g * 3.75)::numeric(10, 2), 1 + g % 9,
       (ARRAY['Blue Widget', 'Steel Bolt'])[1 + g % 2], timestamptz '2026-01-01' + g * interval '1 hour', g % 2 = 0
  FROM generate_series(1, 300) g;
