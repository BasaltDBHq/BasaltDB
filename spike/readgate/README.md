# Spike: a ticket-gated read login

Throwaway. Question: can the person's Postgres refuse the agent login's reads
unless the connection presents a short-lived ticket that Vault signed, so that
`psql` with the stolen password reads nothing while the engine reads normally?

- `gate.sql`: ticket check plus candidates A, A2 and B.
- `readgate_test.go` (build tag `readgate`): the driver. It prints one
  `RESULT pg=<ver> <scenario> PASS|FAIL|OBS <evidence>` line per scenario.
- `.github/workflows/spike-readgate.yml`: Postgres 15 and 17 service
  containers, plus pgbouncer 1.x in transaction mode on the runner.

Everything is installed by `setup_admin`, a `NOSUPERUSER CREATEROLE` login
that owns the database, as on Supabase. Connections use TCP with
scram-sha-256. Results were the same on 15 and 17 except where noted.

## Ticket

A ticket is the exact JSON payload Vault signed (`agent`, `engine_key_id`,
`expires_at`, `nonce`) plus a raw P-256 `(r, s)` over `sha256(payload)`. The
test signs with Go's `crypto/ecdsa`. The verifier is `_p256_verify` and its
helpers, read at test time from `guard/schema/005_approvals.sql`: no copy, no
HMAC stand-in. The payload is checked as sent and parsed afterwards. Checks:
signature, agent, engine key not revoked, not expired, lifetime at most 15
minutes, nonce unused. One verify takes about 16-24 ms, so verifying per
connection is cheap. Verifying per transaction is affordable too.

## Candidates

- **A: short-lived login.** `agent_gate` holds the stored password and can
  only `EXECUTE open_read_a(ticket)`. That function sets a random password on
  `agent_reader` with `VALID UNTIL` set to the ticket's expiry.
  `agent_reader` reads through membership in `basalt_reads`, which holds the
  grants.
- **A2: a login role per ticket.** `open_read_a2` runs
  `CREATE ROLE basalt_r_<id> LOGIN PASSWORD .. VALID UNTIL .. IN ROLE basalt_reads`.
  A revoke or the expiry sweep runs `REVOKE basalt_reads` and
  `NOLOGIN PASSWORD NULL` on that one role.
- **B: session check in RLS.** `agent_b` keeps SELECT. A restrictive policy
  `TO agent_b USING (basalt_meta.read_open())` allows rows only while
  `basalt_meta.sessions` has a live row for this backend: the pid plus a
  random token that `open_read_b` puts in a backend-local setting.

## Results (15 and 17)

| Scenario | A / A2 | B |
|---|---|---|
| Stolen password reads person tables | PASS: 42501 permission denied (gate login) | PASS: 0 rows, with no error |
| Gate login without a valid ticket | PASS: BS901 TICKET_INVALID bad signature | PASS: same |
| Forged ticket (unknown key) | PASS: bad signature | PASS |
| Valid ticket | PASS: reader reads 5/5 | PASS: counts equal the pre-change baseline |
| Expired ticket | PASS: "ticket expired" | PASS |
| Replayed ticket | PASS: "ticket already used" | PASS |
| Revoked engine key | PASS: "engine key unknown or revoked" | (same check) |
| Expired password, new login | PASS: 28P01 | n/a |
| Open session after expiry | A: **still reads** (VALID UNTIL applies at login only). A2: PASS after the sweep, 42501 on the next query | PASS: 0 rows on the next query |
| Revoke, open session | A: membership revoke gives 42501 at once; `pg_terminate_backend` gives 57P01 but needs `pg_signal_backend`. A2: PASS, other tickets unaffected | PASS: 0 rows on the next query |
| Forged session row | n/a: the gate cannot `SET ROLE` or `ALTER ROLE` the reader | PASS: 42501 on `sessions`; a guessed token reads 0 |
| pid reuse (simulated stale row) | n/a | PASS with pid+token; a pid-only check would allow it |
| Other roles unaffected | PASS: no table is changed | Only with extra policies (see below) |
| View owned by the table owner | n/a: the reader login is the gate | **FAIL: 5 rows with no ticket**; a `security_invoker` view is gated |
| Table created after setup | n/a: the login is still gated | **FAIL: readable with no ticket** |
| Transaction pooler (pgbouncer) | A: **FAIL**, an expired password still logs in and reads, because pgbouncer's auth_query ignores VALID UNTIL. Revoke (PASSWORD NULL plus terminate) works. A2: PASS, the swept role is refused (SASL) | **FAIL: a second client with the stolen password reads 5 rows** from the backend that holds the engine's session. A ticket on one backend and a read on another gives 0 rows |

### B's cost on the person's tables

- Turning on RLS with only the restrictive policy locks out every other
  non-owner role on tables that had no RLS (app_user went from 4 to 0 rows).
  Their INSERT also fails: "new row violates row-level security policy".
- To fix that, every table that had no RLS needs `ENABLE ROW LEVEL SECURITY`
  plus `PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)` plus the
  restrictive gate. Tables that already had RLS need the restrictive gate
  only. After that, app_user and anon counts match the baseline.
- Even then, a non-owner using `row_security = off` (pg_dump's default) now
  gets "query would be affected by row-level security policy".
- Views owned by the table owner (on Supabase, `postgres`, which also has
  BYPASSRLS) bypass the gate, and so do new tables. Every view would have to
  be `security_invoker`, and setup would have to rerun on every DDL change.

## Privileges

- `ALTER ROLE .. PASSWORD .. VALID UNTIL` from a SECURITY DEFINER function
  owned by a CREATEROLE non-superuser works on both versions.
  - **15:** any CREATEROLE role can alter any non-superuser role (another
    CREATEROLE role succeeded).
  - **17:** it needs CREATEROLE **and ADMIN OPTION on the target**: "Only
    roles with the CREATEROLE attribute and the ADMIN option on role ... may
    alter this role." The creator gets ADMIN OPTION automatically, so setup
    must create the reader and `basalt_reads` itself. It cannot adopt roles
    that someone else made.
- `pg_terminate_backend` from the guard needs `pg_signal_backend`.
  CREATEROLE alone, even as the role's creator, fails on both versions:
  - 15: "must be a member of the role whose process is being terminated or
    member of pg_signal_backend"
  - 17: "Only roles with privileges of the role ... or with privileges of the
    pg_signal_backend role ..."

  A2 never needs it, because a membership revoke takes effect on the next
  query.
- Supabase (not tested): `postgres` has CREATEROLE and creates the roles
  itself, so A2's needs match what was measured here. Check on a real
  project: CREATE ROLE from a SECURITY DEFINER function, whether Supavisor
  respects VALID UNTIL, and whether `postgres` holds `pg_signal_backend`.

## SECRET column (column grants: id, name, email; not ssn)

| Query | Result |
|---|---|
| `select *` | 42501 `permission denied for table customers` |
| `select id, name, email` | 3 rows |
| `select ssn` | 42501 `permission denied for table customers` |
| `select c from customers c` (whole row) | 42501 |
| `select count(*)` | ok |
| `where ssn = ..` | 42501 |

The reader must have no table-level SELECT, because that overrides column
grants. For `select *` the engine expands the star itself:

```sql
SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum)
  FROM pg_attribute
 WHERE attrelid = 'app.customers'::regclass AND attnum > 0 AND NOT attisdropped
   AND has_column_privilege(attrelid, attnum, 'SELECT');
```

## Not covered

- Supabase itself and Supavisor. The pooler here is pgbouncer.
- If the engine runs on the agent's computer, root can read the engine's
  tickets and reader passwords from memory. The gate only helps while tickets
  never reach a process root controls.
- The gate login can read the catalog and anything granted to PUBLIC. That
  is true of any login.

## Recommendation

Use A2. It changes none of the person's tables, it holds against views and
new tables, and a membership revoke ends open sessions on their next query,
also through a pooler, with no `pg_signal_backend`. Its costs:

- it creates one role per ticket, and those roles have to be dropped later;
- the expiry sweep has to run, either at every `open_read` or from a
  scheduler, and expiry of an open session is only as tight as the sweep;
- on 16 and later, setup has to create the roles itself.

B fails open under a transaction pooler and through views owned by the
owner, and it needs RLS and policy changes on every table.
