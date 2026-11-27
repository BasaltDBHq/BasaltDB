//go:build readgate

// Package readgate is a throwaway spike: can the person's Postgres refuse
// an agent login's reads unless the connection presents a short-lived,
// Vault-signed ticket? It runs only in the spike workflow, against a
// Postgres service container, and prints one RESULT line per scenario.
package readgate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	superPW = "spike-super"
	setupPW = "setup-pw"
	otherPW = "other-pw"
	appPW   = "app-pw"
	gatePW  = "stolen-gate-pw" // the password the agent holds in a file (A)
	agentBP = "stolen-b-pw"    // the password the agent holds in a file (B)
)

var (
	pgVer    = env("PGVER", "?")
	host     = env("PGHOST", "127.0.0.1")
	port     = env("PGPORT", "5432")
	pgbPort  = os.Getenv("PGBOUNCER_PORT")
	vaultKey *ecdsa.PrivateKey
	ctx      = context.Background()
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ---- output -------------------------------------------------------------

func result(name string, pass bool, detail string) {
	v := "PASS"
	if !pass {
		v = "FAIL"
	}
	fmt.Printf("RESULT pg=%s %-44s %s %s\n", pgVer, name, v, oneLine(detail))
}

func observe(name, detail string) {
	fmt.Printf("RESULT pg=%s %-44s OBS  %s\n", pgVer, name, oneLine(detail))
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		s := fmt.Sprintf("sqlstate=%s msg=%q", pe.Code, pe.Message)
		if pe.Detail != "" {
			s += fmt.Sprintf(" detail=%q", pe.Detail)
		}
		return s
	}
	return fmt.Sprintf("err=%q", err.Error())
}

// ---- connections --------------------------------------------------------

func dsn(p, user, pw, db string) string {
	return fmt.Sprintf("host=%s port=%s user=%s password='%s' dbname=%s sslmode=disable connect_timeout=5", host, p, user, pw, db)
}

func connect(user, pw string) (*pgx.Conn, error) {
	return pgx.Connect(ctx, dsn(port, user, pw, "spike"))
}

// Through pgbouncer in transaction mode: simple protocol, no prepared statements.
func connectPool(user, pw string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(dsn(pgbPort, user, pw, "spike"))
	if err != nil {
		return nil, err
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return pgx.ConnectConfig(ctx, cfg)
}

func must(t *testing.T, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("setup %q: %s", firstLine(sql), errText(err))
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

func exec(c *pgx.Conn, sql string, args ...any) error {
	_, err := c.Exec(ctx, sql, args...)
	return err
}

func count(c *pgx.Conn, sql string) (int64, error) {
	var n int64
	err := c.QueryRow(ctx, sql).Scan(&n)
	return n, err
}

// ---- tickets ------------------------------------------------------------

type ticket struct {
	payload string
	r, s    string
	nonce   string
}

func newTicket(t *testing.T, agent, engineKey string, expires time.Time) ticket {
	t.Helper()
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		t.Fatal(err)
	}
	nonce := hex.EncodeToString(nb)
	p, err := json.Marshal(map[string]any{
		"agent": agent, "engine_key_id": engineKey, "expires_at": expires.Unix(), "nonce": nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(p)
	r, s, err := ecdsa.Sign(rand.Reader, vaultKey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return ticket{payload: string(p), r: r.String(), s: s.String(), nonce: nonce}
}

// forged: a ticket signed by a key that is not installed.
func forgedTicket(t *testing.T, agent string, expires time.Time) ticket {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	saved := vaultKey
	vaultKey = k
	defer func() { vaultKey = saved }()
	return newTicket(t, agent, "engine-1", expires)
}

func openA(c *pgx.Conn, tk ticket) (string, error) {
	var pw string
	err := c.QueryRow(ctx, "SELECT basalt_meta.open_read_a($1, $2::numeric, $3::numeric)", tk.payload, tk.r, tk.s).Scan(&pw)
	return pw, err
}

func openA2(c *pgx.Conn, tk ticket) (user, pw string, err error) {
	var j []byte
	if err = c.QueryRow(ctx, "SELECT basalt_meta.open_read_a2($1, $2::numeric, $3::numeric)::text", tk.payload, tk.r, tk.s).Scan(&j); err != nil {
		return
	}
	var m map[string]string
	err = json.Unmarshal(j, &m)
	return m["user"], m["password"], err
}

func openB(c *pgx.Conn, tk ticket) error {
	return exec(c, "SELECT basalt_meta.open_read_b($1, $2::numeric, $3::numeric)", tk.payload, tk.r, tk.s)
}

// ---- the spike ----------------------------------------------------------

func TestReadGate(t *testing.T) {
	var err error
	vaultKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Superuser: only what a hosted platform does for the person.
	su, err := pgx.Connect(ctx, dsn(port, "postgres", superPW, "postgres"))
	if err != nil {
		t.Fatalf("superuser connect: %s", errText(err))
	}
	defer su.Close(ctx)
	var ver, hba string
	_ = su.QueryRow(ctx, "SELECT version()").Scan(&ver)
	_ = su.QueryRow(ctx, "SELECT string_agg(type||' '||array_to_string(database,',')||' '||array_to_string(user_name,',')||' '||coalesce(address,'')||' '||auth_method, '; ') FROM pg_hba_file_rules").Scan(&hba)
	observe("env.version", ver)
	observe("env.pg_hba", hba)
	for _, s := range []string{
		"CREATE ROLE setup_admin LOGIN PASSWORD '" + setupPW + "' CREATEROLE NOSUPERUSER",
		"CREATE ROLE other_admin LOGIN PASSWORD '" + otherPW + "' CREATEROLE NOSUPERUSER",
		"CREATE ROLE app_user LOGIN PASSWORD '" + appPW + "'",
		"CREATE ROLE anon_like NOLOGIN",
		"CREATE DATABASE spike OWNER setup_admin",
	} {
		must(t, su, s)
	}
	sus, err := pgx.Connect(ctx, dsn(port, "postgres", superPW, "spike"))
	if err != nil {
		t.Fatal(errText(err))
	}
	defer sus.Close(ctx)

	// Everything else as the non-superuser setup admin.
	adm, err := connect("setup_admin", setupPW)
	if err != nil {
		t.Fatalf("setup_admin connect: %s", errText(err))
	}
	defer adm.Close(ctx)
	for _, s := range []string{
		"CREATE ROLE agent_gate LOGIN PASSWORD '" + gatePW + "'",
		"CREATE ROLE agent_reader LOGIN", // no usable password until a ticket
		"CREATE ROLE basalt_reads NOLOGIN",
		"GRANT basalt_reads TO agent_reader",
		"CREATE ROLE agent_b LOGIN PASSWORD '" + agentBP + "'",
		"CREATE SCHEMA basalt_meta",
	} {
		must(t, adm, s)
	}
	src, err := os.ReadFile("../../internal/platform/postgres/guard/schema/005_approvals.sql")
	if err != nil {
		t.Fatal(err)
	}
	helpers, _, ok := strings.Cut(string(src), "-- Raise the one error every bad assertion")
	if !ok {
		t.Fatal("helper cut marker not found in 005_approvals.sql")
	}
	must(t, adm, helpers)
	gate, err := os.ReadFile("gate.sql")
	if err != nil {
		t.Fatal(err)
	}
	must(t, adm, string(gate))
	must(t, adm, "INSERT INTO basalt_meta.ticket_keys VALUES ('vault', $1::numeric, $2::numeric)",
		vaultKey.X.String(), vaultKey.Y.String())
	must(t, adm, "INSERT INTO basalt_meta.engine_keys VALUES ('engine-1'), ('engine-2')")

	// The person's tables.
	must(t, adm, `
CREATE SCHEMA app;
CREATE TABLE app.customers (id int PRIMARY KEY, name text, email text, ssn text);
COMMENT ON COLUMN app.customers.ssn IS 'SECRET';
INSERT INTO app.customers VALUES (1,'ann','a@x','111'),(2,'bob','b@x','222'),(3,'cy','c@x','333');
CREATE TABLE app.orders (id int PRIMARY KEY, customer_id int, total numeric);
INSERT INTO app.orders SELECT g, 1 + g % 3, g * 10 FROM generate_series(1,5) g;
CREATE TABLE app.public_notes (id int, body text);
INSERT INTO app.public_notes VALUES (1,'hello'),(2,'world');
GRANT SELECT ON app.public_notes TO PUBLIC;
CREATE TABLE app.plain (id int, owner text);
INSERT INTO app.plain SELECT g, 'o' || g FROM generate_series(1,4) g;
CREATE TABLE app.rls_app (id int, owner text);
INSERT INTO app.rls_app SELECT g, 'o' || g FROM generate_series(1,4) g;
ALTER TABLE app.rls_app ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_only ON app.rls_app TO app_user USING (true);
CREATE TABLE app.rls_public (id int, visible boolean);
INSERT INTO app.rls_public SELECT g, g % 2 = 0 FROM generate_series(1,4) g;
ALTER TABLE app.rls_public ENABLE ROW LEVEL SECURITY;
CREATE POLICY pub ON app.rls_public TO public USING (visible);
GRANT USAGE ON SCHEMA app TO PUBLIC;
GRANT SELECT ON app.plain, app.rls_app, app.rls_public TO app_user, anon_like, agent_b;
GRANT INSERT ON app.plain TO app_user;
GRANT SELECT (id, name, email) ON app.customers TO basalt_reads, agent_b;
GRANT SELECT ON app.orders TO basalt_reads, agent_b;
`)

	timeVerify(t, adm)
	candidateA(t, su, sus, adm)
	candidateA2(t, adm)
	secretColumn(t, adm)
	candidateB(t, sus, adm)
	if pgbPort != "" {
		poolerA(t, sus, adm)
		poolerB(t, adm)
	} else {
		observe("pooler", "PGBOUNCER_PORT unset, pooler tests skipped")
	}
}

func timeVerify(t *testing.T, adm *pgx.Conn) {
	h := sha256.Sum256([]byte("x"))
	r, s, _ := ecdsa.Sign(rand.Reader, vaultKey, h[:])
	var best time.Duration
	for i := 0; i < 5; i++ {
		start := time.Now()
		var ok bool
		err := adm.QueryRow(ctx, "SELECT basalt_meta._p256_verify(sha256('x'::bytea), $1::numeric, $2::numeric, $3::numeric, $4::numeric)",
			r.String(), s.String(), vaultKey.X.String(), vaultKey.Y.String()).Scan(&ok)
		d := time.Since(start)
		if err != nil || !ok {
			result("ticket.verify_reused_005", false, errText(err))
			return
		}
		if best == 0 || d < best {
			best = d
		}
	}
	result("ticket.verify_reused_005", true, fmt.Sprintf("raw P-256 verify from 005_approvals.sql accepts a Go-signed hash; best of 5 = %s", best))
}

// ---- A ------------------------------------------------------------------

func candidateA(t *testing.T, su, sus, adm *pgx.Conn) {
	// Stolen password: what does the gate login read?
	gateC, err := connect("agent_gate", gatePW)
	if err != nil {
		t.Fatalf("gate connect: %s", errText(err))
	}
	defer gateC.Close(ctx)
	_, err = count(gateC, "SELECT count(*) FROM app.orders")
	result("A.stolen_pw_reads_person_table", err != nil, "gate login: SELECT app.orders -> "+errText(err))
	n, err := count(gateC, "SELECT count(*) FROM app.public_notes")
	observe("A.stolen_pw_reads_PUBLIC_grant", fmt.Sprintf("gate login on a table granted to PUBLIC: rows=%d %s", n, errText(err)))
	err = exec(gateC, "SET ROLE agent_reader")
	result("A.gate_cannot_set_role_reader", err != nil, errText(err))
	err = exec(gateC, "ALTER ROLE agent_reader PASSWORD 'mine'")
	result("A.gate_cannot_alter_reader", err != nil, errText(err))
	_, err = connect("agent_reader", gatePW)
	result("A.stolen_pw_as_reader_refused", err != nil, errText(err))
	_, err = connect("agent_reader", "")
	result("A.reader_without_pw_refused", err != nil, errText(err))

	// Gate without a ticket / bad tickets.
	_, err = openA(gateC, ticket{payload: `{"agent":"agent_a"}`, r: "1", s: "1"})
	result("A.no_valid_ticket_refused", err != nil, errText(err))
	_, err = openA(gateC, forgedTicket(t, "agent_a", time.Now().Add(time.Minute)))
	result("A.forged_ticket_refused", err != nil, errText(err))
	_, err = openA(gateC, newTicket(t, "agent_b", "engine-1", time.Now().Add(time.Minute)))
	result("A.other_agent_ticket_refused", err != nil, errText(err))
	_, err = openA(gateC, newTicket(t, "agent_a", "engine-1", time.Now().Add(-time.Second)))
	result("A.expired_ticket_refused", err != nil, errText(err))
	_, err = openA(gateC, newTicket(t, "agent_a", "engine-1", time.Now().Add(time.Hour)))
	result("A.overlong_ticket_refused", err != nil, errText(err))

	// Valid ticket.
	tk := newTicket(t, "agent_a", "engine-1", time.Now().Add(time.Minute))
	start := time.Now()
	pw1, err := openA(gateC, tk)
	result("A.valid_ticket_opens", err == nil, fmt.Sprintf("open_read_a took %s %s", time.Since(start), errText(err)))
	rc, err := connect("agent_reader", pw1)
	if err == nil {
		n, err2 := count(rc, "SELECT count(*) FROM app.orders")
		result("A.valid_ticket_reader_reads", err2 == nil && n == 5, fmt.Sprintf("rows=%d %s", n, errText(err2)))
		rc.Close(ctx)
	} else {
		result("A.valid_ticket_reader_reads", false, errText(err))
	}
	_, err = openA(gateC, tk)
	result("A.replayed_ticket_refused", err != nil, errText(err))

	// Second open_read: the first caller's unused password stops working.
	pw2, err := openA(gateC, newTicket(t, "agent_a", "engine-1", time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatalf("second open: %s", errText(err))
	}
	_, err = connect("agent_reader", pw1)
	observe("A.second_open_kills_first_pw", "login with the first password after a second open_read: "+errText(err))
	_, err = connect("agent_reader", pw2)
	result("A.second_pw_works", err == nil, errText(err))

	// Uncommitted: does the new password work before open_read commits?
	tx, err := gateC.Begin(ctx)
	if err == nil {
		var pw3 string
		err = tx.QueryRow(ctx, "SELECT basalt_meta.open_read_a($1, $2::numeric, $3::numeric)",
			func() []any {
				k := newTicket(t, "agent_a", "engine-1", time.Now().Add(time.Minute))
				return []any{k.payload, k.r, k.s}
			}()...).Scan(&pw3)
		if err == nil {
			_, e1 := connect("agent_reader", pw3)
			observe("A.pw_before_commit", "login with the new password before commit: "+errText(e1))
		}
		_ = tx.Commit(ctx)
	}

	// Revoked engine key: a fresh, validly signed ticket for it is refused.
	must(t, adm, "UPDATE basalt_meta.engine_keys SET revoked_at = now() WHERE key_id = 'engine-2'")
	_, err = openA(gateC, newTicket(t, "agent_a", "engine-2", time.Now().Add(time.Minute)))
	result("A.revoked_engine_key_ticket_refused", err != nil, errText(err))

	// Expired password, and an open session past the expiry.
	pwS, err := openA(gateC, newTicket(t, "agent_a", "engine-1", time.Now().Add(3*time.Second)))
	if err != nil {
		t.Fatalf("short ticket: %s", errText(err))
	}
	open, err := connect("agent_reader", pwS)
	if err != nil {
		t.Fatalf("short reader: %s", errText(err))
	}
	time.Sleep(5 * time.Second)
	_, err = connect("agent_reader", pwS)
	result("A.expired_pw_refused", err != nil, errText(err))
	n, err = count(open, "SELECT count(*) FROM app.orders")
	observe("A.open_session_after_expiry", fmt.Sprintf("session opened before VALID UNTIL, read 2s after it: rows=%d %s", n, errText(err)))

	// Revoke path 1: drop membership in basalt_reads (no signalling needed).
	err = exec(adm, "REVOKE basalt_reads FROM agent_reader")
	_, err2 := count(open, "SELECT count(*) FROM app.orders")
	result("A.revoke_membership_ends_open_reads", err == nil && err2 != nil, "revoke: "+errText(err)+" | next read in open session: "+errText(err2))
	must(t, adm, "GRANT basalt_reads TO agent_reader")
	n, err = count(open, "SELECT count(*) FROM app.orders")
	observe("A.regrant_reopens_old_session", fmt.Sprintf("after GRANT basalt_reads again, the old session reads: rows=%d %s", n, errText(err)))

	// Revoke path 2: pg_terminate_backend from a guard function.
	var killed int
	err = adm.QueryRow(ctx, "SELECT basalt_meta.revoke_reads_a()").Scan(&killed)
	observe("A.terminate_without_pg_signal_backend", fmt.Sprintf("setup_admin (CREATEROLE, creator of agent_reader): killed=%d %s", killed, errText(err)))
	if err != nil {
		must(t, su, "GRANT pg_signal_backend TO setup_admin")
		err = adm.QueryRow(ctx, "SELECT basalt_meta.revoke_reads_a()").Scan(&killed)
		observe("A.terminate_with_pg_signal_backend", fmt.Sprintf("killed=%d %s", killed, errText(err)))
	}
	time.Sleep(300 * time.Millisecond)
	_, err = count(open, "SELECT 1")
	result("A.revoke_terminates_open_session", err != nil, "next query in the open session: "+errText(err))
	open.Close(ctx)
	_, err = connect("agent_reader", pw2)
	result("A.revoke_clears_pw", err != nil, "login with the last issued password after revoke: "+errText(err))

	// Privilege probes: who can ALTER ROLE agent_reader PASSWORD?
	oth, err := connect("other_admin", otherPW)
	if err == nil {
		err = exec(oth, "ALTER ROLE agent_reader PASSWORD 'x' VALID UNTIL 'infinity'")
		observe("A.alter_by_other_createrole_role", "a CREATEROLE role that did not create agent_reader: "+errText(err))
		err = exec(oth, "ALTER ROLE agent_reader PASSWORD NULL")
		_ = err
		oth.Close(ctx)
	}
	must(t, sus, "CREATE ROLE su_made LOGIN")
	err = exec(adm, "ALTER ROLE su_made PASSWORD 'x' VALID UNTIL 'infinity'")
	observe("A.alter_superuser_made_role", "setup_admin altering a role a superuser created: "+errText(err))
	n, err = count(gateC, "SELECT count(*) FROM pg_roles")
	observe("A.gate_sees_catalog", fmt.Sprintf("gate login reads pg_catalog: pg_roles rows=%d %s", n, errText(err)))
}

// ---- A2: a login role per ticket ----------------------------------------

func candidateA2(t *testing.T, adm *pgx.Conn) {
	gateC, err := connect("agent_gate", gatePW)
	if err != nil {
		t.Fatalf("gate connect: %s", errText(err))
	}
	defer gateC.Close(ctx)
	t1 := newTicket(t, "agent_a", "engine-1", time.Now().Add(3*time.Second))
	u1, p1, err := openA2(gateC, t1)
	result("A2.valid_ticket_creates_role", err == nil, u1+" "+errText(err))
	if err != nil {
		return
	}
	t2 := newTicket(t, "agent_a", "engine-1", time.Now().Add(time.Minute))
	u2, p2, err := openA2(gateC, t2)
	if err != nil {
		t.Fatalf("A2 second: %s", errText(err))
	}
	c1, err := connect(u1, p1)
	if err != nil {
		t.Fatalf("A2 c1: %s", errText(err))
	}
	defer c1.Close(ctx)
	c2, err := connect(u2, p2)
	if err != nil {
		t.Fatalf("A2 c2: %s", errText(err))
	}
	defer c2.Close(ctx)
	n, err := count(c1, "SELECT count(*) FROM app.orders")
	result("A2.reader_reads", err == nil && n == 5, fmt.Sprintf("rows=%d %s", n, errText(err)))
	time.Sleep(4 * time.Second)
	var swept int
	err = adm.QueryRow(ctx, "SELECT basalt_meta.sweep_a2()").Scan(&swept)
	_, e1 := count(c1, "SELECT count(*) FROM app.orders")
	result("A2.sweep_ends_expired_open_session", err == nil && e1 != nil, fmt.Sprintf("swept=%d %s | expired ticket's open session reads: %s", swept, errText(err), errText(e1)))
	n, e2 := count(c2, "SELECT count(*) FROM app.orders")
	result("A2.other_ticket_unaffected", e2 == nil && n == 5, fmt.Sprintf("rows=%d %s", n, errText(e2)))
	err = exec(adm, "SELECT basalt_meta.revoke_ticket_a2($1)", t2.nonce)
	_, e2 = count(c2, "SELECT count(*) FROM app.orders")
	result("A2.revoke_ends_open_session", err == nil && e2 != nil, "revoke: "+errText(err)+" | next read: "+errText(e2))
	_, err = connect(u2, p2)
	result("A2.revoked_login_refused", err != nil, errText(err))
}

// ---- SECRET column ------------------------------------------------------

func secretColumn(t *testing.T, adm *pgx.Conn) {
	must(t, adm, "GRANT basalt_reads TO agent_reader")
	gateC, err := connect("agent_gate", gatePW)
	if err != nil {
		t.Fatal(errText(err))
	}
	defer gateC.Close(ctx)
	pw, err := openA(gateC, newTicket(t, "agent_a", "engine-1", time.Now().Add(time.Minute)))
	if err != nil {
		t.Fatal(errText(err))
	}
	c, err := connect("agent_reader", pw)
	if err != nil {
		t.Fatal(errText(err))
	}
	defer c.Close(ctx)
	for _, q := range []struct{ name, sql string }{
		{"SECRET.select_star", "SELECT * FROM app.customers"},
		{"SECRET.select_other_cols", "SELECT id, name, email FROM app.customers"},
		{"SECRET.select_secret_col", "SELECT ssn FROM app.customers"},
		{"SECRET.whole_row_ref", "SELECT c FROM app.customers c"},
		{"SECRET.count_star", "SELECT count(*) FROM app.customers"},
		{"SECRET.where_on_secret", "SELECT id FROM app.customers WHERE ssn = '111'"},
	} {
		rows, err := c.Query(ctx, q.sql)
		var n int
		if err == nil {
			for rows.Next() {
				n++
			}
			err = rows.Err()
			rows.Close()
		}
		observe(q.name, fmt.Sprintf("%s -> rows=%d %s", q.sql, n, errText(err)))
	}
	// What the engine would run to expand *.
	var cols string
	err = c.QueryRow(ctx, `
SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum)
  FROM pg_attribute
 WHERE attrelid = 'app.customers'::regclass AND attnum > 0 AND NOT attisdropped
   AND has_column_privilege(attrelid, attnum, 'SELECT')`).Scan(&cols)
	observe("SECRET.readable_columns_query", "has_column_privilege expansion of * = "+cols+" "+errText(err))
	n, err := count(c, "SELECT count(*) FROM (SELECT "+cols+" FROM app.customers) s")
	result("SECRET.expanded_star_reads", err == nil && n == 3, fmt.Sprintf("rows=%d %s", n, errText(err)))
	var hasTable bool
	_ = c.QueryRow(ctx, "SELECT has_table_privilege('app.customers', 'SELECT')").Scan(&hasTable)
	observe("SECRET.has_table_privilege", fmt.Sprintf("agent_reader has table-level SELECT on customers: %v (column grants only)", hasTable))
}

// ---- B ------------------------------------------------------------------

type roleCount map[string]int64

func countsAs(t *testing.T, sus *pgx.Conn, role string, tables []string) roleCount {
	t.Helper()
	out := roleCount{}
	for _, tb := range tables {
		must(t, sus, "SET ROLE "+role)
		n, err := count(sus, "SELECT count(*) FROM "+tb)
		must(t, sus, "RESET ROLE")
		if err != nil {
			n = -1
		}
		out[tb] = n
	}
	return out
}

func candidateB(t *testing.T, sus, adm *pgx.Conn) {
	tables := []string{"app.plain", "app.rls_app", "app.rls_public", "app.orders"}
	base := map[string]roleCount{}
	for _, r := range []string{"app_user", "anon_like", "agent_b"} {
		base[r] = countsAs(t, sus, r, tables)
	}
	observe("B.baseline", fmt.Sprintf("%v", base))

	// B1: the naive install, only a restrictive policy TO agent_b.
	must(t, adm, `
ALTER TABLE app.plain ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY basalt_gate ON app.plain AS RESTRICTIVE FOR SELECT TO agent_b USING (basalt_meta.read_open());
CREATE POLICY basalt_gate ON app.orders AS RESTRICTIVE FOR SELECT TO agent_b USING (basalt_meta.read_open());
CREATE POLICY basalt_gate ON app.rls_app AS RESTRICTIVE FOR SELECT TO agent_b USING (basalt_meta.read_open());
CREATE POLICY basalt_gate ON app.rls_public AS RESTRICTIVE FOR SELECT TO agent_b USING (basalt_meta.read_open());`)
	for _, r := range []string{"app_user", "anon_like"} {
		got := countsAs(t, sus, r, tables)
		observe("B1.naive_other_role_"+r, fmt.Sprintf("restrictive only: %v (baseline %v)", got, base[r]))
	}
	must(t, sus, "SET ROLE app_user")
	err := exec(sus, "INSERT INTO app.plain VALUES (99, 'new')")
	must(t, sus, "RESET ROLE")
	observe("B1.naive_app_insert_plain", "app_user INSERT into a table that had no RLS: "+errText(err))

	// B2: the complete install. Tables with no RLS before also get a
	// permissive TO PUBLIC USING (true) so other roles keep reading/writing.
	must(t, adm, `
CREATE POLICY basalt_keep ON app.plain AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);
CREATE POLICY basalt_keep ON app.orders AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true);`)
	same := true
	for _, r := range []string{"app_user", "anon_like"} {
		got := countsAs(t, sus, r, tables)
		for k, v := range base[r] {
			if got[k] != v {
				same = false
			}
		}
		observe("B2.other_role_"+r, fmt.Sprintf("%v (baseline %v)", got, base[r]))
	}
	must(t, sus, "SET ROLE app_user")
	err = exec(sus, "INSERT INTO app.plain VALUES (98, 'new')")
	must(t, sus, "RESET ROLE")
	result("B2.other_roles_unaffected", same && err == nil, "counts match baseline for app_user and anon_like; app_user INSERT: "+errText(err))
	must(t, sus, "DELETE FROM app.plain WHERE id IN (98, 99)")

	// row_security = off (what pg_dump does) as a non-owner role.
	must(t, sus, "SET ROLE app_user")
	err = exec(sus, "SET row_security = off")
	_, err2 := count(sus, "SELECT count(*) FROM app.plain")
	must(t, sus, "RESET row_security")
	must(t, sus, "RESET ROLE")
	observe("B2.row_security_off_non_owner", "app_user with row_security=off (pg_dump default) on a table that had no RLS: "+errText(err)+" | "+errText(err2))

	// The agent with the stolen password and no ticket.
	ag, err := connect("agent_b", agentBP)
	if err != nil {
		t.Fatal(errText(err))
	}
	defer ag.Close(ctx)
	got := map[string]int64{}
	for _, tb := range tables {
		n, err := count(ag, "SELECT count(*) FROM "+tb)
		if err != nil {
			n = -1
		}
		got[tb] = n
	}
	zero := got["app.plain"] == 0 && got["app.orders"] == 0 && got["app.rls_public"] == 0 && got["app.rls_app"] == 0
	result("B.stolen_pw_reads_nothing", zero, fmt.Sprintf("no ticket: %v (silently empty, no error)", got))

	// Forgery.
	err = exec(ag, "INSERT INTO basalt_meta.sessions VALUES (pg_backend_pid(), 'x', 'x', now() + interval '1 hour')")
	result("B.forged_session_insert_refused", err != nil, errText(err))
	err = exec(ag, "SET basalt.read_token = 'guess'")
	n, _ := count(ag, "SELECT count(*) FROM app.plain")
	result("B.guessed_token_reads_nothing", n == 0, fmt.Sprintf("set token: %s rows=%d", errText(err), n))
	err = openB(ag, ticket{payload: `{"agent":"agent_b"}`, r: "1", s: "1"})
	result("B.no_valid_ticket_refused", err != nil, errText(err))
	err = openB(ag, forgedTicket(t, "agent_b", time.Now().Add(time.Minute)))
	result("B.forged_ticket_refused", err != nil, errText(err))
	err = openB(ag, newTicket(t, "agent_b", "engine-1", time.Now().Add(-time.Second)))
	result("B.expired_ticket_refused", err != nil, errText(err))
	err = exec(ag, "SET row_security = off")
	_, err2 = count(ag, "SELECT count(*) FROM app.plain")
	result("B.row_security_off_no_bypass", err2 != nil, errText(err)+" | "+errText(err2))
	_ = exec(ag, "RESET row_security")

	// pid reuse, simulated: a stale row for this pid, as a dead backend
	// with the same pid would have left it.
	var pid int
	_ = ag.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
	stale := newTicket(t, "agent_b", "engine-1", time.Now().Add(time.Minute))
	must(t, adm, "INSERT INTO basalt_meta.tickets (nonce, agent, engine_key_id, expires_at) VALUES ($1, 'agent_b', 'engine-1', now() + interval '1 minute')", stale.nonce)
	must(t, adm, "INSERT INTO basalt_meta.sessions VALUES ($1, 'dead-backend-token', $2, now() + interval '1 minute')", pid, stale.nonce)
	n, _ = count(ag, "SELECT count(*) FROM app.plain")
	var naive bool
	_ = ag.QueryRow(ctx, "SELECT basalt_meta.read_open_pid_only()").Scan(&naive)
	result("B.pid_reuse_simulated", n == 0, fmt.Sprintf("pid+token check: rows=%d; a pid-only check would return %v", n, naive))
	must(t, adm, "DELETE FROM basalt_meta.sessions WHERE token = 'dead-backend-token'")

	// Valid ticket, mid-session expiry, revoke.
	tk := newTicket(t, "agent_b", "engine-1", time.Now().Add(3*time.Second))
	err = openB(ag, tk)
	got = map[string]int64{}
	for _, tb := range tables {
		n, e := count(ag, "SELECT count(*) FROM "+tb)
		if e != nil {
			n = -1
		}
		got[tb] = n
	}
	match := true
	for k, v := range base["agent_b"] {
		if got[k] != v {
			match = false
		}
	}
	result("B.valid_ticket_reads", err == nil && match, fmt.Sprintf("%s rows=%v baseline=%v", errText(err), got, base["agent_b"]))
	err = openB(ag, tk)
	result("B.replayed_ticket_refused", err != nil, errText(err))
	time.Sleep(4 * time.Second)
	n, err = count(ag, "SELECT count(*) FROM app.orders")
	result("B.expiry_bites_mid_session", n == 0, fmt.Sprintf("same session after expiry: rows=%d %s", n, errText(err)))
	tk2 := newTicket(t, "agent_b", "engine-1", time.Now().Add(time.Minute))
	if err := openB(ag, tk2); err != nil {
		t.Fatal(errText(err))
	}
	n, _ = count(ag, "SELECT count(*) FROM app.orders")
	err = exec(adm, "SELECT basalt_meta.revoke_ticket_b($1)", tk2.nonce)
	n2, _ := count(ag, "SELECT count(*) FROM app.orders")
	result("B.revoke_bites_mid_session", n == 5 && n2 == 0, fmt.Sprintf("before revoke rows=%d, after rows=%d %s", n, n2, errText(err)))

	// Pooler, simulated: ticket on one backend, read on another.
	ag2, err := connect("agent_b", agentBP)
	if err != nil {
		t.Fatal(errText(err))
	}
	defer ag2.Close(ctx)
	if err := openB(ag, newTicket(t, "agent_b", "engine-1", time.Now().Add(time.Minute))); err != nil {
		t.Fatal(errText(err))
	}
	n, _ = count(ag2, "SELECT count(*) FROM app.orders")
	observe("B.pooler_ticket_other_backend", fmt.Sprintf("open_read on backend 1, read on backend 2: rows=%d", n))
	tx, err := ag2.Begin(ctx)
	if err == nil {
		k := newTicket(t, "agent_b", "engine-1", time.Now().Add(time.Minute))
		_, err = tx.Exec(ctx, "SELECT basalt_meta.open_read_b($1, $2::numeric, $3::numeric)", k.payload, k.r, k.s)
		var m int64
		if err == nil {
			err = tx.QueryRow(ctx, "SELECT count(*) FROM app.orders").Scan(&m)
		}
		_ = tx.Commit(ctx)
		observe("B.ticket_and_read_one_txn", fmt.Sprintf("rows=%d %s", m, errText(err)))
	}

	// A view over a gated table, owned by the table owner, granted to the agent.
	must(t, adm, `
CREATE VIEW app.v_orders AS SELECT * FROM app.orders;
GRANT SELECT ON app.v_orders TO agent_b;
CREATE VIEW app.v_orders_inv WITH (security_invoker = true) AS SELECT * FROM app.orders;
GRANT SELECT ON app.v_orders_inv TO agent_b;`)
	fresh, err := connect("agent_b", agentBP)
	if err != nil {
		t.Fatal(errText(err))
	}
	defer fresh.Close(ctx)
	n, err = count(fresh, "SELECT count(*) FROM app.v_orders")
	result("B.view_owned_by_owner_gated", n == 0, fmt.Sprintf("no ticket, plain view: rows=%d %s", n, errText(err)))
	n, err = count(fresh, "SELECT count(*) FROM app.v_orders_inv")
	result("B.security_invoker_view_gated", n == 0, fmt.Sprintf("no ticket, security_invoker view: rows=%d %s", n, errText(err)))

	// A table added later and granted to the agent is not gated until setup reruns.
	must(t, adm, "CREATE TABLE app.later (id int); INSERT INTO app.later VALUES (1),(2); GRANT SELECT ON app.later TO agent_b")
	n, err = count(fresh, "SELECT count(*) FROM app.later")
	result("B.new_table_gated", n == 0, fmt.Sprintf("no ticket, table created after setup: rows=%d %s", n, errText(err)))

	// The table owner and a BYPASSRLS role.
	n, _ = count(adm, "SELECT count(*) FROM app.orders")
	observe("B.owner_unaffected", fmt.Sprintf("setup_admin (owner) rows=%d", n))

	// SECRET column for agent_b.
	_, err = count(fresh, "SELECT count(*) FROM (SELECT * FROM app.customers) s")
	observe("B.SECRET_select_star", errText(err))
}

// ---- pooler (pgbouncer, transaction mode) -------------------------------

func poolerA(t *testing.T, sus, adm *pgx.Conn) {
	must(t, adm, "GRANT basalt_reads TO agent_reader")
	gateC, err := connect("agent_gate", gatePW)
	if err != nil {
		t.Fatal(errText(err))
	}
	defer gateC.Close(ctx)
	pw, err := openA(gateC, newTicket(t, "agent_a", "engine-1", time.Now().Add(4*time.Second)))
	if err != nil {
		t.Fatal(errText(err))
	}
	e, err := connectPool("agent_reader", pw)
	if err != nil {
		result("POOL.A.login_via_pgbouncer", false, errText(err))
		return
	}
	n, err := count(e, "SELECT count(*) FROM app.orders")
	result("POOL.A.login_via_pgbouncer", err == nil && n == 5, fmt.Sprintf("rows=%d %s", n, errText(err)))
	e.Close(ctx)
	time.Sleep(6 * time.Second)
	_, err = connect("agent_reader", pw)
	observe("POOL.A.expired_pw_direct", errText(err))
	m, err := connectPool("agent_reader", pw)
	if err == nil {
		n, err = count(m, "SELECT count(*) FROM app.orders")
		m.Close(ctx)
	}
	result("POOL.A.expired_pw_refused_via_pooler", err != nil, fmt.Sprintf("new client with the expired password via pgbouncer: rows=%d %s", n, errText(err)))
	var killed int
	err = adm.QueryRow(ctx, "SELECT basalt_meta.revoke_reads_a()").Scan(&killed)
	m, err2 := connectPool("agent_reader", pw)
	if err2 == nil {
		_, err2 = count(m, "SELECT count(*) FROM app.orders")
		m.Close(ctx)
	}
	result("POOL.A.revoked_refused_via_pooler", err2 != nil, fmt.Sprintf("revoke killed=%d %s | client via pgbouncer: %s", killed, errText(err), errText(err2)))
}

func poolerB(t *testing.T, adm *pgx.Conn) {
	eng, err := connectPool("agent_b", agentBP)
	if err != nil {
		result("POOL.B.login_via_pgbouncer", false, errText(err))
		return
	}
	k := newTicket(t, "agent_b", "engine-1", time.Now().Add(time.Minute))
	err = openB(eng, k)
	var n int64
	if err == nil {
		n, err = count(eng, "SELECT count(*) FROM app.orders")
	}
	observe("POOL.B.engine_ticket_then_read", fmt.Sprintf("separate transactions via pgbouncer (pool size 1): rows=%d %s", n, errText(err)))
	eng.Close(ctx)
	thief, err := connectPool("agent_b", agentBP)
	if err != nil {
		result("POOL.B.thief_no_ticket_reads_nothing", false, errText(err))
		return
	}
	defer thief.Close(ctx)
	n, err = count(thief, "SELECT count(*) FROM app.orders")
	result("POOL.B.thief_no_ticket_reads_nothing", err == nil && n == 0, fmt.Sprintf("a second client with the stolen password, no ticket, via pgbouncer: rows=%d %s", n, errText(err)))
}
