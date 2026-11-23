package guard_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
)

// person registers a software passkey as basalt init would.
func person(t *testing.T, d *guardtest.DB) *passkeytest.Authenticator {
	t.Helper()
	p, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, p.Credential(), "app"))
	return p
}

// previewAndHold runs stmt in a preview transaction, reads its lines,
// rolls back, and holds it, as the engine does after APPROVAL_REQUIRED.
func previewAndHold(t *testing.T, c *pgx.Conn, in guard.Intent, stmt string, params []any, assigned []string) (guard.Held, []string) {
	t.Helper()
	ctx := context.Background()
	tx, err := c.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, guard.BeginPreview(ctx, tx, in, guardtest.Timeout))
	_, err = tx.Exec(ctx, stmt, params...)
	require.NoError(t, err)
	lines, err := guard.PreviewLines(ctx, tx, assigned)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	require.NotEmpty(t, lines)
	held, err := guard.Hold(ctx, c, in, guardtest.Timeout, guard.HoldRequest{Statement: stmt, Params: params, Assigned: assigned, Lines: lines})
	require.NoError(t, err)
	return held, lines
}

// applyApproved runs stmt under the approval as the engine does.
func applyApproved(ctx context.Context, c *pgx.Conn, in guard.Intent, id uuid.UUID, stmt string, params []any) error {
	return pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
		if err := guard.BeginApproved(ctx, tx, in, guardtest.Timeout, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, stmt, params...); err != nil {
			return err
		}
		_, err := guard.FinishChange(ctx, tx, guard.Finish{Op: "UPDATE", Statement: stmt, Params: params})
		return err
	})
}

func sign(t *testing.T, p *passkeytest.Authenticator, held guard.Held, tamper func(*passkey.Assertion)) passkey.Assertion {
	t.Helper()
	as, err := p.Sign(approval.Challenge(held.BindingText), passkeytest.FlagsUPUV, tamper)
	require.NoError(t, err)
	return as
}

func requireInvalid(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, guardmodel.CodeApprovalInvalid)
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg))
	require.Contains(t, pg.Detail, detail)
}

// On the installed guard: a held DELETE
// with cascades, signed with the person's passkey, relayed by the agent.
func TestApprovalFlow(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	other := d.NewAgent(t, "other", leads, leads)
	p := person(t, d)
	in := newRun(t, a, "remove the spam lead")
	const stmt = `DELETE FROM public.leads WHERE id = $1`
	params := []any{3}

	requireCode(t, applyApproved(context.Background(), a.Conn, in, uuid.Must(uuid.NewV7()), stmt, params), guardmodel.CodeApprovalInvalid)
	err := pgx.BeginFunc(context.Background(), a.Conn, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(context.Background(), tx, in, guardtest.Timeout); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), stmt, params...)
		return err
	})
	requireCode(t, err, guardmodel.CodeApprovalRequired)

	held, lines := previewAndHold(t, a.Conn, in, stmt, params, []string{})
	// lead 3, its notes 5 and 6, their tags 5 and 6: the agent cannot read
	// notes or tags, so those lines are redacted.
	require.Len(t, lines, 5)
	require.Contains(t, lines[0], `"op": "DELETE", "key": {"id": 3}`)
	for _, l := range lines[1:] {
		require.Contains(t, l, `"redacted": true`)
		require.NotContains(t, l, "note ")
	}
	req := approval.Request{ApprovalID: held.ApprovalID, Binding: held.BindingText, Lines: lines}
	b, err := req.Check()
	require.NoError(t, err, "the Go codec accepts what Postgres built")
	require.Equal(t, in.RunID, b.RunID)
	require.Equal(t, a.Role, b.Agent)
	require.Equal(t, stmt, b.Statement)
	require.WithinDuration(t, time.Now().Add(24*time.Hour), held.ExpiresAt, time.Minute)
	require.Equal(t, "APPROVAL_PENDING", scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_changes WHERE approval_id = $1`, held.ApprovalID))

	t.Run("not signed yet", func(t *testing.T) {
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, params), "not approved yet")
	})
	t.Run("the agent signs with its own key", func(t *testing.T) {
		forger, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		forger.ID = p.ID
		_, err = guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, sign(t, forger, held, nil))
		requireInvalid(t, err, "bad passkey signature")
	})
	t.Run("an unregistered passkey", func(t *testing.T) {
		stranger, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		_, err = guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, sign(t, stranger, held, nil))
		requireInvalid(t, err, "unknown passkey")
	})
	t.Run("a signature for another binding", func(t *testing.T) {
		as, err := p.Sign(approval.Challenge(held.BindingText+" "), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, as)
		requireInvalid(t, err, "client data does not match")
	})
	t.Run("no user verification", func(t *testing.T) {
		as, err := p.Sign(approval.Challenge(held.BindingText), passkeytest.FlagUP, nil)
		require.NoError(t, err)
		_, err = guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, as)
		requireInvalid(t, err, "verification required")
	})
	t.Run("wrong RP ID", func(t *testing.T) {
		_, err := guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, sign(t, p, held, func(as *passkey.Assertion) {
			h := sha256.Sum256([]byte("evil.example"))
			copy(as.AuthenticatorData, h[:])
		}))
		requireInvalid(t, err, "rpIdHash")
	})
	t.Run("garbage signature and client data", func(t *testing.T) {
		as := sign(t, p, held, nil)
		as.Signature = []byte{0x30, 0x02, 0x02, 0x00}
		_, err := guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, as)
		requireInvalid(t, err, "DER")
		as = sign(t, p, held, func(as *passkey.Assertion) { as.ClientDataJSON = []byte{0xff, 0xfe} })
		_, err = guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, as)
		requireInvalid(t, err, "client data")
	})

	signed := sign(t, p, held, nil)
	start := time.Now()
	at, err := guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, signed)
	require.NoError(t, err, "the person's signature, relayed by the agent itself")
	t.Logf("submit_approval with the P-256 check in PL/pgSQL: %s", time.Since(start).Round(time.Millisecond))
	require.WithinDuration(t, time.Now(), at, time.Minute)
	_, err = approvaltest.Verify(held.BindingText, p.Credential(), approvaltest.NewResponse(held.ApprovalID, signed))
	require.NoError(t, err, "the Go mirror agrees")

	t.Run("replayed assertion", func(t *testing.T) {
		_, err := guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, signed)
		requireInvalid(t, err, "already signed")
	})
	t.Run("another agent cannot use the approval", func(t *testing.T) {
		oin := newRun(t, other, "steal")
		requireInvalid(t, applyApproved(context.Background(), other.Conn, oin, held.ApprovalID, stmt, params), "another agent")
	})
	t.Run("another run cannot use the approval", func(t *testing.T) {
		in2 := newRun(t, a, "another run")
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in2, held.ApprovalID, stmt, params), "another run")
	})
	t.Run("different parameters", func(t *testing.T) {
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, []any{4}), "differ from the approval")
	})
	t.Run("a different statement with the same rows", func(t *testing.T) {
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, `DELETE FROM public.leads WHERE id = $1 AND true`, params),
			"differ from the approval")
	})
	t.Run("a person edits a cascaded note after the preview", func(t *testing.T) {
		d.Exec(t, `UPDATE public.lead_notes SET note = 'edited by a person' WHERE id = 5`)
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, params), "rows changed since the preview")
		d.Exec(t, `UPDATE public.lead_notes SET note = 'note 5' WHERE id = 5`)
	})

	require.NoError(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, params))
	require.Zero(t, count(t, d.Admin, `SELECT count(id) FROM public.leads WHERE id = 3`))
	require.Zero(t, count(t, d.Admin, `SELECT count(id) FROM public.lead_notes WHERE lead_id = 3`))
	require.Equal(t, "APPLIED", scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_changes WHERE approval_id = $1`, held.ApprovalID),
		"one record per action: the held record is replaced by the applied one")
	require.Equal(t, "APPLIED", scalarOf[string](t, a.Conn,
		`SELECT status FROM basalt_meta.agent_approvals WHERE approval_id = $1`, held.ApprovalID))
	require.Equal(t, 1, count(t, a.Conn, `SELECT count(seq) FROM basalt_meta.agent_ledger WHERE kind = 'APPROVED'`))
	require.Equal(t, 1, count(t, a.Conn, `SELECT count(seq) FROM basalt_meta.agent_ledger WHERE kind = 'APPROVAL_PENDING'`))

	t.Run("an approval is used once", func(t *testing.T) {
		d.Exec(t, `INSERT INTO public.leads VALUES (3, 'lead 3', 'open', 3)`)
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, params), "already used")
	})
	require.Nil(t, scalarOf[*int64](t, a.Conn, `SELECT basalt_meta.verify_chain()`))
}

func scalarOf[T any](t *testing.T, q guard.Querier, sql string, args ...any) T {
	t.Helper()
	var v T
	require.NoError(t, q.QueryRow(context.Background(), sql, args...).Scan(&v))
	return v
}

// Decision M2-1: bind what the statement assigns, never what the database
// fills in.
func TestApprovalBindsAssignedColumnsOnly(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `
CREATE TABLE public.tasks (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    status     text        NOT NULL DEFAULT 'open',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := clock_timestamp(); RETURN NEW; END $$;
CREATE TRIGGER touch BEFORE UPDATE ON public.tasks FOR EACH ROW EXECUTE FUNCTION public.touch();
INSERT INTO public.tasks (name) SELECT 'task ' || g FROM generate_series(1, 30) g;`)
	tasks := []string{"public.tasks"}
	a := d.NewAgent(t, "bot", tasks, tasks)
	p := person(t, d)

	approve := func(in guard.Intent, stmt string, params []any, assigned []string) (guard.Held, []string) {
		held, lines := previewAndHold(t, a.Conn, in, stmt, params, assigned)
		_, err := guard.SubmitApproval(context.Background(), a.Conn, held.ApprovalID, sign(t, p, held, nil))
		require.NoError(t, err)
		return held, lines
	}

	t.Run("an update whose trigger sets updated_at applies", func(t *testing.T) {
		in := newRun(t, a, "close old tasks")
		const stmt = `UPDATE public.tasks SET status = $1 WHERE name <= 'task 21'`
		held, lines := approve(in, stmt, []any{"closed"}, []string{"status"})
		require.Len(t, lines, 14)
		require.Contains(t, lines[0], `"set": {"status": "closed"}`)
		require.NoError(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, []any{"closed"}))
		require.Equal(t, 14, count(t, d.Admin, `SELECT count(id) FROM public.tasks WHERE status = 'closed'`))
	})
	t.Run("an insert with generated keys and timestamps applies", func(t *testing.T) {
		in := newRun(t, a, "add tasks")
		const stmt = `INSERT INTO public.tasks (name) SELECT 'new ' || g FROM generate_series(1, 12) g`
		held, lines := approve(in, stmt, nil, []string{"name"})
		require.Len(t, lines, 12)
		require.Contains(t, lines[0], `"key": null, "old": null, "set": {"name": "new 1"}`)
		require.NoError(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, nil))
		require.Equal(t, 12, count(t, d.Admin, `SELECT count(id) FROM public.tasks WHERE name LIKE 'new %'`))
	})
	t.Run("a statement that writes another value at apply is refused at commit", func(t *testing.T) {
		in := newRun(t, a, "time bomb")
		const stmt = `UPDATE public.tasks SET status = CASE WHEN current_setting('basalt.mode', true) = 'PREVIEW' THEN 'fine' ELSE 'evil' END WHERE name LIKE 'new %'`
		held, lines := approve(in, stmt, nil, []string{"status"})
		require.Contains(t, lines[0], `"set": {"status": "fine"}`)
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, nil), "rows changed since the preview")
		require.Zero(t, count(t, d.Admin, `SELECT count(id) FROM public.tasks WHERE status = 'evil'`))
	})
	t.Run("more rows at apply than approved", func(t *testing.T) {
		in := newRun(t, a, "grow")
		const stmt = `UPDATE public.tasks SET status = 'grown' WHERE status = 'open'`
		held, _ := approve(in, stmt, nil, []string{"status"})
		d.Exec(t, `INSERT INTO public.tasks (name) VALUES ('late arrival')`)
		requireInvalid(t, applyApproved(context.Background(), a.Conn, in, held.ApprovalID, stmt, nil), "more than")
	})
}

func TestApprovalExpiry(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	in := newRun(t, a, "expiry")
	const stmt = `DELETE FROM public.leads WHERE id = 60`

	unsigned, _ := previewAndHold(t, a.Conn, in, stmt, nil, []string{})
	signedHeld, _ := previewAndHold(t, a.Conn, in, `DELETE FROM public.leads WHERE id = 61`, nil, []string{})
	_, err := guard.SubmitApproval(context.Background(), a.Conn, signedHeld.ApprovalID, sign(t, p, signedHeld, nil))
	require.NoError(t, err)
	d.Exec(t, `UPDATE basalt_meta.approvals SET expires_at = now() - interval '1 second'`)

	_, err = guard.SubmitApproval(context.Background(), a.Conn, unsigned.ApprovalID, sign(t, p, unsigned, nil))
	requireCode(t, err, guardmodel.CodeApprovalExpired)
	requireCode(t, applyApproved(context.Background(), a.Conn, in, signedHeld.ApprovalID, `DELETE FROM public.leads WHERE id = 61`, nil), guardmodel.CodeApprovalExpired)

	_, err = a.Conn.Exec(context.Background(), `SELECT basalt_meta.prune()`)
	require.NoError(t, err)
	require.Equal(t, 2, count(t, a.Conn, `SELECT count(change_id) FROM basalt_meta.agent_changes WHERE status = 'APPROVAL_EXPIRED'`))
	require.Equal(t, 2, count(t, a.Conn, `SELECT count(approval_id) FROM basalt_meta.agent_approvals WHERE status = 'EXPIRED'`))
}

func TestHoldValidation(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	in := newRun(t, a, "validation")
	line := func(id int) string {
		return `{"op": "DELETE", "key": {"id": ` + big.NewInt(int64(id)).String() + `}, "old": null, "set": null, "table": "public.leads", "cascaded": false}`
	}
	many := make([]string, 51)
	for i := range many {
		many[i] = line(100 + i)
	}
	cases := []struct {
		name     string
		in       guard.Intent
		assigned []string
		lines    []string
	}{
		{"no lines", in, nil, nil},
		{"over 50 lines", in, nil, many},
		{"not jsonb text", in, nil, []string{`{"op":"DELETE","table":"t"}`}},
		{"out of order", in, nil, []string{line(20), line(10)}},
		{"only cascaded lines", in, nil, []string{`{"op": "DELETE", "key": {"id": 1}, "old": null, "set": null, "table": "t", "cascaded": true}`}},
		{"duplicate assigned columns", in, []string{"a", "a"}, []string{line(1)}},
	}
	for _, tc := range cases {
		_, err := guard.Hold(context.Background(), a.Conn, tc.in, guardtest.Timeout, guard.HoldRequest{Statement: "DELETE FROM public.leads", Assigned: tc.assigned, Lines: tc.lines})
		requireCode(t, err, guardmodel.CodeLedgerInputInvalid)
	}

	// preview_lines only in a preview.
	err := pgx.BeginFunc(context.Background(), a.Conn, func(tx pgx.Tx) error {
		if err := guard.BeginGuarded(context.Background(), tx, in, guardtest.Timeout); err != nil {
			return err
		}
		_, err := guard.PreviewLines(context.Background(), tx, nil)
		return err
	})
	requireCode(t, err, guardmodel.CodeNotAllowed)
}

func TestPasskeyRegistration(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)

	var label, origin string
	require.NoError(t, a.Conn.QueryRow(context.Background(), `SELECT label, origin FROM basalt_meta.agent_passkeys WHERE credential_id = $1`, p.ID).Scan(&label, &origin))
	require.Equal(t, "app", label)
	require.Equal(t, passkey.Origin, origin)

	// Off the curve.
	_, err := d.Admin.Exec(context.Background(), `SELECT basalt_meta.register_passkey('\x01', $1, $1, 'basaltvault.app', 'https://basaltvault.app', 'x', NULL)`, make([]byte, 32))
	requireCode(t, err, guardmodel.CodeLedgerInputInvalid)

	// Agents cannot register a key or write the passkey table.
	x, y, err := p.Credential().XY()
	require.NoError(t, err)
	_, err = a.Conn.Exec(context.Background(), `SELECT basalt_meta.register_passkey('\x02', $1, $2, 'basaltvault.app', 'https://basaltvault.app', 'mine', NULL)`, x, y)
	require.Equal(t, "42501", guardtest.SQLState(err))
	_, err = a.Conn.Exec(context.Background(), `INSERT INTO basalt_meta.passkeys VALUES ('\x02', $1, $2, 'basaltvault.app', 'https://basaltvault.app', 0, 'mine')`, x, y)
	require.Equal(t, "42501", guardtest.SQLState(err))
	_, err = a.Conn.Exec(context.Background(), `UPDATE basalt_meta.approvals SET approved_at = now()`)
	require.Equal(t, "42501", guardtest.SQLState(err))
	_, err = a.Conn.Exec(context.Background(), `SELECT basalt_meta._verify_assertion('\x00', '\x00', '\x00', '\x00', '\x00')`)
	require.Equal(t, "42501", guardtest.SQLState(err))
}

// The PL/pgSQL verifier against Go's crypto/ecdsa on random keys.
func TestP256Vectors(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Init(t, guardmodel.AgentSpec{})
	const n = 12
	const q = `SELECT basalt_meta._p256_verify($1, $2::text::numeric, $3::text::numeric, $4::text::numeric, $5::text::numeric)`
	for i := range n {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		msg := make([]byte, 32)
		_, _ = rand.Read(msg)
		r, s, err := ecdsa.Sign(rand.Reader, k, msg)
		require.NoError(t, err)
		raw, err := k.PublicKey.Bytes()
		require.NoError(t, err)
		qx, qy := new(big.Int).SetBytes(raw[1:33]).String(), new(big.Int).SetBytes(raw[33:65]).String()
		require.True(t, scalarOf[bool](t, d.Admin, q, msg, r.String(), s.String(), qx, qy), "valid %d", i)
		bad := append([]byte{}, msg...)
		bad[i%32] ^= 1 << (i % 8)
		require.False(t, scalarOf[bool](t, d.Admin, q, bad, r.String(), s.String(), qx, qy), "tampered %d", i)
		require.False(t, scalarOf[bool](t, d.Admin, q, msg, s.String(), r.String(), qx, qy), "swapped %d", i)
	}
}
