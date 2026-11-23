package guard_test

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
)

const heldDelete = `DELETE FROM public.leads WHERE id = $1`

// heldEnv: bot may read and write leads only, and
// holds a delete of lead 20, which cascades to notes 39 and 40 that bot
// cannot read. Three lines, two of them redacted.
type heldEnv struct {
	d    *guardtest.DB
	a    *guardtest.Agent
	p    *passkeytest.Authenticator
	in   guard.Intent
	held guard.Held
	// lines are the held preview lines.
	lines []string
}

var heldParams = []any{20}

func newHeldEnv(t *testing.T) heldEnv {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	e := heldEnv{d: d, a: a, p: person(t, d), in: newRun(t, a, "Drop lead 20")}
	e.held, e.lines = previewAndHold(t, a.Conn, e.in, heldDelete, heldParams, []string{})
	require.Len(t, e.lines, 3)
	require.Len(t, redactedLines(t, e.lines), 2)
	return e
}

func (e heldEnv) nonce(t *testing.T) []byte {
	t.Helper()
	return scalarOf[[]byte](t, e.d.Admin, `SELECT reveal_nonce FROM basalt_meta.approvals WHERE approval_id = $1`, e.held.ApprovalID)
}

func (e heldEnv) rowsHash(t *testing.T) []byte {
	t.Helper()
	return scalarOf[[]byte](t, e.d.Admin, `SELECT rows_hash FROM basalt_meta.approvals WHERE approval_id = $1`, e.held.ApprovalID)
}

// proof is the person's reveal proof for the held approval (a synced
// passkey: counter 0).
func (e heldEnv) proof(t *testing.T, secret string) (passkey.Assertion, []byte) {
	t.Helper()
	key := revealKeyOf(t, secret)
	as, err := e.p.Sign(revealChallenge(t, approval.KindApprove, e.held.ApprovalID, e.nonce(t), key, e.rowsHash(t)),
		passkeytest.FlagsUPUV, zeroCounter)
	require.NoError(t, err)
	return as, key
}

func (e heldEnv) open(t *testing.T) []byte {
	t.Helper()
	as, key := e.proof(t, "the page's reveal secret")
	ticket, err := guard.OpenReveal(context.Background(), e.a.Conn, e.held.ApprovalID, as, key)
	require.NoError(t, err)
	return ticket
}

// rerun is the engine's second transaction: a preview of stmt with params
// in run in, recorded with finish_change unless skipFinish, then after (if
// set), then reveal_approval_rows; always rolled back.
type rerun struct {
	stmt       string
	params     []any
	in         *guard.Intent
	skipFinish bool
	after      func(ctx context.Context, tx pgx.Tx)
}

func (e heldEnv) reveal(t *testing.T, ticket []byte, r rerun) ([]approval.RevealedRow, error) {
	t.Helper()
	ctx := context.Background()
	if r.stmt == "" {
		r.stmt, r.params = heldDelete, heldParams
	}
	in := e.in
	if r.in != nil {
		in = *r.in
	}
	tx, err := e.a.Conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback(ctx)) }()
	require.NoError(t, guard.BeginPreview(ctx, tx, in, guardtest.Timeout))
	_, err = tx.Exec(ctx, r.stmt, r.params...)
	require.NoError(t, err)
	if !r.skipFinish {
		_, err = guard.FinishChange(ctx, tx, guard.Finish{Op: "DELETE", Statement: r.stmt, Params: r.params})
		require.NoError(t, err)
	}
	if r.after != nil {
		r.after(ctx, tx)
	}
	// A savepoint keeps the transaction usable after a refusal, so the
	// deferred rollback runs cleanly.
	_, err = tx.Exec(ctx, `SAVEPOINT reveal`)
	require.NoError(t, err)
	rows, rerr := guard.RevealApprovalRows(ctx, tx, e.held.ApprovalID, ticket)
	if rerr != nil {
		_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT reveal`)
		require.NoError(t, err)
	}
	return rows, rerr
}

// setMode switches basalt.mode for the rest of the transaction.
func setMode(t *testing.T, mode string) func(ctx context.Context, tx pgx.Tx) {
	t.Helper()
	return func(ctx context.Context, tx pgx.Tx) {
		_, err := tx.Exec(ctx, `SELECT set_config('basalt.mode', $1, true)`, mode)
		require.NoError(t, err)
	}
}

func requireApprovalInvalid(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, guardmodel.CodeApprovalInvalid)
	require.Contains(t, scopeErrorText(t, err), "|"+detail+"|")
}

// The person's proof opens a ticket; a re-run preview with it returns the
// two hidden notes, hashing to the held lines; the re-run leaves nothing,
// and the held approval still applies.
func TestRevealApprovalRows(t *testing.T) {
	t.Parallel()
	e := newHeldEnv(t)
	ctx := context.Background()
	nonce, err := guard.RevealNonce(ctx, e.a.Conn, approval.KindApprove, e.held.ApprovalID)
	require.NoError(t, err)
	require.Equal(t, e.nonce(t), nonce)
	notes := tableDigest(t, e.d, "public.lead_notes")
	seq := scalarOf[int64](t, e.d.Admin, `SELECT max(seq) FROM basalt_meta.ledger`)

	ticket := e.open(t)
	require.Len(t, ticket, 16)
	require.NotEqual(t, nonce, e.nonce(t), "the proof used the nonce")
	require.Equal(t, sha256.Sum256(ticket), [32]byte(scalarOf[[]byte](t, e.d.Admin,
		`SELECT reveal_ticket_hash FROM basalt_meta.approvals WHERE approval_id = $1`, e.held.ApprovalID)))
	details := ledgerDetails(t, e.d, "ROWS_REVEALED")
	require.Len(t, details, 1)
	require.Equal(t, "APPROVE", details[0]["kind"])
	require.Equal(t, float64(2), details[0]["rows"])

	rows, err := e.reveal(t, ticket, rerun{})
	require.NoError(t, err)
	want := redactedLines(t, e.lines)
	require.Len(t, rows, 2)
	for _, r := range rows {
		require.Equal(t, want[r.Line], rowHashOf(r.Row), "line %d hashes to its held rowHash", r.Line)
		require.Empty(t, r.SecretColumns)
	}
	require.Contains(t, rows[0].Row+rows[1].Row, `"note": "note 39"`)
	require.Contains(t, rows[0].Row+rows[1].Row, `"note": "note 40"`)
	checked, err := approval.CheckRevealAnswer(e.lines, approval.RevealAnswer{Rows: rows})
	require.NoError(t, err)
	require.Equal(t, []bool{true, true}, checked, "the page's own check passes")

	require.Equal(t, notes, tableDigest(t, e.d, "public.lead_notes"), "the re-run rolled back")
	require.Equal(t, seq+1, scalarOf[int64](t, e.d.Admin, `SELECT max(seq) FROM basalt_meta.ledger`),
		"only ROWS_REVEALED was appended")

	// A second re-run in the window works with the same ticket.
	_, err = e.reveal(t, ticket, rerun{})
	require.NoError(t, err)

	_, err = guard.SubmitApproval(ctx, e.a.Conn, e.held.ApprovalID, sign(t, e.p, e.held, nil))
	require.NoError(t, err)
	require.NoError(t, applyApproved(ctx, e.a.Conn, e.in, e.held.ApprovalID, heldDelete, heldParams))
	require.Zero(t, count(t, e.d.Admin, `SELECT count(id)::int FROM public.lead_notes WHERE lead_id = 20`))
	require.Nil(t, guardVerify(t, e.d))
}

// Without the ticket the agent role gets no row: every ticket, mode or
// statement failure reads the same; changed rows are ROWS_CHANGED.
func TestRevealApprovalRowsRefused(t *testing.T) {
	t.Parallel()
	e := newHeldEnv(t)
	ticket := e.open(t)
	wrong := make([]byte, 16)
	otherRun := newRun(t, e.a, "another run")
	cases := map[string]struct {
		ticket []byte
		r      rerun
	}{
		"no ticket":      {nil, rerun{}},
		"a wrong ticket": {wrong, rerun{}},
		// The held statement re-ran and was recorded in a preview, but the
		// transaction is no longer a preview when it asks.
		"outside PREVIEW":               {ticket, rerun{after: setMode(t, guard.ModeApply)}},
		"a preview in another run":      {ticket, rerun{in: &otherRun}},
		"a preview of other parameters": {ticket, rerun{params: []any{21}, stmt: heldDelete}},
		"a preview of another statement": {ticket, rerun{
			stmt: `DELETE FROM public.leads WHERE id = $1 AND status = 'open'`, params: heldParams,
		}},
		"a preview not recorded with finish_change": {ticket, rerun{skipFinish: true}},
	}
	var text string
	for name, c := range cases {
		rows, err := e.reveal(t, c.ticket, c.r)
		require.Nil(t, rows, name)
		requireApprovalInvalid(t, err, guardmodel.RevealRefused)
		got := scopeErrorText(t, err, e.held.ApprovalID)
		if text == "" {
			text = got
		}
		require.Equal(t, text, got, name)
	}

	// The ticket after its window.
	e.d.Exec(t, `UPDATE basalt_meta.approvals SET reveal_until = now() - interval '1 second' WHERE approval_id = $1`, e.held.ApprovalID)
	_, err := e.reveal(t, ticket, rerun{})
	requireApprovalInvalid(t, err, guardmodel.RevealRefused)
	require.Equal(t, text, scopeErrorText(t, err, e.held.ApprovalID))

	// A hidden row changed since the hold.
	ticket = e.open(t)
	e.d.Exec(t, `UPDATE public.lead_notes SET note = 'edited by a person' WHERE id = 39`)
	rows, err := e.reveal(t, ticket, rerun{})
	require.Nil(t, rows)
	requireApprovalInvalid(t, err, guardmodel.RevealRowsChanged)
}

// open_reveal refuses every proof but the person's for this approval, with
// one text and no change, and refuses an approved, used or expired one.
func TestOpenRevealRefused(t *testing.T) {
	t.Parallel()
	e := newHeldEnv(t)
	ctx := context.Background()
	id := e.held.ApprovalID
	nonce, hash := e.nonce(t), e.rowsHash(t)
	key := revealKeyOf(t, "secret")
	signed := func(challenge []byte) passkey.Assertion {
		as, err := e.p.Sign(challenge, passkeytest.FlagsUPUV, zeroCounter)
		require.NoError(t, err)
		return as
	}
	valid := signed(revealChallenge(t, approval.KindApprove, id, nonce, key, hash))
	widenKey, err := revert.RescopeKey([]byte("secret"))
	require.NoError(t, err)
	cases := map[string]struct {
		proof passkey.Assertion
		key   []byte
	}{
		"no proof":                   {passkey.Assertion{}, key},
		"no key":                     {valid, nil},
		"a guessed key":              {valid, revealKeyOf(t, "guess")},
		"a proof of the REVERT kind": {signed(revealChallenge(t, approval.KindRevert, id, nonce, key, hash)), key},
		"another nonce":              {signed(revealChallenge(t, approval.KindApprove, id, make([]byte, 16), key, hash)), key},
		"the approval signature":     {signed(approval.Challenge(e.held.BindingText)), key},
		"a widen proof":              {signed(reverttest.RescopeChallenge(id, nonce, widenKey, `{}`)), widenKey},
		"a broken DER signature":     {withSig(valid, []byte{0x30, 0x00}), key},
	}
	var text string
	for name, c := range cases {
		_, err := guard.OpenReveal(ctx, e.a.Conn, id, c.proof, c.key)
		requireApprovalInvalid(t, err, guardmodel.RevealRefused)
		got := scopeErrorText(t, err)
		if text == "" {
			text = got
		}
		require.Equal(t, text, got, name)
	}
	require.Equal(t, nonce, e.nonce(t), "nothing changed")
	require.Empty(t, ledgerDetails(t, e.d, "ROWS_REVEALED"))

	_, err = guard.OpenReveal(ctx, e.a.Conn, id, valid, key)
	require.NoError(t, err)
	_, err = guard.OpenReveal(ctx, e.a.Conn, id, valid, key)
	requireApprovalInvalid(t, err, guardmodel.RevealRefused)
	require.Equal(t, text, scopeErrorText(t, err), "a replay reads like any other refusal")

	helper := e.d.NewAgent(t, "helper", leads, leads)
	_, theirs := guard.OpenReveal(ctx, helper.Conn, id, valid, key)
	_, unknown := guard.OpenReveal(ctx, e.a.Conn, uuid.Must(uuid.NewV7()), valid, key)
	requireApprovalInvalid(t, theirs, "no such approval")
	require.Equal(t, scopeErrorText(t, theirs, id), scopeErrorText(t, unknown))

	// Approved, then used: no reveal either way.
	_, err = guard.SubmitApproval(ctx, e.a.Conn, id, sign(t, e.p, e.held, nil))
	require.NoError(t, err)
	_, err = guard.OpenReveal(ctx, e.a.Conn, id, valid, key)
	requireApprovalInvalid(t, err, "approval already approved")
	require.NoError(t, applyApproved(ctx, e.a.Conn, e.in, id, heldDelete, heldParams))
	_, err = guard.OpenReveal(ctx, e.a.Conn, id, valid, key)
	requireApprovalInvalid(t, err, "approval already used")

	// Expired.
	other := newHeldEnv(t)
	other.d.Exec(t, `UPDATE basalt_meta.approvals SET expires_at = now() - interval '1 second'`)
	as, k := other.proof(t, "secret")
	_, err = guard.OpenReveal(ctx, other.a.Conn, other.held.ApprovalID, as, k)
	requireCode(t, err, guardmodel.CodeApprovalExpired)
}

// A SECRET column comes back null and named, and grants and ownership
// hold.
func TestRevealApprovalRowsSecretAndGrants(t *testing.T) {
	t.Parallel()
	e := newHeldEnv(t)
	e.d.Exec(t, `INSERT INTO basalt_meta.pii_columns (table_schema, table_name, column_name, data_type, class, confirmed_at, confirmed_by)
		VALUES ('public', 'lead_notes', 'note', 'text', 'SECRET', now(), 'test')`)
	rows, err := e.reveal(t, e.open(t), rerun{})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, r := range rows {
		require.Equal(t, []string{"note"}, r.SecretColumns)
		require.Contains(t, r.Row, `"note": null`)
		require.NotContains(t, r.Row, "note 39")
	}

	for _, fn := range []string{
		"basalt_meta.open_reveal(uuid, jsonb, bytea)", "basalt_meta.reveal_approval_rows(uuid, bytea)",
		"basalt_meta._reveal_lines(uuid, text[])", "basalt_meta._reveal_approval_lock(uuid)",
	} {
		require.False(t, scalarOf[bool](t, e.d.Admin, `SELECT has_function_privilege('public', $1, 'EXECUTE')`, fn), fn)
		require.Equal(t, e.d.Names.Guard(), scalarOf[string](t, e.d.Admin,
			`SELECT pg_get_userbyid(proowner)::text FROM pg_proc WHERE oid = $1::regprocedure`, fn), fn)
		require.True(t, scalarOf[bool](t, e.d.Admin, `SELECT prosecdef FROM pg_proc WHERE oid = $1::regprocedure`, fn), fn)
	}
	require.False(t, scalarOf[bool](t, e.d.Admin,
		`SELECT has_function_privilege($1, 'basalt_meta._reveal_lines(uuid, text[])', 'EXECUTE')`, e.a.Role))
	require.Equal(t, 0, count(t, e.a.Conn, `SELECT count(1)::int FROM information_schema.columns
		WHERE table_schema = 'basalt_meta' AND table_name = 'agent_approvals' AND column_name LIKE 'reveal%'`),
		"agent_approvals shows no reveal column")
}

// The change compared is the transaction's latest PREVIEW change: an
// ordinary write recorded after the preview, in the same transaction, is
// not the one checked against the held approval.
func TestRevealApprovalRowsReadsThePreviewChange(t *testing.T) {
	t.Parallel()
	e := newHeldEnv(t)
	rows, err := e.reveal(t, e.open(t), rerun{after: func(ctx context.Context, tx pgx.Tx) {
		setMode(t, guard.ModeApply)(ctx, tx)
		const write = `UPDATE public.leads SET score = 1 WHERE id = 1`
		_, err := tx.Exec(ctx, write)
		require.NoError(t, err)
		_, err = guard.FinishChange(ctx, tx, guard.Finish{Op: "UPDATE", Statement: write})
		require.NoError(t, err)
		setMode(t, guard.ModePreview)(ctx, tx)
	}})
	require.NoError(t, err)
	require.Len(t, rows, 2)
}
