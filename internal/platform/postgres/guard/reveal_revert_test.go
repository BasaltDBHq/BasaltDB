package guard_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// revealKeyOf is the key the engine derives from the page's reveal secret
// (16 bytes: the secret text padded or cut).
func revealKeyOf(t *testing.T, secret string) []byte {
	t.Helper()
	raw := make([]byte, approval.RevealSecretLen)
	copy(raw, secret)
	key, err := approval.RevealKey(raw)
	require.NoError(t, err)
	return key
}

// revealChallenge is the challenge a reveal proof signs.
func revealChallenge(t *testing.T, kind string, id uuid.UUID, nonce, key, rowsHash []byte) []byte {
	t.Helper()
	ch, err := approvaltest.RevealChallenge(kind, id, nonce, key, hex.EncodeToString(rowsHash))
	require.NoError(t, err)
	return ch
}

// revealEnv: bot may read and write leads only. Its run deleted lead 5
// with the person's approval, and the cascade deleted notes 9 and 10 and
// their tags, which bot cannot read. Its revert has five lines, four of
// them redacted.
type revealEnv struct {
	d    *guardtest.DB
	a    *guardtest.Agent
	p    *passkeytest.Authenticator
	in   guard.Intent
	prep revertstore.PreparedRevert
}

func newRevealEnv(t *testing.T) revealEnv {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	e := revealEnv{d: d, a: a, p: person(t, d), in: newRun(t, a, "Drop lead 5")}
	approvedWrite(t, a, e.p, e.in, `DELETE FROM public.leads WHERE id = $1`, []any{5}, []string{})
	// The person's passkey is a synced one from here on: its counter stays
	// 0, so only the nonce stops a replay.
	d.Exec(t, `UPDATE basalt_meta.passkeys SET sign_count = 0`)
	prep, err := guard.PrepareRevert(context.Background(), a.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: e.in.RunID}, "Undo it")
	require.NoError(t, err)
	e.prep = prep
	require.Len(t, redactedLines(t, prep.Lines), 4)
	return e
}

// redactedLines maps a request's redacted lines' indexes to their rowHash.
func redactedLines(t *testing.T, lines []string) map[int]string {
	t.Helper()
	out := map[int]string{}
	for i, l := range lines {
		var v struct {
			Redacted bool   `json:"redacted"`
			RowHash  string `json:"rowHash"`
		}
		require.NoError(t, json.Unmarshal([]byte(l), &v))
		if v.Redacted {
			out[i] = v.RowHash
		}
	}
	return out
}

func revertRevealNonce(t *testing.T, d *guardtest.DB, id uuid.UUID) []byte {
	t.Helper()
	return scalarOf[[]byte](t, d.Admin, `SELECT reveal_nonce FROM basalt_meta.reverts WHERE revert_id = $1`, id)
}

func revertRowsHash(t *testing.T, d *guardtest.DB, id uuid.UUID) []byte {
	t.Helper()
	return scalarOf[[]byte](t, d.Admin, `SELECT rows_hash FROM basalt_meta.reverts WHERE revert_id = $1`, id)
}

// proof is the person's reveal proof for revert id with the key derived
// from secret; a synced passkey's (counter 0), so only the nonce stops a
// replay.
func (e revealEnv) proof(t *testing.T, id uuid.UUID, secret string) (passkey.Assertion, []byte) {
	t.Helper()
	key := revealKeyOf(t, secret)
	as, err := e.p.Sign(revealChallenge(t, approval.KindRevert, id, revertRevealNonce(t, e.d, id), key, revertRowsHash(t, e.d, id)),
		passkeytest.FlagsUPUV, zeroCounter)
	require.NoError(t, err)
	return as, key
}

func rowHashOf(row string) string {
	sum := sha256.Sum256([]byte(row))
	return hex.EncodeToString(sum[:])
}

// agentViews is everything the agent role reads about its revert.
func agentViews(t *testing.T, a *guardtest.Agent) string {
	t.Helper()
	return scalarOf[string](t, a.Conn, `SELECT concat_ws(E'\n',
		(SELECT string_agg(r::text, E'\n' ORDER BY r.revert_id) FROM basalt_meta.agent_reverts r),
		(SELECT string_agg(l::text, E'\n' ORDER BY l.revert_id, l.line_no) FROM basalt_meta.agent_revert_lines l))`)
}

func agentLedger(t *testing.T, a *guardtest.Agent) string {
	t.Helper()
	return scalarOf[string](t, a.Conn, `SELECT string_agg(l::text, E'\n' ORDER BY l.seq) FROM basalt_meta.agent_ledger l
		WHERE l.kind <> 'ROWS_REVEALED'`)
}

// A valid proof returns every redacted line's row, each hashing to its
// line's rowHash; the nonce is replaced, ROWS_REVEALED holds no value, and
// what the agent reads is unchanged.
func TestRevealRevertRows(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	nonce, err := guard.RevealNonce(ctx, e.a.Conn, approval.KindRevert, id)
	require.NoError(t, err)
	require.Equal(t, revertRevealNonce(t, e.d, id), nonce)
	require.Len(t, nonce, 16)
	views, ledger := agentViews(t, e.a), agentLedger(t, e.a)

	as, key := e.proof(t, id, "the page's reveal secret")
	out, err := guard.RevealRevertRows(ctx, e.a.Conn, id, as, key)
	require.NoError(t, err)
	require.False(t, out.RowsChanged)
	want := redactedLines(t, e.prep.Lines)
	require.Len(t, out.Rows, len(want))
	for i, r := range out.Rows {
		if i > 0 {
			require.Greater(t, r.Line, out.Rows[i-1].Line, "in line order")
		}
		require.Equal(t, want[r.Line], rowHashOf(r.Row), "line %d hashes to its rowHash", r.Line)
		require.Empty(t, r.SecretColumns)
	}
	require.Contains(t, rowsText(out), `"note": "note 9"`)
	require.Contains(t, rowsText(out), `"tag": "tag 10"`)

	require.NotEqual(t, nonce, revertRevealNonce(t, e.d, id), "the proof used the nonce")
	details := ledgerDetails(t, e.d, "ROWS_REVEALED")
	require.Len(t, details, 1)
	require.Equal(t, map[string]any{
		"kind": "REVERT", "id": id.String(), "credentialId": hex.EncodeToString(as.CredentialID),
		"rows": float64(4),
	}, details[0])
	raw := scalarOf[string](t, e.d.Admin, `SELECT row_to_json(l)::text FROM basalt_meta.ledger l WHERE kind = 'ROWS_REVEALED'`)
	require.NotContains(t, raw, "note 9")
	require.NotContains(t, raw, hex.EncodeToString(key), "the key is never recorded")
	require.Equal(t, 1, count(t, e.a.Conn, `SELECT count(seq)::int FROM basalt_meta.agent_ledger WHERE kind = 'ROWS_REVEALED'`),
		"agent_ledger shows the row as it is")

	require.Equal(t, views, agentViews(t, e.a), "agent_reverts and agent_revert_lines are unchanged")
	require.Equal(t, ledger, agentLedger(t, e.a), "the agent's ledger is unchanged but for ROWS_REVEALED")

	// The revert still applies with the person's signature.
	sig, err := e.p.Sign(passkeytest.Challenge(e.prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	applied, err := guard.ApplyRevert(ctx, e.a.Conn, id, sig)
	require.NoError(t, err)
	require.Equal(t, 5, applied.Rows)
	require.Nil(t, guardVerify(t, e.d))
}

func rowsText(out revertstore.RevealedRevert) string {
	parts := make([]string, 0, len(out.Rows))
	for _, r := range out.Rows {
		parts = append(parts, r.Row)
	}
	return strings.Join(parts, "\n")
}

// Every proof that is not the person's for this revert, nonce, key and
// rowsHash is refused with one text, and nothing changes.
func TestRevealRevertRowsRefused(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	nonce := revertRevealNonce(t, e.d, id)
	hash := revertRowsHash(t, e.d, id)
	key := revealKeyOf(t, "secret")
	sign := func(challenge []byte) passkey.Assertion {
		as, err := e.p.Sign(challenge, passkeytest.FlagsUPUV, zeroCounter)
		require.NoError(t, err)
		return as
	}
	valid := sign(revealChallenge(t, approval.KindRevert, id, nonce, key, hash))
	otherHash := sha256.Sum256([]byte("another rowsHash"))
	other, err := guard.PrepareRevert(ctx, e.a.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: e.in.RunID}, "again")
	require.NoError(t, err)
	widenKey, err := revert.RescopeKey([]byte("secret"))
	require.NoError(t, err)
	held, _ := previewAndHold(t, e.a.Conn, newRun(t, e.a, "another delete"), `DELETE FROM public.leads WHERE id = $1`, []any{6}, []string{})

	cases := map[string]struct {
		proof passkey.Assertion
		key   []byte
	}{
		"no proof":                      {passkey.Assertion{}, key},
		"no key":                        {valid, nil},
		"a guessed key":                 {valid, revealKeyOf(t, "guess")},
		"a short key":                   {valid, key[:16]},
		"a proof over another revert":   {sign(revealChallenge(t, approval.KindRevert, other.RevertID, nonce, key, hash)), key},
		"a proof over another nonce":    {sign(revealChallenge(t, approval.KindRevert, id, make([]byte, 16), key, hash)), key},
		"a proof over another rowsHash": {sign(revealChallenge(t, approval.KindRevert, id, nonce, key, otherHash[:])), key},
		"a proof of the APPROVE kind":   {sign(revealChallenge(t, approval.KindApprove, id, nonce, key, hash)), key},
		"the revert signature":          {sign(passkeytest.Challenge(e.prep.BindingText)), key},
		"an approval signature":         {sign(sha256Of(held.BindingText)), key},
		"a widen proof":                 {sign(reverttest.RescopeChallenge(id, nonce, widenKey, `{}`)), widenKey},
		"a crafted signature, s = n":    {withSig(valid, derSig([]byte{1}, p256Order)), key},
		"an assertion with broken DER":  {withSig(valid, []byte{0x30, 0x00}), key},
	}
	before := revertRevealNonce(t, e.d, id)
	var text string
	for name, c := range cases {
		_, err := guard.RevealRevertRows(ctx, e.a.Conn, id, c.proof, c.key)
		requireRevertInvalid(t, err, guard.RevealRefused)
		got := scopeErrorText(t, err)
		if text == "" {
			text = got
		}
		require.Equal(t, text, got, name)
	}
	require.Equal(t, before, revertRevealNonce(t, e.d, id), "a refused proof changes nothing")
	require.Empty(t, ledgerDetails(t, e.d, "ROWS_REVEALED"))

	// The person's proof works once; replayed (counter 0), it is refused.
	_, err = guard.RevealRevertRows(ctx, e.a.Conn, id, valid, key)
	require.NoError(t, err)
	_, err = guard.RevealRevertRows(ctx, e.a.Conn, id, valid, key)
	requireRevertInvalid(t, err, guard.RevealRefused)
	require.Equal(t, text, scopeErrorText(t, err), "a replay reads like any other refusal")

	// Another agent's revert and an unknown one read alike.
	helper := e.d.NewAgent(t, "helper", leads, leads)
	_, theirs := guard.RevealRevertRows(ctx, helper.Conn, id, valid, key)
	requireRevertRefused(t, theirs, guard.RevertNotFound, "no such revert")
	_, unknown := guard.RevealRevertRows(ctx, e.a.Conn, uuid.Must(uuid.NewV7()), valid, key)
	require.Equal(t, scopeErrorText(t, theirs, id), scopeErrorText(t, unknown))
	_, err = guard.RevealNonce(ctx, helper.Conn, approval.KindRevert, id)
	requireRevertRefused(t, err, guard.RevertNotFound, "no such revert")
	_, err = guard.RevealNonce(ctx, e.a.Conn, "OTHER", id)
	requireCode(t, err, guard.CodeLedgerInputInvalid)
}

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func withSig(a passkey.Assertion, sig []byte) passkey.Assertion {
	a.Signature = sig
	return a
}

// A hidden row changed after prepare: no row comes back, the answer says
// so, and the proof is used up all the same.
func TestRevealRevertRowsChanged(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	e.d.Exec(t, `INSERT INTO public.lead_notes (id, lead_id, note) VALUES (9, 1, 'a person''s note')`)
	before := revertRevealNonce(t, e.d, id)
	as, key := e.proof(t, id, "secret")
	out, err := guard.RevealRevertRows(ctx, e.a.Conn, id, as, key)
	require.NoError(t, err)
	require.True(t, out.RowsChanged)
	require.Empty(t, out.Rows)
	require.NotEqual(t, before, revertRevealNonce(t, e.d, id), "the nonce is used even when rows changed")
	details := ledgerDetails(t, e.d, "ROWS_REVEALED")
	require.Len(t, details, 1)
	require.Equal(t, true, details[0]["rowsChanged"])
	_, err = guard.RevealRevertRows(ctx, e.a.Conn, id, as, key)
	requireRevertInvalid(t, err, guard.RevealRefused)
}

// A SECRET column comes back null and named; the rest of the row is real.
func TestRevealRevertRowsSecretColumn(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	e.d.Exec(t, `INSERT INTO basalt_meta.pii_columns (table_schema, table_name, column_name, data_type, class, confirmed_at, confirmed_by)
		VALUES ('public', 'lead_notes', 'note', 'text', 'SECRET', now(), 'test')`)
	as, key := e.proof(t, e.prep.RevertID, "secret")
	out, err := guard.RevealRevertRows(context.Background(), e.a.Conn, e.prep.RevertID, as, key)
	require.NoError(t, err)
	want := redactedLines(t, e.prep.Lines)
	secret := 0
	for _, r := range out.Rows {
		if len(r.SecretColumns) == 0 {
			require.Equal(t, want[r.Line], rowHashOf(r.Row), "a row without SECRET columns is checked")
			continue
		}
		secret++
		require.Equal(t, []string{"note"}, r.SecretColumns)
		require.Contains(t, r.Row, `"note": null`)
		require.NotContains(t, r.Row, "note 9")
		require.NotContains(t, r.Row, "note 10")
		require.Contains(t, r.Row, `"lead_id": 5`)
	}
	require.Equal(t, 2, secret, "both notes")
}

// The functions are the agents group's only, and a signed or applied
// revert reveals nothing.
func TestRevealRevertRowsGrantsAndState(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	ctx := context.Background()
	for _, fn := range []string{
		"basalt_meta.reveal_nonce(text, uuid)", "basalt_meta.reveal_revert_rows(uuid, jsonb, bytea)",
		"basalt_meta._reveal_row(oid, jsonb, jsonb, jsonb)", "basalt_meta._reveal_proven(text, uuid, bytea, bytea, jsonb, bytea)",
	} {
		require.False(t, scalarOf[bool](t, e.d.Admin, `SELECT has_function_privilege('public', $1, 'EXECUTE')`, fn), fn)
		require.Equal(t, e.d.Names.Guard(), scalarOf[string](t, e.d.Admin,
			`SELECT pg_get_userbyid(proowner)::text FROM pg_proc WHERE oid = $1::regprocedure`, fn), fn)
		require.True(t, scalarOf[bool](t, e.d.Admin, `SELECT prosecdef FROM pg_proc WHERE oid = $1::regprocedure`, fn), fn)
	}
	require.True(t, scalarOf[bool](t, e.d.Admin,
		`SELECT has_function_privilege($1, 'basalt_meta.reveal_revert_rows(uuid, jsonb, bytea)', 'EXECUTE')`, e.a.Role))
	require.False(t, scalarOf[bool](t, e.d.Admin,
		`SELECT has_function_privilege($1, 'basalt_meta._reveal_row(oid, jsonb, jsonb, jsonb)', 'EXECUTE')`, e.a.Role))

	as, key := e.proof(t, e.prep.RevertID, "secret")
	sig, err := e.p.Sign(passkeytest.Challenge(e.prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, e.a.Conn, e.prep.RevertID, sig)
	require.NoError(t, err)
	_, err = guard.RevealRevertRows(ctx, e.a.Conn, e.prep.RevertID, as, key)
	requireRevertInvalid(t, err, "revert already applied")
}

// A large plan reveals the redacted lines of its sample, rebuilt from the
// stored chains: here every line, since bot lost SELECT on items after
// its run.
func TestRevealRevertRowsLargePlan(t *testing.T) {
	t.Parallel()
	b := newBulkEnv(t)
	b.d.Exec(t, `REVOKE SELECT ON public.items FROM `+b.a.Role+`, `+b.d.Names.Agents())
	prep, err := guard.PrepareRevert(context.Background(), b.a.Conn, b.scope(), "Undo the bulk update")
	require.NoError(t, err)
	want := redactedLines(t, prep.Lines)
	require.Len(t, want, revert.MaxLines, "the sample is all redacted")
	e := revealEnv{d: b.d, a: b.a, p: b.p, prep: prep}
	as, key := e.proof(t, prep.RevertID, "secret")
	out, err := guard.RevealRevertRows(context.Background(), b.a.Conn, prep.RevertID, as, key)
	require.NoError(t, err)
	require.False(t, out.RowsChanged)
	require.Len(t, out.Rows, revert.MaxLines)
	for _, r := range out.Rows {
		require.Equal(t, want[r.Line], rowHashOf(r.Row))
	}
}

// Every approval and revert has its own reveal nonce, of 16 bytes, and a
// basalt init that changes nothing keeps a revert's.
func TestEveryApprovalAndRevertHasItsOwnRevealNonce(t *testing.T) {
	t.Parallel()
	e := newRevealEnv(t)
	before := revertRevealNonce(t, e.d, e.prep.RevertID)
	e.d.Init(t, guardmodel.AgentSpec{Name: "bot", Write: leads, Read: leads})
	require.Equal(t, before, revertRevealNonce(t, e.d, e.prep.RevertID))
	require.Zero(t, count(t, e.d.Admin, `SELECT count(approval_id)::int FROM basalt_meta.approvals
		WHERE octet_length(reveal_nonce) <> 16`))
	require.Equal(t, count(t, e.d.Admin, `SELECT count(approval_id)::int FROM basalt_meta.approvals`),
		count(t, e.d.Admin, `SELECT count(DISTINCT reveal_nonce)::int FROM basalt_meta.approvals`))

	as, key := e.proof(t, e.prep.RevertID, "secret")
	_, err := guard.RevealRevertRows(context.Background(), e.a.Conn, e.prep.RevertID, as, key)
	require.NoError(t, err)
}

// Two tables hold rows with the same key, now and set, so their lines have
// the same rowHash; only one table has a SECRET column. Each line is rebuilt
// from its own table's row, so the SECRET rule follows the table.
func TestRevealRevertRowsMatchTheTable(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.parents (id int PRIMARY KEY);
		CREATE TABLE public.child_a (id int PRIMARY KEY, parent_id int NOT NULL REFERENCES public.parents ON DELETE CASCADE, v text);
		CREATE TABLE public.child_b (id int PRIMARY KEY, parent_id int NOT NULL REFERENCES public.parents ON DELETE CASCADE, v text);
		INSERT INTO public.parents VALUES (1);
		INSERT INTO public.child_a VALUES (1, 1, 'same');
		INSERT INTO public.child_b VALUES (1, 1, 'same')`)
	parents := []string{"public.parents"}
	a := d.NewAgent(t, "bot", parents, parents)
	d.Exec(t, `INSERT INTO basalt_meta.pii_columns (table_schema, table_name, column_name, data_type, class, confirmed_at, confirmed_by)
		VALUES ('public', 'child_a', 'v', 'text', 'SECRET', now(), 'test')`)
	e := revealEnv{d: d, a: a, p: person(t, d), in: newRun(t, a, "Drop parent 1")}
	approvedWrite(t, a, e.p, e.in, `DELETE FROM public.parents WHERE id = $1`, []any{1}, []string{})
	d.Exec(t, `UPDATE basalt_meta.passkeys SET sign_count = 0`)
	prep, err := guard.PrepareRevert(context.Background(), a.Conn, revertstore.Scope{Kind: revert.ScopeRun, ID: e.in.RunID}, "Undo it")
	require.NoError(t, err)
	e.prep = prep
	want := redactedLines(t, prep.Lines)
	require.Len(t, want, 2)
	tables := map[int]string{}
	for i := range want {
		var l struct {
			Table string `json:"resource"`
		}
		require.NoError(t, json.Unmarshal([]byte(prep.Lines[i]), &l))
		tables[i] = l.Table
	}
	hashes := make([]string, 0, len(want))
	for _, h := range want {
		hashes = append(hashes, h)
	}
	require.Equal(t, hashes[0], hashes[1], "both lines hash the same row text")

	as, key := e.proof(t, prep.RevertID, "secret")
	out, err := guard.RevealRevertRows(context.Background(), a.Conn, prep.RevertID, as, key)
	require.NoError(t, err)
	require.Len(t, out.Rows, 2)
	for _, r := range out.Rows {
		switch tables[r.Line] {
		case "public.child_a":
			require.Equal(t, []string{"v"}, r.SecretColumns)
			require.NotContains(t, r.Row, "same")
		case "public.child_b":
			require.Empty(t, r.SecretColumns)
			require.Equal(t, want[r.Line], rowHashOf(r.Row))
		default:
			t.Fatalf("unexpected table %q", tables[r.Line])
		}
	}
}
