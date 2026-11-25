package guard_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// counterAt is the offset of the 4-byte signature counter in authenticator
// data (32-byte rpIdHash, then the flags byte).
const counterAt = 33

// zeroCounter makes an assertion look like a synced passkey's, whose
// counter stays 0, so only the nonce can stop a replay.
func zeroCounter(a *passkey.Assertion) {
	binary.BigEndian.PutUint32(a.AuthenticatorData[counterAt:], 0)
}

// widenEnv is scopeTask with the person's passkey and bot's task proposal.
type widenEnv struct {
	scopeTask
	p    *passkeytest.Authenticator
	prep action.PreparedRevert
}

func newWidenEnv(t *testing.T) widenEnv {
	t.Helper()
	e := widenEnv{scopeTask: newScopeTask(t)}
	e.p = person(t, e.d)
	prep, err := guard.PrepareRevert(context.Background(), e.bot.Conn, e.taskScope(), "Undo the task")
	require.NoError(t, err)
	e.prep = prep
	return e
}

// own is bot's own proposal for the task; every is the whole task.
func (e widenEnv) own() revert.Select {
	return revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.bot.Name}}
}

func (e widenEnv) every() revert.Select {
	return revert.Select{Scope: revert.ScopeTask, ScopeID: e.task}
}

// normText is sel as Postgres normalizes it, the text a widen proof signs.
func normText(t *testing.T, d *guardtest.DB, sel revert.Select) string {
	t.Helper()
	b, err := json.Marshal(sel)
	require.NoError(t, err)
	return scalarOf[string](t, d.Admin, `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(b))
}

func nonceOf(t *testing.T, d *guardtest.DB, revertID uuid.UUID) []byte {
	t.Helper()
	return scalarOf[[]byte](t, d.Admin, `SELECT rescope_nonce FROM basalt_meta.reverts WHERE revert_id = $1`, revertID)
}

// proof is what the page sends for a widen of revertID to sel: the
// person's assertion over the widen challenge and the key derived from
// the new link secret it made.
func (e widenEnv) proof(t *testing.T, revertID uuid.UUID, sel revert.Select, secret string) (passkey.Assertion, []byte) {
	t.Helper()
	key, err := revert.RescopeKey([]byte(secret))
	require.NoError(t, err)
	as, err := e.p.Sign(reverttest.RescopeChallenge(revertID, nonceOf(t, e.d, revertID), key, normText(t, e.d, sel)),
		passkeytest.FlagsUPUV, zeroCounter)
	require.NoError(t, err)
	return as, key
}

func (e widenEnv) widen(t *testing.T, sel revert.Select) action.RescopedRevert {
	t.Helper()
	as, key := e.proof(t, e.prep.RevertID, sel, "the page's new secret")
	out, err := guard.RescopeRevert(context.Background(), e.bot.Conn,
		action.RescopeRequest{RevertID: e.prep.RevertID, Select: sel, Proof: &as, RescopeKey: key})
	require.NoError(t, err)
	return out
}

// revertRow is what the guard stored for the revert, read as the admin.
type revertRow struct {
	Selection, Ceiling string
	Nonce              []byte
	Rescoped           int
	HasToken           bool
}

func storedRevert(t *testing.T, d *guardtest.DB, revertID uuid.UUID) revertRow {
	t.Helper()
	var r revertRow
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT selection::text, coalesce(ceiling::text, ''),
		rescope_nonce, rescoped, scope_token_hash IS NOT NULL FROM basalt_meta.reverts WHERE revert_id = $1`, revertID).
		Scan(&r.Selection, &r.Ceiling, &r.Nonce, &r.Rescoped, &r.HasToken))
	return r
}

func ledgerDetails(t *testing.T, d *guardtest.DB, kind string) []map[string]any {
	t.Helper()
	rows, err := d.Admin.Query(context.Background(), `SELECT detail FROM basalt_meta.ledger WHERE kind = $1 ORDER BY seq`, kind)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[map[string]any])
	require.NoError(t, err)
	return out
}

func requireWidenRefused(t *testing.T, err error) string {
	t.Helper()
	requireRevertInvalid(t, err, guardmodel.RevertWidenRefused)
	return scopeErrorText(t, err)
}

// A proven widen: the whole task, both agents' lines, the proposal kept, a
// token and the catalog returned once, the nonce replaced, and the ledger
// row holding only hashes. The person then signs and applies it.
func TestRescopeWidenWithProof(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	before := storedRevert(t, e.d, e.prep.RevertID)
	secret := "the page's new secret"
	as, key := e.proof(t, e.prep.RevertID, e.every(), secret)
	out, err := guard.RescopeRevert(ctx, e.bot.Conn,
		action.RescopeRequest{RevertID: e.prep.RevertID, Select: e.every(), Proof: &as, RescopeKey: key})
	require.NoError(t, err)

	b, err := revert.Request{RevertID: out.RevertID, Binding: out.BindingText, Lines: out.Lines}.Check()
	require.NoError(t, err, "the Go codec accepts the widened request")
	require.True(t, b.Widened)
	require.Equal(t, e.every(), b.Select)
	require.NotNil(t, b.Proposed)
	require.Equal(t, e.own(), *b.Proposed)
	require.Equal(t, map[string]int{e.bot.Name: 3, e.helper.Name: 2}, b.AgentRows)
	require.Equal(t, 5, b.Rows)
	require.True(t, b.ExpiresAt.After(e.prep.ExpiresAt) || b.ExpiresAt.Equal(e.prep.ExpiresAt))

	require.Len(t, out.ScopeToken, 16)
	require.NotNil(t, out.Catalog)
	require.Equal(t, []action.CatalogAgent{{Agent: e.bot.Name, Changes: 3}, {Agent: e.helper.Name, Changes: 2}}, sortedAgents(out.Catalog.Agents, e.bot.Name))
	runs := map[uuid.UUID]string{}
	for _, r := range out.Catalog.Runs {
		runs[r.RunID] = r.Agent
	}
	require.Equal(t, map[uuid.UUID]string{e.botA.RunID: e.bot.Name, e.botB.RunID: e.bot.Name, e.help.RunID: e.helper.Name}, runs,
		"the helper's run outside the task is not in the catalog")
	require.Equal(t, []action.CatalogTable{{Table: "public.lead_owner", Rows: 2}, {Table: "public.leads", Rows: 3}}, out.Catalog.Tables)

	after := storedRevert(t, e.d, e.prep.RevertID)
	require.NotEqual(t, before.Nonce, after.Nonce, "the proof consumed the nonce")
	require.Equal(t, []byte(out.RescopeNonce), after.Nonce)
	require.True(t, after.HasToken)
	require.Equal(t, after.Selection, after.Ceiling)
	require.Equal(t, 1, after.Rescoped)
	require.Equal(t, sha256.Sum256(out.ScopeToken),
		[32]byte(scalarOf[[]byte](t, e.d.Admin, `SELECT scope_token_hash FROM basalt_meta.reverts WHERE revert_id = $1`, e.prep.RevertID)))

	details := ledgerDetails(t, e.d, "REVERT_RESCOPED")
	require.Len(t, details, 1)
	keyHash := sha256.Sum256(key)
	require.Equal(t, guardmodel.RescopeViaProof, details[0]["via"])
	require.Equal(t, hex.EncodeToString(as.CredentialID), details[0]["credentialId"])
	require.Equal(t, hex.EncodeToString(keyHash[:]), details[0]["rescopeKeyHash"])
	raw := scalarOf[string](t, e.d.Admin, `SELECT detail::text FROM basalt_meta.ledger WHERE kind = 'REVERT_RESCOPED'`)
	require.NotContains(t, raw, hex.EncodeToString(key), "the key is never recorded")
	require.NotContains(t, raw, secret)
	require.NotContains(t, raw, out.ScopeToken.String())

	sig, err := e.p.Sign(approval.Challenge(out.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	applied, err := guard.ApplyRevert(ctx, e.bot.Conn, e.prep.RevertID, sig)
	require.NoError(t, err)
	require.Equal(t, 5, applied.Rows)
	require.Equal(t, "open", leadStatus(t, e.d, 32), "the helper's lead the person added is restored")
	require.Equal(t, "x", leadStatus(t, e.d, 33), "the helper's run outside the task is not")
	require.Nil(t, guardVerify(t, e.d))
}

// sortedAgents puts first the agent first, so the comparison does not
// depend on role name order.
func sortedAgents(in []action.CatalogAgent, first string) []action.CatalogAgent {
	out := make([]action.CatalogAgent, 0, len(in))
	for _, a := range in {
		if a.Agent == first {
			out = append([]action.CatalogAgent{a}, out...)
			continue
		}
		out = append(out, a)
	}
	return out
}

// p256Order is the order n of the P-256 group, big-endian.
var p256Order, _ = hex.DecodeString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

// derSig is the ASN.1 DER ECDSA signature (r, s) of big-endian integers.
func derSig(r, s []byte) []byte {
	integer := func(b []byte) []byte {
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	body := append(integer(r), integer(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// Straight to rescope_revert as the agent role: every way of widening
// without the person's proof and its key is refused with one text, and
// nothing changes.
func TestRescopeWidenRefused(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	before := storedRevert(t, e.d, id)
	other, err := guard.PrepareRevert(ctx, e.bot.Conn, action.Scope{Kind: revert.ScopeRun, ID: e.botA.RunID}, "x")
	require.NoError(t, err)
	both := e.every()
	both.Agents = []string{e.bot.Name, e.helper.Name}

	validProof, validKey := e.proof(t, id, e.every(), "secret")
	otherKey, err := revert.RescopeKey([]byte("another secret"))
	require.NoError(t, err)
	overBoth, bothKey := e.proof(t, id, both, "secret")
	otherRevert, otherRevertKey := e.proof(t, other.RevertID, e.every(), "secret")
	revertSig, err := e.p.Sign(approval.Challenge(e.prep.BindingText), passkeytest.FlagsUPUV, zeroCounter)
	require.NoError(t, err)
	cases := map[string]action.RescopeRequest{
		"no proof":                           {Select: e.every()},
		"a proof over another select":        {Select: e.every(), Proof: &overBoth, RescopeKey: bothKey},
		"another revert's proof":             {Select: e.every(), Proof: &otherRevert, RescopeKey: otherRevertKey},
		"the revert signature as a proof":    {Select: e.every(), Proof: &revertSig, RescopeKey: validKey},
		"a pasted proof without its key":     {Select: e.every(), Proof: &validProof},
		"a pasted proof with a guessed key":  {Select: e.every(), Proof: &validProof, RescopeKey: otherKey},
		"a token on a revert never widened":  {Select: e.every(), Token: make([]byte, 16)},
		"the other agent only, no proof":     {Select: revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Name}}},
		"a proof with a short key":           {Select: e.every(), Proof: &validProof, RescopeKey: validKey[:16]},
		"an approval-shaped proof, any text": {Select: e.every(), Proof: &passkey.Assertion{CredentialID: []byte("x")}, RescopeKey: validKey},
	}
	// Crafted signatures over the right challenge: s equal to the curve
	// order (no inverse), r out of range, and DER that does not parse.
	for name, sig := range map[string][]byte{
		"s = n (not invertible)": derSig([]byte{1}, p256Order),
		"r = n":                  derSig(p256Order, []byte{1}),
		"s = 0":                  derSig([]byte{1}, []byte{0}),
		"broken DER":             {0x30, 0x00},
	} {
		crafted := validProof
		crafted.Signature = sig
		cases["a crafted signature, "+name] = action.RescopeRequest{Select: e.every(), Proof: &crafted, RescopeKey: validKey}
	}
	var text string
	for name, req := range cases {
		req.RevertID = id
		_, err := guard.RescopeRevert(ctx, e.bot.Conn, req)
		got := requireWidenRefused(t, err)
		if text == "" {
			text = got
		}
		require.Equal(t, text, got, name)
	}
	require.Equal(t, before, storedRevert(t, e.d, id), "nothing changed")
	require.Empty(t, ledgerDetails(t, e.d, "REVERT_RESCOPED"))

	// The person's valid proof still works once its key comes with it.
	_, err = guard.RescopeRevert(ctx, e.bot.Conn,
		action.RescopeRequest{RevertID: id, Select: e.every(), Proof: &validProof, RescopeKey: validKey})
	require.NoError(t, err)
}

// An agent cannot use a select to learn about other agents' work: another
// agent's run or table, and an unknown one, read byte for byte alike; so
// do another role's revert and an unknown revert.
func TestRescopeProbeUniform(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	refused := func(revertID uuid.UUID, sel revert.Select, ids ...uuid.UUID) string {
		_, err := guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: revertID, Select: sel})
		return scopeErrorText(t, err, ids...)
	}
	withRun := func(run uuid.UUID) revert.Select {
		s := e.own()
		s.Runs = []uuid.UUID{run}
		return s
	}
	withTable := func(table string) revert.Select {
		s := e.own()
		s.Resources = []string{table}
		return s
	}
	unknownRun := uuid.Must(uuid.NewV7())
	runText := refused(e.prep.RevertID, withRun(unknownRun), unknownRun)
	require.Equal(t, runText, refused(e.prep.RevertID, withRun(e.help.RunID), e.help.RunID))
	require.Equal(t, runText, refused(e.prep.RevertID, withRun(e.helperOutside.RunID), e.helperOutside.RunID))
	requireWidenRefused(t, func() error {
		_, err := guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: e.prep.RevertID, Select: withRun(e.help.RunID)})
		return err
	}())
	// A second task: bot wrote leads, the helper lead_owner. The helper's
	// table reads like one that does not exist or is not guarded.
	task := uuid.Must(uuid.NewV7())
	for _, w := range []struct {
		a    *guardtest.Agent
		stmt string
	}{{e.bot, `UPDATE public.leads SET status = 't' WHERE id = 40`}, {e.helper, `UPDATE public.lead_owner SET owner = 't' WHERE id = 3`}} {
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "second task"}
		require.NoError(t, guard.StartRun(ctx, w.a.Conn, in))
		require.NoError(t, guardtest.Guarded(ctx, w.a.Conn, in, w.stmt))
	}
	second, err := guard.PrepareRevert(ctx, e.bot.Conn, action.Scope{Kind: revert.ScopeTask, ID: task}, "x")
	require.NoError(t, err)
	tableText := func(table string) string {
		s := withTable(table)
		s.ScopeID = task
		return refused(second.RevertID, s)
	}
	theirTable := tableText("public.lead_owner")
	require.Equal(t, theirTable, tableText("public.nope"))
	require.Equal(t, theirTable, tableText("public.payroll"))
	require.Contains(t, theirTable, guardmodel.RevertWidenRefused)

	theirRevert, err := guard.PrepareRevert(ctx, e.helper.Conn, action.Scope{Kind: revert.ScopeRun, ID: e.help.RunID}, "x")
	require.NoError(t, err)
	unknown := uuid.Must(uuid.NewV7())
	sel := revert.Select{Scope: revert.ScopeRun, ScopeID: e.help.RunID, Agents: []string{e.bot.Name}}
	require.Equal(t, refused(unknown, sel, unknown), refused(theirRevert.RevertID, sel, theirRevert.RevertID))
	_, err = guard.ResetRevert(ctx, e.bot.Conn, theirRevert.RevertID)
	theirText := scopeErrorText(t, err, theirRevert.RevertID)
	_, err = guard.ResetRevert(ctx, e.bot.Conn, unknown)
	require.Equal(t, scopeErrorText(t, err, unknown), theirText)
	requireRevertInvalid(t, err, "no such revert")
}

// A proof is good for one widen: replayed with its key after it was used,
// or after a reset, it is refused although the passkey's counter stays 0.
func TestRescopeNonceReplay(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	as, key := e.proof(t, e.prep.RevertID, e.every(), "secret")
	req := action.RescopeRequest{RevertID: e.prep.RevertID, Select: e.every(), Proof: &as, RescopeKey: key}
	_, err := guard.RescopeRevert(ctx, e.bot.Conn, req)
	require.NoError(t, err)
	_, err = guard.RescopeRevert(ctx, e.bot.Conn, req)
	requireWidenRefused(t, err)

	// A fresh proof over the current nonce, held back while the agent
	// resets the revert: the reset sets a new nonce, so it is dead.
	held, heldKey := e.proof(t, e.prep.RevertID, e.every(), "secret 2")
	_, err = guard.ResetRevert(ctx, e.bot.Conn, e.prep.RevertID)
	require.NoError(t, err)
	_, err = guard.RescopeRevert(ctx, e.bot.Conn,
		action.RescopeRequest{RevertID: e.prep.RevertID, Select: e.every(), Proof: &held, RescopeKey: heldKey})
	requireWidenRefused(t, err)
	require.Len(t, ledgerDetails(t, e.d, "REVERT_RESCOPED"), 1)
}

// Own work needs nothing while nobody widened the revert. After a widen,
// every call needs the scope token (or a new proof), own work included,
// and a token only narrows inside the ceiling. The ledger records the path.
func TestRescopeTokenAfterCeiling(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	leadsOnly := e.own()
	leadsOnly.Resources = []string{"public.leads"}

	out, err := guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: id, Select: leadsOnly})
	require.NoError(t, err)
	require.Nil(t, out.Catalog, "own work gets no catalog")
	require.Empty(t, out.ScopeToken)
	b, err := revert.ParseBinding(out.BindingText)
	require.NoError(t, err)
	require.Equal(t, 2, b.Rows)
	require.False(t, b.Widened)

	ceiling := e.every()
	ceiling.Resources = []string{"public.leads"}
	widened := e.widen(t, ceiling)
	token := []byte(widened.ScopeToken)

	// Own work, without the token: refused.
	_, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: id, Select: leadsOnly})
	requireWidenRefused(t, err)
	// Inside the ceiling with the token: the helper's leads only.
	helperLeads := revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Name}, Resources: []string{"public.leads"}}
	out, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: id, Select: helperLeads, Token: token})
	require.NoError(t, err)
	require.NotNil(t, out.Catalog)
	require.Empty(t, out.ScopeToken, "only a proof returns a token")
	b, err = revert.ParseBinding(out.BindingText)
	require.NoError(t, err)
	require.Equal(t, 1, b.Rows)
	require.Equal(t, map[string]int{e.helper.Name: 1}, b.AgentRows)
	// Own work with the token: back inside the ceiling.
	_, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: id, Select: leadsOnly, Token: token})
	require.NoError(t, err)

	for name, req := range map[string]action.RescopeRequest{
		"a wrong token":                 {Select: helperLeads, Token: make([]byte, 16)},
		"outside the ceiling (a table)": {Select: e.own(), Token: token},
		"wider than the ceiling":        {Select: e.every(), Token: token},
		"another scope":                 {Select: revert.Select{Scope: revert.ScopeRun, ScopeID: e.botA.RunID, Agents: []string{e.bot.Name}}, Token: token},
	} {
		req.RevertID = id
		_, err := guard.RescopeRevert(ctx, e.bot.Conn, req)
		require.Error(t, err, name)
		requireWidenRefused(t, err)
	}

	details := ledgerDetails(t, e.d, "REVERT_RESCOPED")
	via := make([]string, 0, len(details))
	for _, d := range details {
		via = append(via, d["via"].(string))
	}
	require.Equal(t, []string{guardmodel.RescopeViaOwnWork, guardmodel.RescopeViaProof, guardmodel.RescopeViaScopeToken, guardmodel.RescopeViaScopeToken}, via)
}

// After a valid proof, the select must still lie in the scope: an unknown
// run or table is FILTER, an agent with no change or an unrelated scope
// DESCRIPTOR. Only the person reaches these answers.
func TestRescopeMembership(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	try := func(sel revert.Select) error {
		as, key := e.proof(t, e.prep.RevertID, sel, "secret")
		_, err := guard.RescopeRevert(context.Background(), e.bot.Conn,
			action.RescopeRequest{RevertID: e.prep.RevertID, Select: sel, Proof: &as, RescopeKey: key})
		return err
	}
	run := e.every()
	run.Runs = []uuid.UUID{e.helperOutside.RunID}
	requireScopeRefused(t, try(run), guardmodel.ScopeFilter)
	table := e.every()
	table.Resources = []string{"public.payroll"}
	requireScopeRefused(t, try(table), guardmodel.ScopeFilter)
	agent := e.every()
	agent.Agents = []string{e.helper.Name, "agent:nobody"}
	requireScopeRefused(t, try(agent), guardmodel.ScopeDescriptor)
	requireScopeRefused(t, try(revert.Select{Scope: revert.ScopeRun, ScopeID: e.helperOutside.RunID}), guardmodel.ScopeDescriptor)
	// The agent's own unrelated run: own work, but not this revert's scope.
	outside := newRun(t, e.bot, "elsewhere")
	require.NoError(t, guardtest.Guarded(ctx, e.bot.Conn, outside, `UPDATE public.leads SET status = 'o' WHERE id = 35`))
	_, err := guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{
		RevertID: e.prep.RevertID,
		Select:   revert.Select{Scope: revert.ScopeRun, ScopeID: outside.RunID, Agents: []string{e.bot.Name}},
	})
	requireScopeRefused(t, err, guardmodel.ScopeDescriptor)
	require.Empty(t, ledgerDetails(t, e.d, "REVERT_RESCOPED"))
}

// reset_revert puts a widened revert back to the agent's proposal, clears
// the ceiling and token, sets a new nonce and records the dropped select;
// a signed, expired or applied revert is refused, and so is a rescope.
func TestResetRevert(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	id := e.prep.RevertID
	widened := e.widen(t, e.every())
	widenedRow := storedRevert(t, e.d, id)

	out, err := guard.ResetRevert(ctx, e.bot.Conn, id)
	require.NoError(t, err)
	b, err := revert.Request{RevertID: id, Binding: out.BindingText, Lines: out.Lines}.Check()
	require.NoError(t, err)
	require.False(t, b.Widened)
	require.Nil(t, b.Proposed, "back to the proposal")
	require.Equal(t, e.own(), b.Select)
	require.Equal(t, 3, b.Rows)
	row := storedRevert(t, e.d, id)
	require.Empty(t, row.Ceiling)
	require.False(t, row.HasToken)
	require.NotEqual(t, widenedRow.Nonce, row.Nonce)
	require.Equal(t, []byte(out.RescopeNonce), row.Nonce)
	resets := ledgerDetails(t, e.d, "REVERT_RESET")
	require.Len(t, resets, 1)
	dropped, err := json.Marshal(resets[0]["droppedSelect"])
	require.NoError(t, err)
	// The ledger keeps the select in its stored form (logins and tables),
	// the form agent_ledger's redaction compares with the row's login.
	require.JSONEq(t, widenedRow.Selection, string(dropped))
	require.Contains(t, resets[0]["droppedSelect"], "tables", "the stored form names tables")
	require.NotContains(t, resets[0]["droppedSelect"], "resources")

	// The old token no longer reaches anything wider than own work.
	_, err = guard.RescopeRevert(ctx, e.bot.Conn,
		action.RescopeRequest{RevertID: id, Select: e.every(), Token: widened.ScopeToken})
	requireWidenRefused(t, err)

	// Signed, expired, applied: refused by rescope and reset alike.
	for name, sql := range map[string]string{
		"signed":  `UPDATE basalt_meta.reverts SET signed_at = now(), apply_by = now() + interval '1 day' WHERE revert_id = $1`,
		"expired": `UPDATE basalt_meta.reverts SET expires_at = now() - interval '1 second' WHERE revert_id = $1`,
		"applied": `UPDATE basalt_meta.reverts SET applied_at = now() WHERE revert_id = $1`,
	} {
		prep, err := guard.PrepareRevert(ctx, e.bot.Conn, action.Scope{Kind: revert.ScopeRun, ID: e.botA.RunID}, name)
		require.NoError(t, err)
		e.d.Exec(t, sql, prep.RevertID)
		_, err = guard.ResetRevert(ctx, e.bot.Conn, prep.RevertID)
		code, _ := guard.CodeOf(err)
		require.Contains(t, []guardmodel.Code{guardmodel.CodeRevertInvalid, guardmodel.CodeRevertExpired}, code, name)
		_, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{
			RevertID: prep.RevertID,
			Select:   revert.Select{Scope: revert.ScopeRun, ScopeID: e.botA.RunID, Agents: []string{e.bot.Name}},
		})
		code, _ = guard.CodeOf(err)
		require.Contains(t, []guardmodel.Code{guardmodel.CodeRevertInvalid, guardmodel.CodeRevertExpired}, code, name)
	}
}

// A signature over the binding before a rescope fails after it: the
// rescope replaced the binding, so the challenge changed.
func TestRescopeInvalidatesEarlierSignature(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	sig, err := e.p.Sign(approval.Challenge(e.prep.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	leadsOnly := e.own()
	leadsOnly.Resources = []string{"public.leads"}
	_, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{RevertID: e.prep.RevertID, Select: leadsOnly})
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, e.bot.Conn, e.prep.RevertID, sig)
	requireCode(t, err, guardmodel.CodeRevertInvalid)
	require.Equal(t, "a", leadStatus(t, e.d, 30))
}

// Undoing a widened revert is not the agent's own change (RS-5): its
// preview would show the rows and old values the person added. It reads
// like an unknown change. Undoing a revert of the agent's own work still
// works (AE-14).
func TestUndoWidenedRevertRefused(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	out := e.widen(t, e.every())
	sig, err := e.p.Sign(approval.Challenge(out.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	applied, err := guard.ApplyRevert(ctx, e.bot.Conn, e.prep.RevertID, sig)
	require.NoError(t, err)

	undo := action.Scope{Kind: revert.ScopeChange, ID: applied.ChangeID}
	unknown := uuid.Must(uuid.NewV7())
	none := action.Scope{Kind: revert.ScopeChange, ID: unknown}
	_, err = guard.PreviewRevert(ctx, e.bot.Conn, undo)
	requireScopeRefused(t, err, guardmodel.ScopeNotOwnChange)
	_, errNone := guard.PreviewRevert(ctx, e.bot.Conn, none)
	require.Equal(t, scopeErrorText(t, errNone, unknown), scopeErrorText(t, err, applied.ChangeID))
	_, err = guard.PrepareRevert(ctx, e.bot.Conn, undo, "redo")
	requireScopeRefused(t, err, guardmodel.ScopeNotOwnChange)
	// Nor through rescope_revert of a pending revert, without a proof.
	pending, err := guard.PrepareRevert(ctx, e.bot.Conn, action.Scope{
		Kind: revert.ScopeRun,
		ID:   newRunWith(t, e.bot, `UPDATE public.leads SET status = 'p' WHERE id = 37`),
	}, "x")
	require.NoError(t, err)
	_, err = guard.RescopeRevert(ctx, e.bot.Conn, action.RescopeRequest{
		RevertID: pending.RevertID,
		Select:   revert.Select{Scope: revert.ScopeChange, ScopeID: applied.ChangeID, Agents: []string{e.bot.Name}},
	})
	requireWidenRefused(t, err)

	// An own, not widened revert can still be undone.
	ownApplied := revertScope(t, e.bot, e.p, revert.ScopeRun, newRunWith(t, e.bot, `UPDATE public.leads SET status = 'z' WHERE id = 36`))
	lines, err := guard.PreviewRevert(ctx, e.bot.Conn, action.Scope{Kind: revert.ScopeChange, ID: ownApplied.ChangeID})
	require.NoError(t, err)
	require.Len(t, lines, 1)
}

func newRunWith(t *testing.T, a *guardtest.Agent, stmt string) uuid.UUID {
	t.Helper()
	in := newRun(t, a, "own work")
	require.NoError(t, guardtest.Guarded(context.Background(), a.Conn, in, stmt))
	return in.RunID
}

// After a widen, the requesting agent reads no line, select or ledger
// detail naming the other agents' work: agent_reverts, agent_revert_lines
// (a large plan, by line) and agent_ledger.
// widenHelperRows is how many rows the helper changes in newWidenBulk: with
// bot's ten, a widen makes a large plan.
const widenHelperRows = 1200

// newWidenBulk: public.items, bot changed ids 1 to 10 and the helper ids
// 11 to 1210 in one task, and bot proposed its own part (ten lines).
func newWidenBulk(t *testing.T) widenEnv {
	t.Helper()
	d := guardtest.New(t)
	ctx := context.Background()
	d.Exec(t, fmt.Sprintf(`CREATE TABLE public.items (id int PRIMARY KEY, v text NOT NULL);
		INSERT INTO public.items SELECT g, 'before' FROM generate_series(1, %d) g`, widenHelperRows+10))
	items := []string{"public.items"}
	bot, helper := d.NewAgent(t, "bot", items, items), d.NewAgent(t, "helper", items, items)
	task := uuid.Must(uuid.NewV7())
	start := func(a *guardtest.Agent) guard.Intent {
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "bulk"}
		require.NoError(t, guard.StartRun(ctx, a.Conn, in))
		return in
	}
	botRun, helpRun := start(bot), start(helper)
	require.NoError(t, guardtest.Guarded(ctx, bot.Conn, botRun, `UPDATE public.items SET v = 'bot' WHERE id BETWEEN 1 AND 10`))
	stmts := make([]string, 0, widenHelperRows/10)
	for i := 10; i < widenHelperRows+10; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`UPDATE public.items SET v = 'helper' WHERE id BETWEEN %d AND %d`, i+1, i+10))
	}
	require.NoError(t, guardtest.Guarded(ctx, helper.Conn, helpRun, stmts...))
	e := widenEnv{scopeTask: scopeTask{d: d, bot: bot, helper: helper, task: task}, p: person(t, d)}
	prep, err := guard.PrepareRevert(ctx, bot.Conn, e.taskScope(), "Undo the task")
	require.NoError(t, err)
	e.prep = prep
	require.False(t, prep.Batched)
	return e
}

func TestWidenedRevertRedacted(t *testing.T) {
	t.Parallel()
	e := newWidenBulk(t)
	ctx := context.Background()
	const helperRows = widenHelperRows
	bot, prep := e.bot, e.prep

	out := e.widen(t, e.every())
	b, err := revert.ParseBinding(out.BindingText)
	require.NoError(t, err)
	require.True(t, b.Batched)
	require.Equal(t, helperRows+10, b.Rows)

	var bindingNull, selectionNull, linesNull, widened bool
	require.NoError(t, bot.Conn.QueryRow(ctx, `SELECT binding_text IS NULL, selection IS NULL, lines IS NULL, widened
		FROM basalt_meta.agent_reverts WHERE revert_id = $1`, prep.RevertID).Scan(&bindingNull, &selectionNull, &linesNull, &widened))
	require.True(t, bindingNull && selectionNull && linesNull && widened)

	var total, shown int
	require.NoError(t, bot.Conn.QueryRow(ctx, `SELECT count(line_no)::int, count(line)::int
		FROM basalt_meta.agent_revert_lines WHERE revert_id = $1`, prep.RevertID).Scan(&total, &shown))
	require.Equal(t, helperRows+10, total, "every line number stays, for the batches")
	require.Equal(t, 10, shown, "only bot's own lines keep their text")
	rows, err := bot.Conn.Query(ctx, `SELECT line FROM basalt_meta.agent_revert_lines WHERE revert_id = $1 AND line IS NOT NULL`, prep.RevertID)
	require.NoError(t, err)
	own, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	for _, text := range own {
		l, err := revert.ParseLine(text)
		require.NoError(t, err)
		require.Contains(t, string(l.Now), `"bot"`, "a line of bot's own rows")
	}

	// agent_ledger: the rescope shows only the revert, widened and the path.
	var detail map[string]any
	require.NoError(t, bot.Conn.QueryRow(ctx, `SELECT detail FROM basalt_meta.agent_ledger WHERE kind = 'REVERT_RESCOPED'`).Scan(&detail))
	require.Equal(t, map[string]any{"revertId": prep.RevertID.String(), "widened": true, "via": guardmodel.RescopeViaProof}, detail)
	_, err = guard.ResetRevert(ctx, bot.Conn, prep.RevertID)
	require.NoError(t, err)
	require.NoError(t, bot.Conn.QueryRow(ctx, `SELECT detail FROM basalt_meta.agent_ledger WHERE kind = 'REVERT_RESET'`).Scan(&detail))
	require.Equal(t, map[string]any{"revertId": prep.RevertID.String(), "widened": true}, detail)
	// After the reset the revert is bot's own again: ten lines, readable.
	require.NoError(t, bot.Conn.QueryRow(ctx, `SELECT lines IS NULL, widened FROM basalt_meta.agent_reverts WHERE revert_id = $1`,
		prep.RevertID).Scan(&linesNull, &widened))
	require.False(t, linesNull || widened)
	require.Zero(t, count(t, bot.Conn, `SELECT count(line_no)::int FROM basalt_meta.agent_revert_lines WHERE revert_id = $1`, prep.RevertID),
		"ten lines are no large plan")
}

// The rescope functions are SECURITY DEFINER with search_path pinned to
// pg_catalog, pg_temp, only the two entry points executable by the agents
// group and none by PUBLIC; the (task_id, agent) index exists.
func TestRevertWidenFunctionsAndIndex(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	for _, fn := range []string{
		"basalt_meta.rescope_revert(uuid, jsonb, jsonb, bytea, bytea)", "basalt_meta.reset_revert(uuid)",
		"basalt_meta._revert_rebuild(basalt_meta.reverts, jsonb)", "basalt_meta._rescope_proven(basalt_meta.reverts, jsonb, jsonb, bytea)",
		"basalt_meta._revert_own_refusal(jsonb, name)", "basalt_meta._revert_catalog(jsonb)",
	} {
		var definer, publicExec, agentsExec bool
		var config []string
		require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT p.prosecdef, coalesce(p.proconfig, '{}'),
			EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'),
			has_function_privilege($2, p.oid, 'EXECUTE')
			FROM pg_proc p WHERE p.oid = $1::regprocedure`, fn, e.d.Names.Agents()).Scan(&definer, &config, &publicExec, &agentsExec), fn)
		require.True(t, definer, fn)
		require.Equal(t, []string{"search_path=pg_catalog, pg_temp"}, config, fn)
		require.False(t, publicExec, fn)
		public := fn == "basalt_meta.rescope_revert(uuid, jsonb, jsonb, bytea, bytea)" || fn == "basalt_meta.reset_revert(uuid)"
		require.Equal(t, public, agentsExec, "only the two entry points are the agents' %s", fn)
	}
	require.Equal(t, 1, count(t, e.d.Admin, `SELECT count(indexname)::int FROM pg_indexes
		WHERE schemaname = 'basalt_meta' AND indexname = 'changes_task_agent'`))

	e.widen(t, e.every())
	_, err := guard.ResetRevert(context.Background(), e.bot.Conn, e.prep.RevertID)
	require.NoError(t, err)
	require.Nil(t, guardVerify(t, e.d))
}

// A widened large plan, signed and applied in batches by the requesting
// agent, with lines of the helper's rows skipped at the trial and during a
// batch: no ledger row the agent reads names the helper, its keys or its
// rows' values (REVERT_SIGNED, REVERT_BATCH and REVERTED copy skipped
// lines; the revert's ROW_CHANGE rows hold restored values).
func TestWidenedBatchedLedgerRedacted(t *testing.T) {
	t.Parallel()
	e := newWidenBulk(t)
	ctx := context.Background()
	e.d.Exec(t, `UPDATE public.items SET v = 'person' WHERE id = 500`)
	out := e.widen(t, e.every())
	b, err := revert.ParseBinding(out.BindingText)
	require.NoError(t, err)
	require.True(t, b.Batched)
	require.Equal(t, 1, b.Skipped, "the helper's row 500 the person changed")

	sig, err := e.p.Sign(approval.Challenge(out.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	signed, err := guard.ApplyRevert(ctx, e.bot.Conn, e.prep.RevertID, sig)
	require.NoError(t, err)
	require.True(t, signed.Batched)
	e.d.Exec(t, `UPDATE public.items SET v = 'person' WHERE id = 900`)
	for {
		lines := pendingLines(t, e.bot.Conn, e.prep.RevertID, revert.MaxBatch)
		if len(lines) == 0 {
			break
		}
		_, err := guard.ApplyRevertBatch(ctx, e.bot.Conn, e.prep.RevertID, lines)
		require.NoError(t, err)
	}
	require.Equal(t, "APPLIED", scalarOf[string](t, e.bot.Conn, `SELECT status FROM basalt_meta.agent_reverts WHERE revert_id = $1`, e.prep.RevertID))
	require.Equal(t, 2, count(t, e.d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger
		WHERE kind IN ('REVERT_SIGNED', 'REVERT_BATCH') AND jsonb_array_length(detail -> 'skipped') > 0`),
		"the stored rows do carry the skipped helper rows")

	rows, err := e.bot.Conn.Query(ctx, `SELECT kind, row_to_json(x)::text FROM basalt_meta.agent_ledger x ORDER BY seq`)
	require.NoError(t, err)
	type ledgerRow struct{ Kind, Text string }
	all, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ledgerRow])
	require.NoError(t, err)
	kinds := map[string]bool{}
	for _, r := range all {
		kinds[r.Kind] = true
		require.NotContains(t, r.Text, e.helper.Role, r.Kind)
		require.NotContains(t, r.Text, e.helper.Name, r.Kind)
		require.NotContains(t, r.Text, `"helper"`, "a helper row's values: %s", r.Kind)
		require.NotContains(t, r.Text, `"id": 500`, r.Kind)
		require.NotContains(t, r.Text, `"id": 900`, r.Kind)
		require.NotContains(t, r.Text, `"skipped": [`, r.Kind)
	}
	for _, k := range []string{"REVERT_RESCOPED", "REVERT_SIGNED", "REVERT_BATCH", "REVERTED", "ROW_CHANGE"} {
		require.True(t, kinds[k], "the agent still sees its %s rows", k)
	}
	// The revert's own rows of bot's ten changes keep their values.
	require.Equal(t, 10, count(t, e.bot.Conn, `SELECT count(l.seq)::int FROM basalt_meta.agent_ledger l
		WHERE l.kind = 'ROW_CHANGE' AND l.change_id = $1 AND l.row_key IS NOT NULL`, signed.ChangeID))
}

// agent_ledger looks reverts and changes up by their primary keys (ids
// from details are cast to uuid, not compared as text), and a malformed
// id in a detail neither fails the view nor shows anything.
func TestAgentLedgerRevertLookups(t *testing.T) {
	t.Parallel()
	e := newWidenEnv(t)
	ctx := context.Background()
	out := e.widen(t, e.every())
	sig, err := e.p.Sign(approval.Challenge(out.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.ApplyRevert(ctx, e.bot.Conn, e.prep.RevertID, sig)
	require.NoError(t, err)
	e.d.Exec(t, `SELECT basalt_meta._append($1, NULL, 'REVERT_BATCH', NULL, NULL, NULL, NULL, NULL, NULL,
		'{"revertId": "not-a-uuid", "skipped": []}'::jsonb)`, e.bot.Role)

	require.Equal(t, `{"skipped": [], "revertId": "not-a-uuid"}`, scalarOf[string](t, e.bot.Conn,
		`SELECT detail::text FROM basalt_meta.agent_ledger WHERE detail ->> 'revertId' = 'not-a-uuid'`))
	require.Positive(t, count(t, e.bot.Conn, `SELECT count(seq)::int FROM basalt_meta.agent_ledger`))

	var plan []string
	err = pgx.BeginFunc(ctx, e.bot.Conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `EXPLAIN SELECT * FROM basalt_meta.agent_ledger`)
		if err != nil {
			return err
		}
		plan, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	require.NoError(t, err)
	text := strings.Join(plan, "\n")
	require.NotContains(t, text, "Seq Scan on reverts", text)
	require.NotContains(t, text, "Seq Scan on changes", text)
	require.Contains(t, text, "reverts_pkey", text)
	require.Nil(t, guardVerify(t, e.d))
}
