package agent_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// pgCalls records every statement and its parameters the engine sends to
// Postgres on the agent's credential.
type pgCalls struct {
	mu    sync.Mutex
	calls []pgx.TraceQueryStartData
}

func (c *pgCalls) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, d)
	return ctx
}

func (c *pgCalls) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// requireNoSecret checks that no statement or parameter sent to Postgres
// holds any of the link secrets, as text or as their raw bytes, and that a
// rescope was among them.
func (c *pgCalls) requireNoSecret(t *testing.T, secrets ...string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	needles := make([][]byte, 0, 2*len(secrets))
	for _, s := range secrets {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		require.NoError(t, err)
		needles = append(needles, []byte(s), raw)
	}
	rescopes := 0
	for _, call := range c.calls {
		if strings.Contains(call.SQL, "rescope_revert") {
			rescopes++
		}
		hay := [][]byte{[]byte(call.SQL)}
		for _, a := range call.Args {
			switch v := a.(type) {
			case string:
				hay = append(hay, []byte(v))
			case []byte:
				hay = append(hay, v)
			default:
				hay = append(hay, fmt.Append(nil, v))
			}
		}
		for _, h := range hay {
			for _, n := range needles {
				require.False(t, bytes.Contains(h, n), "a link secret reached Postgres in %q", call.SQL)
			}
		}
	}
	require.Positive(t, rescopes, "the engine called rescope_revert")
}

// rescopeEnv is a task two agents wrote in, bot's engine serving the local
// pages, and the person's passkey. The links persist in a file, so the
// engine can restart with the same links and nothing in memory.
type rescopeEnv struct {
	d           *guardtest.DB
	bot, helper *guardtest.Agent
	person      *passkeytest.Authenticator
	task        uuid.UUID
	linksPath   string
	calls       *pgCalls
	sent        *notices

	svc *agent.Service
	h   harness
	p   localPages
}

func newRescopeEnv(t *testing.T) *rescopeEnv {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	all := []string{"public.leads", "public.lead_owner"}
	e := &rescopeEnv{
		d: d, bot: d.NewAgent(t, "bot", all, all), helper: d.NewAgent(t, "helper", all, all),
		task: uuid.Must(uuid.NewV7()), linksPath: filepath.Join(t.TempDir(), "bot.links.json"), calls: &pgCalls{}, sent: &notices{},
	}
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	e.person = person
	ctx := context.Background()
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, person.Credential(), "app"))
	for _, w := range []struct {
		a   *guardtest.Agent
		sql string
	}{
		{e.bot, `UPDATE public.leads SET status = 'bot' WHERE id = 30`},
		{e.helper, `UPDATE public.leads SET status = 'helper' WHERE id = 32`},
	} {
		in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: e.task, Text: "work in the task"}
		require.NoError(t, guard.StartRun(ctx, w.a.Conn, in))
		require.NoError(t, guardtest.Guarded(ctx, w.a.Conn, in, w.sql))
	}
	e.start(t, nil)
	return e
}

// start (re)starts bot's engine: a new pool, the links read back from
// their file, and nothing else kept. wrap, when set, wraps the revert
// store.
func (e *rescopeEnv) start(t *testing.T, wrap func(agent.RevertStore) agent.RevertStore) {
	t.Helper()
	secrets, err := links.OpenSecrets(e.linksPath, time.Now, rand.Reader)
	require.NoError(t, err)
	e.svc = pgService(t, e.bot.URL,
		withPoolConfig(func(cfg *pgxpool.Config) { cfg.ConnConfig.Tracer = e.calls }),
		withDeps(func(d *agent.Deps, _ *pgxpool.Pool) {
			if wrap != nil {
				d.Reverts = wrap(d.Reverts)
			}
			d.Notifier, d.PagesOrigin, d.Links, d.Poll = e.sent, pageOrigin, secrets, testPoll
		})).Svc
	e.h = harness{server: mcp.NewServer(mcp.Info{Name: "basalt"}, agent.Tools(e.svc)...)}
	e.p = newLocalPages(t, agentEnv{svc: e.svc})
}

// request has bot request a revert of its own work in the task, and
// returns the revert id and its link's secret.
func (e *rescopeEnv) request(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	body, isError := e.h.call(t, "request_revert", map[string]any{"taskId": e.task.String(), "intent": "Undo the task"})
	require.False(t, isError, "%v", body)
	return uuid.MustParse(str(t, body["revertId"])), links.SecretOf(str(t, body["revertUrl"]))
}

func (e *rescopeEnv) own() revert.Select {
	return revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.bot.Role}}
}

// every is the whole task, every agent: wider than bot's own work.
func (e *rescopeEnv) every() revert.Select {
	return revert.Select{Scope: revert.ScopeTask, ScopeID: e.task}
}

// nonce is the nonce of the next widen as the page reads it from the
// engine with the link's secret, which reads it as the agent role
// (basalt_meta.revert_nonce): the request's, or for a widened revert the
// engine no longer holds, the 409's.
func (e *rescopeEnv) nonce(t *testing.T, id uuid.UUID, secret string) []byte {
	t.Helper()
	var out struct {
		RescopeNonce passkey.Bytes `json:"rescopeNonce"`
		Code         string        `json:"code"`
	}
	status := e.p.get(revertPath(id), secret, &out)
	require.Contains(t, []int{http.StatusOK, http.StatusConflict}, status, out.Code)
	require.Len(t, out.RescopeNonce, 16)
	return out.RescopeNonce
}

// adminNonce is the stored nonce, read as the admin, to check what the
// engine served.
func (e *rescopeEnv) adminNonce(t *testing.T, id uuid.UUID) []byte {
	t.Helper()
	var n []byte
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT rescope_nonce FROM basalt_meta.reverts WHERE revert_id = $1`, id).Scan(&n))
	return n
}

// widenBody is what the page posts for a widen to sel: the person's proof
// over the widen challenge with nonce, bound to the key of newSecret.
func (e *rescopeEnv) widenBody(t *testing.T, signer *passkeytest.Authenticator, id uuid.UUID, nonce []byte, sel revert.Select, newSecret string) []byte {
	t.Helper()
	raw, err := links.DecodeSecret(newSecret)
	require.NoError(t, err)
	key, err := revert.RescopeKey(raw)
	require.NoError(t, err)
	selJSON, err := json.Marshal(sel)
	require.NoError(t, err)
	var norm string
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(selJSON)).Scan(&norm))
	as, err := signer.Sign(revert.RescopeChallenge(id, nonce, key, norm), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return scopeBody(t, agent.ScopeRequest{Select: sel, NewSecret: newSecret, Proof: &agent.ScopeProof{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
	}})
}

func scopeBody(t *testing.T, in agent.ScopeRequest) []byte {
	t.Helper()
	b, err := json.Marshal(in)
	require.NoError(t, err)
	return b
}

func newLinkSecret(t *testing.T) string {
	t.Helper()
	raw := make([]byte, links.SecretBytes)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func scopePath(id uuid.UUID) string  { return "/api/v1/reverts/" + id.String() + "/scope" }
func revertPath(id uuid.UUID) string { return "/api/v1/reverts/" + id.String() }

// scopeAnswer is the scope route's 200 answer as the page reads it.
type scopeAnswer struct {
	Request revert.Request       `json:"request"`
	Catalog *guard.RevertCatalog `json:"catalog"`
}

// A widen with the person's proof rotates the revert's link to the page's
// new secret: the agent's link stops working, the page reads the widened
// lines and the catalog with the new one, and narrows inside the person's
// scope without another prompt. The secrets never reach Postgres.
func TestScopeRouteWidenRotatesTheLink(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, agentSecret := e.request(t)
	var perr pageError

	// Back to the proposal: own work, the link secret is enough. The answer
	// carries the nonce the widen proof signs; the page reads it there.
	var own scopeAnswer
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, agentSecret, scopeBody(t, agent.ScopeRequest{Select: e.own()}), &own))
	require.Nil(t, own.Catalog, "no catalog without a proof or token")
	require.Len(t, own.Request.RescopeNonce, 16)
	require.Equal(t, e.adminNonce(t, id), []byte(own.Request.RescopeNonce))
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), agentSecret, &read))
	require.Equal(t, own.Request.RescopeNonce, read.RescopeNonce)

	newSecret := newLinkSecret(t)
	var wide scopeAnswer
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, agentSecret,
		e.widenBody(t, e.person, id, own.Request.RescopeNonce, e.every(), newSecret), &wide))
	b, err := wide.Request.Check()
	require.NoError(t, err)
	require.True(t, b.Widened)
	require.Equal(t, map[string]int{e.bot.Role: 1, e.helper.Role: 1}, b.AgentRows)
	require.NotNil(t, wide.Catalog)
	require.Len(t, wide.Catalog.Agents, 2)
	agents := map[string]int{}
	for _, role := range wide.Catalog.ChangeAgents {
		agents[role]++
	}
	require.Equal(t, map[string]int{e.bot.Role: 1, e.helper.Role: 1}, agents, "the proven answer maps each change to its agent")
	require.NotEqual(t, own.Request.RescopeNonce, wide.Request.RescopeNonce, "the proof consumed the nonce")

	// The agent's link is dead: read and relay alike read as an unknown id.
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), agentSecret, &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)
	require.Equal(t, "LINK", perr.Reason)
	require.Equal(t, http.StatusNotFound, e.p.post(scopePath(id), pageOrigin, agentSecret, scopeBody(t, agent.ScopeRequest{Select: e.own()}), &perr))

	// The rotated link reads the widened request from the engine's memory.
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), newSecret, &read))
	require.Equal(t, wide.Request.Binding, read.Binding)
	require.Equal(t, wide.Request.Lines, read.Lines)

	// Narrow inside the person's scope: the engine adds the token.
	helperOnly := revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Role}}
	var narrow scopeAnswer
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, newSecret, scopeBody(t, agent.ScopeRequest{Select: helperOnly}), &narrow))
	nb, err := narrow.Request.Check()
	require.NoError(t, err)
	require.Equal(t, helperOnly.Agents, nb.Select.Agents)
	require.NotNil(t, narrow.Catalog, "a narrow under the token gets the catalog")

	// No link for the agent to a widened revert: the CLI's issue route
	// refuses it, whatever proof it shows.
	for _, proof := range []string{links.IssueProof(""), links.IssueProof(narrow.Request.Binding)} {
		require.Equal(t, http.StatusNotFound, e.p.post("/api/v1/reverts/"+id.String()+"/links", "", "",
			[]byte(`{"proof":"`+proof+`"}`), &perr))
	}

	e.calls.requireNoSecret(t, agentSecret, newSecret)
}

// Every refused widen gets one answer, 409 REVERT_INVALID with the same
// body, whatever the cause; nothing changes and the link stays. A body bad
// on its shape alone is 400.
func TestScopeRouteRefusesEveryBadWidenAlike(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	nonce := e.nonce(t, id, secret)
	require.Equal(t, e.adminNonce(t, id), nonce, "GET serves the stored nonce")
	thief, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	signedFor := newLinkSecret(t)
	swapped := e.widenBody(t, e.person, id, nonce, e.every(), signedFor)
	var in agent.ScopeRequest
	require.NoError(t, json.Unmarshal(swapped, &in))
	in.NewSecret = newLinkSecret(t)
	otherSelect := e.widenBody(t, e.person, id, nonce, revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Role}}, signedFor)
	var other agent.ScopeRequest
	require.NoError(t, json.Unmarshal(otherSelect, &other))
	other.Select = e.every()

	cases := map[string][]byte{
		"no proof":                     scopeBody(t, agent.ScopeRequest{Select: e.every()}),
		"another passkey":              e.widenBody(t, thief, id, nonce, e.every(), newLinkSecret(t)),
		"a proof for another secret":   scopeBody(t, in),
		"a proof for another select":   scopeBody(t, other),
		"a stale nonce":                e.widenBody(t, e.person, id, make([]byte, 16), e.every(), newLinkSecret(t)),
		"another agent's run as own":   scopeBody(t, agent.ScopeRequest{Select: revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.bot.Role}, Runs: []uuid.UUID{uuid.Must(uuid.NewV7())}}}),
		"the helper only, no proof":    scopeBody(t, agent.ScopeRequest{Select: revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Role}}}),
		"another task, no proof":       scopeBody(t, agent.ScopeRequest{Select: revert.Select{Scope: revert.ScopeTask, ScopeID: uuid.Must(uuid.NewV7())}}),
		"a table bot never wrote, own": scopeBody(t, agent.ScopeRequest{Select: revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.bot.Role}, Tables: []string{"public.lead_owner"}}}),
	}
	var first *pageError
	for name, body := range cases {
		var perr pageError
		require.Equal(t, http.StatusConflict, e.p.post(scopePath(id), pageOrigin, secret, body, &perr), name)
		require.Equal(t, "REVERT_INVALID", perr.Code, name)
		require.NotEmpty(t, perr.PersonMessage, name)
		if first == nil {
			first = &perr
			continue
		}
		require.Equal(t, *first, perr, "%s reads like every other refusal", name)
	}

	shapes := map[string]string{
		"the reserved store key":   `{"select":{"scope":"TASK","scopeId":"` + e.task.String() + `","agents":null,"runs":null,"tables":null,"store":"x"}}`,
		"a proof without a secret": `{"select":{"scope":"TASK","scopeId":"` + e.task.String() + `","agents":null,"runs":null,"tables":null},"proof":{"credentialId":"AA","authenticatorData":"AA","clientDataJson":"AA","signature":"AA"}}`,
		"a secret without a proof": `{"select":{"scope":"TASK","scopeId":"` + e.task.String() + `","agents":null,"runs":null,"tables":null},"newSecret":"` + newLinkSecret(t) + `"}`,
		"not json":                 `select`,
		"twenty-one tables, with a proof": string(scopeBody(t, agent.ScopeRequest{
			Select:    revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Tables: manyTables(revert.MaxFilter + 1)},
			NewSecret: newLinkSecret(t), Proof: &agent.ScopeProof{CredentialID: []byte{1}, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{1}, Signature: []byte{1}},
		})),
	}
	for name, body := range shapes {
		var perr pageError
		require.Equal(t, http.StatusBadRequest, e.p.post(scopePath(id), pageOrigin, secret, []byte(body), &perr), name)
		require.Equal(t, "INVALID_ARGUMENT", perr.Code, name)
	}

	require.Equal(t, nonce, e.nonce(t, id, secret), "no refusal consumed the nonce")

	// A widen that names the link's current secret as the new one would
	// leave the agent's link working: refused on its shape.
	var perr pageError
	require.Equal(t, http.StatusBadRequest, e.p.post(scopePath(id), pageOrigin, secret,
		e.widenBody(t, e.person, id, nonce, e.every(), secret), &perr))
	require.Equal(t, "INVALID_ARGUMENT", perr.Code)
	require.Equal(t, nonce, e.nonce(t, id, secret))
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), secret, &read), "the link still works")
	b, err := read.Check()
	require.NoError(t, err)
	require.False(t, b.Widened)
}

func manyTables(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("public.t%02d", i)
	}
	return out
}

// The agent's reissueLink on a widened revert resets it to its proposal:
// the person's link answers LINK_RESET so the page can say why, and the
// agent's new link opens the proposal.
func TestResetGivesTheRotatedLinkLinkReset(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	personSecret := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, secret,
		e.widenBody(t, e.person, id, e.nonce(t, id, secret), e.every(), personSecret), nil))

	body, isError := e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "reissueLink": true})
	require.False(t, isError, "%v", body)
	agentSecret := links.SecretOf(str(t, body["revertUrl"]))
	require.NotEmpty(t, agentSecret)

	var perr pageError
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), personSecret, &perr))
	require.Equal(t, "NOT_FOUND", perr.Code)
	require.Equal(t, "LINK_RESET", perr.Reason)
	require.Equal(t, "The agent reset this revert to its own work. Ask it for the new link, and widen again if you "+
		"still want to include other agents.", perr.PersonMessage)
	require.Len(t, perr.NextSteps, 1)
	require.Equal(t, mcp.ActorPerson, perr.NextSteps[0].Actor)
	require.Equal(t, http.StatusNotFound, e.p.post(scopePath(id), pageOrigin, personSecret,
		scopeBody(t, agent.ScopeRequest{Select: e.own()}), &perr))
	require.Equal(t, "LINK_RESET", perr.Reason)

	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), agentSecret, &read))
	b, err := read.Check()
	require.NoError(t, err)
	require.False(t, b.Widened, "back to the agent's proposal")
	require.Equal(t, e.own().Agents, b.Select.Agents)

	var resets int
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT count(seq) FROM basalt_meta.ledger WHERE kind = 'REVERT_RESET'`).Scan(&resets))
	require.Equal(t, 1, resets)

	// Another engine start still tells the person why: the reset hash is
	// kept with the links.
	e.start(t, nil)
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), personSecret, &perr))
	require.Equal(t, "LINK_RESET", perr.Reason)
}

// The scope token and the widened lines live in the engine's memory only:
// after a restart the rotated link still opens, but the page must widen
// again; a narrow without a new proof is refused.
func TestScopeTokenIsLostOnRestart(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	personSecret := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, secret,
		e.widenBody(t, e.person, id, e.nonce(t, id, secret), e.every(), personSecret), nil))

	e.start(t, nil)
	var perr pageError
	require.Equal(t, http.StatusConflict, e.p.get(revertPath(id), personSecret, &perr), "the lines were in memory only")
	require.Equal(t, "REVERT_INVALID", perr.Code)
	require.Contains(t, perr.PersonMessage, "Include other agents' changes again")
	helperOnly := scopeBody(t, agent.ScopeRequest{Select: revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Role}}})
	require.Equal(t, http.StatusConflict, e.p.post(scopePath(id), pageOrigin, personSecret, helperOnly, &perr), "no token, no narrow")
	require.Equal(t, http.StatusConflict, e.p.post(scopePath(id), pageOrigin, personSecret, scopeBody(t, agent.ScopeRequest{Select: e.own()}), &perr),
		"after a widen even the agent's own work needs the token")

	// The 409 carries the nonce, read as the agent role: the page widens
	// again with it.
	var lost struct {
		Code         string        `json:"code"`
		RescopeNonce passkey.Bytes `json:"rescopeNonce"`
	}
	require.Equal(t, http.StatusConflict, e.p.get(revertPath(id), personSecret, &lost))
	require.Len(t, lost.RescopeNonce, 16)
	again := newLinkSecret(t)
	var wide scopeAnswer
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, personSecret,
		e.widenBody(t, e.person, id, lost.RescopeNonce, e.every(), again), &wide))
	require.NotNil(t, wide.Catalog)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, again, helperOnly, nil), "the new widen's token narrows")
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), personSecret, &perr), "the earlier rotated link is dead")
	e.calls.requireNoSecret(t, secret, personSecret, again)
}

// Postgres wins over the engine's memory: when the agent resets a widened
// revert straight in Postgres, the person's page gets LINK_RESET, not the
// lines the engine still held, and the agent's view is served again.
func TestDirectResetInPostgresBeatsTheEnginesMemory(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	personSecret := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, secret,
		e.widenBody(t, e.person, id, e.nonce(t, id, secret), e.every(), personSecret), nil))
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), personSecret, &read))

	_, err := e.bot.Conn.Exec(context.Background(), `SELECT basalt_meta.reset_revert($1)`, id)
	require.NoError(t, err)

	var perr pageError
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), personSecret, &perr))
	require.Equal(t, "LINK_RESET", perr.Reason)
	require.Equal(t, http.StatusNotFound, e.p.post(scopePath(id), pageOrigin, personSecret,
		scopeBody(t, agent.ScopeRequest{Select: e.own()}), &perr))
	require.Equal(t, "LINK_RESET", perr.Reason, "the held token is gone with it")

	body, isError := e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "reissueLink": true})
	require.False(t, isError, "%v", body)
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), links.SecretOf(str(t, body["revertUrl"])), &read))
	b, err := read.Check()
	require.NoError(t, err)
	require.False(t, b.Widened)
}

// The agent resets a widened revert in Postgres directly and asks for a
// new link before the person reloads: the person's link still answers
// LINK_RESET, not as an unknown link, and the agent's new link works.
func TestReissueAfterADirectResetTellsThePerson(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	personSecret := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, secret,
		e.widenBody(t, e.person, id, e.nonce(t, id, secret), e.every(), personSecret), nil))

	_, err := e.bot.Conn.Exec(context.Background(), `SELECT basalt_meta.reset_revert($1)`, id)
	require.NoError(t, err)
	body, isError := e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "reissueLink": true})
	require.False(t, isError, "%v", body)
	agentSecret := links.SecretOf(str(t, body["revertUrl"]))

	var perr pageError
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), personSecret, &perr))
	require.Equal(t, "LINK_RESET", perr.Reason)
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), agentSecret, &read))
	b, err := read.Check()
	require.NoError(t, err)
	require.False(t, b.Widened)

	// Without a held token a reissue is a plain one: the earlier link reads
	// as replaced.
	body, isError = e.h.call(t, "request_revert", map[string]any{"revertId": id.String(), "reissueLink": true})
	require.False(t, isError, "%v", body)
	require.Equal(t, http.StatusNotFound, e.p.get(revertPath(id), agentSecret, &perr))
	require.Equal(t, "LINK", perr.Reason)
}

// Rescopes of one revert run one at a time: after many concurrent narrows
// under the token, the request the engine serves is the one Postgres
// stored last.
func TestConcurrentRescopesKeepTheLatest(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	personSecret := newLinkSecret(t)
	require.Equal(t, http.StatusOK, e.p.post(scopePath(id), pageOrigin, secret,
		e.widenBody(t, e.person, id, e.nonce(t, id, secret), e.every(), personSecret), nil))
	selects := [][]byte{
		scopeBody(t, agent.ScopeRequest{Select: revert.Select{Scope: revert.ScopeTask, ScopeID: e.task, Agents: []string{e.helper.Role}}}),
		scopeBody(t, agent.ScopeRequest{Select: e.every()}),
	}
	const posts = 8
	var wg sync.WaitGroup
	statuses := make([]int, posts)
	for i := range posts {
		wg.Go(func() { statuses[i] = e.p.post(scopePath(id), pageOrigin, personSecret, selects[i%2], nil) })
	}
	wg.Wait()
	for _, st := range statuses {
		require.Equal(t, http.StatusOK, st)
	}
	var read revert.Request
	require.Equal(t, http.StatusOK, e.p.get(revertPath(id), personSecret, &read))
	var stored string
	require.NoError(t, e.d.Admin.QueryRow(context.Background(), `SELECT binding_text FROM basalt_meta.reverts WHERE revert_id = $1`, id).Scan(&stored))
	require.Equal(t, stored, read.Binding, "the engine serves what Postgres stored last")
}

// slowReverts answers every rescope as Postgres does once the statement
// timeout cancels it.
type slowReverts struct{ agent.RevertStore }

func (slowReverts) RescopeRevert(context.Context, action.RescopeRequest, time.Duration) (action.RescopedRevert, error) {
	return action.RescopedRevert{}, &pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"}
}

// A rescope past 100 seconds is 504 QUERY_TIMEOUT TIME_LIMIT, with what the
// page tells the person.
func TestScopeRouteTimeLimit(t *testing.T) {
	t.Parallel()
	e := newRescopeEnv(t)
	id, secret := e.request(t)
	e.start(t, func(s agent.RevertStore) agent.RevertStore { return slowReverts{s} })
	var perr pageError
	require.Equal(t, http.StatusGatewayTimeout, e.p.post(scopePath(id), pageOrigin, secret, scopeBody(t, agent.ScopeRequest{Select: e.own()}), &perr))
	require.Equal(t, "QUERY_TIMEOUT", perr.Code)
	require.Equal(t, "TIME_LIMIT", perr.Reason)
	require.Equal(t, "Changing the scope took longer than 100 seconds and was stopped. Nothing changed. "+
		"Choose fewer agents, runs or tables, or try again.", perr.PersonMessage)
	require.Equal(t, 100*time.Second, agent.RescopeTimeout)
}
