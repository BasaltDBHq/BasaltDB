package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// credConn is a connection with the agent's credential, as the engine
// holds it.
func credConn(t *testing.T, cred string) *pgx.Conn {
	t.Helper()
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return conn
}

// agentRequests is the agent requesting a revert of its run, as
// request_revert does, and returns its id.
func agentRequests(t *testing.T, cred string, run uuid.UUID) uuid.UUID {
	t.Helper()
	prep, err := guard.PrepareRevert(context.Background(), credConn(t, cred), guard.RevertScope{Kind: revert.ScopeRun, ID: run}, "Undo it")
	require.NoError(t, err)
	return prep.RevertID
}

// storedRevert is what Postgres holds for revert id, read as the admin.
func storedRevert(t *testing.T, d *guardtest.DB, id uuid.UUID) (status, selection, note string) {
	t.Helper()
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT CASE WHEN rejected_at IS NOT NULL THEN 'REJECTED' ELSE 'OTHER' END,
		selection::text, coalesce(reject_note, '') FROM basalt_meta.reverts WHERE revert_id = $1`, id).Scan(&status, &selection, &note))
	return status, selection, note
}

func TestRevertScopeFlagsUsage(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7()).String()
	many := make([]string, revert.MaxFilter+1)
	for i := range many {
		many[i] = uuid.Must(uuid.NewV7()).String()
	}
	for _, args := range [][]string{
		{"revert", "--run", id, "--runs", id},
		{"revert", "--task", id, "--runs", strings.Join(many, ",")},
		{"revert", "--task", id, "--runs", "nope"},
		{"revert", "--run", id, "--tables", "leads"},
		{"revert", "--run", id, "--tables", "public.leads;drop"},
		{"revert", "--run", id, "--note", "why"},
		{"revert", "--reject", id, "--run", id},
		{"revert", "--reject", id, "--tables", "public.leads"},
		{"revert", "--reject", "nope"},
		{"revert", "--reject", id, "--note", strings.Repeat("x", maxNoteChars+1)},
		{"revert", "--reject", id, "--apply", "basalt-revert.1.x"},
		{"revert", "--rescope", id, "--task", id},
		{"revert", "--rescope", id, "--dry-run"},
		{"revert", "--rescope", id, "--status", id},
		{"revert", "--status", id, "--tables", "public.leads"},
		{"revert", "--run", id, "--agents", "all", "--dry-run"},
	} {
		r := cli(t, map[string]string{envAgentURL: "postgres://unused"}, "", args...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
	}
}

// --tables narrows the revert to tables the agent wrote; one it did not
// write reads like any table outside its work.
func TestRevertTablesFilter(t *testing.T) {
	t.Parallel()
	_, _, cred, run := revertSetup(t)
	r := cli(t, nil, "", "revert", "--run", run.String(), "--tables", "public.leads", "--credential-file", cred, "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, 6, strings.Count(r.stdout, "restore    public.leads"))

	r = cli(t, nil, "", "revert", "--run", run.String(), "--tables", "public.lead_notes", "--credential-file", cred, "--dry-run")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "public.lead_notes")
	require.Contains(t, r.stderr, "has no change of yours in this scope")
}

// --agents beyond the credential's own agent needs the revert page; with
// no engine serving it, it is a usage error and nothing is prepared.
func TestRevertAgentsNeedsThePage(t *testing.T) {
	t.Parallel()
	d, _, cred, run := revertSetup(t)
	r := cli(t, nil, "", "revert", "--run", run.String(), "--agents", "all", "--credential-file", cred)
	require.Equal(t, exitUsage, r.code, r.stderr)
	require.Contains(t, r.stderr, "needs the revert page from the engine")
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(revert_id)::int FROM basalt_meta.reverts`).Scan(&n))
	require.Zero(t, n, "nothing was prepared")
}

// With the engine serving the pages, --agents all prepares the agent's own
// work and opens the page, where the person widens; the CLI then waits for
// the page. Here the person rejects it on the page, and the wait ends.
func TestRevertAgentsOpensThePageForAWiden(t *testing.T) {
	t.Parallel()
	d, _, cred, run := revertSetup(t)
	cfg := localConfig(t, cred)
	h := newFakeHost(t)
	h.pagesUp = true
	conn := credConn(t, cred)
	go func() {
		// The person rejects the revert the CLI prepared once it exists.
		ctx := context.Background()
		for range 200 {
			var id uuid.UUID
			if err := d.Admin.QueryRow(ctx, `SELECT revert_id FROM basalt_meta.reverts LIMIT 1`).Scan(&id); err == nil {
				_, _ = guard.RejectRevert(ctx, conn, id, "", nil)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	r := cliHost(t, h, "revert", "--agent", "bot", "--config", cfg, "--run", run.String(), "--agents", "all")
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, `choose "Include other agents' changes" on the revert page`)
	require.Len(t, h.opened, 1, "the page is opened")
	require.Contains(t, h.opened[0], testPagesOrigin+"/reverts/")
	require.Contains(t, r.stderr, "rejected on the revert page; nothing was reverted")
	var agents string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT selection->>'agents' FROM basalt_meta.reverts`).Scan(&agents))
	require.NotContains(t, agents, "null", "the CLI prepared the agent's own work only")
}

func TestRevertReject(t *testing.T) {
	t.Parallel()
	d, _, cred, run := revertSetup(t)
	id := agentRequests(t, cred, run)

	r := cli(t, nil, "", "revert", "--reject", id.String(), "--note", "Not this one.", "--credential-file", cred, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var out guard.RejectedRevert
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Equal(t, id, out.RevertID)
	require.Equal(t, "REJECTED", out.Status)
	status, _, note := storedRevert(t, d, id)
	require.Equal(t, "REJECTED", status)
	require.Equal(t, "Not this one.", note)
	require.Equal(t, "won", leadStatusOf(t, d, 40), "nothing was reverted")

	r = cli(t, nil, "", "revert", "--reject", id.String(), "--credential-file", cred)
	require.Equal(t, exitError, r.code, "a rejected revert cannot be rejected again")
	require.Contains(t, r.stderr, "cannot reject revert")

	r = cli(t, nil, "", "revert", "--reject", uuid.Must(uuid.NewV7()).String(), "--credential-file", cred)
	require.Equal(t, exitError, r.code)
}

// --rescope narrows the agent's request inside its own work and hands it
// to the person again, keeping the revert id; a select it cannot make is
// refused and changes nothing.
func TestRevertRescope(t *testing.T) {
	t.Parallel()
	d, _, cred, run := revertSetup(t)
	id := agentRequests(t, cred, run)

	r := cli(t, nil, "", "revert", "--rescope", id.String(), "--tables", "public.leads", "--credential-file", cred)
	require.Equal(t, exitError, r.code, "no code pasted")
	require.Contains(t, r.stderr, "revert "+id.String())
	require.Equal(t, 6, strings.Count(r.stdout, "restore    public.leads"))
	require.NotNil(t, revertLink.FindStringSubmatch(r.stderr), r.stderr)
	_, sel, _ := storedRevert(t, d, id)
	require.Contains(t, sel, `"tables": ["public.leads"]`)

	r = cli(t, nil, "", "revert", "--rescope", id.String(), "--tables", "public.lead_notes", "--credential-file", cred)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "cannot change the scope of revert "+id.String())
	_, after, _ := storedRevert(t, d, id)
	require.Equal(t, sel, after, "nothing changed")

	r = cli(t, nil, "", "revert", "--rescope", id.String(), "--runs", uuid.Must(uuid.NewV7()).String(), "--credential-file", cred)
	require.Equal(t, exitError, r.code, "a run revert takes no --runs: Postgres refuses it")
}

// With --credential-file there is no --agent, so --agents naming the
// credential's own agent is the agent's own work, not a widen: the revert
// is prepared as usual, without the page or --open.
func TestRevertAgentsOwnNameIsOwnWork(t *testing.T) {
	t.Parallel()
	d, _, cred, run := revertSetup(t)
	r := cli(t, nil, "", "revert", "--run", run.String(), "--agents", "bot", "--credential-file", cred, "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, 6, strings.Count(r.stdout, "restore    public.leads"))

	r = cli(t, nil, "", "revert", "--run", run.String(), "--agents", "bot", "--credential-file", cred)
	require.Equal(t, exitError, r.code, "no code pasted")
	require.NotContains(t, r.stderr, "needs the revert page")
	require.NotNil(t, revertLink.FindStringSubmatch(r.stderr), r.stderr)
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(revert_id)::int FROM basalt_meta.reverts`).Scan(&n))
	require.Equal(t, 1, n, "the agent's own revert was prepared")

	r = cli(t, nil, "", "revert", "--run", run.String(), "--agents", "bot,other", "--credential-file", cred)
	require.Equal(t, exitUsage, r.code, "another agent in the list still widens: %s", r.stderr)
	require.Contains(t, r.stderr, "needs the revert page from the engine")
}

// Once the person has widened a revert on the page, --rescope is refused
// with the guard's message and the revert keeps its widened scope.
func TestRevertRescopeRefusedAfterWiden(t *testing.T) {
	t.Parallel()
	d, person, cred, _ := revertSetup(t)
	ctx := context.Background()
	helper := d.NewAgent(t, "helper", []string{"public.leads"}, []string{"public.leads"})
	conn := credConn(t, cred)
	task := uuid.Must(uuid.NewV7())
	mine := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "first part"}
	theirs := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "helping"}
	require.NoError(t, guard.StartRun(ctx, conn, mine))
	require.NoError(t, guard.StartRun(ctx, helper.Conn, theirs))
	require.NoError(t, guardtest.Guarded(ctx, conn, mine, `UPDATE public.leads SET status = 'a' WHERE id = 30`))
	require.NoError(t, guardtest.Guarded(ctx, helper.Conn, theirs, `UPDATE public.leads SET status = 'h' WHERE id = 32`))
	prep, err := guard.PrepareRevert(ctx, conn, guard.RevertScope{Kind: revert.ScopeTask, ID: task}, "Undo the task")
	require.NoError(t, err)

	// The widen, as the page makes it: the whole task, signed by the person.
	sel := revert.Select{Scope: revert.ScopeTask, ScopeID: task}
	selJSON, err := json.Marshal(sel)
	require.NoError(t, err)
	var norm string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT basalt_meta._revert_select_norm($1::jsonb)::text`, string(selJSON)).Scan(&norm))
	var nonce []byte
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT rescope_nonce FROM basalt_meta.reverts WHERE revert_id = $1`, prep.RevertID).Scan(&nonce))
	key, err := revert.RescopeKey([]byte("the page's new secret"))
	require.NoError(t, err)
	as, err := person.Sign(revert.RescopeChallenge(prep.RevertID, nonce, key, norm), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	_, err = guard.RescopeRevert(ctx, conn, guard.RescopeRequest{RevertID: prep.RevertID, Select: sel, Proof: &as, RescopeKey: key})
	require.NoError(t, err)
	_, before, _ := storedRevert(t, d, prep.RevertID)

	r := cli(t, nil, "", "revert", "--rescope", prep.RevertID.String(), "--tables", "public.leads", "--credential-file", cred)
	require.Equal(t, exitError, r.code, r.stderr)
	require.Contains(t, r.stderr, "cannot change the scope of revert "+prep.RevertID.String())
	require.Contains(t, r.stderr, "if the person widened it on the revert page, change its scope there")
	_, after, _ := storedRevert(t, d, prep.RevertID)
	require.Equal(t, before, after, "the widened scope is untouched")
}
