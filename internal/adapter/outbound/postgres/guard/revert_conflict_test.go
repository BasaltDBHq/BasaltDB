package guard_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// suiteEnv is one case of the conflict suite: a demo database, the agent
// bot (writes and reads leads), the person's passkey, and the bot's run.
type suiteEnv struct {
	d  *guardtest.DB
	a  *guardtest.Agent
	p  *passkeytest.Authenticator
	in guard.Intent
}

func (e suiteEnv) agent(t *testing.T, stmts ...string) {
	t.Helper()
	require.NoError(t, guardtest.Guarded(context.Background(), e.a.Conn, e.in, stmts...))
}

func (e suiteEnv) agentDelete(t *testing.T, table string, id int) {
	t.Helper()
	approvedWrite(t, e.a, e.p, e.in, fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, table), []any{id}, []string{})
}

// conflictCase: the agent acts in a run, a person acts after, and the run
// is reverted through prepare, the person's signature and apply. want maps
// a leads key to its conflict ("" restores); after checks the tables.
type conflictCase struct {
	name   string
	agent  func(t *testing.T, e suiteEnv)
	person string
	want   map[string]string
	after  func(t *testing.T, e suiteEnv)
}

func statusIs(id int, want string) func(t *testing.T, e suiteEnv) {
	return func(t *testing.T, e suiteEnv) {
		t.Helper()
		require.Equal(t, want, leadStatus(t, e.d, id))
	}
}

// TestRevertConflictSuite is M3's gate: every way a row can
// change after the agent is skipped and named, never overwritten, and the
// rest of the revert still lands, through the full signed path.
func TestRevertConflictSuite(t *testing.T) {
	t.Parallel()
	cases := []conflictCase{{
		name: "a person edits a row",
		agent: func(t *testing.T, e suiteEnv) {
			e.agent(t, `UPDATE public.leads SET status = 'won' WHERE id IN (1, 2)`)
		},
		person: `UPDATE public.leads SET status = 'person' WHERE id = 2`,
		want:   map[string]string{`{"id":1}`: "", `{"id":2}`: revert.ConflictChangedAfter},
		after:  func(t *testing.T, e suiteEnv) { statusIs(1, "open")(t, e); statusIs(2, "person")(t, e) },
	}, {
		name: "a person saves a row without changing it",
		agent: func(t *testing.T, e suiteEnv) {
			e.agent(t, `UPDATE public.leads SET status = 'won' WHERE id IN (1, 2)`)
		},
		person: `UPDATE public.leads SET status = status WHERE id = 2`,
		want:   map[string]string{`{"id":1}`: "", `{"id":2}`: revert.ConflictChangedAfter},
		after:  statusIs(2, "won"),
	}, {
		name: "a person deletes a row",
		agent: func(t *testing.T, e suiteEnv) {
			e.agent(t, `UPDATE public.leads SET status = 'won' WHERE id IN (1, 2)`)
		},
		person: `DELETE FROM public.leads WHERE id = 2`,
		want:   map[string]string{`{"id":1}`: "", `{"id":2}`: revert.ConflictRowGone},
		after: func(t *testing.T, e suiteEnv) {
			require.Zero(t, count(t, e.d.Admin, `SELECT count(id)::int FROM public.leads WHERE id = 2`))
		},
	}, {
		name: "a person re-creates a deleted row",
		agent: func(t *testing.T, e suiteEnv) {
			e.agent(t, `UPDATE public.leads SET status = 'won' WHERE id = 1`)
			e.agentDelete(t, "public.leads", 150)
		},
		person: `INSERT INTO public.leads (id, name) VALUES (150, 'person''s lead')`,
		want:   map[string]string{`{"id":1}`: "", `{"id":150}`: revert.ConflictKeyTaken},
		after: func(t *testing.T, e suiteEnv) {
			require.Equal(t, "person's lead", scalarOf[string](t, e.d.Admin, `SELECT name FROM public.leads WHERE id = 150`))
		},
	}, {
		name: "a person takes the old key of a renumbered row",
		agent: func(t *testing.T, e suiteEnv) {
			e.agent(t, `UPDATE public.leads SET id = 9150 WHERE id = 150`, `UPDATE public.leads SET status = 'won' WHERE id = 1`)
		},
		person: `INSERT INTO public.leads (id, name) VALUES (150, 'new 150')`,
		want:   map[string]string{`{"id":1}`: "", `{"id":9150}`: revert.ConflictKeyTaken},
	}, {
		name: "removing the agent's row would cascade into a person's row",
		agent: func(t *testing.T, e suiteEnv) {
			e.agent(t, `INSERT INTO public.leads (id, name) VALUES (900, 'a'), (901, 'b')`)
		},
		person: `INSERT INTO public.lead_notes (id, lead_id, note) VALUES (900, 900, 'person''s note')`,
		want:   map[string]string{`{"id":900}`: revert.ConflictCascade, `{"id":901}`: ""},
		after: func(t *testing.T, e suiteEnv) {
			require.Equal(t, 1, count(t, e.d.Admin, `SELECT count(id)::int FROM public.lead_notes WHERE id = 900`))
		},
	}, {
		name: "restoring would break a constraint",
		agent: func(t *testing.T, e suiteEnv) {
			e.agent(t, `UPDATE public.leads SET name = 'renamed' WHERE id = 3`, `UPDATE public.leads SET status = 'won' WHERE id = 1`)
		},
		person: `CREATE UNIQUE INDEX leads_name ON public.leads (name); UPDATE public.leads SET name = 'lead 3' WHERE id = 4`,
		want:   map[string]string{`{"id":1}`: "", `{"id":3}`: revert.ConflictConstraint},
	}, {
		name:   "old values pruned",
		agent:  func(t *testing.T, e suiteEnv) { e.agent(t, `UPDATE public.leads SET status = 'won' WHERE id = 1`) },
		person: `SELECT basalt_meta._prune(now() + interval '31 days')`,
		want:   map[string]string{`{"id":1}`: revert.ConflictValuesPruned},
	}, {
		name:   "a column was dropped",
		agent:  func(t *testing.T, e suiteEnv) { e.agent(t, `UPDATE public.leads SET status = 'won' WHERE id = 1`) },
		person: `ALTER TABLE public.leads DROP COLUMN score`,
		want:   map[string]string{`{"id":1}`: revert.ConflictSchemaChanged},
	}, {
		name: "a cascaded delete comes back",
		agent: func(t *testing.T, e suiteEnv) {
			e.agentDelete(t, "public.leads", 5) // notes 9, 10 and their tags cascade
		},
		want: map[string]string{`{"id":5}`: ""},
		after: func(t *testing.T, e suiteEnv) {
			require.Equal(t, 2, count(t, e.d.Admin, `SELECT count(id)::int FROM public.lead_notes WHERE lead_id = 5`))
			require.Equal(t, 2, count(t, e.d.Admin, `SELECT count(id)::int FROM public.note_tags WHERE note_id IN (9, 10)`))
		},
	}, {
		name:  "a renumbered row and its SET NULL cascade come back",
		agent: func(t *testing.T, e suiteEnv) { e.agent(t, `UPDATE public.leads SET id = 9101 WHERE id = 101`) },
		want:  map[string]string{`{"id":9101}`: ""},
		after: func(t *testing.T, e suiteEnv) {
			require.Equal(t, 101, scalarOf[int](t, e.d.Admin, `SELECT lead_id::int FROM public.lead_owner WHERE id = 1`))
		},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newSuiteEnv(t)
			tc.agent(t, e)
			if tc.person != "" {
				e.d.Exec(t, tc.person)
			}
			lines := previewRevert(t, e.a.Conn, revert.ScopeRun, e.in.RunID)
			restores := 0
			for key, want := range tc.want {
				l := lineFor(t, lines, "public.leads", key)
				require.Equal(t, want, conflictOf(l), key)
			}
			for _, l := range lines {
				if l.Action == revert.ActionRestore {
					restores++
				}
			}
			if restores == 0 {
				_, err := guard.PrepareRevert(context.Background(), e.a.Conn, action.Scope{Kind: revert.ScopeRun, ID: e.in.RunID}, "Undo")
				requireCode(t, err, guardmodel.CodeNothingToRevert)
				return
			}
			out := revertScope(t, e.a, e.p, revert.ScopeRun, e.in.RunID)
			require.Equal(t, restores, out.Rows)
			require.Equal(t, len(lines)-restores, out.Skipped)
			if tc.after != nil {
				tc.after(t, e)
			}
			require.Nil(t, guardVerify(t, e.d), "the chain still verifies")
		})
	}
}

func newSuiteEnv(t *testing.T) suiteEnv {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	return suiteEnv{d: d, a: a, p: person(t, d), in: newRun(t, a, "Suite run")}
}

// The two-minute demo, step 4: a bot updates leads in one
// run, a person edits one of them, and reverting the run restores the rest
// and skips the person's lead.
func TestDemoStepFourRevertSkipsThePersonsLead(t *testing.T) {
	t.Parallel()
	e := newSuiteEnv(t)
	before := tableDigest(t, e.d, "public.leads")
	e.agent(t, `UPDATE public.leads SET status = 'contacted' WHERE id BETWEEN 1 AND 6`)
	e.agent(t, `UPDATE public.leads SET status = 'contacted' WHERE id BETWEEN 7 AND 12`)
	e.d.Exec(t, `UPDATE public.leads SET status = 'call back friday' WHERE id = 7`)

	out := revertScope(t, e.a, e.p, revert.ScopeRun, e.in.RunID)
	require.Equal(t, 11, out.Rows)
	require.Equal(t, 1, out.Skipped)
	require.Equal(t, "call back friday", leadStatus(t, e.d, 7))
	e.d.Exec(t, `UPDATE public.leads SET status = 'open' WHERE id = 7`)
	require.Equal(t, before, tableDigest(t, e.d, "public.leads"), "everything else is as before the run")
}

// A task proposal reverts only the requesting agent's own lines (RS-1):
// the helper's rows go back to what bot left them as, and bot's row the
// helper never touched stays as bot wrote it.
func TestRevertTaskAcrossAgentsApplies(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	b := d.NewAgent(t, "helper", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	task := uuid.Must(uuid.NewV7())
	inA := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "first half"}
	inB := guard.Intent{RunID: uuid.Must(uuid.NewV7()), TaskID: task, Text: "second half"}
	require.NoError(t, guard.StartRun(ctx, a.Conn, inA))
	require.NoError(t, guard.StartRun(ctx, b.Conn, inB))
	require.NoError(t, guardtest.Guarded(ctx, a.Conn, inA, `UPDATE public.leads SET status = 'a' WHERE id IN (20, 21)`))
	require.NoError(t, guardtest.Guarded(ctx, b.Conn, inB, `UPDATE public.leads SET status = 'b' WHERE id IN (21, 22)`))

	out := revertScope(t, b, p, revert.ScopeTask, task)
	require.Equal(t, 2, out.Rows)
	require.Equal(t, "a", leadStatus(t, d, 20), "bot's own row is not the helper's to revert")
	require.Equal(t, "a", leadStatus(t, d, 21), "back to what bot left")
	require.Equal(t, "open", leadStatus(t, d, 22))
	require.Zero(t, count(t, a.Conn, `SELECT count(change_id)::int FROM basalt_meta.agent_changes WHERE change_id = $1`, out.ChangeID),
		"bot's changes were not covered, so it does not see the helper's revert")
	require.Equal(t, "APPLIED", scalarOf[string](t, a.Conn, `SELECT status FROM basalt_meta.agent_changes WHERE run_id = $1`, inA.RunID))
}
