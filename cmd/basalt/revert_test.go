package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

var revertLink = regexp.MustCompile(`http://localhost:8787/reverts/[0-9a-f-]{36}#(2\.[A-Za-z0-9_-]+)`)

// revertSetup is a demo database with basalt init done (agent bot on
// leads, the person's passkey registered), and a run of the agent that
// marked leads 40 to 45 won.
func revertSetup(t *testing.T) (*guardtest.DB, *passkeytest.Authenticator, string, uuid.UUID) {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	cred := initWithPasskey(t, d, person)
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Mark leads won"}
	require.NoError(t, guard.StartRun(ctx, conn, in))
	require.NoError(t, guardtest.Guarded(ctx, conn, in, `UPDATE public.leads SET status = 'won' WHERE id BETWEEN 40 AND 45`))
	return d, person, cred, in.RunID
}

// signRevertLink does what the person does on the revert page.
func signRevertLink(t *testing.T, person *passkeytest.Authenticator, fragment string) string {
	t.Helper()
	req, b, err := revert.ParseRequest(fragment)
	require.NoError(t, err)
	require.Contains(t, req.CredentialIDs, passkey.Bytes(person.Credential().ID), "the link names the database's passkeys, for allowCredentials")
	as, err := person.Sign(revert.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := revert.NewResponse(b.RevertID, as).Code()
	require.NoError(t, err)
	return code
}

// pageSigner is stderr for an interactive basalt revert: when the revert
// link appears, it signs it as the person and types the code on stdin.
type pageSigner struct {
	t      *testing.T
	person *passkeytest.Authenticator
	stdin  *io.PipeWriter
	mu     sync.Mutex
	buf    bytes.Buffer
	done   bool
}

func (p *pageSigner) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf.Write(b)
	if m := revertLink.FindStringSubmatch(p.buf.String()); m != nil && !p.done {
		p.done = true
		code := signRevertLink(p.t, p.person, m[1])
		go func() { _, _ = io.WriteString(p.stdin, code+"\n") }()
	}
	return len(b), nil
}

func leadStatusOf(t *testing.T, d *guardtest.DB, id int) string {
	t.Helper()
	var s string
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT status FROM public.leads WHERE id = $1`, id).Scan(&s))
	return s
}

func TestRevertSignsAndApplies(t *testing.T) {
	t.Parallel()
	d, person, cred, run := revertSetup(t)
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 43`)

	inR, inW := io.Pipe()
	var stdout bytes.Buffer
	stderr := &pageSigner{t: t, person: person, stdin: inW}
	c := newIO(context.Background(), stdio{in: inR, out: &stdout, err: stderr}, func(string) string { return "" })
	code := runRevert(c, []string{"--run", run.String(), "--credential-file", cred, "--intent", "The bulk update was wrong"})
	require.Equal(t, exitOK, code, stderr.buf.String())

	require.Contains(t, stdout.String(), `restore    public.leads {"id": 40}: status: "won" -> "open"`)
	require.Contains(t, stdout.String(), `skip       public.leads {"id": 43}: CHANGED_AFTER`)
	require.Contains(t, stderr.buf.String(), "5 rows to restore, 1 left as they are")
	require.Contains(t, stderr.buf.String(), "reverted: 5 rows restored, 1 left as they are")
	require.Equal(t, "open", leadStatusOf(t, d, 40))
	require.Equal(t, "person", leadStatusOf(t, d, 43), "people win")

	var reverts int
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT count(*) FROM basalt_meta.changes WHERE op = 'REVERT' AND intent LIKE '%The bulk update was wrong%'`).Scan(&reverts))
	require.Positive(t, reverts, "the ledger records the revert with its intent")
}

func TestRevertApplyLater(t *testing.T) {
	t.Parallel()
	d, person, cred, run := revertSetup(t)

	r := cli(t, nil, "", "revert", "--run", run.String(), "--credential-file", cred)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no code given; nothing was reverted")
	m := revertLink.FindStringSubmatch(r.stderr)
	require.NotNil(t, m, r.stderr)
	require.Equal(t, "won", leadStatusOf(t, d, 40))

	code := signRevertLink(t, person, m[1])
	r = cli(t, nil, "", "revert", "--apply", code, "--credential-file", cred, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var out guard.AppliedRevert
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Equal(t, 6, out.Rows)
	require.Equal(t, "open", leadStatusOf(t, d, 40))

	r = cli(t, nil, "", "revert", "--apply", code, "--credential-file", cred)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "signature counter did not increase", "a replayed code is refused before it reaches Postgres")

	r = cli(t, nil, "", "revert", "--run", run.String(), "--credential-file", cred)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "NOTHING_TO_REVERT")
}

func TestRevertOpensTheLink(t *testing.T) {
	t.Parallel()
	d, person, cred, run := revertSetup(t)

	h := newFakeHost(t)
	r := cliHost(t, h, "revert", "--run", run.String(), "--credential-file", cred, "--open")
	require.Equal(t, exitError, r.code, "no code pasted")
	require.Len(t, h.opened, 1)
	m := revertLink.FindStringSubmatch(h.opened[0])
	require.NotNil(t, m, h.opened[0])
	require.NotContains(t, r.stderr, "/reverts/", "an opened link is not printed")
	require.Contains(t, r.stderr, "opened the link in your browser")
	require.Equal(t, "won", leadStatusOf(t, d, 40))

	r = cli(t, nil, "", "revert", "--apply", signRevertLink(t, person, m[1]), "--credential-file", cred)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, "open", leadStatusOf(t, d, 40))
}

func TestRevertRefusesAForgedCode(t *testing.T) {
	t.Parallel()
	d, person, cred, run := revertSetup(t)
	r := cli(t, nil, "", "revert", "--run", run.String(), "--credential-file", cred)
	m := revertLink.FindStringSubmatch(r.stderr)
	require.NotNil(t, m, r.stderr)

	// The forger claims the registered passkey's credential id, as an agent
	// forging a signature would.
	forger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	forger.ID = person.ID
	r = cli(t, nil, "", "revert", "--apply", signRevertLink(t, forger, m[1]), "--credential-file", cred)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "the code does not verify, nothing was reverted")
	require.Equal(t, "won", leadStatusOf(t, d, 40))
}

func TestRevertDryRun(t *testing.T) {
	t.Parallel()
	d, _, cred, run := revertSetup(t)
	r := cli(t, nil, "", "revert", "--run", run.String(), "--credential-file", cred, "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, 6, strings.Count(r.stdout, "restore    public.leads"))
	require.Contains(t, r.stderr, "dry run, nothing was reverted")
	require.NotContains(t, r.stderr, "/reverts/")
	require.Equal(t, "won", leadStatusOf(t, d, 40))

	r = cli(t, nil, "", "revert", "--run", run.String(), "--credential-file", cred, "--dry-run", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var lines []revert.Line
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &lines))
	require.Len(t, lines, 6)
}

func TestRevertUsage(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7()).String()
	for _, args := range [][]string{
		{"revert"},
		{"revert", "--run", id, "--task", id},
		{"revert", "--run", "nope"},
		{"revert", "--apply", "basalt-revert.1.x", "--run", id},
		{"revert", "--run", id, "extra"},
		{"revert", "--status", id, "--run", id},
		{"revert", "--status", id, "--apply", "basalt-revert.1.x"},
		{"revert", "--status", id, "--dry-run"},
		{"revert", "--run", id, "--dry-run", "--open"},
		{"revert", "--apply", "basalt-revert.1.x", "--open"},
	} {
		r := cli(t, map[string]string{envAgentURL: "postgres://unused"}, "", args...)
		require.Equal(t, exitUsage, r.code, "%v: %s", args, r.stderr)
	}
}

var statusCommand = regexp.MustCompile(`basalt revert --status ([0-9a-f-]{36})`)

// TestRevertLargePlan: a run of 1010 inserted leads is one plan. basalt
// revert shows its size and the sample, the person signs once, and the
// agent applies it in batches; --status follows the progress and names
// every row left alone, at the signature or when its batch ran.
func TestRevertLargePlan(t *testing.T) {
	t.Parallel()
	const (
		first = 1001
		rows  = 1010
	)
	d := guardtest.New(t).WithDemo(t)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	cred := initWithPasskey(t, d, person)
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Import leads"}
	require.NoError(t, guard.StartRun(ctx, conn, in))
	stmts := make([]string, 0, rows/10)
	for i := first; i < first+rows; i += 10 {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO public.leads (id, name) SELECT g, 'imported ' || g FROM generate_series(%d, %d) g`, i, i+9))
	}
	require.NoError(t, guardtest.Guarded(ctx, conn, in, stmts...))
	d.Exec(t, `UPDATE public.leads SET name = 'kept by a person' WHERE id = 1005`)

	inR, inW := io.Pipe()
	var stdout bytes.Buffer
	stderr := &pageSigner{t: t, person: person, stdin: inW}
	c := newIO(ctx, stdio{in: inR, out: &stdout, err: stderr}, func(string) string { return "" })
	code := runRevert(c, []string{"--run", in.RunID.String(), "--credential-file", cred})
	require.Equal(t, exitOK, code, stderr.buf.String())
	require.Contains(t, stderr.buf.String(), "large revert: 1010 rows, 1009 to restore and 1 left as they are")
	require.Contains(t, stderr.buf.String(), "below and in the link: 1000 rows, 999 to restore and 1 left as they are")
	require.Contains(t, stderr.buf.String(), "signed. Your agent restores the 1009 remaining rows in batches of up to 200")
	require.Regexp(t, `basalt: tell your agent: apply revert [0-9a-f-]{36} in batches\n`, stderr.buf.String())
	require.Contains(t, stdout.String(), `skip       public.leads {"id": 1005}: CHANGED_AFTER`)
	require.Equal(t, 1000, strings.Count(stdout.String(), "\n"), "the sample")
	m := statusCommand.FindStringSubmatch(stderr.buf.String())
	require.NotNil(t, m, stderr.buf.String())
	id := uuid.MustParse(m[1])
	require.Equal(t, rows+200, countLeads(t, d), "the signature writes no row")

	r := cli(t, nil, "", "revert", "--status", id.String(), "--credential-file", cred)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "APPLYING")
	require.Contains(t, r.stdout, "1010 rows: 0 restored, 1 left as they are, 1009 pending, in 0 batches")

	// The agent's loop, with a person editing a row before its batch runs.
	d.Exec(t, `UPDATE public.leads SET name = 'edited during the revert' WHERE id = 2000`)
	for {
		page, err := ledger.ListRevertLines(ctx, conn, ledger.RevertLineParams{
			Params: pagination.Params{Limit: revert.MaxBatch}, RevertID: id, Outcome: ledger.OutcomePending,
		})
		require.NoError(t, err)
		if len(page.Items) == 0 {
			break
		}
		lines := make([]int, 0, len(page.Items))
		for _, l := range page.Items {
			lines = append(lines, l.No)
		}
		_, err = guard.ApplyRevertBatch(ctx, conn, id, lines)
		require.NoError(t, err)
	}
	require.Equal(t, 202, countLeads(t, d), "the demo's 200 and the two rows people changed")

	r = cli(t, nil, "", "revert", "--status", id.String(), "--credential-file", cred)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "APPLIED")
	require.Contains(t, r.stdout, "1010 rows: 1008 restored, 2 left as they are, 0 pending, in 6 batches")
	require.Contains(t, r.stdout, `skip       public.leads {"id": 2000}: CHANGED_AFTER`)

	r = cli(t, nil, "", "revert", "--status", id.String(), "--credential-file", cred, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var status revertStatusDTO
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &status))
	require.Equal(t, ledger.RevertApplied, status.Status)
	require.True(t, status.Batched)
	require.Len(t, status.SkippedLines, 2)
	require.Equal(t, 0, *status.SkippedLines[1].Batch, "skipped at the signature")
	require.Positive(t, *status.SkippedLines[0].Batch, "skipped when its batch ran")

	r = cli(t, nil, "", "revert", "--status", uuid.Must(uuid.NewV7()).String(), "--credential-file", cred)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no revert")
}

func countLeads(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT count(id)::int FROM public.leads`).Scan(&n))
	return n
}
