package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// fixedRand is a deterministic randomness source, so a test can build the
// same registration request basalt init builds.
func fixedRand() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024)) }

// cliRand is cli with a fixed randomness source.
func cliRand(t *testing.T, env map[string]string, stdin string, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(stdin), out: &stdout, err: &stderr},
		func(k string) string { return env[k] })
	c.rand = fixedRand()
	code := runGuard(c, args)
	return result{code, stdout.String(), stderr.String()}
}

// registrationCode is what the registration page returns for the request
// basalt init makes with fixedRand on database db.
func registrationCode(t *testing.T, person *passkeytest.Authenticator, db string) string {
	t.Helper()
	req, err := passkey.NewRegistrationRequest(fixedRand(), db, "BasaltDB · "+db)
	require.NoError(t, err)
	resp, err := person.Register(req, nil)
	require.NoError(t, err)
	code, err := resp.Code()
	require.NoError(t, err)
	return code
}

func dbName(t *testing.T, d *guardtest.DB) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(d.URL)
	require.NoError(t, err)
	return cfg.Database
}

// initWithPasskey sets up agent bot in d with the person's portal passkey
// registered, and returns the agent's credential file.
func initWithPasskey(t *testing.T, d *guardtest.DB, person *passkeytest.Authenticator) string {
	t.Helper()
	return setUpAgent(t, d, filepath.Join(t.TempDir(), "engine.json"), "bot", agentFixture{write: []string{"public.leads"}, person: person})
}

func count(t *testing.T, d *guardtest.DB, sql string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Admin.QueryRow(context.Background(), sql).Scan(&n))
	return n
}

// holdDelete holds DELETE FROM public.leads WHERE id = 9 as the agent,
// as the engine does on APPROVAL_REQUIRED.
func holdDelete(t *testing.T, credFile string) guard.Held {
	t.Helper()
	ctx := context.Background()
	dsn, err := config.ReadCredential(credFile)
	require.NoError(t, err)
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "remove spam"}
	require.NoError(t, guard.StartRun(ctx, conn, in))
	const stmt = `DELETE FROM public.leads WHERE id = 9`
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, guard.BeginPreview(ctx, tx, in, guardtest.Timeout))
	_, err = tx.Exec(ctx, stmt)
	require.NoError(t, err)
	lines, err := guard.PreviewLines(ctx, tx, nil)
	require.NoError(t, err)
	require.NoError(t, tx.Rollback(ctx))
	held, err := guard.Hold(ctx, conn, in, guardtest.Timeout, guard.HoldRequest{Statement: stmt, Lines: lines})
	require.NoError(t, err)
	return held
}

func TestApprove(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	credFile := initWithPasskey(t, d, person)
	held := holdDelete(t, credFile)
	agentFlags := []string{"--credential-file", credFile}

	r := cli(t, nil, "", append(append([]string{"approve"}, agentFlags...), "--show", held.ApprovalID.String())...)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr,
		"basalt: Delete 1 row in public.leads + 4 cascaded rows (public.lead_notes 2 [values hidden], public.note_tags 2 [values hidden])\n")
	link := strings.TrimSpace(r.stdout)
	require.True(t, strings.HasPrefix(link, links.DefaultLocal+"/approvals/"+held.ApprovalID.String()+"#2."), link)
	req, b, err := approval.ParseRequest(link[strings.Index(link, "#"):])
	require.NoError(t, err)
	require.Equal(t, held.ApprovalID, b.ApprovalID)

	// --open opens the same link in the browser and does not print it.
	h := newFakeHost(t)
	r = cliHost(t, h, append(append([]string{"approve"}, agentFlags...), "--open", held.ApprovalID.String())...)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, []string{link}, h.opened)
	require.Empty(t, r.stdout)
	require.Contains(t, r.stderr, "basalt: Delete 1 row in public.leads")
	require.Contains(t, r.stderr, "opened the link in your browser")
	require.NotContains(t, r.stderr, "#2.")

	// No browser: the link is printed to copy by hand.
	h.openErr = errors.New("xdg-open not found")
	r = cliHost(t, h, append(append([]string{"approve"}, agentFlags...), "--open", held.ApprovalID.String())...)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, link, strings.TrimSpace(r.stdout))
	require.Contains(t, r.stderr, "could not open a browser (xdg-open not found)")

	r = cli(t, nil, "", append(append([]string{"approve"}, agentFlags...), "--open", held.ApprovalID.String(), "--show", held.ApprovalID.String())...)
	require.Equal(t, exitUsage, r.code, r.stderr)
	r = cli(t, nil, "", append(append([]string{"approve"}, agentFlags...), "--open", held.ApprovalID.String(), "code")...)
	require.Equal(t, exitUsage, r.code, r.stderr)

	sign := func(a *passkeytest.Authenticator) string {
		as, err := a.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		code, err := approval.NewResponse(held.ApprovalID, as).Code()
		require.NoError(t, err)
		return code
	}

	forger, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	forger.ID = person.ID
	r = cli(t, nil, "", append(append([]string{"approve"}, agentFlags...), sign(forger))...)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "does not verify, nothing was submitted")

	r = cli(t, nil, "", append(append([]string{"approve"}, agentFlags...), "not-a-code")...)
	require.Equal(t, exitUsage, r.code, r.stderr)

	// The code on stdin, as pasted at the prompt.
	r = cli(t, nil, sign(person)+"\n", append([]string{"approve"}, agentFlags...)...)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "signed")
	var approved bool
	require.NoError(t, d.Admin.QueryRow(context.Background(),
		`SELECT approved_at IS NOT NULL FROM basalt_meta.approvals WHERE approval_id = $1`, held.ApprovalID).Scan(&approved))
	require.True(t, approved)

	r = cli(t, nil, "", append(append([]string{"approve"}, agentFlags...), sign(person))...)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "already signed")

	r = cli(t, nil, "", "approve", "--show", held.ApprovalID.String(), "x", "--credential-file", credFile)
	require.Equal(t, exitUsage, r.code)
}
