package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// testPagesOrigin is the local approval page origin of localConfig.
const testPagesOrigin = "http://localhost:18787"

// localConfig is an engine config for agent bot with credential cred and a
// local approval page, so the engine serves the pages on 127.0.0.1:18787.
func localConfig(t *testing.T, cred string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.json")
	body := `{"socketDir": "/tmp/bt", "pagesUrl": "` + testPagesOrigin + `",
		"agents": [{"name": "bot", "osUser": "tester", "store": {"kind": "POSTGRES", "credentialFile": "` + cred + `"}}]}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	_, err := config.Load(path)
	require.NoError(t, err)
	return path
}

func TestApproveShowsTheShortLinkWhenTheEngineServesThePages(t *testing.T) {
	t.Parallel()
	d, _, cred, _ := revertSetup(t)
	held := holdDelete(t, cred)
	cfg := localConfig(t, cred)
	id := held.ApprovalID.String()

	h := newFakeHost(t)
	h.pagesUp = true
	// The commands wait for the page, so each runs until its time is up.
	show := func(args ...string) result {
		return cliPages(t, h, "", time.Second, append([]string{"approve", "--agent", "bot", "--config", cfg}, args...)...)
	}
	// Locally the short link is issued without --reissue.
	show("--show", id)
	require.Len(t, h.issued, 1)
	h.issued = nil

	r := show("--show", id, "--reissue")
	short := testPagesOrigin + "/approvals/" + id + "#s=" + fakeSecret
	require.Equal(t, short+"\n", r.stdout, "the short link with the secret the engine issued")
	binding := bindingOf(t, cred, held.ApprovalID)
	require.Equal(t, []issuedLink{{endpoint: testPagesOrigin + "/api/v1/approvals/" + id + "/links", proof: links.IssueProof(binding)}}, h.issued,
		"issued against proof of the binding text")

	r = show("--open", id, "--reissue")
	require.Equal(t, []string{short}, h.opened)
	require.Contains(t, r.stderr, "waiting for your signature on the approval page")

	// The engine gives no link: the long one stands.
	h.issueErr = errors.New("engine answered 404")
	r = show("--show", id, "--reissue")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.True(t, strings.HasPrefix(r.stdout, testPagesOrigin+"/approvals/"+id+"#2."), r.stdout)
	require.Contains(t, r.stderr, "the engine gave no short link (engine answered 404)")
	h.issueErr = nil

	// No engine answering: the long link on the config's page.
	h.pagesUp = false
	r = cliHost(t, h, "approve", "--agent", "bot", "--config", cfg, "--show", id)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.True(t, strings.HasPrefix(r.stdout, testPagesOrigin+"/approvals/"+id+"#2."), r.stdout)
	require.Equal(t, 1, count(t, d, `SELECT count(approval_id)::int FROM basalt_meta.approvals WHERE approved_at IS NULL`), "showing approves nothing")
}

// bindingOf is a held write's binding text, read with the agent's credential.
func bindingOf(t *testing.T, cred string, id uuid.UUID) string {
	t.Helper()
	dsn, err := config.ReadCredential(cred)
	require.NoError(t, err)
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn.Close(ctx)
	a, err := ledger.FindApproval(ctx, conn, id)
	require.NoError(t, err)
	return a.BindingText
}
