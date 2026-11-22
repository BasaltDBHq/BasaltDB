package guard_test

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// pageEngine is a person-operated engine whose engine.json serves agent
// a on d, and its setup page's jobs.
func pageEngine(t *testing.T, d *guardtest.DB, name string, a *guardtest.Agent) *localsetup.Service {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "engine.json")
	cred := filepath.Join(dir, "agents", name+".url")
	require.NoError(t, config.WriteFile(cred, []byte(a.URL+"\n")))
	_, err := config.UpsertAgentVault(cfgPath, config.Settings{
		SocketDir: config.DefaultSocketDir(runtime.GOOS), Mode: config.ModeService, PagesURL: links.DefaultLocal,
		OperatedBy: "PERSON", PersonUIDs: []uint32{4242}, VaultDefault: config.VaultOff,
	}, config.Agent{Name: name, OSUser: "alice", Store: config.PostgresStore(cred)})
	require.NoError(t, err)
	svc, err := localsetup.New(localsetup.Options{
		ConfigPath: cfgPath, Origin: "http://localhost:8787", Prefix: d.Names.Prefix, Configured: true,
		Euid: func() int { return 4000 },
	})
	require.NoError(t, err)
	return svc
}

// The Update check's PASSKEY_REMOVE revokes a lost device's passkey with
// only the admin connection string, even the database's last one, and the
// guard then refuses an approval that passkey signs.
func TestPasskeyRemoveOnTheSetupPageRevokesTheLastPasskey(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	ctx := context.Background()
	svc := pageEngine(t, d, "bot", a)

	in := newRun(t, a, "remove the spam lead")
	held, _ := previewAndHold(t, a.Conn, in, `DELETE FROM public.leads WHERE id = $1`, []any{3}, []string{})

	req := localsetup.Request{
		Job: localsetup.JobPasskeyRemove, Agent: "bot", OSUser: "alice", DatabaseURL: d.URL,
		CredentialID: base64.RawURLEncoding.EncodeToString(p.ID),
	}
	checked, err := svc.Check(ctx, req)
	require.NoError(t, err)
	lines := strings.Join(checked.Lines, "\n")
	require.Contains(t, lines, "This removes the passkey app, added ")
	require.Contains(t, lines, "It is the last passkey for this computer")
	require.Contains(t, checked.SQL, "basalt_meta.revoke_passkey('\\x")
	require.Contains(t, checked.SQL, "::bytea, true);")
	keys, err := guard.ActivePasskeys(ctx, d.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 1, "the check changes nothing")

	done, err := svc.Run(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, done.Remaining)
	require.Equal(t, 0, *done.Remaining)
	keys, err = guard.ActivePasskeys(ctx, d.Admin)
	require.NoError(t, err)
	require.Empty(t, keys, "the last passkey is gone")
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger
		WHERE kind = 'PASSKEY_REVOKED' AND detail ->> 'credentialId' = $1 AND (detail ->> 'forced')::boolean`, passkey.Bytes(p.ID).String()))

	// The revoked passkey can no longer approve.
	_, err = guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
	requireInvalid(t, err, "passkey revoked")

	// Removing it again: it is not active any more.
	_, err = svc.Run(ctx, req)
	var r *localsetup.RefusalError
	require.ErrorAs(t, err, &r)
	require.Equal(t, localsetup.CodeAnswersInvalid, r.Code)
	require.Equal(t, "This passkey is not active any more. Nothing changed.", r.Message)
	for _, bad := range []string{"not base64!", "", strings.Repeat("A", 2000)} {
		req.CredentialID = bad
		_, err = svc.Check(ctx, req)
		require.ErrorAs(t, err, &r)
		require.Equal(t, localsetup.CodeAnswersInvalid, r.Code, bad)
	}
}
