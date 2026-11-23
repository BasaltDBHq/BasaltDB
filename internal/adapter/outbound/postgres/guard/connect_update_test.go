package guard_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// updateCode is an AGENT code with no change for d's bot, with a target,
// as basalt init --remote makes it for the Update on the connect page.
func updateCode(t *testing.T, d *guardtest.DB, edit func(*setupcode.Payload)) string {
	t.Helper()
	u, err := url.Parse(d.URL)
	require.NoError(t, err)
	target, err := setupcode.TargetOf(u)
	require.NoError(t, err)
	id, expires, err := setupcode.NewSetupID(time.Now(), rand.Reader)
	require.NoError(t, err)
	p := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: setupcode.KindAgent, Prefix: d.Names.Prefix, Target: &target,
		Guard: setupcode.Guard{From: guard.LatestVersion(), To: guard.LatestVersion()}, Build: "1.0.0", ExpiresAt: expires,
		Agent: &setupcode.Agent{Name: "bot", Write: leads, Read: []string{}, StatementTimeoutMs: 30000},
	}
	if edit != nil {
		edit(&p)
	}
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	return code
}

func setupCodeOf(t *testing.T, err error) string {
	t.Helper()
	var e *setup.Error
	require.True(t, errors.As(err, &e), "%v", err)
	return e.Code
}

// RevokePasskey removes a passkey with the admin connection string alone,
// the last one included; the guard then refuses a signature by it. An id
// that is not active is ANSWERS_INVALID; another database is
// TARGET_MISMATCH; nothing changes on a refusal.
func TestRevokePasskeyWithTheAdminStringAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	a := d.NewAgent(t, "bot", leads, leads)
	p := person(t, d)
	in := newRun(t, a, "Remove a lead")
	const stmt = `DELETE FROM public.leads WHERE id = $1`
	held, _ := previewAndHold(t, a.Conn, in, stmt, []any{3}, []string{})
	code := updateCode(t, d, nil)
	req := setup.Request{Code: code, Now: time.Now(), ConnectPage: true}

	// Check lists the passkeys for a code with a target.
	checked, err := setup.Check(ctx, d.Admin, req)
	require.NoError(t, err)
	require.Len(t, checked.Passkeys, 1)
	require.Equal(t, p.ID, checked.Passkeys[0].CredentialID)
	require.Equal(t, setup.PortalRPID, checked.Passkeys[0].RPID)

	other := updateCode(t, d, func(pl *setupcode.Payload) { pl.Target.Database = "another_db" })
	_, err = setup.RevokePasskey(ctx, d.Admin, setup.Request{Code: other, Now: time.Now(), ConnectPage: true}, p.ID)
	require.Equal(t, setup.CodeTargetMismatch, setupCodeOf(t, err))
	wrongPrefix := updateCode(t, d, func(pl *setupcode.Payload) { pl.Prefix = "zz" })
	_, err = setup.RevokePasskey(ctx, d.Admin, setup.Request{Code: wrongPrefix, Now: time.Now(), ConnectPage: true}, p.ID)
	require.Equal(t, string(setupcode.RefusalPrefixMismatch), setupCodeOf(t, err))
	_, err = setup.RevokePasskey(ctx, d.Admin, req, []byte("not a passkey"))
	require.Equal(t, setup.CodeAnswersInvalid, setupCodeOf(t, err))
	require.Equal(t, "This passkey is not active any more. Nothing changed.", err.Error())

	done, err := setup.RevokePasskey(ctx, d.Admin, req, p.ID)
	require.NoError(t, err, "the last passkey goes: the admin login allows it")
	require.Empty(t, done.Remaining)
	require.NotEmpty(t, done.Lines)

	_, err = guard.SubmitApproval(ctx, a.Conn, held.ApprovalID, sign(t, p, held, nil))
	requireInvalid(t, err, "passkey revoked")
	_, err = setup.RevokePasskey(ctx, d.Admin, req, p.ID)
	require.Equal(t, setup.CodeAnswersInvalid, setupCodeOf(t, err), "revoked is not active")
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'PASSKEY_REVOKED' AND (detail ->> 'forced')::boolean`))
}

// After the install, an AGENT code with a target labels the agent's
// columns on the connect page and records the certificate its login was
// verified against; an UPGRADE-free database's AGENT code needs no ticks.
func TestLabelsOnAnAgentCodeAfterInstall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)
	person(t, d)
	req := setup.Request{Code: updateCode(t, d, nil), Now: time.Now(), ConnectPage: true}
	checked, err := setup.Check(ctx, d.Admin, req)
	require.NoError(t, err)
	require.NotEmpty(t, checked.Columns)
	for _, c := range checked.Columns {
		require.Equal(t, "public.leads", c.Table)
		require.Equal(t, guardmodel.ClassUnclassified, c.Class)
	}
	unlabeled := setup.Label{Class: guardmodel.ClassUnclassified}
	name := setup.Label{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPersonName}
	const pin = "5f9b77951a7aa1303f9b58eea9bfa89e5f9b77951a7aa1303f9b58eea9bfa89e"
	res, err := setup.Run(ctx, d.Admin, req, setup.RunInput{
		ColumnClasses: []setup.ColumnClass{{Table: "public.leads", Column: "name", Label: name, Was: unlabeled}},
		RestPublic:    true,
		TrustPin:      &setup.TrustPin{Host: "db.internal.example.com", Port: 5432, SHA256: pin},
	})
	require.NoError(t, err)
	require.True(t, res.Ran)
	got, err := guard.ReadLabels(ctx, d.Admin, d.Names, leads)
	require.NoError(t, err)
	for _, c := range got {
		want := guardmodel.Label{Class: guardmodel.ClassPublic}
		if c.Column == "name" {
			want = guardmodel.Label(name)
		}
		require.Equal(t, want, c.Label, c.Column)
	}
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED'`),
		"RunSetup records the certificate it logged in against")
}

// Check on a database with no guard yet lists no passkey and refuses
// nothing for it: an INSTALL code with a target on the connect page.
func TestCheckPasskeysWithoutAGuard(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	d.Exec(t, `CREATE TABLE public.leads (id int PRIMARY KEY)`)
	code := updateCode(t, d, func(p *setupcode.Payload) {
		verifier, err := setupcode.NewVerifier("not-a-real-password")
		require.NoError(t, err)
		p.Kind, p.Guard.From, p.Agent.Verifier = setupcode.KindInstall, 0, verifier
	})
	checked, err := setup.Check(context.Background(), d.Admin, setup.Request{Code: code, Now: time.Now(), ConnectPage: true})
	require.NoError(t, err)
	require.Empty(t, checked.Passkeys)
	require.True(t, checked.PasskeyNeeded)
}

// The changed-certificate code of a bot saved with every table in public
// is an UPGRADE code from guard version 0: on a database whose guard is
// current it has nothing to do, changes no grant, and still records the
// certificate its login was verified against. Labels with it are refused.
func TestUpgradeWithNothingToDoRecordsTheTrustPin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", leads, leads)
	code := updateCode(t, d, func(p *setupcode.Payload) {
		p.Kind, p.Agent, p.Guard.From = setupcode.KindUpgrade, nil, 0
	})
	req := setup.Request{Code: code, Now: time.Now(), ConnectPage: true}
	const pin = "5f9b77951a7aa1303f9b58eea9bfa89e5f9b77951a7aa1303f9b58eea9bfa89e"
	_, err := setup.Run(ctx, d.Admin, req, setup.RunInput{RestPublic: true, TrustPin: &setup.TrustPin{Host: "db.internal.example.com", Port: 5432, SHA256: pin}})
	require.Equal(t, setup.CodeAnswersInvalid, setupCodeOf(t, err))
	require.Equal(t, 0, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED'`))

	res, err := setup.Run(ctx, d.Admin, req, setup.RunInput{TrustPin: &setup.TrustPin{Host: "db.internal.example.com", Port: 5432, SHA256: pin}})
	require.NoError(t, err)
	require.NotNil(t, res.NothingToDo)
	require.False(t, res.Ran)
	require.Equal(t, 1, count(t, d.Admin, `SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED'`))
	sha, ok, err := guard.RecordedTrustPin(ctx, d.Admin, "db.internal.example.com", 5432)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, pin, sha)
}
