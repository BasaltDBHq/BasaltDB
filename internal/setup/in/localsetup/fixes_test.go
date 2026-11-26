package localsetup_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

func (f *fixture) doctor() localsetup.DoctorRequest {
	return localsetup.DoctorRequest{Agent: "demo_bot", OSUser: "alice"}
}

func (f *fixture) fix(job string) localsetup.Request {
	return localsetup.Request{Job: job, Agent: "demo_bot", OSUser: "alice", DatabaseURL: f.db.URL}
}

func (f *fixture) credentialFile() string {
	return filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url")
}

func (f *fixture) agentRole(t *testing.T) string {
	t.Helper()
	role, err := f.db.Names.Agent("demo_bot")
	require.NoError(t, err)
	return role
}

func TestDoctorReportsAnInstalledAgent(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	got, err := svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	var db string
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT pg_catalog.current_database()::text`).Scan(&db))
	require.Equal(t, db, got.Database)
	require.Nil(t, got.Login)
	require.Equal(t, localsetup.StateCurrent, got.Guard.State)
	require.Equal(t, localsetup.StateOK, got.Certificate.State)
	require.Equal(t, localsetup.StateUnlabeled, got.Labels.State, "the demo install labels nothing")
	require.Positive(t, got.Labels.Count)
	require.Contains(t, got.Labels.Columns, "basalt_demo.leads.email")
	require.Equal(t, localsetup.StateOK, got.Passkeys.State)
	require.Len(t, got.Passkeys.Items, 1)
	k := got.Passkeys.Items[0]
	require.Equal(t, "laptop", k.Label)
	require.Equal(t, "localhost", k.RPID)
	require.Equal(t, origin, k.Origin)
	require.NotEmpty(t, k.CredentialID)
	require.Nil(t, k.LastUsedAt)
}

func TestDoctorRefusesWhatIsNotTheEnginesAgent(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		req  localsetup.DoctorRequest
		code string
	}{
		"another agent":   {localsetup.DoctorRequest{Agent: "sales_bot", OSUser: "alice"}, localsetup.CodeInvalidArgument},
		"another OS user": {localsetup.DoctorRequest{Agent: "demo_bot", OSUser: "carol"}, localsetup.CodeInvalidArgument},
		"no OS user":      {localsetup.DoctorRequest{Agent: "demo_bot"}, localsetup.CodeInvalidArgument},
		"a bad name":      {localsetup.DoctorRequest{Agent: "Bad-Name", OSUser: "alice"}, localsetup.CodeInvalidArgument},
	} {
		_, err := svc.Doctor(ctx, tc.req)
		require.Error(t, err, name)
		refusal(t, err, tc.code)
	}
	// An engine with no config, and one running as root, check nothing.
	_, err := f.svc.Doctor(ctx, f.doctor())
	refusal(t, err, localsetup.CodeJobUnavailable)
	root, err := localsetup.New(localsetup.Options{Backend: setupbackend.Backend{}, ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix, Configured: true, Euid: func() int { return 0 }})
	require.NoError(t, err)
	_, err = root.Doctor(ctx, f.doctor())
	refusal(t, err, localsetup.CodeJobUnavailable)
}

// While the agent cannot log in, doctor reads nothing from the database.
func TestDoctorReadsNothingWhenTheAgentCannotLogIn(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	f.db.Exec(t, `ALTER ROLE `+f.agentRole(t)+` PASSWORD 'changed-by-someone'`)
	got, err := svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.NotNil(t, got.Login)
	require.Equal(t, "CREDENTIAL_REJECTED", got.Login.Code)
	require.Empty(t, got.Database)
	require.Equal(t, localsetup.StateUnknown, got.Labels.State)
	require.Equal(t, localsetup.StateUnknown, got.Passkeys.State)
	require.Equal(t, localsetup.StateUnknown, got.Guard.State)

	require.NoError(t, os.Remove(f.credentialFile()))
	got, err = svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.Equal(t, "CREDENTIAL_REJECTED", got.Login.Code, "a credential file that is gone")
}

func TestFixJobsTakeOnlyTheirOwnFields(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		job  string
		edit func(*localsetup.Request)
		run  bool
	}{
		"labels on a LABELS check":         {localsetup.JobLabels, func(r *localsetup.Request) { r.RestPublic = true }, false},
		"a trustRoot on LABELS":            {localsetup.JobLabels, func(r *localsetup.Request) { r.TrustRoot = strings.Repeat("a", 64) }, true},
		"a credential id on TRUST":         {localsetup.JobTrust, func(r *localsetup.Request) { r.CredentialID = "AAAA" }, false},
		"labels on REPAIR":                 {localsetup.JobRepair, func(r *localsetup.Request) { r.RestPublic = true }, true},
		"a passkey on a PASSKEY_ADD check": {localsetup.JobPasskeyAdd, func(r *localsetup.Request) { r.Passkey = &localsetup.Passkey{} }, false},
		"a challenge on PASSKEY_REMOVE":    {localsetup.JobPasskeyRemove, func(r *localsetup.Request) { r.Challenge = &localsetup.Challenge{} }, false},
		"a credential id on UPDATE":        {localsetup.JobUpdate, func(r *localsetup.Request) { r.CredentialID = "AAAA" }, false},
		"tables on a fix":                  {localsetup.JobLabels, func(r *localsetup.Request) { r.Tables = []localsetup.TablePick{} }, true},
		"a database name on a fix":         {localsetup.JobRepair, func(r *localsetup.Request) { r.ConfirmName = "app" }, true},
	} {
		req := f.fix(tc.job)
		tc.edit(&req)
		var err error
		if tc.run {
			_, err = svc.Run(ctx, req)
		} else {
			_, err = svc.Check(ctx, req)
		}
		refusal(t, err, localsetup.CodeAnswersInvalid)
		require.NotContains(t, err.Error(), "admin"+":", name)
	}
	// Each fix checks the admin string's database before anything else.
	req := f.fix(localsetup.JobLabels)
	req.DatabaseURL = unusedAdminURL
	_, err := svc.Check(ctx, req)
	refusal(t, err, localsetup.CodeTargetMismatch)
}

// TestLabelsCheckSuggestsForADottedSchema: a schema whose name holds a dot
// and a mixed-case table are read by their own names, so a domain over text
// in them is sampled and gets a suggestion.
func TestLabelsCheckSuggestsForADottedSchema(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	role := pgx.Identifier{f.agentRole(t)}.Sanitize()
	f.db.Exec(t, `CREATE DOMAIN public.mail AS text;
		CREATE SCHEMA "app.v2";
		CREATE TABLE "app.v2"."People" (id bigint PRIMARY KEY, email public.mail);
		INSERT INTO "app.v2"."People" SELECT i, 'person' || i || '@example.com' FROM generate_series(1, 20) i;
		GRANT USAGE ON SCHEMA "app.v2" TO `+role+`;
		GRANT SELECT ON "app.v2"."People" TO `+role)

	checked, err := svc.Check(ctx, f.fix(localsetup.JobLabels))
	require.NoError(t, err)
	var email *localsetup.ColumnInfo
	for i, c := range checked.Columns {
		if c.Table == "app.v2.People" && c.Column == "email" {
			email = &checked.Columns[i]
		}
	}
	require.NotNil(t, email)
	require.Equal(t, guardmodel.ClassIdentifier, email.SuggestedClass, email.Reason)
	require.Equal(t, guardmodel.EntityEmail, email.SuggestedEntityType, email.Reason)
}

// (b) A column added after the install shows in doctor and in the LABELS
// check, and the LABELS run writes it; a stale was is CLASSES_CHANGED.
func TestLabelsFixLabelsAColumnAddedAfterTheInstall(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	f.db.Exec(t, `ALTER TABLE basalt_demo.leads ADD COLUMN mobile text`)
	f.db.Exec(t, `CREATE TABLE public.hidden (id bigint PRIMARY KEY, secret text)`)

	got, err := svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.Equal(t, localsetup.StateUnlabeled, got.Labels.State)
	require.Contains(t, got.Labels.Columns, "basalt_demo.leads.mobile")
	before := got.Labels.Count

	checked, err := svc.Check(ctx, f.fix(localsetup.JobLabels))
	require.NoError(t, err)
	var mobile *localsetup.ColumnInfo
	for i, c := range checked.Columns {
		require.NotEqual(t, "public.hidden", c.Table, "only columns the agent may read")
		if c.Table == "basalt_demo.leads" && c.Column == "mobile" {
			mobile = &checked.Columns[i]
		}
	}
	require.NotNil(t, mobile)
	require.Equal(t, guardmodel.ClassUnclassified, mobile.Class)
	require.Len(t, checked.Columns, before)

	run := f.fix(localsetup.JobLabels)
	label := localsetup.ColumnClass{Table: "basalt_demo.leads", Column: "mobile", Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, PhoneRegion: "US", Was: localsetup.Label{Class: guardmodel.ClassUnclassified}}
	run.ColumnClasses = []localsetup.ColumnClass{label}
	done, err := svc.Run(ctx, run)
	require.NoError(t, err)
	require.Contains(t, strings.Join(done.Lines, " "), "1 columns labeled")
	var class, entity, region string
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT class, entity_type, phone_region FROM basalt_meta.pii_columns
		WHERE table_schema = 'basalt_demo' AND table_name = 'leads' AND column_name = 'mobile'`).Scan(&class, &entity, &region))
	require.Equal(t, []string{guardmodel.ClassIdentifier, guardmodel.EntityPhone, "US"}, []string{class, entity, region})

	// The same label again: the column's class is no longer the one shown.
	_, err = svc.Run(ctx, run)
	refusal(t, err, localsetup.CodeClassesChanged)
	// A column the agent cannot read, and a column with a class, are not listed.
	hidden := run
	hidden.ColumnClasses = []localsetup.ColumnClass{{Table: "public.hidden", Column: "secret", Class: guardmodel.ClassSecret, Was: localsetup.Label{Class: guardmodel.ClassUnclassified}}}
	_, err = svc.Run(ctx, hidden)
	refusal(t, err, localsetup.CodeAnswersInvalid)
	labeled := run
	labeled.ColumnClasses = []localsetup.ColumnClass{{Table: "basalt_demo.leads", Column: "mobile", Class: guardmodel.ClassSecret, Was: localsetup.Label{Class: guardmodel.ClassIdentifier, EntityType: guardmodel.EntityPhone, PhoneRegion: "US"}}}
	_, err = svc.Run(ctx, labeled)
	refusal(t, err, localsetup.CodeAnswersInvalid)

	got, err = svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.Equal(t, before-1, got.Labels.Count)
	require.NotContains(t, got.Labels.Columns, "basalt_demo.leads.mobile")

	// The rest as not personal: every column the agent reads with no class.
	rest := f.fix(localsetup.JobLabels)
	rest.RestPublic = true
	_, err = svc.Run(ctx, rest)
	require.NoError(t, err)
	got, err = svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.Equal(t, localsetup.StateOK, got.Labels.State)
	require.Zero(t, got.Labels.Count)
	var hiddenRows int
	require.NoError(t, f.db.Admin.QueryRow(ctx, `SELECT count(table_name)::int FROM basalt_meta.pii_columns WHERE table_name = 'hidden'`).Scan(&hiddenRows))
	require.Zero(t, hiddenRows, "restPublic marks only the agent's columns")
}

func TestPasskeyAddRegistersAnotherPasskey(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	checked, err := svc.Check(ctx, f.fix(localsetup.JobPasskeyAdd))
	require.NoError(t, err)
	require.True(t, checked.PasskeyNeeded)
	require.NotNil(t, checked.Challenge)

	run := f.fix(localsetup.JobPasskeyAdd)
	_, err = svc.Run(ctx, run)
	refusal(t, err, localsetup.CodePasskeyRequired)

	run.Challenge, run.Passkey = checked.Challenge, register(t, *checked.Challenge)
	tampered := run
	ch := *checked.Challenge
	ch.MAC = append(passkey.Bytes{}, ch.MAC...)
	ch.MAC[0] ^= 1
	tampered.Challenge = &ch
	_, err = svc.Run(ctx, tampered)
	refusal(t, err, localsetup.CodeChallengeInvalid)

	done, err := svc.Run(ctx, run)
	require.NoError(t, err)
	require.Len(t, done.Passkeys, 1)
	require.NotEmpty(t, done.Passkeys[0].CheckCode)
	got, err := svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.Len(t, got.Passkeys.Items, 2)

	f.now = f.now.Add(time.Hour)
	_, err = svc.Run(ctx, run)
	refusal(t, err, localsetup.CodeChallengeExpired)
}

func TestRepairSetsANewPasswordForAnAgentThatCannotLogIn(t *testing.T) {
	t.Parallel()
	f, _ := installed(t)
	var told atomic.Value
	svc, err := localsetup.New(localsetup.Options{
		Backend:    setupbackend.Backend{},
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix, Configured: true,
		Now: func() time.Time { return f.now }, CredentialChanged: func(agent, password string) { told.Store(agent + ":" + password) },
	})
	require.NoError(t, err)
	ctx := context.Background()

	_, err = svc.Check(ctx, f.fix(localsetup.JobRepair))
	refusal(t, err, localsetup.CodeNothingToFix)

	f.db.Exec(t, `ALTER ROLE `+f.agentRole(t)+` PASSWORD 'changed-by-someone'`)
	checked, err := svc.Check(ctx, f.fix(localsetup.JobRepair))
	require.NoError(t, err)
	require.Contains(t, checked.Lines[0], "This sets a new password for "+f.agentRole(t))
	require.Contains(t, checked.SQL, "********")
	require.NotContains(t, checked.SQL, "SCRAM-SHA-256$")

	old, err := config.ReadCredential(f.credentialFile())
	require.NoError(t, err)
	done, err := svc.Run(ctx, f.fix(localsetup.JobRepair))
	require.NoError(t, err)
	require.NotEmpty(t, done.Lines)
	next, err := config.ReadCredential(f.credentialFile())
	require.NoError(t, err)
	require.NotEqual(t, old, next)
	u, err := url.Parse(next)
	require.NoError(t, err)
	pw, _ := u.User.Password()
	require.Equal(t, "demo_bot:"+pw, told.Load(), "the running engine is told the new password")
	for _, a := range []string{done.Lines[0], strings.Join(done.Warnings, " ")} {
		require.NotContains(t, a, pw)
	}

	got, err := svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.Nil(t, got.Login, "the agent logs in again")
	_, err = svc.Check(ctx, f.fix(localsetup.JobRepair))
	refusal(t, err, localsetup.CodeNothingToFix)
}

// trustFixture is an installed agent whose database host db.pin.example
// this engine pins, read through a fake chain.
type trustFixture struct {
	*fixture
	svc      *localsetup.Service
	adminURL string
	oldCA    *x509.Certificate
	newCA    *x509.Certificate
	chain    atomic.Pointer[[]*x509.Certificate]
	newChain []*x509.Certificate
	pinned   []*trustprofile.Profile
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	f, _ := installed(t)
	tf := &trustFixture{fixture: f}
	var oldLeaf, newLeaf *x509.Certificate
	tf.oldCA, oldLeaf = chainOf(t)
	tf.newCA, newLeaf = chainOf(t)
	tf.chain.Store(&[]*x509.Certificate{oldLeaf, tf.oldCA})
	tf.adminURL = "postgres://admin:" + mustPassword(t, f.db.URL) + "@" + pinHost + ":5432/app"
	// The agent's credential names the pinned host; the fake dial reaches
	// the test server with the real credential once the chain is pinned.
	agentURL, err := config.ReadCredential(f.credentialFile())
	require.NoError(t, err)
	u, err := url.Parse(agentURL)
	require.NoError(t, err)
	pw, _ := u.User.Password()
	pinnedCred := "postgres://" + u.User.Username() + ":" + pw + "@" + pinHost + ":5432/app?sslmode=verify-full"
	require.NoError(t, config.WriteFile(f.credentialFile(), []byte(pinnedCred+"\n")))
	_, err = trustdir.PinNew(f.config, pinHost, tf.oldCA, false)
	require.NoError(t, err)
	svc, err := localsetup.New(localsetup.Options{
		Backend:    setupbackend.Backend{},
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix, Configured: true,
		Now:      func() time.Time { return f.now },
		Profiles: func() *trustprofile.Set { return trustdir.Set(f.config) },
		Dial: func(ctx context.Context, dsn string) (localsetup.Conn, error) {
			if !strings.Contains(dsn, pinHost) {
				return setupbackend.Wrap(pgdial.Connect(ctx, dsn))
			}
			if !tf.pinHolds((*tf.chain.Load())[1]) {
				return nil, x509.UnknownAuthorityError{}
			}
			return setupbackend.Wrap(pgdial.Connect(ctx, agentURL))
		},
		DialPinned: func(ctx context.Context, _ string, pin *trustprofile.Profile) (localsetup.Conn, error) {
			tf.pinned = append(tf.pinned, pin)
			return setupbackend.Wrap(pgdial.Connect(ctx, f.db.URL))
		},
		Probe: func(_ context.Context, host string, _ int) ([]*x509.Certificate, error) {
			require.Equal(t, pinHost, host)
			return *tf.chain.Load(), nil
		},
	})
	require.NoError(t, err)
	tf.svc = svc
	// The new chain, for the tests that rotate.
	tf.newChain = []*x509.Certificate{newLeaf, tf.newCA}
	return tf
}

func chainOf(t *testing.T) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	ca, leaf := trustprofiletest.Chain(t, pinHost)
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	require.NoError(t, err)
	return ca, leafCert
}

func (tf *trustFixture) pinHolds(c *x509.Certificate) bool {
	p := trustdir.Set(tf.config).For(pinHost)
	if p == nil {
		return false
	}
	for _, have := range p.Certificates() {
		if have.Equal(c) {
			return true
		}
	}
	return false
}

func (tf *trustFixture) trust(trustRoot string) localsetup.Request {
	r := tf.fix(localsetup.JobTrust)
	r.DatabaseURL, r.TrustRoot = tf.adminURL, trustRoot
	return r
}

func recordedPins(t *testing.T, tf *trustFixture) []string {
	t.Helper()
	rows, err := tf.db.Admin.Query(context.Background(), `SELECT detail ->> 'sha256' FROM basalt_meta.ledger
		WHERE kind = 'TRUST_PIN_RECORDED' AND detail ->> 'host' = $1 AND (detail ->> 'port')::int = 5432 ORDER BY seq`, pinHost)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return out
}

// (c) A new certificate: doctor sees it without logging in, the TRUST
// check offers it with the pinned one, and the run replaces the pin file
// and records the new pin in the ledger.
func TestTrustFixReplacesThePinOfAChangedCertificate(t *testing.T) {
	t.Parallel()
	tf := newTrustFixture(t)
	ctx := context.Background()
	oldSHA, newSHA := trustprofile.DERSHA256(tf.oldCA), trustprofile.DERSHA256(tf.newCA)

	_, err := tf.svc.Check(ctx, tf.trust(""))
	refusal(t, err, localsetup.CodeNothingToFix)
	tf.pinned = nil

	tf.chain.Store(&tf.newChain)
	got, err := tf.svc.Doctor(ctx, tf.doctor())
	require.NoError(t, err)
	require.Equal(t, localsetup.StateChanged, got.Certificate.State)
	require.Equal(t, pinHost, got.Certificate.Host)
	require.Equal(t, oldSHA, got.Certificate.Pinned)
	require.Equal(t, newSHA, got.Certificate.Presented.SHA256)
	require.Equal(t, trustpin.SubjectOf(tf.oldCA), got.Certificate.PinnedSubject, "the old pin's issuer, read from its PEM in trust.d")
	require.Equal(t, "app", got.Certificate.Database, "the database the agent's credential names")
	require.False(t, got.Certificate.SameIssuer, "another key under the same name is a new issuer")
	require.Nil(t, got.Login)
	require.Equal(t, localsetup.StateUnknown, got.Labels.State, "nothing is read while the certificate changed")
	require.Equal(t, localsetup.StateUnknown, got.Passkeys.State)

	_, err = tf.svc.Check(ctx, tf.trust(""))
	var r *localsetup.RefusalError
	require.True(t, errors.As(err, &r))
	require.Equal(t, localsetup.CodeCertificateNotVerified, r.Code)
	require.Equal(t, newSHA, r.TrustRoot.SHA256)
	require.Equal(t, oldSHA, r.Pinned)
	require.Empty(t, tf.pinned, "no login before the person trusted it")

	_, err = tf.svc.Check(ctx, tf.trust(oldSHA))
	refusal(t, err, localsetup.CodeTrustRootMismatch)

	checked, err := tf.svc.Check(ctx, tf.trust(newSHA))
	require.NoError(t, err)
	require.Equal(t, []string{"This replaces the certificate BasaltDB trusts for " + pinHost + "."}, checked.Lines)
	require.Equal(t, "SELECT basalt_meta.record_trust_pin('"+pinHost+"', 5432, '"+newSHA+"');\n", checked.SQL)
	require.Len(t, tf.pinned, 1)
	require.True(t, tf.pinned[0].Certificates()[0].Equal(tf.newCA), "the login trusts the new certificate alone")
	require.False(t, tf.pinHolds(tf.newCA), "a check pins nothing")

	_, err = tf.svc.Run(ctx, tf.trust(newSHA))
	require.NoError(t, err)
	require.True(t, tf.pinHolds(tf.newCA))
	require.False(t, tf.pinHolds(tf.oldCA))
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(tf.config), "trust.d"))
	require.NoError(t, err)
	var pems []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pem") {
			pems = append(pems, e.Name())
		}
	}
	require.Equal(t, []string{"pin-db-pin-example-" + newSHA[:16] + ".pem"}, pems, "the old PEM file is removed")
	require.Equal(t, []string{newSHA}, recordedPins(t, tf))

	got, err = tf.svc.Doctor(ctx, tf.doctor())
	require.NoError(t, err)
	require.Equal(t, localsetup.StateOK, got.Certificate.State)
	require.Nil(t, got.Login)
}

// (c) The ledger names another pin than the engine's: the fix records the
// engine's pin and writes no file.
func TestTrustFixRecordsTheEnginesPinOnAMismatch(t *testing.T) {
	t.Parallel()
	tf := newTrustFixture(t)
	ctx := context.Background()
	oldSHA := trustprofile.DERSHA256(tf.oldCA)
	other := strings.Repeat("c", 64)
	require.NoError(t, guard.RecordTrustPin(ctx, tf.db.Admin, pinHost, 5432, other))

	got, err := tf.svc.Doctor(ctx, tf.doctor())
	require.NoError(t, err)
	require.Equal(t, localsetup.StateMismatch, got.Certificate.State)
	require.Equal(t, oldSHA, got.Certificate.Pinned)
	require.Equal(t, other, got.Certificate.Recorded)
	require.Equal(t, localsetup.StateUnlabeled, got.Labels.State, "a mismatch still reads the rest")

	_, err = tf.svc.Check(ctx, tf.trust(oldSHA))
	refusal(t, err, localsetup.CodeAnswersInvalid)

	checked, err := tf.svc.Check(ctx, tf.trust(""))
	require.NoError(t, err)
	require.Equal(t, oldSHA, checked.Pinned)
	require.Equal(t, other, checked.Recorded)
	require.Equal(t, "SELECT basalt_meta.record_trust_pin('"+pinHost+"', 5432, '"+oldSHA+"');\n", checked.SQL)
	require.True(t, tf.pinned[0].Certificates()[0].Equal(tf.oldCA), "the login trusts the engine's pin alone")

	before, err := os.ReadDir(filepath.Join(filepath.Dir(tf.config), "trust.d"))
	require.NoError(t, err)
	// The run carries the pin the check showed: none, or another, records
	// nothing.
	_, err = tf.svc.Run(ctx, tf.trust(""))
	refusal(t, err, localsetup.CodeTrustRootMismatch)
	stale := tf.trust("")
	stale.Pinned = strings.Repeat("d", 64)
	_, err = tf.svc.Run(ctx, stale)
	refusal(t, err, localsetup.CodeTrustRootMismatch)
	require.Equal(t, []string{other}, recordedPins(t, tf), "nothing recorded")
	onCheck := tf.trust("")
	onCheck.Pinned = oldSHA
	_, err = tf.svc.Check(ctx, onCheck)
	refusal(t, err, localsetup.CodeAnswersInvalid)
	run := tf.trust("")
	run.Pinned = checked.Pinned
	_, err = tf.svc.Run(ctx, run)
	require.NoError(t, err)
	require.Equal(t, []string{other, oldSHA}, recordedPins(t, tf))
	after, err := os.ReadDir(filepath.Join(filepath.Dir(tf.config), "trust.d"))
	require.NoError(t, err)
	require.Equal(t, len(before), len(after), "no file is written")

	_, err = tf.svc.Check(ctx, tf.trust(""))
	refusal(t, err, localsetup.CodeNothingToFix)
	got, err = tf.svc.Doctor(ctx, tf.doctor())
	require.NoError(t, err)
	require.Equal(t, localsetup.StateOK, got.Certificate.State)
}

// REPAIR with the credential file gone writes a new one for the database
// the admin string names, after the agent's role checks; the other fixes
// still need the credential.
func TestRepairWritesANewCredentialWhenTheFileIsGone(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	require.NoError(t, os.Remove(f.credentialFile()))

	_, err := svc.Check(ctx, f.fix(localsetup.JobLabels))
	refusal(t, err, localsetup.CodeSetupFailed)
	checked, err := svc.Check(ctx, f.fix(localsetup.JobRepair))
	require.NoError(t, err)
	require.Contains(t, strings.Join(checked.Lines, " "), "has no credential for demo_bot any more")
	_, statErr := os.Stat(f.credentialFile())
	require.ErrorIs(t, statErr, os.ErrNotExist, "a check writes nothing")

	_, err = svc.Run(ctx, f.fix(localsetup.JobRepair))
	require.NoError(t, err)
	dsn, err := config.ReadCredential(f.credentialFile())
	require.NoError(t, err)
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, f.agentRole(t), u.User.Username())
	got, err := svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	require.Nil(t, got.Login, "the agent logs in with the new credential")
}

// The agent's own connection string is not an admin string: a passkey fix
// made with it changes nothing.
func TestPasskeyFixesRefuseTheAgentsOwnString(t *testing.T) {
	t.Parallel()
	f, svc := installed(t)
	ctx := context.Background()
	agentURL, err := config.ReadCredential(f.credentialFile())
	require.NoError(t, err)
	got, err := svc.Doctor(ctx, f.doctor())
	require.NoError(t, err)
	id := got.Passkeys.Items[0].CredentialID

	remove := f.fix(localsetup.JobPasskeyRemove)
	remove.DatabaseURL, remove.CredentialID = agentURL, id
	_, err = svc.Check(ctx, remove)
	require.Error(t, err)
	_, err = svc.Run(ctx, remove)
	require.Error(t, err)
	add := f.fix(localsetup.JobPasskeyAdd)
	add.DatabaseURL = agentURL
	_, err = svc.Check(ctx, add)
	require.Error(t, err)
	for _, e := range []error{err} {
		require.NotContains(t, e.Error(), mustPassword(t, agentURL))
	}
	keys, err := guard.ActivePasskeys(ctx, f.db.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 1, "the passkey stays")
}
