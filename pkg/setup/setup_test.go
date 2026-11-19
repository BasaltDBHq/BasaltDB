package setup_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

const engineAddr = "https://engine.example.com"

// newCode is a setup code for d's database, made as basalt init --remote
// makes one: an INSTALL code for agent bot writing public.leads, changed
// by edit.
func newCode(t *testing.T, d *guardtest.DB, edit func(p *setupcode.Payload)) string {
	t.Helper()
	u, err := url.Parse(d.URL)
	require.NoError(t, err)
	target, err := setupcode.TargetOf(u)
	require.NoError(t, err)
	id, expires, err := setupcode.NewSetupID(time.Now(), rand.Reader)
	require.NoError(t, err)
	verifier, err := setupcode.NewVerifier("not-a-real-password")
	require.NoError(t, err)
	p := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: setupcode.KindInstall, Prefix: d.Names.Prefix, Target: target,
		Guard: setupcode.Guard{From: 0, To: guard.LatestVersion()}, Build: "1.0.0", ExpiresAt: expires,
		Agent: &setupcode.Agent{Name: "bot", Write: []string{"public.leads"}, Verifier: verifier, StatementTimeoutMs: 30000},
	}
	if edit != nil {
		edit(&p)
	}
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	return code
}

// engineKey is a fresh engine signing key as a setup code carries it, and
// its engine id.
func engineKey(t *testing.T) (*setupcode.Engine, []byte, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(der)}, der, channel.EngineIDOf(der)
}

func request(code string) setup.Request { return setup.Request{Code: code, Now: time.Now()} }

// personPasskey is the person's portal passkey, registered through the
// package's request and verified by it.
func personPasskey(t *testing.T, database string) (*passkeytest.Authenticator, func(context.Context) (setup.Passkey, error)) {
	t.Helper()
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	return person, func(context.Context) (setup.Passkey, error) {
		req, err := setup.NewPasskeyRequest(rand.Reader, database+" · bot", database)
		if err != nil {
			return setup.Passkey{}, err
		}
		link, err := req.Link()
		if err != nil {
			return setup.Passkey{}, err
		}
		_, frag, _ := strings.Cut(link, "#")
		page, err := passkey.ParseRegistrationRequest(frag)
		if err != nil {
			return setup.Passkey{}, err
		}
		resp, err := person.Register(page, nil)
		if err != nil {
			return setup.Passkey{}, err
		}
		code, err := resp.Code()
		if err != nil {
			return setup.Passkey{}, err
		}
		return req.Verify(code)
	}
}

func codeOf(t *testing.T, err error) string {
	t.Helper()
	var e *setup.Error
	require.ErrorAs(t, err, &e)
	return e.Code
}

func installedVersion(t *testing.T, d *guardtest.DB) int {
	t.Helper()
	v, err := guard.InstalledVersion(context.Background(), d.Admin)
	require.NoError(t, err)
	return v
}

func TestDescribe(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	code := newCode(t, d, nil)
	desc, err := setup.Describe(request("  " + code[:30] + "\n" + code[30:]))
	require.NoError(t, err)
	require.Equal(t, setup.KindInstall, desc.Kind)
	require.Equal(t, "bot", desc.Agent)
	require.Equal(t, d.Names.Prefix+"_agent_bot", desc.AgentRole)
	require.Equal(t, []string{"public.leads"}, desc.Write)
	require.Contains(t, desc.Summary, "Setup fingerprint: "+desc.Fingerprint+". Check that bot shows the same fingerprint.")
	require.Empty(t, desc.EngineFingerprint)

	_, err = setup.Describe(setup.Request{Code: code, Now: desc.ExpiresAt})
	require.Equal(t, "EXPIRED", codeOf(t, err))
	_, err = setup.Describe(request("hello"))
	require.Equal(t, "NOT_A_SETUP_CODE", codeOf(t, err))
	_, err = setup.Describe(setup.Request{Code: code, Now: time.Now(), EngineURL: engineAddr})
	require.Equal(t, setup.CodeEngineKeyMissing, codeOf(t, err))
	_, err = setup.Describe(setup.Request{Code: "hello", Now: time.Now(), EngineURL: "http://engine.example.com"})
	require.Equal(t, setup.CodeEngineURLInvalid, codeOf(t, err), "the address is checked before anything else")
}

func TestCheckThenRunInstalls(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	d.Exec(t, `ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY; INSERT INTO public.payroll VALUES (1, 10), (2, 20)`)
	code := newCode(t, d, func(p *setupcode.Payload) {
		p.Agent.Read = []string{"public.payroll", "crm_app.accounts"}
	})
	d.Exec(t, `CREATE SCHEMA crm_app; CREATE TABLE crm_app.accounts (id bigint PRIMARY KEY)`)

	checked, err := setup.Check(ctx, d.Admin, request(code))
	require.NoError(t, err)
	require.Nil(t, checked.NothingToDo)
	require.True(t, checked.PasskeyNeeded, "no guard yet, so no passkey")
	require.Len(t, checked.Questions.RowSecurity, 1)
	q := checked.Questions.RowSecurity[0]
	require.Equal(t, "public.payroll", q.Table)
	require.Equal(t, int64(2), q.Rows)
	require.Equal(t, "public.payroll hides its rows with row-level security. Let bot see all 2 rows of this table?", q.Text)
	require.Equal(t, []string{"crm_app.accounts"}, checked.Questions.OutsidePublic)
	require.Contains(t, checked.Summary[0], "This creates the agent bot")
	require.Zero(t, installedVersion(t, d), "Check changes nothing")

	person, give := personPasskey(t, "db")
	var shown setup.Plan
	committed := 0
	res, err := setup.Run(ctx, d.Admin, request(code), setup.RunInput{
		Answers:   setup.Answers{AllRows: []string{"public.payroll"}},
		Approve:   func(p setup.Plan) error { shown = p; return nil },
		Committed: func(setup.Result) { committed++ },
		Passkey:   give,
	})
	require.NoError(t, err)
	require.True(t, res.Ran)
	require.Equal(t, 1, committed)
	require.Contains(t, shown.SQL, "basalt_meta.record_setup(")
	require.NotNil(t, res.Passkey)
	require.Equal(t, person.ID, res.Passkey.CredentialID)
	require.Equal(t, "basaltvault.app", res.Passkey.RPID)

	require.Equal(t, guard.LatestVersion(), installedVersion(t, d))
	setups, err := guard.SetupsFor(ctx, d.Admin, uuid.MustParse(checked.Description.SetupID), "")
	require.NoError(t, err)
	require.Len(t, setups, 1, "record_setup ran")
	keys, err := guard.ActivePasskeys(ctx, d.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	var policies int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1) FROM pg_policies WHERE tablename = 'payroll'`).Scan(&policies))
	require.Equal(t, 1, policies, "the answer added the agent's policy")

	// The same code again: refused by Check and by Run alone, alike.
	_, err = setup.Check(ctx, d.Admin, request(code))
	require.Equal(t, "USED", codeOf(t, err))
	_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.Equal(t, "USED", codeOf(t, err))
	require.Contains(t, err.Error(), "This setup code was already used on ")
}

// Run stands alone: each refusal of Describe and Check comes from Run in
// the same order, with nothing changed.
func TestRunRefusesInTheContractsOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	other := guardtest.New(t)
	expired := func(p *setupcode.Payload) { p.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) }

	for name, tc := range map[string]struct {
		code   string
		engine string
		in     setup.RunInput
		want   string
	}{
		"not a code":                {code: "hello", want: "NOT_A_SETUP_CODE"},
		"bad engine address first":  {code: "hello", engine: "https://127.0.0.1", want: setup.CodeEngineURLInvalid},
		"expired before the target": {code: newCode(t, other, expired), want: "EXPIRED"},
		"engine key missing":        {code: newCode(t, d, nil), engine: engineAddr, want: setup.CodeEngineKeyMissing},
		"another database": {code: newCode(t, other, func(p *setupcode.Payload) {
			p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
		}), want: setup.CodeTargetMismatch},
		"role missing": {code: newCode(t, d, func(p *setupcode.Payload) {
			p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
		}), want: "ROLE_MISSING"},
		"table missing": {code: newCode(t, d, func(p *setupcode.Payload) {
			p.Agent.Write = []string{"public.nope"}
		}), want: setup.CodeTablesMissing},
		"an answer not asked": {
			code: newCode(t, d, nil), in: setup.RunInput{Answers: setup.Answers{AllRows: []string{"public.leads"}}},
			want: setup.CodeUnknownAnswer,
		},
		"an engine not asked about": {
			code: newCode(t, d, nil), in: setup.RunInput{Answers: setup.Answers{Revoke: []string{"x"}}},
			want: setup.CodeUnknownAnswer,
		},
	} {
		approved := false
		tc.in.Approve = func(setup.Plan) error { approved = true; return nil }
		req := setup.Request{Code: tc.code, Now: time.Now(), EngineURL: tc.engine}
		_, err := setup.Run(ctx, d.Admin, req, tc.in)
		require.Equal(t, tc.want, codeOf(t, err), name)
		require.False(t, approved, name)
		if tc.want != setup.CodeUnknownAnswer {
			_, cerr := setup.Check(ctx, d.Admin, req)
			require.Equal(t, tc.want, codeOf(t, cerr), "%s: Check refuses alike", name)
		}
	}
	require.Zero(t, installedVersion(t, d))
	require.Zero(t, installedVersion(t, other))
}

func TestRunRefusesByTheDatabasesState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	_, give := personPasskey(t, "db")
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: give})
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		edit func(p *setupcode.Payload)
		want string
	}{
		"prefix":      {func(p *setupcode.Payload) { p.Prefix = "other" }, "PREFIX_MISMATCH"},
		"role exists": {nil, "ROLE_EXISTS"},
	} {
		_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, tc.edit)), setup.RunInput{})
		require.Equal(t, tc.want, codeOf(t, err), name)
	}

	// A revoked engine is refused, after the role checks.
	eng, der, id := engineKey(t)
	_, err = guard.RecordEngine(ctx, d.Admin, der, nil)
	require.NoError(t, err)
	_, err = guard.RevokeEngine(ctx, d.Admin, id)
	require.NoError(t, err)
	install := newCode(t, d, func(p *setupcode.Payload) { p.Engine = eng })
	_, err = setup.Run(ctx, d.Admin, request(install), setup.RunInput{})
	require.Equal(t, "ROLE_EXISTS", codeOf(t, err), "the role checks come first")
	change := newCode(t, d, func(p *setupcode.Payload) { p.Kind, p.Agent.Verifier, p.Engine = setupcode.KindAgent, "", eng })
	_, err = setup.Run(ctx, d.Admin, request(change), setup.RunInput{})
	require.Equal(t, setup.CodeEngineRevoked, codeOf(t, err))
}

func TestRunRevokesOnlyWhatWasAsked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	_, give := personPasskey(t, "db")
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: give})
	require.NoError(t, err)
	_, oldDER, oldID := engineKey(t)
	addr := engineAddr
	_, err = guard.RecordEngine(ctx, d.Admin, oldDER, &addr)
	require.NoError(t, err)

	eng, _, newID := engineKey(t)
	code := newCode(t, d, func(p *setupcode.Payload) { p.Kind, p.Agent.Verifier, p.Engine = setupcode.KindAgent, "", eng })
	req := setup.Request{Code: code, Now: time.Now(), EngineURL: engineAddr + "/"}
	checked, err := setup.Check(ctx, d.Admin, req)
	require.NoError(t, err)
	require.False(t, checked.PasskeyNeeded)
	require.Len(t, checked.Questions.Revoke, 1)
	require.Equal(t, oldID, checked.Questions.Revoke[0].EngineID)
	require.Equal(t, "This records engine "+channel.FingerprintOf(newID)+" for bot. Its address: "+engineAddr+".", checked.EngineLines[0])

	res, err := setup.Run(ctx, d.Admin, req, setup.RunInput{Answers: setup.Answers{Revoke: []string{oldID}}})
	require.NoError(t, err)
	require.True(t, res.EngineRecorded)
	require.Nil(t, res.Passkey, "a portal passkey is registered already")
	engines, err := guard.Engines(ctx, d.Admin, true)
	require.NoError(t, err)
	for _, e := range engines {
		require.Equal(t, e.ID == oldID, e.RevokedAt != nil, e.ID)
	}
}

func TestRunStopsWhenNotApproved(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	stop := errors.New("not now")
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Approve: func(setup.Plan) error { return stop }})
	require.ErrorIs(t, err, stop)
	require.Zero(t, installedVersion(t, d))
}

func TestRunWithoutTheNeededPasskey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	res, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{})
	require.Equal(t, setup.CodePasskeyNotRegistered, codeOf(t, err))
	require.True(t, res.Ran, "the setup ran")
	require.Contains(t, err.Error(), "the setup ran but no passkey was registered")

	// A Passkey that Verify did not make is refused.
	res, err = setup.Run(ctx, d.Admin, request(newCode(t, d, func(p *setupcode.Payload) {
		p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
	})), setup.RunInput{Passkey: func(context.Context) (setup.Passkey, error) { return setup.Passkey{}, nil }})
	require.Equal(t, setup.CodePasskeyNotRegistered, codeOf(t, err))
	require.True(t, res.Ran)
}

// No message carries the connection's password or parameters.
func TestMessagesCarryNoConnectionSecret(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	other := guardtest.New(t)
	// The admin logs in with a planted password and parameter.
	const marker = "planted-marker-7f3a"
	role := other.Names.Prefix + "_marker"
	other.Exec(t, "CREATE ROLE "+role+" LOGIN SUPERUSER PASSWORD '"+marker+"'")
	u, err := url.Parse(other.URL)
	require.NoError(t, err)
	u.User = url.UserPassword(role, marker)
	q := u.Query()
	q.Set("application_name", marker+"-app")
	u.RawQuery = q.Encode()
	conn, err := pgdial.Connect(ctx, u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })

	var out []string
	note := func(_ any, err error) {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	note(setup.Check(ctx, conn, request(newCode(t, d, nil))))
	note(setup.Run(ctx, conn, request(newCode(t, d, nil)), setup.RunInput{}))
	note(setup.Run(ctx, conn, request(newCode(t, other, func(p *setupcode.Payload) { p.Agent.Write = []string{"public.nope"} })), setup.RunInput{}))
	note(setup.Run(ctx, conn, request(newCode(t, other, nil)), setup.RunInput{}))
	require.Len(t, out, 4)
	for _, msg := range out {
		require.NotContains(t, msg, marker)
	}
	require.Contains(t, out[0], "Your admin connection string points at database ")
}
