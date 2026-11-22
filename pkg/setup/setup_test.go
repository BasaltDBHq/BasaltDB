package setup_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
		Format: setupcode.Format, SetupID: id, Kind: setupcode.KindInstall, Prefix: d.Names.Prefix, Target: &target,
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
func personPasskey(t *testing.T) (*passkeytest.Authenticator, func(context.Context) (setup.Passkey, error)) {
	t.Helper()
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	return person, func(context.Context) (setup.Passkey, error) {
		req, err := setup.NewPasskeyRequest(rand.Reader, "db · bot", "db")
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

// verified is the person's passkey, verified, for RunInput.Passkey.
func verified(t *testing.T, give func(context.Context) (setup.Passkey, error)) *setup.Passkey {
	t.Helper()
	pk, err := give(context.Background())
	require.NoError(t, err)
	return &pk
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
	require.Equal(t, setup.Connected{Database: d.Admin.Config().Database, User: d.Admin.Config().User}, checked.Connected, "the confirm step names what the server says it reached")
	require.Len(t, checked.Questions.RowSecurity, 1)
	q := checked.Questions.RowSecurity[0]
	require.Equal(t, "public.payroll", q.Table)
	require.Equal(t, int64(2), q.Rows)
	require.Equal(t, "public.payroll hides its rows with row-level security. Let bot see all 2 rows of this table?", q.Text)
	require.Equal(t, []string{"crm_app.accounts"}, checked.Questions.OutsidePublic)
	require.Contains(t, checked.Summary[0], "This creates the agent bot")
	require.Zero(t, installedVersion(t, d), "Check changes nothing")

	person, give := personPasskey(t)
	var shown setup.Plan
	committed := 0
	res, err := setup.Run(ctx, d.Admin, request(code), setup.RunInput{
		Answers:   setup.Answers{AllRows: []string{"public.payroll"}},
		Approve:   func(p setup.Plan) error { shown = p; return nil },
		Committed: func(setup.Result) { committed++ },
		Passkey:   verified(t, give),
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
		code    string
		in      setup.RunInput
		want    string
		runOnly bool
	}{
		"not a code":                {code: "hello", want: "NOT_A_SETUP_CODE"},
		"expired before the target": {code: newCode(t, other, expired), want: "EXPIRED"},
		"a passkey Verify did not make, before the target": {
			code: newCode(t, other, nil), in: setup.RunInput{Passkey: &setup.Passkey{}}, want: setup.CodePasskeyInvalid, runOnly: true,
		},
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
			want: setup.CodeAnswersInvalid, runOnly: true,
		},
	} {
		approved := false
		tc.in.Approve = func(setup.Plan) error { approved = true; return nil }
		req := setup.Request{Code: tc.code, Now: time.Now()}
		_, err := setup.Run(ctx, d.Admin, req, tc.in)
		require.Equal(t, tc.want, codeOf(t, err), name)
		require.False(t, approved, name)
		if !tc.runOnly {
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
	_, give := personPasskey(t)
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: verified(t, give)})
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
	_, err = guard.RecordEngine(ctx, d.Admin, der)
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

// A code's engine is recorded by its key alone; the other engines the
// database records are left as they are.
func TestRunRecordsTheEngine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	_, give := personPasskey(t)
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	_, oldDER, oldID := engineKey(t)
	_, err = guard.RecordEngine(ctx, d.Admin, oldDER)
	require.NoError(t, err)

	eng, _, newID := engineKey(t)
	code := newCode(t, d, func(p *setupcode.Payload) { p.Kind, p.Agent.Verifier, p.Engine = setupcode.KindAgent, "", eng })
	checked, err := setup.Check(ctx, d.Admin, request(code))
	require.NoError(t, err)
	require.False(t, checked.PasskeyNeeded)
	require.Equal(t, "This records engine "+channel.FingerprintOf(newID)+" for bot.", checked.EngineLines[0])

	res, err := setup.Run(ctx, d.Admin, request(code), setup.RunInput{})
	require.NoError(t, err)
	require.True(t, res.EngineRecorded)
	require.Nil(t, res.Passkey, "a portal passkey is registered already")
	engines, err := guard.Engines(ctx, d.Admin, true)
	require.NoError(t, err)
	require.Len(t, engines, 2)
	for _, e := range engines {
		require.Nil(t, e.RevokedAt, e.ID)
	}
	require.Contains(t, []string{engines[0].ID, engines[1].ID}, oldID)
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

// With no passkey given, a setup that needs one is refused in its
// transaction: nothing changes.
func TestRunWithoutTheNeededPasskey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	committed := false
	res, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Committed: func(setup.Result) { committed = true }})
	require.Equal(t, setup.CodePasskeyRequired, codeOf(t, err))
	require.Contains(t, err.Error(), "nothing changed")
	require.False(t, res.Ran)
	require.False(t, committed)
	require.Zero(t, installedVersion(t, d), "the migrations rolled back")
	require.False(t, roleExists(t, d, d.Names.Prefix+"_agent_bot"))

	// AddPasskey asks for one even when the database has one.
	_, give := personPasskey(t)
	_, err = setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	change := func() string {
		return newCode(t, d, func(p *setupcode.Payload) { p.Kind, p.Agent.Verifier = setupcode.KindAgent, "" })
	}
	_, err = setup.Run(ctx, d.Admin, request(change()), setup.RunInput{AddPasskey: true})
	require.Equal(t, setup.CodePasskeyRequired, codeOf(t, err))

	// Passkey and AskPasskey together are a mistake, refused before anything.
	_, err = setup.Run(ctx, d.Admin, request(change()), setup.RunInput{Passkey: verified(t, give), AskPasskey: give})
	require.Error(t, err)
}

// The laptop's passkey step comes after the setup committed: when it
// fails, the setup has run and Run says so.
func TestRunAsksForThePasskeyAfterCommitting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	var order []string
	res, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{
		Committed: func(setup.Result) { order = append(order, "committed") },
		AskPasskey: func(context.Context) (setup.Passkey, error) {
			order = append(order, "asked")
			return setup.Passkey{}, errors.New("no code pasted")
		},
	})
	require.Equal(t, setup.CodePasskeyNotRegistered, codeOf(t, err))
	require.Contains(t, err.Error(), "the setup ran but no passkey was registered")
	require.True(t, res.Ran, "the setup ran")
	require.Equal(t, []string{"committed", "asked"}, order)

	// A Passkey that Verify did not make is refused.
	res, err = setup.Run(ctx, d.Admin, request(newCode(t, d, func(p *setupcode.Payload) {
		p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
	})), setup.RunInput{AskPasskey: func(context.Context) (setup.Passkey, error) { return setup.Passkey{}, nil }})
	require.Equal(t, setup.CodePasskeyNotRegistered, codeOf(t, err))
	require.True(t, res.Ran)

	// The person's passkey, asked for and registered.
	person, give := personPasskey(t)
	res, err = setup.Run(ctx, d.Admin, request(newCode(t, d, func(p *setupcode.Payload) {
		p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
	})), setup.RunInput{AskPasskey: give})
	require.NoError(t, err)
	require.Equal(t, person.ID, res.Passkey.CredentialID)
}

// A passkey the database refuses to register rolls the whole setup back:
// no role, no grant, no setup record.
func TestRunRollsBackWhenThePasskeyIsNotRegistered(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	person, give := personPasskey(t)
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	// The person revokes that passkey: the database never takes it again.
	_, err = guard.RevokePasskey(ctx, d.Admin, person.ID, true)
	require.NoError(t, err)

	code := newCode(t, d, func(p *setupcode.Payload) { p.Agent.Name = "helper" })
	desc, err := setup.Describe(request(code))
	require.NoError(t, err)
	committed := false
	res, err := setup.Run(ctx, d.Admin, request(code), setup.RunInput{
		Passkey: verified(t, give), Committed: func(setup.Result) { committed = true },
	})
	require.Equal(t, setup.CodeSetupFailed, codeOf(t, err))
	require.Contains(t, err.Error(), "this passkey was revoked")
	require.False(t, res.Ran)
	require.Nil(t, res.Passkey)
	require.False(t, committed)

	role := desc.AgentRole
	require.False(t, roleExists(t, d, role), "no role")
	var grants int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1) FROM information_schema.role_table_grants WHERE grantee = $1`, role).Scan(&grants))
	require.Zero(t, grants, "no grant")
	setups, err := guard.SetupsFor(ctx, d.Admin, uuid.MustParse(desc.SetupID), role)
	require.NoError(t, err)
	require.Empty(t, setups, "no setup record")
	keys, err := guard.ActivePasskeys(ctx, d.Admin)
	require.NoError(t, err)
	require.Empty(t, keys)
}

func roleExists(t *testing.T, d *guardtest.DB, role string) bool {
	t.Helper()
	var ok bool
	require.NoError(t, d.Admin.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1)`, role).Scan(&ok))
	return ok
}

// A service rebuilds the request of the challenge it issued and verifies
// the browser's answer against it; an answer to another challenge fails.
func TestPasskeyRequestForAChallenge(t *testing.T) {
	t.Parallel()
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	issue := func() setup.PasskeyChallenge {
		c := setup.PasskeyChallenge{Challenge: make([]byte, 32), UserID: make([]byte, 16), UserName: "db", DisplayName: "BasaltDB · db"}
		_, err := rand.Read(c.Challenge)
		require.NoError(t, err)
		_, err = rand.Read(c.UserID)
		require.NoError(t, err)
		return c
	}
	answer := func(c setup.PasskeyChallenge) string {
		page, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
		require.NoError(t, err)
		resp, err := person.Register(page, nil)
		require.NoError(t, err)
		code, err := resp.Code()
		require.NoError(t, err)
		return code
	}
	issued, other := issue(), issue()
	req, err := setup.PasskeyRequestFor(issued, "db · bot")
	require.NoError(t, err)
	code := answer(issued)
	issued.Challenge[0] ^= 0xff // the request holds its own copy
	_, err = req.Verify(code)
	require.NoError(t, err)
	_, err = req.Verify(answer(other))
	require.Error(t, err, "an answer to another challenge")

	for name, edit := range map[string]func(c *setup.PasskeyChallenge){
		"short challenge": func(c *setup.PasskeyChallenge) { c.Challenge = c.Challenge[:31] },
		"long user id":    func(c *setup.PasskeyChallenge) { c.UserID = append(c.UserID, 0) },
		"no user name":    func(c *setup.PasskeyChallenge) { c.UserName = "" },
	} {
		c := issue()
		edit(&c)
		_, err := setup.PasskeyRequestFor(c, "label")
		require.Error(t, err, name)
	}
	_, err = setup.PasskeyRequestFor(issue(), "")
	require.Error(t, err, "no label")
	_, err = setup.PasskeyRequestFor(issue(), strings.Repeat("x", 65))
	require.Error(t, err, "a label over 64 bytes")
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
	require.Len(t, out, 3)
	require.Contains(t, out[0], "Your admin connection string points at database ")

	// A transaction that fails inside Run: the role appears after Check.
	other.Exec(t, guardtest.Demo)
	code := newCode(t, other, func(p *setupcode.Payload) { p.Agent.Read = []string{"public.payroll"} })
	other.Exec(t, `ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY`)
	checked, err := setup.Check(ctx, conn, request(code))
	require.NoError(t, err)
	out = append(out, checked.Summary...)
	for _, q := range checked.Questions.RowSecurity {
		out = append(out, q.Text)
	}
	_, err = setup.Run(ctx, conn, request(code), setup.RunInput{Approve: func(p setup.Plan) error {
		out = append(out, p.SQL)
		other.Exec(t, "CREATE ROLE "+other.Names.Prefix+"_agent_bot NOLOGIN")
		return nil
	}})
	require.Equal(t, setup.CodeSetupFailed, codeOf(t, err))
	require.Contains(t, err.Error(), "already exists")
	require.Zero(t, installedVersion(t, other), "the transaction rolled back")
	note(nil, err)

	// A run that goes through, with its warnings.
	other.Exec(t, "DROP ROLE "+other.Names.Prefix+"_agent_bot")
	_, give := personPasskey(t)
	res, err := setup.Run(ctx, conn, request(newCode(t, other, func(p *setupcode.Payload) { p.Agent.Read = []string{"public.payroll"} })), setup.RunInput{
		Approve: func(p setup.Plan) error { out = append(out, p.SQL); out = append(out, p.Warnings...); return nil },
		Passkey: verified(t, give),
	})
	require.True(t, res.Ran)
	require.NotEmpty(t, res.Warnings, "payroll stays hidden")
	out = append(out, res.Warnings...)
	note(nil, err)

	for _, msg := range out {
		require.NotContains(t, msg, marker)
		require.NotContains(t, msg, "postgres://")
		require.NotContains(t, msg, "postgresql://")
	}
}

// UPGRADE codes: one that runs, then one with nothing to do, which Run
// alone recognizes and records nothing for.
func TestRunUpgrade(t *testing.T) {
	ctx := context.Background()
	guardtest.NextVersion(t, false) // a breaking version 2: the build has one version
	d := guardtest.New(t).WithDemo(t)
	_, give := personPasskey(t)
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	latest := guard.LatestVersion()
	d.Exec(t, `DELETE FROM basalt_meta.schema_version WHERE version = `+strconv.Itoa(latest))

	upgrade := func() string {
		return newCode(t, d, func(p *setupcode.Payload) {
			p.Kind, p.Agent, p.Guard = setupcode.KindUpgrade, nil, setupcode.Guard{From: latest - 1, To: latest}
		})
	}
	checked, err := setup.Check(ctx, d.Admin, request(upgrade()))
	require.NoError(t, err)
	require.Contains(t, checked.Summary, fmt.Sprintf("This upgrades Basalt's guard from version %d to %d; no agent changes.", latest-1, latest))
	res, err := setup.Run(ctx, d.Admin, request(upgrade()), setup.RunInput{})
	require.NoError(t, err)
	require.True(t, res.Ran)
	require.Equal(t, latest, installedVersion(t, d))

	nothing := upgrade()
	_, err = setup.Run(ctx, d.Admin, request(nothing), setup.RunInput{Answers: setup.Answers{AllRows: []string{"public.leads"}}})
	require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, err), "nothing is asked, so no answer is taken")
	res, err = setup.Run(ctx, d.Admin, request(nothing), setup.RunInput{Approve: func(setup.Plan) error { return errors.New("nothing to approve") }})
	require.NoError(t, err)
	require.False(t, res.Ran)
	require.Equal(t, &setup.NothingToDo{Installed: latest, To: latest}, res.NothingToDo)
	desc, err := setup.Describe(request(nothing))
	require.NoError(t, err)
	setups, err := guard.SetupsFor(ctx, d.Admin, uuid.MustParse(desc.SetupID), "")
	require.NoError(t, err)
	require.Empty(t, setups, "nothing recorded")
}

func TestRunRefusesASupersededCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	_, give := personPasskey(t)
	_, err := setup.Run(ctx, d.Admin, request(newCode(t, d, nil)), setup.RunInput{Passkey: verified(t, give)})
	require.NoError(t, err)
	change := func(made time.Time) string {
		return newCode(t, d, func(p *setupcode.Payload) {
			p.Kind, p.Agent.Verifier = setupcode.KindAgent, ""
			id, expires, err := setupcode.NewSetupID(made, rand.Reader)
			require.NoError(t, err)
			p.SetupID, p.ExpiresAt = id, expires
		})
	}
	older := change(time.Now().Add(-time.Minute))
	_, err = setup.Run(ctx, d.Admin, request(change(time.Now())), setup.RunInput{})
	require.NoError(t, err)
	_, err = setup.Run(ctx, d.Admin, request(older), setup.RunInput{})
	require.Equal(t, "SUPERSEDED", codeOf(t, err))
}

// The contract's invalid codes are refused by Describe with their refusal.
func TestDescribeRefusesTheInvalidFixtures(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "api", "mcp", "setup", "setup-code.fixtures.json"))
	require.NoError(t, err)
	var fixtures struct {
		Invalid []struct {
			Name    string `json:"name"`
			Code    string `json:"code"`
			Refusal string `json:"refusal"`
		} `json:"invalid"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixtures))
	require.NotEmpty(t, fixtures.Invalid)
	for _, f := range fixtures.Invalid {
		_, err := setup.Describe(request(f.Code))
		require.Equal(t, f.Refusal, codeOf(t, err), f.Name)
	}
}

// TestCheckAsksOnlyAboutTheAgentsRLSTables: the connect page's row-level
// security questions are the agent's own tables. A table the agents group
// can already SELECT through PUBLIC, with RLS as the only barrier, is not
// asked about when the code lists no read tables, and an answer naming it
// is refused.
func TestCheckAsksOnlyAboutTheAgentsRLSTables(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	d.Init(t, guard.AgentSpec{Name: "other", Password: guard.NewPassword(), Read: []string{"public.lead_notes"}})
	d.Exec(t, `ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
		ALTER TABLE public.payroll ENABLE ROW LEVEL SECURITY;
		GRANT SELECT ON public.payroll TO PUBLIC`)
	code := newCode(t, d, nil) // bot writes public.leads and reads nothing

	checked, err := setup.Check(ctx, d.Admin, request(code))
	require.NoError(t, err)
	asked := make([]string, 0, len(checked.Questions.RowSecurity))
	for _, q := range checked.Questions.RowSecurity {
		asked = append(asked, q.Table)
	}
	require.Equal(t, []string{"public.leads"}, asked)

	_, err = setup.Run(ctx, d.Admin, request(code), setup.RunInput{Answers: setup.Answers{AllRows: []string{"public.leads", "public.payroll"}}})
	require.Equal(t, setup.CodeAnswersInvalid, codeOf(t, err))
	var payroll int
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT count(1)::int FROM pg_policy WHERE polrelid = 'public.payroll'::regclass`).Scan(&payroll))
	require.Zero(t, payroll)
}
