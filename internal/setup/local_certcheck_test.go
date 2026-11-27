package setup_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/app/setupbackend"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// supabaseHost is a host the built-in supabase profile covers.
const supabaseHost = "db.abcdefghijklmnopqrst.supabase.co"

// supabaseDial dials a string that names supabaseHost at the test server
// instead, with the string's own user and password, as if the provider's
// certificate had been checked. With failVerify set, a string with
// sslmode=verify-full fails on the certificate, before anything is sent.
type supabaseDial struct {
	test       *url.URL
	failVerify atomic.Bool
}

func newSupabaseDial(t *testing.T, testURL string) *supabaseDial {
	t.Helper()
	u, err := url.Parse(testURL)
	require.NoError(t, err)
	return &supabaseDial{test: u}
}

func (d *supabaseDial) dial(ctx context.Context, dsn string) (setup.Conn, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != supabaseHost {
		return setupbackend.Wrap(pgdial.Connect(ctx, dsn))
	}
	if d.failVerify.Load() && u.Query().Get("sslmode") == "verify-full" {
		return nil, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
	}
	to := *d.test
	to.User = u.User
	return setupbackend.Wrap(pgdial.Connect(ctx, to.String()))
}

// supabaseURL is the test server's admin string as a Supabase string,
// with query (such as "?sslmode=require") appended.
func supabaseURL(t *testing.T, testURL, query string) string {
	t.Helper()
	u, err := url.Parse(testURL)
	require.NoError(t, err)
	pw, _ := u.User.Password()
	return "postgresql://" + u.User.Username() + ":" + pw + "@" + supabaseHost + ":5432" + u.Path + query
}

// A demo install with a Supabase string writes the agent's credential with
// the sslmode the page sent: verify-full after the page's Check the
// certificate (or with no sslmode, which verifies by default), require when
// the person continued without checking.
func TestInstallWithASupabaseStringWritesItsSSLMode(t *testing.T) {
	t.Parallel()
	for query, want := range map[string]string{
		"?sslmode=verify-full": "verify-full",
		"":                     "verify-full",
		"?sslmode=require":     "require",
	} {
		f := newFixture(t)
		d := newSupabaseDial(t, f.db.URL)
		svc, err := setup.NewLocal(setup.LocalOptions{
			Backend:    setupbackend.Backend{},
			ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix,
			Now: func() time.Time { return f.now }, Profiles: trustprofile.BuiltInSet, Dial: d.dial,
		})
		require.NoError(t, err)
		f.svc = svc
		req := f.request()
		req.DatabaseURL = supabaseURL(t, f.db.URL, query)
		checked, err := svc.Check(context.Background(), req)
		require.NoError(t, err, query)
		req.Challenge, req.Passkey = checked.Challenge, register(t, *checked.Challenge)
		_, err = svc.Run(context.Background(), req)
		require.NoError(t, err, query)

		cred, err := config.ReadCredential(filepath.Join(filepath.Dir(f.config), "agents", "demo_bot.url"))
		require.NoError(t, err)
		u, err := url.Parse(cred)
		require.NoError(t, err)
		require.Equal(t, supabaseHost, u.Hostname(), query)
		require.Equal(t, want, u.Query().Get("sslmode"), query)
	}
}

// certCheckFixture is an installed agent whose credential names a Supabase
// host with sslmode=require, on a service with the built-in profiles.
type certCheckFixture struct {
	*fixture
	svc     *setup.LocalService
	dial    *supabaseDial
	admin   string
	reloads atomic.Int32
}

func newCertCheckFixture(t *testing.T) *certCheckFixture {
	t.Helper()
	f, _ := installed(t)
	cred, err := config.ReadCredential(f.credentialFile())
	require.NoError(t, err)
	u, err := url.Parse(cred)
	require.NoError(t, err)
	pw, _ := u.User.Password()
	require.NoError(t, config.WriteFile(f.credentialFile(),
		[]byte("postgresql://"+u.User.Username()+":"+pw+"@"+supabaseHost+":5432"+u.Path+"?sslmode=require\n")))
	cf := &certCheckFixture{fixture: f, dial: newSupabaseDial(t, f.db.URL), admin: supabaseURL(t, f.db.URL, "?sslmode=require")}
	svc, err := setup.NewLocal(setup.LocalOptions{
		Backend:    setupbackend.Backend{},
		ConfigPath: f.config, Origin: origin, Users: fakeUsers{}, Prefix: f.db.Names.Prefix, Configured: true,
		Now: func() time.Time { return f.now }, Profiles: trustprofile.BuiltInSet, Dial: cf.dial.dial,
		Reload: func() { cf.reloads.Add(1) },
	})
	require.NoError(t, err)
	cf.svc = svc
	return cf
}

func (cf *certCheckFixture) trust() setup.Request {
	r := cf.fix(setup.JobTrust)
	r.DatabaseURL = cf.admin
	return r
}

func (cf *certCheckFixture) sslMode(t *testing.T) string {
	t.Helper()
	cred, err := config.ReadCredential(cf.credentialFile())
	require.NoError(t, err)
	u, err := url.Parse(cred)
	require.NoError(t, err)
	require.Equal(t, supabaseHost, u.Hostname())
	return u.Query().Get("sslmode")
}

// The TRUST fix of an agent whose connection does not check the
// certificate turns the check on once a login with sslmode=verify-full
// passes: a certificate that does not verify changes nothing, and a fixed
// agent has nothing left to fix.
func TestTrustFixTurnsTheCertificateCheckOn(t *testing.T) {
	t.Parallel()
	cf := newCertCheckFixture(t)
	ctx := context.Background()

	// The test server has no TLS, so the doctor's NOT_CHECKED row, which
	// reads the login's TLS, is TestUncheckedCredential's.
	checked, err := cf.svc.Check(ctx, cf.trust())
	require.NoError(t, err)
	require.Len(t, checked.Lines, 1)
	require.Contains(t, checked.Lines[0], "from sslmode=require to sslmode=verify-full")
	require.Equal(t, "require", cf.sslMode(t), "a check changes nothing")

	withRoot := cf.trust()
	withRoot.TrustRoot = strings.Repeat("a", 64)
	_, err = cf.svc.Check(ctx, withRoot)
	refusal(t, err, setup.CodeAnswersInvalid)

	cf.dial.failVerify.Store(true)
	_, err = cf.svc.Run(ctx, cf.trust())
	refusal(t, err, setup.CodeCertificateNotVerified)
	require.Contains(t, err.Error(), "didn't match Supabase's, so nothing was sent")
	require.Equal(t, "require", cf.sslMode(t), "a certificate that does not verify changes nothing")
	require.Zero(t, cf.reloads.Load())

	cf.dial.failVerify.Store(false)
	done, err := cf.svc.Run(ctx, cf.trust())
	require.NoError(t, err)
	require.Contains(t, done.Lines[0], "now checks the certificate")
	require.Equal(t, "verify-full", cf.sslMode(t))
	require.Equal(t, int32(1), cf.reloads.Load(), "the engine serves the new credential")

	got, err := cf.svc.Doctor(ctx, cf.doctor())
	require.NoError(t, err)
	require.Nil(t, got.Login, "the agent logs in with the new credential")
	require.Equal(t, setup.StateOK, got.Certificate.State)
	_, err = cf.svc.Check(ctx, cf.trust())
	refusal(t, err, setup.CodeNothingToFix)
}
