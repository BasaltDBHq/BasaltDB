package trustprofile_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

const (
	supabaseHost = "db.abcdefghijklmnopqrst.supabase.co"
	rdsHost      = "mydb.cluster-c9akciq32xyz.eu-central-1.rds.amazonaws.com"
)

const connectTimeout = 10 * time.Second

func name(p *trustprofile.Profile) string {
	if p == nil {
		return ""
	}
	return p.Name
}

func TestBuiltInMatch(t *testing.T) {
	t.Parallel()
	set := trustprofile.BuiltInSet()
	for host, want := range map[string]string{
		"db.abcdefghijklmnopqrst.supabase.co":                      "supabase",
		"aws-0-eu-central-1.pooler.supabase.com":                   "supabase",
		"aws-1-us-east-1.pooler.supabase.co":                       "supabase",
		"DB.ABCDEFGHIJKLMNOPQRST.SUPABASE.CO":                      "supabase",
		"db.abcdefghijklmnopqrst.supabase.co.":                     "supabase",
		rdsHost:                                                    "aws-rds",
		"mydb.c9akciq32xyz.us-east-1.rds.amazonaws.com":            "aws-rds",
		"mydb.cluster-ro-c9akciq32xyz.us-east-1.rds.amazonaws.com": "aws-rds",
		"MYDB.C9AKCIQ32XYZ.US-EAST-1.RDS.AMAZONAWS.COM.":           "aws-rds",
		"mydb.c9akciq32xyz.cn-north-1.rds.amazonaws.com.cn":        "aws-rds",
		"supabase.co":                 "",
		"supabase.com":                "",
		"rds.amazonaws.com":           "",
		"rds.amazonaws.com.cn":        "",
		"evilsupabase.co":             "",
		"db.evilsupabase.com":         "",
		"db.supabase.co.example.com":  "",
		"db.supabase.cofe":            "",
		"mydb.evilrds.amazonaws.com":  "",
		"mydb.rds.amazonaws.com.evil": "",
		"mydb.rds.amazonaws.co":       "",
		"mydb.s3.amazonaws.com":       "",
		"db.example.com":              "",
		"203.0.113.7":                 "",
		"/var/run/postgresql":         "",
		"":                            "",
	} {
		require.Equal(t, want, name(set.For(host)), host)
	}
}

// Precedence (CONTRACT.md, Trust profiles): an exact host first, then the
// operator's suffixes longest first, then the built-in ones longest first.
func TestPrecedence(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, "x")
	op := func(n string, match ...string) *trustprofile.Profile {
		return trustprofiletest.Profile(t, trustprofile.Operator, n, match, ca)
	}
	bi := func(n string, match ...string) *trustprofile.Profile {
		return trustprofiletest.Profile(t, trustprofile.BuiltIn, n, match, ca)
	}
	set := trustprofile.NewSet(
		[]*trustprofile.Profile{bi("wide", "example.com"), bi("narrow", "eu.example.com"), bi("pinned", "=db.eu.example.com")},
		[]*trustprofile.Profile{op("ops", "example.com"), op("ops-eu", "west.eu.example.com"), op("exact", "=pin.example.com", "=203.0.113.7")},
		nil)
	for host, want := range map[string]string{
		"db.eu.example.com":      "pinned", // an exact host beats every suffix
		"pin.example.com":        "exact",
		"203.0.113.7":            "exact",
		"a.west.eu.example.com":  "ops-eu", // the operator's longest suffix
		"a.east.eu.example.com":  "ops",    // an operator suffix beats a longer built-in one
		"a.example.com":          "ops",
		"a.example.org":          "",
		"pin.example.com.other":  "",
		"x.pin.example.com":      "ops", // an exact entry matches no host below it
		"example.com":            "",
		"west.eu.example.com":    "ops",
		"DB.EU.EXAMPLE.COM.":     "pinned",
		"another.eu.example.com": "ops",
	} {
		require.Equal(t, want, name(set.For(host)), host)
	}

	onlyBuiltIn := trustprofile.NewSet([]*trustprofile.Profile{bi("wide", "example.com"), bi("narrow", "eu.example.com")}, nil, nil)
	require.Equal(t, "narrow", name(onlyBuiltIn.For("a.eu.example.com")), "the longest built-in suffix")
}

// An operator profile with a built-in's name replaces it; disabled turns it
// off; a refused file changes nothing.
func TestOperatorReplacesAndDisables(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, "x")
	replace := trustprofiletest.Profile(t, trustprofile.Operator, "supabase", []string{"abcdefghijklmnopqrst.supabase.co"}, ca)
	set := trustprofile.NewSet(trustprofile.BuiltIns(), []*trustprofile.Profile{replace}, nil)
	require.Same(t, replace, set.For(supabaseHost))
	require.Nil(t, set.For("aws-0-eu-central-1.pooler.supabase.com"), "the replaced built-in no longer applies")
	require.Equal(t, "aws-rds", name(set.For(rdsHost)))

	off, err := trustprofile.Parse([]byte(`{"name":"aws-rds","disabled":true}`), trustprofile.Operator, nil)
	require.NoError(t, err)
	set = trustprofile.NewSet(trustprofile.BuiltIns(), []*trustprofile.Profile{off}, []trustprofile.Refused{{File: "supabase.json", Reason: "bad"}})
	require.Nil(t, set.For(rdsHost))
	require.Nil(t, set.For(supabaseHost), "a refused file named after a built-in keeps the built-in off")
	states := map[string]trustprofile.State{}
	for _, l := range trustprofile.Profiles(set) {
		states[string(l.Origin)+"/"+l.Name] = l.State
	}
	require.Equal(t, map[string]trustprofile.State{
		"OPERATOR/aws-rds": trustprofile.Disabled, "BUILT_IN/aws-rds": trustprofile.Disabled, "BUILT_IN/supabase": trustprofile.Disabled,
	}, states)
	require.Len(t, set.Refused(), 1)

	_, err = trustprofile.Parse([]byte(`{"name":"aws-rds","disabled":true}`), trustprofile.BuiltIn, nil)
	require.Error(t, err, "only an operator profile can be disabled")
	_, err = trustprofile.Parse([]byte(`{"name":"aws-rds","disabled":true,"match":["x.example.com"]}`), trustprofile.Operator, nil)
	require.Error(t, err)
}

func selfSigned(t *testing.T, isCA bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

func spec(t *testing.T, s trustprofile.Spec) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	require.NoError(t, err)
	return b
}

// Each rule of a profile refuses the whole profile.
func TestParseRefuses(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, "x")
	good := trustprofiletest.PEM(ca)
	leaf := trustprofiletest.PEM(selfSigned(t, false))
	sum := trustprofile.FileSHA256(good)
	files := map[string][]byte{"ca.pem": good, "leaf.pem": leaf}
	read := func(n string) ([]byte, error) {
		if b, ok := files[n]; ok {
			return b, nil
		}
		return nil, os.ErrNotExist
	}
	ok := trustprofile.Spec{Name: "mine", Match: []string{"db.example.com"}, Roots: []trustprofile.RootSpec{{File: "ca.pem", SHA256: sum}}}
	p, err := trustprofile.Parse(spec(t, ok), trustprofile.Operator, read)
	require.NoError(t, err)
	require.Len(t, p.Certificates(), 1)

	colons := ok
	colons.Roots = []trustprofile.RootSpec{{File: "ca.pem", SHA256: "  " + upperColons(sum)}}
	_, err = trustprofile.Parse(spec(t, colons), trustprofile.Operator, read)
	require.NoError(t, err, "a SHA-256 with colons in any case is accepted")

	for why, s := range map[string]trustprofile.Spec{
		"sha256 mismatch":    {Name: "mine", Match: ok.Match, Roots: []trustprofile.RootSpec{{File: "ca.pem", SHA256: trustprofile.FileSHA256(leaf)}}},
		"not a CA":           {Name: "mine", Match: ok.Match, Roots: []trustprofile.RootSpec{{File: "leaf.pem", SHA256: trustprofile.FileSHA256(leaf)}}},
		"missing file":       {Name: "mine", Match: ok.Match, Roots: []trustprofile.RootSpec{{File: "gone.pem", SHA256: sum}}},
		"path in file":       {Name: "mine", Match: ok.Match, Roots: []trustprofile.RootSpec{{File: "../ca.pem", SHA256: sum}}},
		"hidden file":        {Name: "mine", Match: ok.Match, Roots: []trustprofile.RootSpec{{File: ".ca.pem", SHA256: sum}}},
		"bad sha":            {Name: "mine", Match: ok.Match, Roots: []trustprofile.RootSpec{{File: "ca.pem", SHA256: "abc"}}},
		"no roots":           {Name: "mine", Match: ok.Match},
		"no match":           {Name: "mine", Roots: ok.Roots},
		"bad name":           {Name: "Mine!", Match: ok.Match, Roots: ok.Roots},
		"wildcard":           {Name: "mine", Match: []string{"*.example.com"}, Roots: ok.Roots},
		"bare tld":           {Name: "mine", Match: []string{"com"}, Roots: ok.Roots},
		"country 2nd level":  {Name: "mine", Match: []string{"co.uk"}, Roots: ok.Roots},
		"shared cloud apex":  {Name: "mine", Match: []string{"amazonaws.com"}, Roots: ok.Roots},
		"address suffix":     {Name: "mine", Match: []string{"113.7"}, Roots: ok.Roots},
		"twice":              {Name: "mine", Match: []string{"db.example.com", "DB.example.com."}, Roots: ok.Roots},
		"verify ca suffix":   {Name: "mine", Match: ok.Match, Roots: ok.Roots, Verify: trustprofile.VerifyCA},
		"verify other":       {Name: "mine", Match: ok.Match, Roots: ok.Roots, Verify: "none"},
		"source not https":   {Name: "mine", Match: ok.Match, Roots: ok.Roots, Source: []string{"http://example.com/ca.pem"}},
		"source count":       {Name: "mine", Match: ok.Match, Roots: ok.Roots, Source: []string{"https://a/1", "https://a/2"}},
		"roots listed twice": {Name: "mine", Match: ok.Match, Roots: []trustprofile.RootSpec{ok.Roots[0], ok.Roots[0]}},
	} {
		_, err := trustprofile.Parse(spec(t, s), trustprofile.Operator, read)
		require.Error(t, err, why)
	}
	_, err = trustprofile.Parse([]byte(`{"name":"mine","match":["db.example.com"],"roots":[],"extra":1}`), trustprofile.Operator, read)
	require.Error(t, err, "unknown keys are refused")
	_, err = trustprofile.Parse(append(spec(t, ok), []byte(` {}`)...), trustprofile.Operator, read)
	require.Error(t, err, "one JSON value")

	exactCA := trustprofile.Spec{Name: "pin-db", Match: []string{"=db.example.com", "=203.0.113.7"}, Roots: ok.Roots, Verify: trustprofile.VerifyCA}
	p, err = trustprofile.Parse(spec(t, exactCA), trustprofile.Operator, read)
	require.NoError(t, err, "verify ca on exact hosts parses")
	require.True(t, p.Exact())

	apex := trustprofile.Spec{Name: "aws", Match: []string{"amazonaws.com"}, Roots: ok.Roots}
	_, err = trustprofile.Parse(spec(t, apex), trustprofile.BuiltIn, read)
	require.NoError(t, err, "the public suffix rule is the operator's")
}

func upperColons(h string) string {
	pairs := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		pairs = append(pairs, strings.ToUpper(h[i:i+2]))
	}
	return strings.Join(pairs, ":")
}

func connect(t *testing.T, dsn string, cert tls.Certificate, set *trustprofile.Set) error {
	t.Helper()
	cfg, err := pgconn.ParseConfig(dsn)
	require.NoError(t, err)
	trustprofile.Trust(cfg, set)
	cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }
	cfg.DialFunc = trustprofiletest.Serve(t, cert)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	conn, err := pgconn.ConnectConfig(ctx, cfg)
	if err == nil {
		_ = conn.Close(ctx)
	}
	return err
}

func supabaseOnly(t *testing.T, ca ...*x509.Certificate) *trustprofile.Set {
	t.Helper()
	return trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": ca})
}

func dsnFor(host, params string) string {
	return "postgres://basalt_agent_bot:pw@" + host + ":5432/postgres?" + params
}

func refusedPassword(t *testing.T, err error) {
	t.Helper()
	var pg *pgconn.PgError
	require.True(t, errors.As(err, &pg), "want the server's refusal, got %v", err)
	require.Equal(t, "28P01", pg.Code)
}

func notVerified(t *testing.T, err error) {
	t.Helper()
	var verify *tls.CertificateVerificationError
	require.True(t, errors.As(err, &verify), "want a certificate verification error, got %v", err)
}

func TestSupabaseHostVerifies(t *testing.T) {
	t.Parallel()
	for _, host := range []string{supabaseHost, "aws-0-eu-central-1.pooler.supabase.com", "aws-1-us-east-1.pooler.supabase.co"} {
		ca, cert := trustprofiletest.Chain(t, host)
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert, supabaseOnly(t, ca)))
		refusedPassword(t, connect(t, dsnFor(host, "sslmode=verify-full&channel_binding=require"), cert, supabaseOnly(t, ca)))
	}
}

func TestEitherRootVerifies(t *testing.T) {
	t.Parallel()
	caA, certA := trustprofiletest.Chain(t, supabaseHost)
	caB, certB := trustprofiletest.Chain(t, supabaseHost)
	dsn := dsnFor(supabaseHost, "sslmode=verify-full")
	for _, cert := range []tls.Certificate{certA, certB} {
		refusedPassword(t, connect(t, dsn, cert, supabaseOnly(t, caA, caB)))
	}
	_, other := trustprofiletest.Chain(t, supabaseHost)
	notVerified(t, connect(t, dsn, other, supabaseOnly(t, caA, caB)))
	host := "db.example.com"
	ca1, c1 := trustprofiletest.Chain(t, host)
	ca2, c2 := trustprofiletest.Chain(t, host)
	for _, cert := range []tls.Certificate{c1, c2} {
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert, supabaseOnly(t, ca1, ca2)))
	}
}

// One profile's roots never verify another profile's hosts, built-in or
// operator.
func TestProfilesAreSeparate(t *testing.T) {
	t.Parallel()
	const opHost = "db.internal.example.com"
	hosts := map[string]string{"supabase": supabaseHost, "aws-rds": rdsHost, "mine": opHost, "": "db.example.org"}
	for _, signer := range []string{"supabase", "aws-rds", "mine"} {
		for profile, host := range hosts {
			ca, cert := trustprofiletest.Chain(t, host)
			decoy, _ := trustprofiletest.Chain(t, host)
			pick := func(n string) []*x509.Certificate {
				if n == signer {
					return []*x509.Certificate{ca}
				}
				return []*x509.Certificate{decoy}
			}
			set := trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": pick("supabase"), "aws-rds": pick("aws-rds")},
				trustprofiletest.Profile(t, trustprofile.Operator, "mine", []string{"internal.example.com"}, pick("mine")...))
			err := connect(t, dsnFor(host, "sslmode=verify-full"), cert, set)
			if profile == signer {
				refusedPassword(t, err)
			} else {
				notVerified(t, err)
			}
		}
	}
}

func TestOtherHostsKeepTheSystemRoots(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"db.example.com", "db.evilsupabase.co", "db.supabase.co.example.com", "mydb.evilrds.amazonaws.com", "mydb.rds.amazonaws.com.evil"} {
		ca, cert := trustprofiletest.Chain(t, host)
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full"), cert,
			trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}, "aws-rds": {ca}})))
	}
}

func TestHostNameStillChecked(t *testing.T) {
	t.Parallel()
	ca, cert := trustprofiletest.Chain(t, "db.otherprojectref000000.supabase.co")
	notVerified(t, connect(t, dsnFor(supabaseHost, "sslmode=verify-full"), cert, supabaseOnly(t, ca)))
	ca, cert = trustprofiletest.Chain(t, "other.c9akciq32xyz.eu-central-1.rds.amazonaws.com")
	notVerified(t, connect(t, dsnFor(rdsHost, "sslmode=verify-full"), cert, trustprofiletest.Set(t, map[string][]*x509.Certificate{"aws-rds": {ca}})))
}

func TestUserRootCertWins(t *testing.T) {
	t.Parallel()
	for _, host := range []string{supabaseHost, rdsHost} {
		ca, cert := trustprofiletest.Chain(t, host)
		other, _ := trustprofiletest.Chain(t, host)
		set := trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}, "aws-rds": {ca}})
		file := filepath.Join(t.TempDir(), "root.crt")
		require.NoError(t, os.WriteFile(file, trustprofiletest.PEM(other), 0o600))
		notVerified(t, connect(t, dsnFor(host, "sslmode=verify-full&sslrootcert="+file), cert, set))

		cfg, err := pgconn.ParseConfig(dsnFor(host, "sslmode=verify-full&sslrootcert="+file))
		require.NoError(t, err)
		require.Equal(t, trustprofile.AppliesRootCert, trustprofile.Explain(cfg, set).Applies)

		cfg, err = pgconn.ParseConfig(dsnFor(host, "sslmode=verify-full&sslrootcert=system"))
		require.NoError(t, err)
		before := cfg.TLSConfig.RootCAs
		trustprofile.Trust(cfg, set)
		require.Same(t, before, cfg.TLSConfig.RootCAs, "sslrootcert=system stays the system's roots only")
	}
}

func TestTrustScope(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, supabaseHost)
	for _, host := range []string{supabaseHost, rdsHost} {
		for _, mode := range []string{"require", "verify-ca", "prefer", "allow", "disable"} {
			cfg, err := pgconn.ParseConfig(dsnFor(host, "sslmode="+mode))
			require.NoError(t, err)
			require.Equal(t, trustprofile.AppliesNotVerified, trustprofile.Explain(cfg, trustprofile.BuiltInSet()).Applies, mode)
			trustprofile.Trust(cfg, trustprofile.BuiltInSet())
			for _, tc := range append([]*tls.Config{cfg.TLSConfig}, fallbackTLS(cfg)...) {
				if tc != nil {
					require.Nil(t, tc.RootCAs, mode)
				}
			}
		}
	}

	cfg, err := pgconn.ParseConfig("postgres://u:pw@" + supabaseHost + "," + rdsHost + ",db.example.com/postgres?sslmode=verify-full")
	require.NoError(t, err)
	set := supabaseOnly(t, ca)
	a := trustprofile.Explain(cfg, set)
	require.Equal(t, trustprofile.AppliesProfile, a.Applies)
	require.Equal(t, "supabase", a.Profile.Name)
	trustprofile.Trust(cfg, set)
	require.Equal(t, supabaseHost, cfg.TLSConfig.ServerName)
	_, err = ca.Verify(x509.VerifyOptions{Roots: cfg.TLSConfig.RootCAs})
	require.NoError(t, err, "the Supabase host trusts the Supabase root")
	require.Len(t, cfg.Fallbacks, 2)
	require.Equal(t, rdsHost, cfg.Fallbacks[0].Host)
	rds := cfg.Fallbacks[0].TLSConfig.RootCAs
	require.NotNil(t, rds)
	_, err = ca.Verify(x509.VerifyOptions{Roots: rds})
	require.Error(t, err, "the RDS host does not trust the Supabase root")
	for _, root := range trustprofile.BuiltInNamed("aws-rds").Certificates() {
		_, err = root.Verify(x509.VerifyOptions{Roots: rds})
		require.NoError(t, err, "the RDS host trusts %s", root.Subject)
	}
	require.Equal(t, "db.example.com", cfg.Fallbacks[1].Host)
	require.Nil(t, cfg.Fallbacks[1].TLSConfig.RootCAs, "the other host keeps the system's roots")

	cfg, err = pgconn.ParseConfig(dsnFor("db.example.com", "sslmode=verify-full"))
	require.NoError(t, err)
	require.Equal(t, trustprofile.AppliesSystem, trustprofile.Explain(cfg, set).Applies)
}

func fallbackTLS(cfg *pgconn.Config) []*tls.Config {
	out := make([]*tls.Config, 0, len(cfg.Fallbacks))
	for _, fb := range cfg.Fallbacks {
		out = append(out, fb.TLSConfig)
	}
	return out
}

// An operator verify: ca profile whose root is in the system's store is
// refused: pins and hand-written profiles alike. Not parallel: it swaps the
// system's store.
func TestVerifyCARefusesPublicRoots(t *testing.T) {
	ca, _ := trustprofiletest.Chain(t, "x")
	store := x509.NewCertPool()
	store.AddCert(ca)
	defer trustprofile.SetSystemRootsForTest(store)()
	_, err := trustprofile.NewPin("203.0.113.7", ca, true)
	require.ErrorIs(t, err, trustprofile.ErrPublic)
	_, err = trustprofile.NewPin("203.0.113.7", ca, false)
	require.NoError(t, err, "verify-full checks the name, so the rule is trustpin's there")
	require.True(t, trustprofile.IsPublic(ca, nil))
	other, _ := trustprofiletest.Chain(t, "x")
	require.False(t, trustprofile.IsPublic(other, nil))
}
