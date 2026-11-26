package trustprofile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

const (
	supabaseHost = "db.abcdefghijklmnopqrst.supabase.co"
	rdsHost      = "mydb.cluster-c9akciq32xyz.eu-central-1.rds.amazonaws.com"
)

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

// TrustTLS and ExplainTLS take one host and its TLS config: a config that
// verifies the host name trusts the matching profile's roots, another host
// keeps the system's, and a config that does not verify is left alone.
func TestTrustTLSForOneHost(t *testing.T) {
	t.Parallel()
	ca, _ := trustprofiletest.Chain(t, supabaseHost)
	set := trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}})

	require.Equal(t, trustprofile.AppliesNotVerified, trustprofile.ExplainTLS(supabaseHost, nil, set).Applies)
	skip := &tls.Config{ServerName: supabaseHost, InsecureSkipVerify: true}
	require.Equal(t, trustprofile.AppliesNotVerified, trustprofile.ExplainTLS(supabaseHost, skip, set).Applies)
	trustprofile.TrustTLS(supabaseHost, skip, set)
	require.Nil(t, skip.RootCAs)

	cfg := &tls.Config{ServerName: supabaseHost, MinVersion: tls.VersionTLS12}
	a := trustprofile.ExplainTLS(supabaseHost, cfg, set)
	require.Equal(t, trustprofile.AppliesProfile, a.Applies)
	require.Equal(t, "supabase", a.Profile.Name)
	trustprofile.TrustTLS(supabaseHost, cfg, set)
	_, err := ca.Verify(x509.VerifyOptions{Roots: cfg.RootCAs})
	require.NoError(t, err, "the Supabase host trusts the Supabase root")
	require.Equal(t, trustprofile.AppliesRootCert, trustprofile.ExplainTLS(supabaseHost, cfg, set).Applies)

	other := &tls.Config{ServerName: "db.example.com", MinVersion: tls.VersionTLS12}
	require.Equal(t, trustprofile.AppliesSystem, trustprofile.ExplainTLS("db.example.com", other, set).Applies)
	trustprofile.TrustTLS("db.example.com", other, set)
	require.Nil(t, other.RootCAs, "another host keeps the system's roots")
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
