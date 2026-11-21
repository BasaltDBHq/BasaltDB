//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

type trustRun struct {
	code           int
	stdout, stderr string
}

// runTrustWith runs basalt trust with env as the whole environment.
func runTrustWith(t *testing.T, env map[string]string, args ...string) trustRun {
	t.Helper()
	var out, errb bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &out, err: &errb}, func(k string) string { return env[k] })
	code := runTrust(c, args)
	return trustRun{code, out.String(), errb.String()}
}

func trustConfig(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o700))
	return filepath.Join(dir, "engine.json")
}

func caFile(t *testing.T, host string) (string, string) {
	t.Helper()
	ca, _ := trustprofiletest.Chain(t, host)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, trustprofiletest.PEM(ca), 0o600))
	return path, ca.Subject.CommonName
}

// add, list, disable and remove, with the fingerprints printed.
func TestTrustCommands(t *testing.T) {
	t.Parallel()
	cfg := trustConfig(t)
	ca, cn := caFile(t, "db.internal.example.com")

	r := runTrustWith(t, nil, "add", "--config", cfg, "--name", "internal", "--match", "internal.example.com,=db.other.example.com", "--ca", ca)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "added trust profile internal for internal.example.com, =db.other.example.com")
	require.Contains(t, r.stdout, "SHA-256 ")
	require.Contains(t, r.stdout, cn)
	require.Contains(t, r.stderr, "no restart is needed")

	r = runTrustWith(t, nil, "disable", "--config", cfg, "--name", "aws-rds")
	require.Equal(t, exitOK, r.code, r.stderr)
	r = runTrustWith(t, nil, "disable", "--config", cfg, "--name", "internal")
	require.Equal(t, exitUsage, r.code, "only a built-in is disabled")

	r = runTrustWith(t, nil, "list", "--config", cfg, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var v trustListView
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &v))
	states := map[string]string{}
	for _, p := range v.Profiles {
		states[p.Origin+"/"+p.Name] = p.State
	}
	require.Equal(t, map[string]string{
		"OPERATOR/internal": "ACTIVE", "OPERATOR/aws-rds": "DISABLED", "BUILT_IN/aws-rds": "DISABLED", "BUILT_IN/supabase": "ACTIVE",
	}, states)
	require.Empty(t, v.Refused)

	r = runTrustWith(t, nil, "list", "--config", cfg)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "internal  operator  active  match internal.example.com, =db.other.example.com")

	r = runTrustWith(t, nil, "remove", "--config", cfg, "--name", "supabase")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "basalt trust disable --name supabase")
	for _, n := range []string{"internal", "aws-rds"} {
		r = runTrustWith(t, nil, "remove", "--config", cfg, "--name", n)
		require.Equal(t, exitOK, r.code, r.stderr)
	}
	require.Contains(t, r.stdout, "the built-in profile aws-rds applies again")
	entries, err := os.ReadDir(trustdir.Path(cfg))
	require.NoError(t, err)
	require.Empty(t, entries)
}

// add refuses a bare public suffix, a certificate that is not a CA, and any
// run under an agent marker, writing nothing.
func TestTrustAddRefuses(t *testing.T) {
	t.Parallel()
	cfg := trustConfig(t)
	ca, _ := caFile(t, "db.internal.example.com")
	_, leaf := trustprofiletest.Chain(t, "db.internal.example.com")
	leafFile := filepath.Join(t.TempDir(), "leaf.pem")
	leafCert := mustCert(t, leaf.Certificate[0])
	require.NoError(t, os.WriteFile(leafFile, trustprofiletest.PEM(leafCert), 0o600))

	r := runTrustWith(t, nil, "add", "--config", cfg, "--name", "x", "--match", "co.uk", "--ca", ca)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "public suffix")
	r = runTrustWith(t, nil, "add", "--config", cfg, "--name", "x", "--match", "internal.example.com", "--ca", leafFile)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "not a certificate authority")
	r = runTrustWith(t, map[string]string{"CLAUDECODE": "1"}, "add", "--config", cfg, "--name", "x", "--match", "internal.example.com", "--ca", ca)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "an agent never adds a root certificate")
	r = runTrustWith(t, nil, "add", "--config", cfg, "--name", "x")
	require.Equal(t, exitUsage, r.code)
	_, err := os.Stat(trustdir.Path(cfg))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func mustCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}
