package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// caExpiring is a CA certificate valid until notAfter.
func caExpiring(t *testing.T, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: notAfter.Add(-365 * 24 * time.Hour), NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c
}

func trustLocal(t *testing.T, probe *fakeProbe, rep TrustReporter) StatusReport {
	t.Helper()
	cmds, err := NewCommands("bot", "", "linux", []string{"--agent=bot", "--write=public.leads"})
	require.NoError(t, err)
	r, err := LocalStatus{
		Name: "bot", Commands: cmds.Foreground(), EngineRunning: true, Trust: rep, Probe: probe,
		Passkeys: func(context.Context) ([]passkey.Credential, error) { return []passkey.Credential{{}}, nil },
		Log:      slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
	}.Report(context.Background())
	require.NoError(t, err)
	return r
}

func reporter(a trustprofile.Applied, refused ...trustprofile.Refused) TrustReporter {
	return func() TrustReport { return TrustReport{Applied: a, Refused: refused} }
}

// status.trust names the profile and its roots, earliest expiry first, and
// warns 90 days before a root in use expires.
func TestStatusTrust(t *testing.T) {
	t.Parallel()
	ok := &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}
	host := "db.internal.example.com"
	later := caExpiring(t, statusNow.Add(400*24*time.Hour))
	soon := caExpiring(t, statusNow.Add(30*24*time.Hour))
	p := trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, later, soon)

	r := trustLocal(t, ok, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: p}))
	require.Equal(t, &TrustStatus{
		Host: host, Applies: "PROFILE", Profile: "internal", Origin: "OPERATOR", RootCount: 2,
		Roots: []TrustRootStatus{
			{Subject: soon.Subject.String(), SHA256: trustprofile.Fingerprint(soon), NotAfter: soon.NotAfter.UTC()},
			{Subject: later.Subject.String(), SHA256: trustprofile.Fingerprint(later), NotAfter: later.NotAfter.UTC()},
		},
	}, r.Trust)
	w := findProblem(t, r, problemTrustRootExpiring)
	require.Equal(t, "WARNING", w.Severity)
	require.Contains(t, w.Message, trustprofile.Fingerprint(soon))
	require.Contains(t, w.Message, soon.NotAfter.Format(time.DateOnly))
	require.Equal(t, "basalt trust list", w.NextSteps[0].Command)
	require.True(t, r.Ready)

	fine := trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, later)
	r = trustLocal(t, ok, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: fine}))
	require.Empty(t, r.Problems)

	r = trustLocal(t, ok, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem}))
	require.Equal(t, &TrustStatus{Host: host, Applies: "SYSTEM"}, r.Trust)

	r = trustLocal(t, ok, nil)
	require.Nil(t, r.Trust)
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"trust"`)
}

// A refused trust.d file is a warning per file, naming it and why.
func TestStatusTrustRefused(t *testing.T) {
	t.Parallel()
	ok := &fakeProbe{st: guardAt(guard.GuardOK, nil, nil)}
	r := trustLocal(t, ok, reporter(trustprofile.Applied{Host: "db.example.com", Applies: trustprofile.AppliesSystem},
		trustprofile.Refused{File: "/etc/basalt/trust.d/a.json", Reason: "it is writable by group or others"},
		trustprofile.Refused{File: "/etc/basalt/trust.d/b.json", Reason: "roots file b.pem has SHA-256 x, the profile pins y"}))
	n := 0
	for _, p := range r.Problems {
		if p.Code == problemTrustProfileRefused {
			n++
			require.Equal(t, "WARNING", p.Severity)
			require.Contains(t, p.Message, "/etc/basalt/trust.d/")
			require.Contains(t, p.PersonMessage, "built-in profiles")
		}
	}
	require.Equal(t, 2, n)
	require.True(t, r.Ready)
}

// A database whose certificate does not verify is CERTIFICATE_NOT_VERIFIED,
// naming the host and basalt trust add, not DATABASE_UNREACHABLE.
func TestStatusCertificateNotVerified(t *testing.T) {
	t.Parallel()
	host := "db.internal.example.com"
	err := fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
	r := trustLocal(t, &fakeProbe{err: err}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem}))
	p := findProblem(t, r, problemCertificateNotVerified)
	require.Equal(t, "ERROR", p.Severity)
	require.Contains(t, p.Message, host)
	require.Equal(t, "basalt trust add --name db-internal-example-com --match '=db.internal.example.com' --ca ./ca.pem", p.NextSteps[0].Command)
	require.Contains(t, p.PersonMessage, "sslrootcert")
	for _, q := range r.Problems {
		require.NotEqual(t, problemDatabaseUnreachable, q.Code)
	}
	require.False(t, r.Ready)

	cmds, cerr := NewCommands("bot", "/srv/basalt/engine.json", "linux", nil)
	require.NoError(t, cerr)
	require.Equal(t, "sudo basalt trust add --name db-x-y --match '=db.x.y' --ca ./ca.pem --config /srv/basalt/engine.json", cmds.TrustAdd("DB.X.Y."))
}

// trustStatusOf is the engine's status with rep as its trust reporter.
func trustStatusOf(t *testing.T, operatedBy string, probe *fakeProbe, rep TrustReporter) StatusReport {
	t.Helper()
	d := deps()
	d.OperatedBy = operatedBy
	d.Probe = probe
	setApprovals(&d, keys{n: 1})
	d.Now = func() time.Time { return statusNow }
	d.Trust = rep
	cmds, err := NewCommands("bot", "", "linux", []string{"--agent=bot", "--write=public.leads"})
	require.NoError(t, err)
	d.Commands = cmds
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}

// trustStatusCases are the status cases of the trust problems.
func trustStatusCases(operatedBy string) map[string]statusCase {
	ok := guardAt(guard.GuardOK, nil, nil)
	const host = "db.internal.example.com"
	return map[string]statusCase{
		problemCertificateNotVerified: {state: guard.GuardUnknown, report: func(t *testing.T) StatusReport {
			t.Helper()
			err := fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
			return trustStatusOf(t, operatedBy, &fakeProbe{err: err}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem}))
		}},
		problemTrustRootExpiring: {state: guard.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			p := trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, caExpiring(t, statusNow.Add(24*time.Hour)))
			return trustStatusOf(t, operatedBy, &fakeProbe{st: ok}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: p}))
		}},
		problemTrustProfileRefused: {state: guard.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return trustStatusOf(t, operatedBy, &fakeProbe{st: ok}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem},
				trustprofile.Refused{File: "/etc/basalt/trust.d/a.json", Reason: "it is writable by group or others"}))
		}},
	}
}
