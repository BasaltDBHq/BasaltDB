package status

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

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
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

func trustLocal(t *testing.T, probe *fakeProbe, rep TrustReporter) guidance.StatusReport {
	t.Helper()
	cmds := commandsAt("")
	r, err := localStatus{
		Errors: testErrors(), LatestGuardVersion: guard.LatestVersion,
		Name: "bot", Commands: cmds.Foreground(), EngineRunning: true, Trust: rep, Probe: probe,
		Passkeys: func(context.Context) ([]passkey.Credential, error) {
			return []passkey.Credential{{Relying: passkey.Relying{Origin: links.DefaultLocal}}}, nil
		},
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
	}.report(context.Background())
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
	ok := &fakeProbe{st: currentGuard()}
	host := "db.internal.example.com"
	later := caExpiring(t, statusNow.Add(400*24*time.Hour))
	soon := caExpiring(t, statusNow.Add(30*24*time.Hour))
	p := trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, later, soon)

	r := trustLocal(t, ok, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: p}))
	require.Equal(t, &guidance.TrustStatus{
		Host: host, Applies: "PROFILE", Profile: "internal", Origin: "OPERATOR", RootCount: 2,
		Roots: []guidance.TrustRootStatus{
			{Subject: soon.Subject.String(), SHA256: trustprofile.Fingerprint(soon), NotAfter: soon.NotAfter.UTC()},
			{Subject: later.Subject.String(), SHA256: trustprofile.Fingerprint(later), NotAfter: later.NotAfter.UTC()},
		},
	}, r.Trust)
	w := findProblem(t, r, "TRUST_ROOT_EXPIRING")
	require.Equal(t, "WARNING", w.Severity)
	require.Contains(t, w.Message, trustprofile.Fingerprint(soon))
	require.Contains(t, w.Message, soon.NotAfter.Format(time.DateOnly))
	require.Equal(t, toolresult.ActionAskPerson, w.NextSteps[0].Action)
	require.Equal(t, "basalt init --agent bot", w.NextSteps[1].Command)
	require.Contains(t, w.NextSteps[1].Text, "Only once", "the page adds nothing before the database presents the new certificate")
	require.NotContains(t, w.PersonMessage, "add the provider's new root")
	require.Contains(t, w.PersonMessage, "Update check")
	require.True(t, r.Ready)

	fine := trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, later)
	r = trustLocal(t, ok, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: fine}))
	require.Empty(t, r.Problems)

	r = trustLocal(t, ok, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem}))
	require.Equal(t, &guidance.TrustStatus{Host: host, Applies: "SYSTEM"}, r.Trust)

	r = trustLocal(t, ok, nil)
	require.Nil(t, r.Trust)
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"trust"`)
}

// A refused trust.d file is a warning per file, naming it and why.
func TestStatusTrustRefused(t *testing.T) {
	t.Parallel()
	ok := &fakeProbe{st: currentGuard()}
	r := trustLocal(t, ok, reporter(trustprofile.Applied{Host: "db.example.com", Applies: trustprofile.AppliesSystem},
		trustprofile.Refused{File: "/etc/basalt/trust.d/a.json", Reason: "it is writable by group or others"},
		trustprofile.Refused{File: "/etc/basalt/trust.d/b.json", Reason: "roots file b.pem has SHA-256 x, the profile pins y"}))
	n := 0
	for _, p := range r.Problems {
		if p.Code == "TRUST_PROFILE_REFUSED" {
			n++
			require.Equal(t, "WARNING", p.Severity)
			require.Contains(t, p.Message, "/etc/basalt/trust.d/")
			require.Contains(t, p.PersonMessage, "stays off until it is fixed")
		}
	}
	require.Equal(t, 2, n)
	require.True(t, r.Ready)
}

// A database whose certificate does not verify is CERTIFICATE_NOT_VERIFIED,
// naming the host and the agent's basalt init, whose page trusts the
// certificate, not DATABASE_UNREACHABLE.
func TestStatusCertificateNotVerified(t *testing.T) {
	t.Parallel()
	host := "db.internal.example.com"
	err := fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
	r := trustLocal(t, &fakeProbe{err: err}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem}))
	p := findProblem(t, r, "CERTIFICATE_NOT_VERIFIED")
	require.Equal(t, "ERROR", p.Severity)
	require.Contains(t, p.Message, host)
	require.Equal(t, toolresult.NextStep{Actor: toolresult.ActorAgent, Action: toolresult.ActionRunCommand, Text: "Run this once and show the person the link it prints: the setup page shows the database's certificate, and they decide.", Command: "basalt init --agent bot"}, p.NextSteps[0])
	require.NotContains(t, p.PersonMessage, "basalt ", "the person runs no command")
	require.Contains(t, p.PersonMessage, "trust it there")
	require.NotContains(t, p.PersonMessage, "sslrootcert", "the setup page refuses sslrootcert, so no message suggests it")
	for _, q := range r.Problems {
		require.NotEqual(t, guidance.ReasonDatabaseUnreachable, q.Code)
	}
	require.False(t, r.Ready)
}

// When the connection names its own roots, or does not use verify-full, a
// trust profile cannot help: CERTIFICATE_NOT_VERIFIED says what can.
func TestStatusCertificateNotVerifiedOwnRoots(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
	for applies, want := range map[trustprofile.Applies]string{ //nolint:exhaustive // only the two states a profile cannot fix
		trustprofile.AppliesRootCert:    "names its own roots",
		trustprofile.AppliesNotVerified: "below verify-full",
	} {
		r := trustLocal(t, &fakeProbe{err: err}, reporter(trustprofile.Applied{Host: "db.example.com", Applies: applies}))
		p := findProblem(t, r, "CERTIFICATE_NOT_VERIFIED")
		require.Contains(t, p.PersonMessage, want, applies)
		require.Equal(t, "basalt init --agent bot", p.NextSteps[0].Command, applies)
		require.NotContains(t, p.PersonMessage, "basalt ", applies)
	}
}
