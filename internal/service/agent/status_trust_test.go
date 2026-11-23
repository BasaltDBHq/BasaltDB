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

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
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

func trustLocal(t *testing.T, probe *fakeProbe, rep TrustReporter) StatusReport {
	t.Helper()
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	r, err := LocalStatus{
		Errors: testErrors(), LatestGuardVersion: guard.LatestVersion,
		Name: "bot", Commands: cmds.Foreground(), EngineRunning: true, Trust: rep, Probe: probe,
		Passkeys: func(context.Context) ([]passkey.Credential, error) {
			return []passkey.Credential{{Relying: passkey.Relying{Origin: links.DefaultLocal}}}, nil
		},
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return statusNow },
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
	ok := &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
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
	ok := &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	r := trustLocal(t, ok, reporter(trustprofile.Applied{Host: "db.example.com", Applies: trustprofile.AppliesSystem},
		trustprofile.Refused{File: "/etc/basalt/trust.d/a.json", Reason: "it is writable by group or others"},
		trustprofile.Refused{File: "/etc/basalt/trust.d/b.json", Reason: "roots file b.pem has SHA-256 x, the profile pins y"}))
	n := 0
	for _, p := range r.Problems {
		if p.Code == problemTrustProfileRefused {
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
	p := findProblem(t, r, problemCertificateNotVerified)
	require.Equal(t, "ERROR", p.Severity)
	require.Contains(t, p.Message, host)
	require.Equal(t, toolresult.NextStep{Actor: toolresult.ActorAgent, Action: toolresult.ActionRunCommand, Text: trustInitText, Command: "basalt init --agent bot"}, p.NextSteps[0])
	require.NotContains(t, p.PersonMessage, "basalt ", "the person runs no command")
	require.Contains(t, p.PersonMessage, "trust it there")
	require.NotContains(t, p.PersonMessage, "sslrootcert", "the setup page refuses sslrootcert, so no message suggests it")
	for _, q := range r.Problems {
		require.NotEqual(t, problemDatabaseUnreachable, q.Code)
	}
	require.False(t, r.Ready)
}

// trustStatusOf is the engine's status with rep as its trust reporter.
func trustStatusOf(t *testing.T, operatedBy string, probe *fakeProbe, rep TrustReporter) StatusReport {
	t.Helper()
	d := deps()
	d.Status.OperatedBy = operatedBy
	d.Status.Probe = probe
	setApprovals(&d, keys{n: 1})
	d.Core.Now = func() time.Time { return statusNow }
	d.Status.Trust = rep
	cmds, err := NewCommands("bot", "", "linux", testManager())
	require.NoError(t, err)
	d.Core.Commands = cmds
	r, err := NewService(d).Status(context.Background())
	require.NoError(t, err)
	return r
}

// trustStatusCases are the status cases of the trust problems.
func trustStatusCases(operatedBy string) map[string]statusCase {
	ok := guardAt(guardmodel.GuardOK, nil, nil)
	const host = "db.internal.example.com"
	return map[string]statusCase{
		problemCertificateNotVerified: {state: guardmodel.GuardUnknown, report: func(t *testing.T) StatusReport {
			t.Helper()
			err := fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
			return trustStatusOf(t, operatedBy, &fakeProbe{err: err}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem}))
		}},
		problemTrustRootExpiring: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			p := trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, caExpiring(t, statusNow.Add(24*time.Hour)))
			return trustStatusOf(t, operatedBy, &fakeProbe{st: ok}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: p}))
		}},
		problemTrustRootChanged: {state: guardmodel.GuardUnknown, report: func(t *testing.T) StatusReport {
			t.Helper()
			r, _ := pinnedStatus(t, operatedBy, true, "")
			return r
		}},
		problemTrustPinMismatch: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			r, _ := pinnedStatus(t, operatedBy, false, pinSHAOther)
			return r
		}},
		problemTrustProfileRefused: {state: guardmodel.GuardOK, report: func(t *testing.T) StatusReport {
			t.Helper()
			return trustStatusOf(t, operatedBy, &fakeProbe{st: ok}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem},
				trustprofile.Refused{File: "/etc/basalt/trust.d/a.json", Reason: "it is writable by group or others"}))
		}},
	}
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
		p := findProblem(t, r, problemCertificateNotVerified)
		require.Contains(t, p.PersonMessage, want, applies)
		require.Equal(t, "basalt init --agent bot", p.NextSteps[0].Command, applies)
		require.NotContains(t, p.PersonMessage, "basalt ", applies)
	}
}

// pinSHAOther is a fingerprint no test pin holds.
const pinSHAOther = "5f9b77951a7aa1303f9b58eea9bfa89e358cfdc15f9786ff10d4930a722c9ae2"

// pinnedStatus is the status of an agent whose database is pinned: with
// certErr the connection fails on the certificate and the database now
// presents another root; recorded, when set, is the ledger's pin.
func pinnedStatus(t *testing.T, operatedBy string, certErr bool, recorded string) (StatusReport, *x509.Certificate) {
	t.Helper()
	const host = "db.internal.example.com"
	pinnedCA := caExpiring(t, statusNow.Add(400*24*time.Hour))
	p := trustprofiletest.Profile(t, trustprofile.Operator, trustprofile.PinName(host), []string{"=" + host}, pinnedCA)
	now := caExpiring(t, statusNow.Add(500*24*time.Hour))
	probe := &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	if certErr {
		probe = &fakeProbe{err: fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})}
	}
	rep := func() TrustReport {
		r := TrustReport{
			Applied: trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: p}, Port: 5432,
			Presented: func(context.Context) (*x509.Certificate, error) { return now, nil },
		}
		if recorded != "" {
			r.Recorded = func(context.Context) (string, bool, error) { return recorded, true, nil }
		}
		return r
	}
	return trustStatusOf(t, operatedBy, probe, rep), now
}

// A pinned database presenting another root is TRUST_ROOT_CHANGED, naming
// both fingerprints and the agent's basalt init, whose page pins the new
// one, not CERTIFICATE_NOT_VERIFIED.
func TestStatusTrustRootChanged(t *testing.T) {
	t.Parallel()
	r, now := pinnedStatus(t, "", true, "")
	p := findProblem(t, r, problemTrustRootChanged)
	require.Equal(t, "ERROR", p.Severity)
	require.Contains(t, p.Message, trustprofile.Fingerprint(now))
	require.Contains(t, p.Message, "pinned to")
	require.Equal(t, "basalt init --agent bot", p.NextSteps[0].Command)
	require.NotContains(t, p.PersonMessage, "basalt ", "the person runs no command")
	for _, q := range r.Problems {
		require.NotEqual(t, problemCertificateNotVerified, q.Code)
	}
}

// The ledger recording another pin is TRUST_PIN_MISMATCH; the same pin, or
// none recorded, is no problem.
func TestStatusTrustPinMismatch(t *testing.T) {
	t.Parallel()
	r, _ := pinnedStatus(t, "", false, pinSHAOther)
	p := findProblem(t, r, problemTrustPinMismatch)
	require.Equal(t, "WARNING", p.Severity)
	require.Contains(t, p.Message, pinSHAOther)
	require.True(t, r.Ready)

	r, _ = pinnedStatus(t, "", false, "")
	require.Empty(t, r.Problems, "no record is no problem")
}
