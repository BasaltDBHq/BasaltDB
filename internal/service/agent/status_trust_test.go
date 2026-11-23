package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	statussvc "github.com/basaltdbhq/basaltdb/internal/status"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// trustStatusOf is the engine's status with rep as its trust reporter.
func trustStatusOf(t *testing.T, operatedBy string, probe *fakeProbe, rep statussvc.TrustReporter) guidance.StatusReport {
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
		"CERTIFICATE_NOT_VERIFIED": {state: guardmodel.GuardUnknown, report: func(t *testing.T) guidance.StatusReport {
			t.Helper()
			err := fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
			return trustStatusOf(t, operatedBy, &fakeProbe{err: err}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem}))
		}},
		"TRUST_ROOT_EXPIRING": {state: guardmodel.GuardOK, report: func(t *testing.T) guidance.StatusReport {
			t.Helper()
			p := trustprofiletest.Profile(t, trustprofile.Operator, "internal", []string{"internal.example.com"}, caExpiring(t, statusNow.Add(24*time.Hour)))
			return trustStatusOf(t, operatedBy, &fakeProbe{st: ok}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesProfile, Profile: p}))
		}},
		"TRUST_ROOT_CHANGED": {state: guardmodel.GuardUnknown, report: func(t *testing.T) guidance.StatusReport {
			t.Helper()
			r, _ := pinnedStatus(t, operatedBy, true, "")
			return r
		}},
		"TRUST_PIN_MISMATCH": {state: guardmodel.GuardOK, report: func(t *testing.T) guidance.StatusReport {
			t.Helper()
			r, _ := pinnedStatus(t, operatedBy, false, pinSHAOther)
			return r
		}},
		"TRUST_PROFILE_REFUSED": {state: guardmodel.GuardOK, report: func(t *testing.T) guidance.StatusReport {
			t.Helper()
			return trustStatusOf(t, operatedBy, &fakeProbe{st: ok}, reporter(trustprofile.Applied{Host: host, Applies: trustprofile.AppliesSystem},
				trustprofile.Refused{File: "/etc/basalt/trust.d/a.json", Reason: "it is writable by group or others"}))
		}},
	}
}

// pinSHAOther is a fingerprint no test pin holds.
const pinSHAOther = "5f9b77951a7aa1303f9b58eea9bfa89e358cfdc15f9786ff10d4930a722c9ae2"

// pinnedStatus is the status of an agent whose database is pinned: with
// certErr the connection fails on the certificate and the database now
// presents another root; recorded, when set, is the ledger's pin.
func pinnedStatus(t *testing.T, operatedBy string, certErr bool, recorded string) (guidance.StatusReport, *x509.Certificate) {
	t.Helper()
	const host = "db.internal.example.com"
	pinnedCA := caExpiring(t, statusNow.Add(400*24*time.Hour))
	p := trustprofiletest.Profile(t, trustprofile.Operator, trustprofile.PinName(host), []string{"=" + host}, pinnedCA)
	now := caExpiring(t, statusNow.Add(500*24*time.Hour))
	probe := &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	if certErr {
		probe = &fakeProbe{err: fmt.Errorf("failed to connect: %w", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})}
	}
	rep := func() statussvc.TrustReport {
		r := statussvc.TrustReport{
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
	p := findProblem(t, r, "TRUST_ROOT_CHANGED")
	require.Equal(t, "ERROR", p.Severity)
	require.Contains(t, p.Message, trustprofile.Fingerprint(now))
	require.Contains(t, p.Message, "pinned to")
	require.Equal(t, "basalt init --agent bot", p.NextSteps[0].Command)
	require.NotContains(t, p.PersonMessage, "basalt ", "the person runs no command")
	for _, q := range r.Problems {
		require.NotEqual(t, "CERTIFICATE_NOT_VERIFIED", q.Code)
	}
}

// The ledger recording another pin is TRUST_PIN_MISMATCH; the same pin, or
// none recorded, is no problem.
func TestStatusTrustPinMismatch(t *testing.T) {
	t.Parallel()
	r, _ := pinnedStatus(t, "", false, pinSHAOther)
	p := findProblem(t, r, "TRUST_PIN_MISMATCH")
	require.Equal(t, "WARNING", p.Severity)
	require.Contains(t, p.Message, pinSHAOther)
	require.True(t, r.Ready)

	r, _ = pinnedStatus(t, "", false, "")
	require.Empty(t, r.Problems, "no record is no problem")
}

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

func reporter(a trustprofile.Applied, refused ...trustprofile.Refused) statussvc.TrustReporter {
	return func() statussvc.TrustReport { return statussvc.TrustReport{Applied: a, Refused: refused} }
}
