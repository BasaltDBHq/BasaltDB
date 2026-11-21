package agent

import (
	"cmp"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Problem codes of the status tool for trust profiles (CONTRACT.md, Trust
// profiles).
const (
	// problemTrustRootExpiring: a root of the profile that verifies the
	// agent's database expires within trustExpiringWithin.
	problemTrustRootExpiring = "TRUST_ROOT_EXPIRING"
	// problemTrustProfileRefused: a file in trust.d was not loaded.
	problemTrustProfileRefused = "TRUST_PROFILE_REFUSED"
	// problemCertificateNotVerified: the agent's database's certificate
	// does not verify.
	problemCertificateNotVerified = "CERTIFICATE_NOT_VERIFIED"
	// problemTrustRootChanged: the agent's database is pinned and now
	// presents another chain top.
	problemTrustRootChanged = "TRUST_ROOT_CHANGED"
	// problemTrustPinMismatch: the ledger records another pin for the
	// agent's database than the engine's.
	problemTrustPinMismatch = "TRUST_PIN_MISMATCH"
)

// trustExpiringWithin is how long before a root in use expires status
// warns.
const trustExpiringWithin = 90 * 24 * time.Hour

// maxTrustRoots bounds status.trust.roots: a bundle (AWS's holds 114 roots)
// lists the ones that expire first, and rootCount says how many there are.
const maxTrustRoots = 8

// TrustReport is what verifies the agent's database certificate now, and
// the operator files that were refused.
type TrustReport struct {
	Applied trustprofile.Applied
	Refused []trustprofile.Refused
	// Port is the agent's database port, which a pin is recorded for.
	Port uint16
	// Presented reads the chain top the database presents now, with the
	// TLS handshake alone (TRUST_ROOT_CHANGED); nil reads nothing.
	Presented func(ctx context.Context) (*x509.Certificate, error)
	// Recorded is the pin's fingerprint the ledger records for the host
	// and port (TRUST_PIN_MISMATCH): false for none; nil reads nothing.
	Recorded func(ctx context.Context) (string, bool, error)
}

// TrustReporter reads the TrustReport now.
type TrustReporter func() TrustReport

// TrustStatus is status.trust.
type TrustStatus struct {
	Host string `json:"host"`
	// Applies is PROFILE, SSLROOTCERT, SYSTEM or NOT_VERIFIED.
	Applies string `json:"applies"`
	// Profile and Origin name the profile when Applies is PROFILE.
	Profile string `json:"profile,omitempty"`
	Origin  string `json:"origin,omitempty"`
	// Verify is CA for a pin that checks the chain against its own root
	// without the host name; absent for a full check.
	Verify string `json:"verify,omitempty"`
	// RootCount is how many roots the profile holds; Roots lists up to 8,
	// those that expire first.
	RootCount int               `json:"rootCount,omitempty"`
	Roots     []TrustRootStatus `json:"roots,omitempty"`
}

// TrustRootStatus is one root of status.trust.roots.
type TrustRootStatus struct {
	Subject  string    `json:"subject"`
	SHA256   string    `json:"sha256"`
	NotAfter time.Time `json:"notAfter"`
}

// trustStatus is status.trust, adding TRUST_PROFILE_REFUSED for each
// refused file and TRUST_ROOT_EXPIRING for roots in use that expire soon,
// and the report it read; nil without a reporter.
func (s statusDeps) trustStatus(ctx context.Context, ps *problems) (*TrustStatus, *TrustReport) {
	if s.trust == nil {
		return nil, nil
	}
	rep := s.trust()
	for _, r := range rep.Refused {
		s.addTrustRefused(ps, r)
	}
	a := rep.Applied
	out := &TrustStatus{Host: a.Host, Applies: string(a.Applies)}
	if a.Profile == nil {
		return out, &rep
	}
	certs := a.Profile.Certificates()
	slices.SortStableFunc(certs, func(x, y *x509.Certificate) int { return x.NotAfter.Compare(y.NotAfter) })
	out.Profile, out.Origin, out.RootCount = a.Profile.Name, string(a.Profile.Origin), len(certs)
	if a.Profile.VerifiesCA() {
		out.Verify = verifyCAStatus
	}
	for _, c := range certs[:min(len(certs), maxTrustRoots)] {
		out.Roots = append(out.Roots, TrustRootStatus{Subject: c.Subject.String(), SHA256: trustprofile.Fingerprint(c), NotAfter: c.NotAfter.UTC()})
	}
	s.addTrustExpiring(ps, a, certs)
	s.addPinMismatch(ctx, ps, rep)
	return out, &rep
}

// verifyCAStatus is status.trust.verify for a pin with verify: ca.
const verifyCAStatus = "CA"

// pinned is the profile of rep when it is an exact-host pin.
func pinned(rep *TrustReport) *trustprofile.Profile {
	if rep == nil || rep.Applied.Profile == nil || rep.Applied.Profile.Name != trustprofile.PinName(rep.Applied.Host) {
		return nil
	}
	return rep.Applied.Profile
}

// pinHolds reports whether p holds the certificate whose DER SHA-256 is sha.
func pinHolds(p *trustprofile.Profile, sha string) bool {
	for _, c := range p.Certificates() {
		if trustprofile.DERSHA256(c) == sha {
			return true
		}
	}
	return false
}

// pinFingerprints are p's certificates' fingerprints, for messages.
func pinFingerprints(p *trustprofile.Profile) string {
	fps := make([]string, 0, len(p.Certificates()))
	for _, c := range p.Certificates() {
		fps = append(fps, trustprofile.Fingerprint(c))
	}
	return strings.Join(fps, ", ")
}

// addPinMismatch is TRUST_PIN_MISMATCH when the ledger records, for the
// pinned host and port, another certificate than the engine's pin. No
// record is no problem: only basalt init records one.
func (s statusDeps) addPinMismatch(ctx context.Context, ps *problems, rep TrustReport) {
	p := pinned(&rep)
	if p == nil || rep.Recorded == nil {
		return
	}
	sha, ok, err := rep.Recorded(ctx)
	if err != nil {
		s.log.Debug("status: read the recorded trust pin", "err", err)
		return
	}
	if !ok || pinHolds(p, sha) {
		return
	}
	host := rep.Applied.Host
	ps.add(problemTrustPinMismatch, fmt.Sprintf("the engine pins %s to %s, but the ledger records SHA-256 %s for it", host, pinFingerprints(p), sha),
		func(b *Steps) string {
			b.RunCommand(s.cmds.TrustList(), "Compare the engine's pin with the one the ledger records, and with your provider's console.")
			return fmt.Sprintf("The engine trusts the certificate authority with SHA-256 %s for your database %s, but the pin recorded in the "+
				"ledger is SHA-256 %s. Check both in your provider's console; after a rotation you accepted, run basalt init again "+
				"to record the engine's pin. To see it: %s", pinFingerprints(p), host, sha, s.cmds.TrustList())
		})
}

func (s statusDeps) addTrustRefused(ps *problems, r trustprofile.Refused) {
	ps.add(problemTrustProfileRefused, "the trust profile file "+r.File+" is refused: "+r.Reason,
		func(b *Steps) string {
			b.RunCommand(s.cmds.TrustList(), "See why the file is refused, then fix it or remove it with basalt trust remove.")
			return "Basalt refused the trust profile file " + r.File + ": " + r.Reason + ". It does not apply, and a built-in profile of the same " +
				"name stays off until it is fixed; the other files still apply. To see it, run: " + s.cmds.TrustList()
		})
}

func (s statusDeps) addTrustExpiring(ps *problems, a trustprofile.Applied, sorted []*x509.Certificate) {
	now := s.now()
	var soon []*x509.Certificate
	for _, c := range sorted {
		if c.NotAfter.Sub(now) < trustExpiringWithin {
			soon = append(soon, c)
		}
	}
	if len(soon) == 0 {
		return
	}
	first := soon[0]
	when := "expires on " + first.NotAfter.UTC().Format(time.DateOnly)
	if !first.NotAfter.After(now) {
		when = "expired on " + first.NotAfter.UTC().Format(time.DateOnly)
	}
	what := fmt.Sprintf("root %s (SHA-256 %s)", first.Subject, trustprofile.Fingerprint(first))
	if len(soon) > 1 {
		what = fmt.Sprintf("%d roots, the first %s (SHA-256 %s),", len(soon), first.Subject, trustprofile.Fingerprint(first))
	}
	fix := "Add the provider's new root with basalt trust add, or name it with sslrootcert in the agent's connection string."
	if a.Profile.Origin == trustprofile.BuiltIn {
		fix = "Update basalt for the provider's new roots, or add them with basalt trust add."
	}
	ps.add(problemTrustRootExpiring, fmt.Sprintf("the trust profile %s verifying %s holds %s that %s", a.Profile.Name, a.Host, what, when),
		func(b *Steps) string {
			b.RunCommand(s.cmds.TrustList(), "Check the profile's roots. "+fix)
			return fmt.Sprintf("The certificate authority that verifies your database %s %s (trust profile %s). "+
				"Once no root of it is valid, the agent cannot connect. %s To see the roots, run: %s",
				a.Host, when, a.Profile.Name, fix, s.cmds.TrustList())
		})
}

// addCertificateNotVerified is CERTIFICATE_NOT_VERIFIED for a database
// whose certificate does not verify, naming the host and the fix that can
// work: a trust profile when the system's authorities or a profile
// verified it, the connection string's own roots when it names them, and
// verify-full when its sslmode is weaker (no profile applies then).
func (s statusDeps) addCertificateNotVerified(ctx context.Context, ps *problems, err error, trust *TrustReport) {
	s.log.Error("status: the database's certificate does not verify", "err", err)
	a := trustprofile.Applied{Host: "the database", Applies: trustprofile.AppliesSystem}
	if trust != nil {
		a = trust.Applied
		a.Host = cmp.Or(a.Host, "the database")
	}
	host := a.Host
	if s.addRootChanged(ctx, ps, trust) {
		return
	}
	msg := "the certificate of " + host + " does not verify, so the agent cannot connect"
	switch a.Applies {
	case trustprofile.AppliesRootCert, trustprofile.AppliesNotVerified:
		why := "the agent's connection string names its own roots (sslrootcert, PGSSLROOTCERT or ~/.postgresql/root.crt), and they do not " +
			"verify it; a trust profile does not apply while it names them. Fix or remove that root file"
		if a.Applies == trustprofile.AppliesNotVerified {
			why = "its sslmode is below verify-full, so trust profiles do not apply. Name the CA with sslrootcert in the agent's connection string"
		}
		ps.add(problemCertificateNotVerified, msg,
			func(b *Steps) string {
				b.RunCommand(s.cmds.TrustList(), "See what verifies the database's certificate, then fix the root its connection string names.")
				b.TellAgent("Tell the agent when it is done.")
				return "The certificate of your database " + host + " does not verify: " + why + ". To see what verifies it, run: " +
					s.cmds.TrustList() + "\nThen tell the agent."
			})
		return
	case trustprofile.AppliesProfile, trustprofile.AppliesSystem:
	}
	add := s.cmds.TrustAdd(host)
	ps.add(problemCertificateNotVerified, msg,
		func(b *Steps) string {
			b.RunCommand(add, "Save your database provider's CA certificate as "+strings.TrimPrefix(TrustCAFile, "./")+
				", then run this on the engine's machine (or name the CA with sslrootcert in the agent's connection string).")
			b.TellAgent("Tell the agent when it is done.")
			return "The certificate of your database " + host + " does not verify against the system's authorities or any trust profile. " +
				"Get its CA certificate from your provider, save it as " + strings.TrimPrefix(TrustCAFile, "./") +
				", and on the engine's machine run: " + add + "\nOr name the CA with sslrootcert in the agent's connection string. Then tell the agent."
		})
}

// addRootChanged is TRUST_ROOT_CHANGED when the agent's database is pinned
// and the chain top it presents now is not the pinned one: refused, naming
// both, with basalt trust pin to accept the new one. Never automatic.
func (s statusDeps) addRootChanged(ctx context.Context, ps *problems, rep *TrustReport) bool {
	p := pinned(rep)
	if p == nil || rep.Presented == nil {
		return false
	}
	top, err := rep.Presented(ctx)
	if err != nil || pinHolds(p, trustprofile.DERSHA256(top)) {
		return false
	}
	host := rep.Applied.Host
	cmd := s.cmds.TrustPin(host, rep.Port)
	ps.add(problemTrustRootChanged, fmt.Sprintf("%s presents the certificate authority SHA-256 %s, but it is pinned to %s, so the agent cannot connect",
		host, trustprofile.Fingerprint(top), pinFingerprints(p)),
		func(b *Steps) string {
			b.RunCommand(cmd, "Check the new certificate against your database provider's console, then accept it on the engine's machine.")
			b.TellAgent("Tell the agent when it is done.")
			return fmt.Sprintf("Your database %s presents another certificate authority than the pinned one.\nPinned: %s\nNow: %s\n"+
				"A provider's CA rotation, or someone between the engine and the database. Check it in your provider's console; "+
				"to accept it, on the engine's machine run: %s",
				host, pinFingerprints(p), trustprofile.Fingerprint(top), cmd)
		})
	return true
}
