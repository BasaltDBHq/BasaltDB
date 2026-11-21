package agent

import (
	"cmp"
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
func (s statusDeps) trustStatus(ps *problems) (*TrustStatus, *TrustReport) {
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
	for _, c := range certs[:min(len(certs), maxTrustRoots)] {
		out.Roots = append(out.Roots, TrustRootStatus{Subject: c.Subject.String(), SHA256: trustprofile.Fingerprint(c), NotAfter: c.NotAfter.UTC()})
	}
	s.addTrustExpiring(ps, a, certs)
	return out, &rep
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
func (s statusDeps) addCertificateNotVerified(ps *problems, err error, trust *TrustReport) {
	s.log.Error("status: the database's certificate does not verify", "err", err)
	a := trustprofile.Applied{Host: "the database", Applies: trustprofile.AppliesSystem}
	if trust != nil {
		a = trust.Applied
		a.Host = cmp.Or(a.Host, "the database")
	}
	host := a.Host
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
