package status

import (
	"cmp"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
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
	// problemCertificateNotChecked: the agent's connection uses TLS with an
	// sslmode below verify-full, so the certificate is not checked.
	problemCertificateNotChecked = "CERTIFICATE_NOT_CHECKED"
	// problemConnectionNotEncrypted: the agent's connection uses no TLS
	// (sslmode=disable, or prefer and allow on a server without it).
	problemConnectionNotEncrypted = "CONNECTION_NOT_ENCRYPTED"
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
	// Encrypted reports whether a connection of the agent's pool uses TLS
	// now (prefer falls back to none on a server without it), so a mode
	// below verify-full is CERTIFICATE_NOT_CHECKED; nil reads nothing.
	Encrypted func(ctx context.Context) (bool, error)
	// SSLMode is the sslmode the agent's connection string names, "" for
	// none (the driver's prefer).
	SSLMode string
	// Provider is the provider whose built-in profile covers the host
	// ("Supabase"), "" for none.
	Provider string
}

// TrustReporter reads the TrustReport now.
type TrustReporter func() TrustReport

// trustStatus is status.trust, adding TRUST_PROFILE_REFUSED for each
// refused file and TRUST_ROOT_EXPIRING for roots in use that expire soon,
// and the report it read; nil without a reporter.
func (s statusDeps) trustStatus(ctx context.Context, ps *guidance.Problems) (*guidance.TrustStatus, *TrustReport) {
	if s.trust == nil {
		return nil, nil
	}
	rep := s.trust()
	for _, r := range rep.Refused {
		s.addTrustRefused(ps, r)
	}
	a := rep.Applied
	out := &guidance.TrustStatus{Host: a.Host, Applies: string(a.Applies)}
	s.addNotChecked(ctx, ps, rep)
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
		out.Roots = append(out.Roots, guidance.TrustRootStatus{Subject: c.Subject.String(), SHA256: trustprofile.Fingerprint(c), NotAfter: c.NotAfter.UTC()})
	}
	s.addTrustExpiring(ps, a, certs)
	s.addPinMismatch(ctx, ps, rep)
	return out, &rep
}

// sslModeDefault is the driver's sslmode when the string names none.
const sslModeDefault = "prefer"

// addNotChecked is CERTIFICATE_NOT_CHECKED when the agent's connection is
// encrypted but its sslmode is below verify-full, so nothing checks the
// certificate is its database's, and CONNECTION_NOT_ENCRYPTED when it uses
// no TLS at all (sslmode=disable, or prefer and allow that fell back on a
// server without TLS). Both are read from a live connection; the setup
// page's check-up is where the person turns the check on. A Unix socket is
// not a network connection and is neither.
func (s statusDeps) addNotChecked(ctx context.Context, ps *guidance.Problems, rep TrustReport) {
	if rep.Applied.Applies != trustprofile.AppliesNotVerified || rep.Encrypted == nil || s.cmds.AgentOperated() ||
		strings.HasPrefix(rep.Applied.Host, "/") {
		return
	}
	on, err := rep.Encrypted(ctx)
	if err != nil {
		s.log.Debug("status: read whether the agent's connection is encrypted", "err", err)
		return
	}
	host := cmp.Or(rep.Applied.Host, "the database")
	mode := cmp.Or(rep.SSLMode, sslModeDefault)
	if !on {
		s.addNotEncrypted(ps, host, mode, rep.Provider)
		return
	}
	who := cmp.Or(rep.Provider, host)
	ps.Add(problemCertificateNotChecked, fmt.Sprintf("the agent's connection to %s uses sslmode=%s: encrypted, but the certificate is not checked", host, mode),
		func(b *guidance.Steps) string {
			b.AgentRunCommand(s.cmds.Init(), "Run this and show the person the link it prints: its check-up turns the certificate check on.")
			b.OpenGivenLink("Open the link the agent gives you and choose Check it on the certificate row.")
			return "Your agent's connection to " + who + " is encrypted but doesn't check the certificate. Open the link to turn the check on."
		})
}

// addNotEncrypted is CONNECTION_NOT_ENCRYPTED for host: on a provider's
// host the check-up's fix sets verify-full; elsewhere it says to give a
// string with sslmode=verify-full.
func (s statusDeps) addNotEncrypted(ps *guidance.Problems, host, mode, provider string) {
	ps.Add(problemConnectionNotEncrypted, fmt.Sprintf("the agent's connection to %s uses no TLS (sslmode=%s): its data and queries travel unencrypted", host, mode),
		func(b *guidance.Steps) string {
			b.AgentRunCommand(s.cmds.Init(), "Run this and show the person the link it prints: its check-up shows the connection that is not encrypted.")
			if provider != "" {
				b.OpenGivenLink("Open the link the agent gives you and choose Check it on the certificate row.")
				return "Your agent's connection to " + host + " isn't encrypted: its data and queries travel unencrypted. Open the link to turn encryption and the " + provider + " certificate check on."
			}
			b.OpenGivenLink("Open the link the agent gives you: the certificate row says what to change.")
			return "Your agent's connection to " + host + " isn't encrypted: its data and queries travel unencrypted. Open the link to see how to turn encryption on."
		})
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

// trustInitText is the text of the agent's basalt init step for a
// certificate the person checks and trusts on the setup page.
const trustInitText = "Run this once and show the person the link it prints: the setup page shows the database's certificate, and they decide."

// addPinMismatch is TRUST_PIN_MISMATCH when the ledger records, for the
// pinned host and port, another certificate than the engine's pin. No
// record is no problem: only basalt init records one.
func (s statusDeps) addPinMismatch(ctx context.Context, ps *guidance.Problems, rep TrustReport) {
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
	ps.Add(problemTrustPinMismatch, fmt.Sprintf("the engine pins %s to %s, but the ledger records SHA-256 %s for it", host, pinFingerprints(p), sha),
		func(b *guidance.Steps) string {
			b.AskPerson("Tell the person the ledger records another pin than the engine's, and ask whether they accepted a rotation.")
			b.AgentRunCommand(s.cmds.Init(), "On the person's yes, run this and show them the link it prints, where they record the engine's pin.")
			return fmt.Sprintf("The engine trusts the certificate authority with SHA-256 %s for your database %s, but the pin recorded in the "+
				"ledger is SHA-256 %s. Check both in your provider's console; after a rotation you accepted, the agent gives you a link "+
				"to record the engine's pin.", pinFingerprints(p), host, sha)
		})
}

func (s statusDeps) addTrustRefused(ps *guidance.Problems, r trustprofile.Refused) {
	ps.Add(problemTrustProfileRefused, "the trust profile file "+r.File+" is refused: "+r.Reason,
		func(b *guidance.Steps) string {
			b.TellAgent("Fix or remove the file on the engine's machine, then tell the agent.")
			return "Basalt refused the trust profile file " + r.File + ": " + r.Reason + ". It does not apply, and a built-in profile of the same " +
				"name stays off until it is fixed; the other files still apply. Fix or remove the file, then tell the agent."
		})
}

func (s statusDeps) addTrustExpiring(ps *guidance.Problems, a trustprofile.Applied, sorted []*x509.Certificate) {
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
	fix := "Once your provider has put the new certificate on the database, run basalt init again: its Update check offers to trust it."
	if a.Profile.Origin == trustprofile.BuiltIn {
		fix = "Update basalt for the provider's new roots. Nothing on the setup page adds a root before the database presents a new certificate."
	}
	ps.Add(problemTrustRootExpiring, fmt.Sprintf("the trust profile %s verifying %s holds %s that %s", a.Profile.Name, a.Host, what, when),
		func(b *guidance.Steps) string {
			b.AskPerson("Tell the person the root that verifies their database expires soon, and ask whether their provider has already put the new certificate on the database.")
			b.AgentRunCommand(s.cmds.Init(), "Only once they say it has, run this and show them the link it prints: its Update check shows the renewed certificate, and they decide. Before that it finds nothing to add.")
			return fmt.Sprintf("The certificate authority that verifies your database %s %s (trust profile %s). "+
				"Once no root of it is valid, the agent cannot connect. %s",
				a.Host, when, a.Profile.Name, fix)
		})
}

// addCertificateNotVerified is CERTIFICATE_NOT_VERIFIED for a database
// whose certificate does not verify, naming the host and the fix that can
// work: the setup page's trust step when the system's authorities or a
// profile verified it or its sslmode is weaker than verify-full, and the
// connection string's own roots when it names them.
func (s statusDeps) addCertificateNotVerified(ctx context.Context, ps *guidance.Problems, err error, trust *TrustReport) {
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
			why = "its sslmode is below verify-full, so trust profiles do not apply. Trust its CA on the setup page the agent gives you a link to"
		}
		ps.Add(problemCertificateNotVerified, msg,
			func(b *guidance.Steps) string {
				b.AgentRunCommand(s.cmds.Init(), trustInitText)
				b.TellAgent("Tell the agent when it is done.")
				return "The certificate of your database " + host + " does not verify: " + why + ". Or change the agent's connection on the " +
					"setup page the agent gives you a link to. Then tell the agent."
			})
		return
	case trustprofile.AppliesProfile, trustprofile.AppliesSystem:
	}
	ps.Add(problemCertificateNotVerified, msg,
		func(b *guidance.Steps) string {
			b.AgentRunCommand(s.cmds.Init(), trustInitText)
			b.TellAgent("Tell the agent when it is done.")
			return "The certificate of your database " + host + " does not verify against the system's authorities or any trust profile. " +
				"The agent gives you a link: the setup page shows the certificate the database presents, and you check it against your " +
				"provider's console and trust it there. Then tell the agent."
		})
}

// addRootChanged is TRUST_ROOT_CHANGED when the agent's database is pinned
// and the chain top it presents now is not the pinned one: refused, naming
// both; the person accepts the new one on the setup page basalt init links
// to. Never automatic.
func (s statusDeps) addRootChanged(ctx context.Context, ps *guidance.Problems, rep *TrustReport) bool {
	p := pinned(rep)
	if p == nil || rep.Presented == nil {
		return false
	}
	top, err := rep.Presented(ctx)
	if err != nil || pinHolds(p, trustprofile.DERSHA256(top)) {
		return false
	}
	host := rep.Applied.Host
	ps.Add(problemTrustRootChanged, fmt.Sprintf("%s presents the certificate authority SHA-256 %s, but it is pinned to %s, so the agent cannot connect",
		host, trustprofile.Fingerprint(top), pinFingerprints(p)),
		func(b *guidance.Steps) string {
			b.AgentRunCommand(s.cmds.Init(), trustInitText)
			b.TellAgent("Tell the agent when it is done.")
			return fmt.Sprintf("Your database %s presents another certificate authority than the pinned one.\nPinned: %s\nNow: %s\n"+
				"A provider's CA rotation, or someone between the engine and the database. Check it in your provider's console; "+
				"to accept it, open the link the agent gives you and pin it on the setup page.",
				host, pinFingerprints(p), trustprofile.Fingerprint(top))
		})
	return true
}
