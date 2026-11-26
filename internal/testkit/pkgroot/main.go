// Command pkgroot is the second root of the dead code check (make deadcode).
// The packages under pkg/ are a public API that other programs call, so their
// exported functions count as used even when cmd/basalt does not call them.
// main calls each one, so deadcode follows them like any call from cmd/basalt.
//
// It is never meant to run: the calls sit behind a condition that is never
// true. A new exported function under pkg/ goes here. An exported function
// that nothing should call any more stays out, so the check keeps reporting
// it until it is deleted.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/netip"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/pkg/setup"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

func main() {
	if len(os.Args) > 1<<20 {
		useSetup()
		useTrustpin()
		useTrustprofile()
	}
}

func useSetup() {
	ctx := context.Background()
	_ = setup.CertificateOf(nil, "", "")
	_, _ = setup.ConnectedAs(ctx, nil)
	r, _ := setup.PasskeyRequestFor(setup.PasskeyChallenge{}, "")
	_, _ = r.Verify("")
	_, _ = setup.CheckRemove(ctx, nil)
	_, _ = setup.RunRemove(ctx, nil, "")
	d, _ := setup.Describe(setup.Request{})
	_ = d.AcceptsTrustRoot()
	_ = setup.ConnDatabase(nil)
	_, _ = setup.Check(ctx, nil, setup.Request{})
	_, _ = setup.Run(ctx, nil, setup.Request{}, setup.RunInput{})
	_, _ = setup.RevokePasskey(ctx, nil, setup.Request{}, nil)
	_ = setup.Codes()
	var e error = &setup.Error{}
	_ = e.Error()
	_ = (&setup.Error{}).Unwrap()
	useSetupConnect(ctx)
}

// useSetupConnect calls the connect side of pkg/setup: the address policy,
// the signed connect texts and the passkey check code.
func useSetupConnect(ctx context.Context) {
	_ = setup.AddressAllowed(netip.Addr{})
	_ = setup.RefusedPrefixes()
	a, err := setup.PickAddress(ctx, setup.SystemResolver{}, "")
	_ = setup.AddressRefused(err)
	_ = a
	t := setup.Target{}.Canonical()
	_ = setup.ConnectCollectBody("", "", "")
	_ = setup.ConnectReachBody("", "", "", t, "", "")
	_ = setup.VerifyConnectCollect(nil, nil, "", "", "")
	_ = setup.VerifyConnectReach(nil, nil, "", "", "", t, "", "")
	_ = setup.CheckCode(nil, nil)
	_ = setup.SupabaseRef("", "")
}

func useTrustpin() {
	ctx := context.Background()
	_ = trustpin.Name(pkix.Name{})
	_ = trustpin.IssuerOf(tls.ConnectionState{})
	_, _ = trustpin.Fetch(ctx, nil, "", 0)
	s := trustpin.Check(nil, "", time.Time{})
	_ = s.Pinnable()
	_ = s.Subject()
	_ = trustpin.SubjectOf(nil)
	_ = trustpin.ValidSHA256("")
	if _, p, err := trustpin.Approved(nil, "", time.Time{}, ""); err == nil {
		_ = p
	}
}

func useTrustprofile() {
	var c *x509.Certificate
	set := trustprofile.NewSet(nil, nil, nil)
	trustprofile.Trust(nil, set)
	_ = trustprofile.Explain(nil, set)
	_ = trustprofile.CertificateNotVerified(nil)
	_, _ = trustprofile.NewPin("", c, false)
	_, _ = trustprofile.SystemRoots()
	trustprofile.SetSystemRootsForTest(nil)()
	_ = trustprofile.IsPublic(c, nil)
	_ = trustprofile.PublicRoots()
	_ = trustprofile.BuiltInSet()
	p := set.For("")
	_ = set.Refused()
	_ = set.Replacing("", nil)
	_, _ = trustprofile.LoadFS(nil, "", "")
	_ = trustprofile.FileName("")
	_ = trustprofile.CheckFileName("", "")
	var e error = &trustprofile.FileError{}
	_ = e.Error()
	_ = (&trustprofile.FileError{}).Unwrap()
	_ = trustprofile.CheckOperatorMatch("")
	_ = p.Certificates()
	_ = p.Pool()
	_ = p.OwnPool()
	_ = p.VerifiesCA()
	_ = p.Exact()
	_, _ = trustprofile.Parse(nil, "", nil)
	_, _ = trustprofile.ParseCAs(nil)
	_, _ = trustprofile.ParseCerts(nil)
	_ = trustprofile.FileSHA256(nil)
	_ = trustprofile.Fingerprint(c)
	_, _ = trustprofile.NormalizeSHA256("")
	_ = trustprofile.ValidName("")
	_ = trustprofile.ValidFileName("")
	_, _ = trustprofile.NormalizeMatch("")
	_ = trustprofile.NormalizeHost("")
	_ = trustprofile.PinName("")
	_ = trustprofile.DERSHA256(c)
	_ = trustprofile.ProviderName("")
	_ = trustprofile.VerifyFullByDefault("", set)
}
