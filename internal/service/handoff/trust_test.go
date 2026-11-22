package handoff

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// trustServer is a Postgres server whose certificate no profile and no
// system authority verifies, reached through a dialer that counts every
// connection: Approve makes one (the handshake alone), each probe login one
// more.
type trustServer struct {
	leaf   *x509.Certificate
	dials  atomic.Int32
	prober Prober
}

func newTrustServer(t *testing.T, certHost string, operator ...*trustprofile.Profile) *trustServer {
	t.Helper()
	_, cert := trustprofiletest.Chain(t, certHost)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	s := &trustServer{leaf: leaf}
	dial := trustprofiletest.Serve(t, cert)
	s.prober = Prober{
		Resolver: resolverFunc(func(string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil }),
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			s.dials.Add(1)
			if addr != "8.8.8.8:5432" {
				t.Errorf("dialed %s, not the resolved and checked address", addr)
			}
			return dial(ctx, network, addr)
		},
		Profiles:   trustprofiletest.Set(t, nil, operator...),
		ConnConfig: pgdial.ConnConfigTrusting,
	}
	return s
}

func (s *trustServer) fingerprint() string { return trustprofile.DERSHA256(s.leaf) }

var publicIP = netip.MustParseAddr("8.8.8.8")

// The engine reads the chain itself: the approved top it finds there is a
// pin, used for the probe and written nowhere; another top, or a malformed
// approval, is TRUST_ROOT_MISMATCH after the handshake alone, with no
// login.
func TestApproveReadsTheChainItself(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	s := newTrustServer(t, db.Host)
	_, err := s.prober.ProbeAt(ctx, db, publicIP, fixtureRole, Pin{})
	r, ok := ReachOf(err)
	require.True(t, ok)
	require.Equal(t, ReasonTLSNotVerified, r.Reason, "without a pin the certificate does not verify")

	s = newTrustServer(t, db.Host)
	pin, err := s.prober.Approve(ctx, db, publicIP, s.fingerprint())
	require.NoError(t, err)
	require.Equal(t, int32(1), s.dials.Load(), "the handshake alone")
	require.Equal(t, trustprofile.PinName(db.Host), pin.Profile.Name)
	require.True(t, pin.Top.Equal(s.leaf))
	require.False(t, pin.CAOnly)
	_, err = s.prober.ProbeAt(ctx, db, publicIP, fixtureRole, pin)
	require.NoError(t, err, "the probe verifies against the pin")

	other, _ := trustprofiletest.Chain(t, db.Host)
	for name, approved := range map[string]string{
		"another root": trustprofile.DERSHA256(other),
		"malformed":    "not-a-fingerprint",
	} {
		s := newTrustServer(t, db.Host)
		pin, err := s.prober.Approve(ctx, db, publicIP, approved)
		require.ErrorIs(t, err, ErrTrustRootMismatch, name)
		r, ok := ReachOf(err)
		require.True(t, ok)
		require.Equal(t, ReasonTrustRootMismatch, r.Reason)
		require.Nil(t, pin.Profile, name)
		require.Equal(t, int32(1), s.dials.Load(), name+": no login after the handshake")
	}
}

// A leaf that does not name the host pins with verify: ca.
func TestApproveNameOnly(t *testing.T) {
	t.Parallel()
	s := newTrustServer(t, "other.example.com")
	pin, err := s.prober.Approve(context.Background(), db, publicIP, s.fingerprint())
	require.NoError(t, err)
	require.True(t, pin.CAOnly)
	require.Equal(t, trustprofile.VerifyCA, pin.Profile.Verify)
	_, err = s.prober.ProbeAt(context.Background(), db, publicIP, fixtureRole, pin)
	require.NoError(t, err)
}

// A host a trust profile covers is the engine's own trust: the approval is
// not read, and nothing comes of it.
func TestApproveCoveredHostAddsNothing(t *testing.T) {
	t.Parallel()
	other, _ := trustprofiletest.Chain(t, db.Host)
	covers := trustprofiletest.Profile(t, trustprofile.Operator, "mine", []string{"=" + db.Host}, other)
	s := newTrustServer(t, db.Host, covers)
	pin, err := s.prober.Approve(context.Background(), db, publicIP, s.fingerprint())
	require.NoError(t, err)
	require.Nil(t, pin.Profile)
	require.Zero(t, s.dials.Load())
	_, err = s.prober.ProbeAt(context.Background(), db, publicIP, fixtureRole, pin)
	r, _ := ReachOf(err)
	require.Equal(t, ReasonTLSNotVerified, r.Reason, "the operator's profile decides, and it does not verify this server")
}

// The connect service can never add trust by itself: the trustRoot it hands
// over pins only when the engine's own chain top has that SHA-256. A
// mismatch is TRUST_ROOT_MISMATCH, with nothing pinned, no login and no
// confirmation asked; the match is pinned only by the person's yes, before
// the credential.
func TestServiceCannotAddTrustWithoutTheEnginesCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	other, _ := trustprofiletest.Chain(t, db.Host)
	pending := func(t *testing.T, trustRoot func(*trustServer) string) (*Pending, *fakeFiles, *trustServer) {
		t.Helper()
		s := newTrustServer(t, db.Host)
		setup := fixtureSetup()
		files := &fakeFiles{setup: &setup, secret: "the-real-password"}
		clk := &clock{now: fixtureMade.Add(time.Minute)}
		p, err := New(Options{
			Agent: "lead_bot", Setup: setup, Collector: &fakeCollector{addr: db, trustRoot: trustRoot(s)}, Prober: s.prober, Files: files,
			Changed: func() {}, Log: slog.New(slog.DiscardHandler), Now: clk.Now,
		})
		require.NoError(t, err)
		p.Step(ctx)
		return p, files, s
	}

	for name, root := range map[string]string{"another root": trustprofile.DERSHA256(other), "malformed": "zz", "none": ""} {
		p, files, s := pending(t, func(*trustServer) string { return root })
		st := p.State()
		require.Equal(t, PhaseWaiting, st.Phase, name)
		if root == "" {
			require.Equal(t, ProblemUnreachable, st.Problem, name+": no approval, no trust")
		} else {
			require.Equal(t, ProblemTrustRootMismatch, st.Problem, name)
			require.Equal(t, db, *st.Database, name)
			require.Equal(t, int32(1), s.dials.Load(), name+": the handshake alone, no login")
		}
		_, err := p.Confirm(ctx, fixtureID, db, true)
		require.ErrorIs(t, err, ErrNotWaiting, name)
		require.Empty(t, files.ops, name+": nothing written, nothing pinned")
	}

	p, files, s := pending(t, (*trustServer).fingerprint)
	require.Equal(t, PhaseConfirm, p.State().Phase)
	require.Empty(t, files.ops, "nothing is pinned before the person's answer")
	_, err := p.Confirm(ctx, fixtureID, db, true)
	require.NoError(t, err)
	require.Equal(t, []string{"lock", "read secret", "write pin", "write credential", "remove secret", "confirm setup", "unlock"}, files.ops)
	require.Len(t, files.pinned, 1)
	require.True(t, files.pinned[0].Top.Equal(s.leaf))
}

// A NO pins nothing, and a pin that cannot be written fails the YES before
// the credential.
func TestTrustedRootNoAndFailedPin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pinned := func(t *testing.T) harness {
		t.Helper()
		h := newHarness(t)
		h.col.err, h.col.addr, h.col.trustRoot = nil, db, "ab"
		h.prober.pin = Pin{Profile: &trustprofile.Profile{}, Top: &x509.Certificate{}}
		h.p.Step(ctx)
		require.Equal(t, PhaseConfirm, h.p.State().Phase)
		require.Equal(t, []string{"ab"}, h.prober.approved)
		require.Equal(t, h.prober.pin, h.prober.pins[0], "the probe runs with the pin")
		return h
	}
	h := pinned(t)
	_, err := h.p.Confirm(ctx, fixtureID, db, false)
	require.NoError(t, err)
	require.NotContains(t, h.files.ops, "write pin")

	h = pinned(t)
	h.files.failPin = true
	_, err = h.p.Confirm(ctx, fixtureID, db, true)
	require.Error(t, err)
	require.NotContains(t, h.files.ops, "write credential")
	require.Equal(t, "the-real-password", h.files.secret)
	require.True(t, h.files.setup.AwaitingAddress)
}

// A preview with a trusted root is checked and probed with the pin, which
// is then dropped; a passed preview stands in only for a SET_UP hold with
// the same trusted root, and the root is read again even then.
func TestPreviewWithTrustedRoot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	h := newHarness(t)
	h.col.err, h.col.addr, h.col.phase, h.col.trustRoot = nil, db, HoldPreview, "ab"
	h.prober.pin = Pin{Profile: &trustprofile.Profile{}, Top: &x509.Certificate{}}
	h.p.Step(ctx)
	require.Equal(t, 1, h.prober.probes)
	require.Equal(t, h.prober.pin, h.prober.pins[0])
	require.Len(t, h.col.reports, 1)
	require.Empty(t, h.files.ops, "a preview writes nothing")

	h.col.phase = HoldSetUp
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Equal(t, PhaseConfirm, h.p.State().Phase)
	require.Equal(t, 1, h.prober.probes, "the same trusted root: the preview stands in")
	require.Equal(t, []string{"ab", "ab"}, h.prober.approved, "the root is read again")

	h = newHarness(t)
	h.col.err, h.col.addr, h.col.phase = nil, db, HoldPreview
	h.p.Step(ctx)
	h.col.phase, h.col.trustRoot = HoldSetUp, "ab"
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Equal(t, 2, h.prober.probes, "a preview without the root stands in for none with it")

	h = newHarness(t)
	h.col.err, h.col.addr, h.col.phase, h.col.trustRoot = nil, db, HoldPreview, "ab"
	h.prober.approveErr = &ReachError{Reason: ReasonTrustRootMismatch}
	h.p.Step(ctx)
	require.Zero(t, h.prober.probes)
	require.Equal(t, []report{{db, Reach{Reason: ReasonTrustRootMismatch}}}, h.col.reports)
}

// A passed preview stands in for SET_UP only on the same trust: when the
// chain read again for SET_UP gives another pin, or none, it probes again.
func TestPreviewReuseNeedsTheSamePin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ca, _ := trustprofiletest.Chain(t, db.Host)
	other, _ := trustprofiletest.Chain(t, db.Host)
	for name, setUp := range map[string]Pin{
		"no pin now":  {},
		"another pin": {Profile: &trustprofile.Profile{}, Top: other},
	} {
		h := newHarness(t)
		h.col.err, h.col.addr, h.col.phase, h.col.trustRoot = nil, db, HoldPreview, "ab"
		h.prober.pin = Pin{Profile: &trustprofile.Profile{}, Top: ca}
		h.p.Step(ctx)
		require.Equal(t, 1, h.prober.probes, name)
		h.col.phase = HoldSetUp
		h.prober.pin = setUp
		h.clock.advance(fastEvery)
		h.p.Step(ctx)
		require.Equal(t, PhaseConfirm, h.p.State().Phase, name)
		require.Equal(t, 2, h.prober.probes, name+": probed again on the new trust")
		require.Equal(t, setUp, h.prober.pins[1], name)
	}
}

// A chain from an authority in the system's store is never pinned from the
// page either: the probe is TLS_NOT_VERIFIED, with nothing pinned and no
// login. Not parallel: it swaps the system's store.
func TestApproveRefusesPublicAuthorities(t *testing.T) {
	s := newTrustServer(t, "other.example.com")
	store := x509.NewCertPool()
	store.AddCert(s.leaf)
	defer trustprofile.SetSystemRootsForTest(store)()
	pin, err := s.prober.Approve(context.Background(), db, publicIP, s.fingerprint())
	r, ok := ReachOf(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, ReasonTLSNotVerified, r.Reason)
	require.Nil(t, pin.Profile)
	require.Equal(t, int32(1), s.dials.Load(), "the handshake alone")
}
