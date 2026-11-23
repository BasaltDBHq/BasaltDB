package handoff

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// The contract's connect-only fixture (api/mcp/setup/setup-code.fixtures.json,
// "connect-only install of all tables"): setupId ...e1, made at its UUIDv7
// time, role basalt_agent_lead_bot.
const (
	fixtureCode        = "basalt-setup.1.PJBdb6JAFIb_y0nvlmlnrKJO4sUUtFXESou2uNmYAQecOjB0gPrR-N837G72XJ3kPDlvnvcbUm1yXgMlFlSibsrpDihgwknaHySo14kHqJ_cczRMMUb4_wgCFhxk0dLTxWvI5nOwoDQilSegEPOKqxosyBpudkC_ITU6B4otqDVQYl8tiBup_oTd9m4xWMAzUdQtWvBcAAUl-G4b6_YLVyrksRJVe66Svch5BfQnlE2sZAK_rhZ8CSNTKQxQeHVemI9enxjq9OybLh7alAVT94GtHh-O2czJKt8NussxG41uzt33U3R3Kcovd_nj7TDTy_eJDPjjnVfNVPg514P95lE5jX4ejGjWU5FbzLpv2jddW77tz59RkXB395Lovn_5IpNz9vR81vu78QgsqGpei1wUdShzoZvar4Det-VdLRCnUhpRsRoodHDHRoSgDg6xTUmHErIBC0SRyUK0xn81PXEGCv7kcBwfoydPb6aXD-ywIJr-210WJG6QsfFqfRzGpvhQ5jDG276XknB4CS4P9kZsF-TeW61NUFbPmJHhZGG69mrpR2ibqxdycLScBB4aLNbI8Vf9ue-o-JRuULhmcL3-DgAA__8.mvDCHA"
	fixtureID          = "01a1f78c-52b8-7c3a-9f00-0000000000e1"
	fixtureFingerprint = "734b aaea 804e 1065 4148"
	fixtureRole        = "basalt_agent_lead_bot"
)

// fixtureMade is the fixture's setupId time.
var fixtureMade = time.UnixMilli(0x01a1f78c52b8).UTC()

var db = setupcode.Address{Host: "db.example.com", Port: 5432, Database: "app"}

func fixtureSetup() config.Setup {
	return config.Setup{
		SetupID: fixtureID, Kind: guardmodel.SetupInstall, GuardVersion: 16, ExpiresAt: "2026-11-20T06:12:11Z",
		Code: fixtureCode, Fingerprint: fixtureFingerprint, AwaitingAddress: true,
	}
}

type fakeCollector struct {
	mu   sync.Mutex
	addr setupcode.Address
	// phase is the hold's; "" is SET_UP here, so the older tests read as
	// before.
	phase   string
	err     error
	calls   int
	reports []report
	// trustRoot is the certificate authority the hold carries.
	trustRoot string
}

type report struct {
	addr  setupcode.Address
	reach Reach
}

func (c *fakeCollector) Collect(_ context.Context, id, fp string) (Collected, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if id != fixtureID || fp != fixtureFingerprint {
		return Collected{}, errors.New("another setup")
	}
	phase := c.phase
	if phase == "" {
		phase = HoldSetUp
	}
	return Collected{Address: c.addr, Phase: phase, TrustRoot: c.trustRoot}, c.err
}

func (c *fakeCollector) Report(_ context.Context, id, fp string, a setupcode.Address, r Reach) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id != fixtureID || fp != fixtureFingerprint {
		return errors.New("another setup")
	}
	c.reports = append(c.reports, report{a, r})
	return nil
}

type fakeProber struct {
	err error
	// ip is what every host resolves to; 8.8.8.8 when unset.
	ip     netip.Addr
	users  []string
	probes int
	// approved records every Approve; pin and approveErr are its answer.
	approved   []string
	pin        Pin
	approveErr error
	// pins records the pin each probe ran with.
	pins []Pin
}

func (p *fakeProber) Approve(_ context.Context, _ setupcode.Address, _ netip.Addr, approved string) (Pin, error) {
	p.approved = append(p.approved, approved)
	return p.pin, p.approveErr
}

func (p *fakeProber) Resolve(_ context.Context, a setupcode.Address) (netip.Addr, error) {
	if err := a.Check(); err != nil {
		return netip.Addr{}, err
	}
	if errors.Is(p.err, setupcode.ErrAddressInvalid) {
		return netip.Addr{}, p.err
	}
	if p.ip.IsValid() {
		return p.ip, nil
	}
	return netip.MustParseAddr("8.8.8.8"), nil
}

func (p *fakeProber) ProbeAt(_ context.Context, _ setupcode.Address, ip netip.Addr, user string, pin Pin) (Probed, error) {
	p.users = append(p.users, user)
	p.pins = append(p.pins, pin)
	p.probes++
	if p.err != nil {
		return Probed{}, p.err
	}
	return Probed{IP: ip, ChannelBinding: true}, nil
}

// fakeFiles keeps the agent's files in memory and records each use, so a
// test sees what was read and written, in order.
type fakeFiles struct {
	setup      *config.Setup
	secret     string
	credential string
	ops        []string
	failWrite  bool
	pinned     []Pin
	failPin    bool
}

func (f *fakeFiles) WritePin(_ string, pin Pin) error {
	f.ops = append(f.ops, "write pin")
	if f.failPin {
		return errors.New("a profile covers the host now")
	}
	f.pinned = append(f.pinned, pin)
	return nil
}

func (f *fakeFiles) Lock() (func(), error) {
	f.ops = append(f.ops, "lock")
	return func() { f.ops = append(f.ops, "unlock") }, nil
}

func (f *fakeFiles) PendingSetup() (config.Setup, bool, error) {
	if f.setup == nil {
		return config.Setup{}, false, nil
	}
	return *f.setup, true, nil
}

func (f *fakeFiles) ReadSecret() (string, error) {
	f.ops = append(f.ops, "read secret")
	if f.secret == "" {
		return "", errors.New("no .secret")
	}
	return f.secret, nil
}

func (f *fakeFiles) WriteCredential(dsn string) error {
	f.ops = append(f.ops, "write credential")
	if f.failWrite {
		return errors.New("disk full")
	}
	f.credential = dsn
	return nil
}

func (f *fakeFiles) RemoveSecret() error {
	f.ops = append(f.ops, "remove secret")
	f.secret = ""
	return nil
}

func (f *fakeFiles) ConfirmSetup(string) error {
	f.ops = append(f.ops, "confirm setup")
	f.setup.AwaitingAddress = false
	return nil
}

func (f *fakeFiles) MarkAddressInvalid(string) error {
	f.ops = append(f.ops, "mark address invalid")
	f.setup.AddressInvalid = true
	return nil
}

func (f *fakeFiles) RefuseSetup(string) error {
	f.ops = append(f.ops, "refuse setup")
	f.setup.AwaitingAddress, f.setup.Refused = false, true
	return nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type harness struct {
	p       *Pending
	col     *fakeCollector
	prober  *fakeProber
	files   *fakeFiles
	clock   *clock
	changed chan struct{}
}

func newHarness(t *testing.T) harness {
	t.Helper()
	s := fixtureSetup()
	h := harness{
		col: &fakeCollector{err: ErrNotHeld}, prober: &fakeProber{},
		files: &fakeFiles{setup: &s, secret: "the-real-password"}, clock: &clock{now: fixtureMade.Add(time.Minute)},
		changed: make(chan struct{}, 1),
	}
	p, err := New(Options{
		Agent: "lead_bot", Setup: s, Collector: h.col, Prober: h.prober, Files: h.files,
		Changed: func() { h.changed <- struct{}{} }, Log: slog.New(slog.DiscardHandler), Now: h.clock.Now,
	})
	require.NoError(t, err)
	h.p = p
	return h
}

func TestAllowedAddresses(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"8.8.8.8", "34.120.1.2", "2600:1f18::1"} {
		require.True(t, Allowed(netip.MustParseAddr(a)), a)
	}
	for _, a := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"192.0.2.1", "198.18.0.1", "203.0.113.5", "224.0.0.1", "255.255.255.255",
		"::1", "::ffff:10.0.0.1", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1", "2001::1", "fd00::1", "fe80::1", "2001:db8::1",
	} {
		require.False(t, Allowed(netip.MustParseAddr(a)), a)
	}
}

// A host with any refused address among those it resolves to is refused
// as a whole; IPv4 is preferred; a name that does not resolve is
// unreachable.
func TestPickResolvesOnce(t *testing.T) {
	t.Parallel()
	r := resolverFunc(func(host string) ([]netip.Addr, error) {
		switch host {
		case "mixed.example.com":
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, nil
		case "dual.example.com":
			return []netip.Addr{netip.MustParseAddr("2600:1f18::1"), netip.MustParseAddr("8.8.4.4")}, nil
		case "metadata.example.com":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		}
		return nil, errors.New("no such host")
	})
	ctx := context.Background()
	_, err := pick(ctx, r, "mixed.example.com")
	require.ErrorIs(t, err, setupcode.ErrAddressInvalid)
	_, err = pick(ctx, r, "metadata.example.com")
	require.ErrorIs(t, err, setupcode.ErrAddressInvalid)
	_, err = pick(ctx, r, "10.0.0.1")
	require.ErrorIs(t, err, setupcode.ErrAddressInvalid, "an IP literal is checked as it is")
	a, err := pick(ctx, r, "dual.example.com")
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("8.8.4.4"), a)
	_, err = pick(ctx, r, "nowhere.example.com")
	require.ErrorIs(t, err, errUnresolved)
}

type resolverFunc func(string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return f(host)
}

// A probe of an address that resolves to a private range never dials.
func TestProbeRefusesAPrivateAddressBeforeDialing(t *testing.T) {
	t.Parallel()
	dialed := false
	p := Prober{
		Resolver: resolverFunc(func(string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil }),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("dialed")
		},
	}
	_, err := p.Probe(context.Background(), db, fixtureRole)
	require.ErrorIs(t, err, setupcode.ErrAddressInvalid)
	require.False(t, dialed)
	_, err = p.Probe(context.Background(), setupcode.Address{Host: "db example", Port: 5432, Database: "app"}, fixtureRole)
	require.ErrorIs(t, err, setupcode.ErrAddressInvalid)
	require.False(t, dialed)
}

func TestConnString(t *testing.T) {
	t.Parallel()
	require.Equal(t, "postgres://basalt_agent_bot:pw@db.example.com:5432/app?channel_binding=require&sslmode=verify-full",
		ConnString(db, "basalt_agent_bot", "pw", true))
	require.Equal(t, "postgres://basalt_agent_bot:pw@db.example.com:5432/app?sslmode=verify-full", ConnString(db, "basalt_agent_bot", "pw", false))
}

// The cadence: every 15 seconds for the code's life plus the 30-minute
// hold (40 minutes after the code was made).
func TestCollectCadence(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	wait := func() time.Duration {
		d, ok := h.p.nextWait()
		require.True(t, ok)
		return d
	}
	require.Zero(t, wait(), "the first collect is at once")
	h.p.Step(context.Background())
	require.Equal(t, fastEvery, wait())

	h.clock.now = fixtureMade.Add(30 * time.Minute)
	h.p.Step(context.Background())
	require.Equal(t, fastEvery, wait())

	// While the database cannot be reached, the cadence is the same.
	h.col.err, h.col.addr, h.prober.err = nil, db, &ReachError{Reason: ReasonNoRoute}
	h.clock.now = fixtureMade.Add(35 * time.Minute)
	h.p.Step(context.Background())
	require.Equal(t, ProblemUnreachable, h.p.State().Problem)
	require.Equal(t, fastEvery, wait())

	// A status call collects at once, however recent the last collect.
	calls := h.col.calls
	h.p.StatusCollect(context.Background())
	require.Equal(t, calls+1, h.col.calls)

	h.clock.now = fixtureMade.Add(40 * time.Minute)
	_, ok := h.p.nextWait()
	require.False(t, ok, "no collect after the collect window")
	calls = h.col.calls
	h.p.Step(context.Background())
	require.Equal(t, calls, h.col.calls, "nor on status")
	require.True(t, h.p.State().Expired)
}

func TestRateLimitedWaits(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.col.err = &RateLimitedError{After: time.Minute}
	h.p.Step(context.Background())
	d, ok := h.p.nextWait()
	require.True(t, ok)
	require.Equal(t, time.Minute, d)
	h.p.Step(context.Background())
	require.Equal(t, 1, h.col.calls, "no collect before retryAfterSeconds")
}

// Unknown and clock skew keep the setup waiting; a probe that passed asks
// the person; the address the service holds is collected again after a
// restart, and a changed one is probed again.
func TestStepCollectsChecksAndProbes(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()

	h.p.Step(ctx)
	st := h.p.State()
	require.Equal(t, PhaseWaiting, st.Phase)
	require.Empty(t, st.Problem)

	h.col.err = ErrClockSkew
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Equal(t, ProblemClockSkew, h.p.State().Problem)

	h.col.err, h.col.addr = nil, setupcode.Address{Host: "db example", Port: 5432, Database: "app"}
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	st = h.p.State()
	require.Equal(t, ProblemAddressInvalid, st.Problem)
	require.Nil(t, st.Database, "nothing of a refused address is kept to show")
	require.True(t, h.files.setup.AddressInvalid, "engine.json records it, so the next basalt init --remote makes a new code")
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Equal(t, ProblemAddressInvalid, h.p.State().Problem)
	marks := 0
	for _, op := range h.files.ops {
		if op == "mark address invalid" {
			marks++
		}
	}
	require.Equal(t, 1, marks, "recorded once, not at every collect")

	h.col.addr, h.prober.err = db, ErrUnreachable
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	st = h.p.State()
	require.Equal(t, ProblemUnreachable, st.Problem)
	require.Equal(t, &db, st.Database)

	h.prober.err = nil
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	st = h.p.State()
	require.Equal(t, PhaseConfirm, st.Phase)
	require.Equal(t, &db, st.Database)
	require.Equal(t, []string{fixtureRole, fixtureRole}, h.prober.users, "the probe logs in as the agent's role, and a refused address is never probed")

	// Once the probe passed, nothing collects: the database the person is
	// asked about cannot change under the question.
	calls := h.col.calls
	h.col.addr = setupcode.Address{Host: "other.example.com", Port: 5432, Database: "app"}
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	h.p.StatusCollect(ctx)
	require.Equal(t, calls, h.col.calls)
	require.Equal(t, &db, h.p.State().Database)
	require.NotContains(t, h.files.ops, "read secret", "nothing reads .secret before the person's answer")
}

func confirmable(t *testing.T) harness {
	t.Helper()
	h := newHarness(t)
	h.col.err, h.col.addr = nil, db
	h.p.Step(context.Background())
	require.Equal(t, PhaseConfirm, h.p.State().Phase)
	require.Empty(t, h.files.ops, "no file is touched before the answer")
	return h
}

func TestConfirmRefusesAnotherSetupOrDatabase(t *testing.T) {
	t.Parallel()
	h := confirmable(t)
	ctx := context.Background()
	_, err := h.p.Confirm(ctx, "01a1f78c-52b8-7c3a-9f00-0000000000e2", db, true)
	require.ErrorIs(t, err, ErrNotWaiting)
	other := db
	other.Database = "other"
	_, err = h.p.Confirm(ctx, fixtureID, other, true)
	require.ErrorIs(t, err, ErrNotWaiting)
	require.Empty(t, h.files.ops, "a refused answer touches nothing")
}

// YES: under the lock, .secret read, the credential for exactly the probed
// address written, .secret removed, awaitingAddress cleared, in that order;
// then the engine builds the agent anew.
func TestConfirmYes(t *testing.T) {
	t.Parallel()
	h := confirmable(t)
	ans, err := h.p.Confirm(context.Background(), fixtureID, db, true)
	require.NoError(t, err)
	require.True(t, ans.Confirmed)
	require.Equal(t, []string{"lock", "read secret", "write credential", "remove secret", "confirm setup", "unlock"}, h.files.ops)
	require.Equal(t, "postgres://basalt_agent_lead_bot:the-real-password@db.example.com:5432/app?channel_binding=require&sslmode=verify-full", h.files.credential)
	select {
	case <-h.changed:
	case <-time.After(5 * time.Second):
		t.Fatal("the engine is not told to build the agent anew")
	}
	_, err = h.p.Confirm(context.Background(), fixtureID, db, true)
	require.ErrorIs(t, err, ErrNotWaiting, "an answer counts once")
}

// A missing .secret fails the YES with nothing written; a credential that
// cannot be written leaves .secret and engine.json as they were.
func TestConfirmYesFailsClosed(t *testing.T) {
	t.Parallel()
	h := confirmable(t)
	h.files.secret = ""
	_, err := h.p.Confirm(context.Background(), fixtureID, db, true)
	require.Error(t, err)
	require.Empty(t, h.files.credential)
	require.NotContains(t, h.files.ops, "write credential")
	require.True(t, h.files.setup.AwaitingAddress)

	h = confirmable(t)
	h.files.failWrite = true
	_, err = h.p.Confirm(context.Background(), fixtureID, db, true)
	require.Error(t, err)
	require.NotContains(t, h.files.ops, "remove secret")
	require.Equal(t, "the-real-password", h.files.secret)
	require.True(t, h.files.setup.AwaitingAddress)
}

// NO: .secret removed and refused recorded, without reading .secret or
// writing a credential.
func TestConfirmNo(t *testing.T) {
	t.Parallel()
	h := confirmable(t)
	ans, err := h.p.Confirm(context.Background(), fixtureID, db, false)
	require.NoError(t, err)
	require.False(t, ans.Confirmed)
	require.Equal(t, []string{"lock", "remove secret", "refuse setup", "unlock"}, h.files.ops)
	st := h.p.State()
	require.Equal(t, PhaseRefused, st.Phase)
	require.Nil(t, st.Database)
	require.Empty(t, h.files.credential)
	h.clock.advance(time.Minute)
	h.p.Step(context.Background())
	_, ok := h.p.nextWait()
	require.False(t, ok, "a refused setup never collects")
}

// A pending setup that engine.json no longer records drops the address
// and has the engine build the agent anew.
func TestConfigChangeDropsTheAddress(t *testing.T) {
	t.Parallel()
	h := confirmable(t)
	h.files.setup = nil
	st := h.p.State()
	require.Equal(t, PhaseGone, st.Phase)
	require.Nil(t, st.Database)
	select {
	case <-h.changed:
	case <-time.After(5 * time.Second):
		t.Fatal("the engine is not told")
	}
	_, err := h.p.Confirm(context.Background(), fixtureID, db, true)
	require.ErrorIs(t, err, ErrNotWaiting)
}

// A PREVIEW address is checked, probed and reported, and nothing else: the
// setup stays waiting, status shows nothing of it, nothing reads .secret,
// and the collecting goes on.
func TestPreviewOnlyReports(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()
	h.col.err, h.col.addr, h.col.phase = nil, setupcode.Address{Host: "DB.Example.com", Port: 6543, Database: "app"}, HoldPreview
	h.p.Step(ctx)
	st := h.p.State()
	require.Equal(t, PhaseWaiting, st.Phase)
	require.Nil(t, st.Database)
	require.Empty(t, st.Problem)
	require.Empty(t, h.files.ops, "no file is touched")
	require.Equal(t, []report{{setupcode.Address{Host: "DB.Example.com", Port: 6543, Database: "app"}, Reach{}}}, h.col.reports)
	require.Equal(t, 1, h.prober.probes)
	_, ok := h.p.nextWait()
	require.True(t, ok, "it keeps collecting")

	// The same address again within 5 minutes: reported again, not probed.
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Len(t, h.col.reports, 2)
	require.Equal(t, 1, h.prober.probes)

	// Another address: probed and reported; a failure carries its reason
	// and is still not shown.
	h.col.addr, h.prober.err = db, &ReachError{Reason: ReasonTLSNotVerified}
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Equal(t, 2, h.prober.probes)
	require.Equal(t, report{db, Reach{Reason: ReasonTLSNotVerified}}, h.col.reports[2])
	st = h.p.State()
	require.Equal(t, PhaseWaiting, st.Phase)
	require.Nil(t, st.Database)
	require.Empty(t, st.Problem)

	// The same address that was not reached is probed again after 5
	// minutes; once reached, never again while it stays the same, so a flow
	// leaves at most two failed logins.
	h.prober.err = nil
	h.clock.advance(reuseFor + time.Second)
	h.p.Step(ctx)
	require.Equal(t, 3, h.prober.probes)
	require.Equal(t, report{db, Reach{}}, h.col.reports[3])
	h.clock.advance(20 * time.Minute)
	h.p.Step(ctx)
	require.Equal(t, 3, h.prober.probes, "a reached address is not probed again")
	require.Equal(t, report{db, Reach{}}, h.col.reports[4])
	h.col.reports = h.col.reports[:4]

	// A refused range is reported ADDRESS_REFUSED; a shape that fails is
	// never reported.
	h.prober.err = &ReachError{Reason: ReasonAddressRefused}
	h.col.addr = setupcode.Address{Host: "private.example.com", Port: 5432, Database: "app"}
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Equal(t, report{h.col.addr, Reach{Reason: ReasonAddressRefused}}, h.col.reports[4])
	h.col.addr = setupcode.Address{Host: "db example", Port: 5432, Database: "app"}
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Len(t, h.col.reports, 5)
	st = h.p.State()
	require.Equal(t, PhaseWaiting, st.Phase)
	require.Empty(t, st.Problem, "a preview never shows a problem")
	require.NotContains(t, h.files.ops, "read secret")
}

// Any phase but SET_UP is a preview: the engine never asks about it.
func TestUnknownPhaseIsAPreview(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.col.err, h.col.addr, h.col.phase = nil, db, "SOMETHING_ELSE"
	h.p.Step(context.Background())
	require.Equal(t, PhaseWaiting, h.p.State().Phase)
	require.Len(t, h.col.reports, 1)
}

// The SET_UP probe reuses a passed PREVIEW probe of the same address and
// IP within 5 minutes, and probes again otherwise. It never reports.
func TestSetUpReusesAPassedPreviewProbe(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	preview := func(t *testing.T) harness {
		t.Helper()
		h := newHarness(t)
		h.col.err, h.col.addr, h.col.phase = nil, db, HoldPreview
		h.p.Step(ctx)
		require.Equal(t, 1, h.prober.probes)
		h.col.phase = HoldSetUp
		h.clock.advance(fastEvery)
		return h
	}

	h := preview(t)
	h.p.Step(ctx)
	require.Equal(t, PhaseConfirm, h.p.State().Phase)
	require.Equal(t, 1, h.prober.probes, "the passed preview probe stands in")
	require.Len(t, h.col.reports, 1, "a SET_UP address is never reported")

	h = preview(t)
	h.prober.ip = netip.MustParseAddr("8.8.4.4")
	h.p.Step(ctx)
	require.Equal(t, PhaseConfirm, h.p.State().Phase)
	require.Equal(t, 2, h.prober.probes, "another IP: probed again")

	h = preview(t)
	h.col.addr = setupcode.Address{Host: "other.example.com", Port: 5432, Database: "app"}
	h.p.Step(ctx)
	require.Equal(t, 2, h.prober.probes, "another address on the same IP: probed again")

	h = preview(t)
	h.clock.advance(reuseFor)
	h.p.Step(ctx)
	require.Equal(t, 2, h.prober.probes, "after 5 minutes: probed again")
}

func TestReachReasons(t *testing.T) {
	t.Parallel()
	r, ok := ReachOf(nil)
	require.True(t, ok)
	require.Empty(t, r.Reason)
	_, ok = ReachOf(setupcode.ErrAddressInvalid)
	require.False(t, ok, "a shape that fails is never reported")
	r, ok = ReachOf(&ReachError{Reason: ReasonAddressRefused})
	require.True(t, ok)
	require.Equal(t, ReasonAddressRefused, r.Reason)
	require.ErrorIs(t, &ReachError{Reason: ReasonAddressRefused}, setupcode.ErrAddressInvalid)
	require.ErrorIs(t, &ReachError{Reason: ReasonTimeout}, ErrUnreachable)
	require.NotErrorIs(t, &ReachError{Reason: ReasonTimeout}, setupcode.ErrAddressInvalid)

	require.Equal(t, ReasonTimeout, reasonOf(context.DeadlineExceeded))
	require.Equal(t, ReasonTLSNotVerified, reasonOf(fmt.Errorf("connect: %w", x509.HostnameError{Host: "db.example.com", Certificate: &x509.Certificate{}})))
	require.Equal(t, ReasonTLSNotVerified, reasonOf(fmt.Errorf("connect: %w", x509.UnknownAuthorityError{})))
	require.Equal(t, ReasonTLSNotVerified, reasonOf(errors.New("failed to connect: server refused TLS connection")))
	require.Equal(t, ReasonNoRoute, reasonOf(&net.OpError{Op: "dial", Err: errors.New("connection refused")}))

	// A resolver with nothing, and a refused range, before any dial.
	p := Prober{Resolver: resolverFunc(func(host string) ([]netip.Addr, error) {
		if host == "private.example.com" {
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		}
		return nil, errors.New("no such host")
	})}
	_, err := p.Resolve(context.Background(), db)
	r, _ = ReachOf(err)
	require.Equal(t, ReasonNoRoute, r.Reason)
	_, err = p.Resolve(context.Background(), setupcode.Address{Host: "private.example.com", Port: 5432, Database: "app"})
	r, _ = ReachOf(err)
	require.Equal(t, ReasonAddressRefused, r.Reason)
	require.ErrorIs(t, err, setupcode.ErrAddressInvalid)
}

// A preview leaves status as before the address came: a problem from an
// earlier collect goes.
func TestPreviewClearsAnEarlierProblem(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.col.err = ErrClockSkew
	h.p.Step(context.Background())
	require.Equal(t, ProblemClockSkew, h.p.State().Problem)
	h.col.err, h.col.addr, h.col.phase = nil, db, HoldPreview
	h.clock.advance(fastEvery)
	h.p.Step(context.Background())
	require.Empty(t, h.p.State().Problem)
}

// A status call does not wait for the loop's step: it returns the state as
// it is while that step runs.
func TestStatusCollectDoesNotWaitForTheLoop(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.p.stepMu.Lock()
	done := make(chan State, 1)
	go func() { done <- h.p.StatusCollect(context.Background()) }()
	select {
	case st := <-done:
		require.Equal(t, PhaseWaiting, st.Phase)
	case <-time.After(5 * time.Second):
		t.Fatal("status waited for the loop's step")
	}
	h.p.stepMu.Unlock()
	require.Zero(t, h.col.calls, "no collect while the loop's step runs")
}

type memCache struct {
	c  Cached
	ok bool
}

func (m *memCache) Load(id string) (Cached, bool) { return m.c, m.ok && m.c.SetupID == id }
func (m *memCache) Save(c Cached) error           { m.c, m.ok = c, true; return nil }

// The probe cache carries a preview probe to the next process: a reached
// address is reported again without a new probe, and a process that does
// not probe SET_UP addresses (basalt status) reuses a passed one or waits.
func TestProbeCacheAcrossProcesses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache := &memCache{}
	process := func(noSetUp bool) harness {
		h := newHarness(t)
		p, err := New(Options{
			Agent: "lead_bot", Setup: fixtureSetup(), Collector: h.col, Prober: h.prober, Files: h.files,
			Changed: func() {}, Log: slog.New(slog.DiscardHandler), Now: h.clock.Now, Cache: cache, NoSetUpProbe: noSetUp,
		})
		require.NoError(t, err)
		h.p = p
		h.col.err, h.col.addr, h.col.phase = nil, db, HoldPreview
		return h
	}
	first := process(true)
	first.p.StatusCollect(ctx)
	require.Equal(t, 1, first.prober.probes)
	require.True(t, cache.ok)
	require.NotContains(t, cache.c.AddressKey, "example", "the cache keeps a hash, never the address")

	second := process(true)
	second.p.StatusCollect(ctx)
	require.Zero(t, second.prober.probes, "a reached address is not probed again in another process")
	require.Len(t, second.col.reports, 1)

	// SET_UP in a process that does not probe it: the passed preview
	// stands in within 5 minutes; without it, nothing is probed.
	second.col.phase = HoldSetUp
	second.p.StatusCollect(ctx)
	require.Equal(t, PhaseConfirm, second.p.State().Phase)
	require.Zero(t, second.prober.probes)

	third := process(true)
	third.col.phase = HoldSetUp
	third.clock.advance(reuseFor + time.Minute)
	third.p.StatusCollect(ctx)
	require.Equal(t, PhaseWaiting, third.p.State().Phase)
	require.Zero(t, third.prober.probes, "basalt status never probes a SET_UP address")
}

// probeAt probes a at a public address, through a server presenting a chain
// for certHost from a test CA that stands in for Supabase's root.
func probeAt(t *testing.T, a setupcode.Address, certHost string) error {
	t.Helper()
	ca, cert := trustprofiletest.Chain(t, certHost)
	p := Prober{Login: pgdial.Login, Dial: trustprofiletest.Serve(t, cert), Profiles: trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}})}
	_, err := p.ProbeAt(context.Background(), a, netip.MustParseAddr("203.0.113.7"), fixtureRole, Pin{})
	return err
}

// The probe verifies a chain from Supabase's root on a Supabase host, the
// direct one and the pooler; the same chain on any other host, or for
// another host name, is TLS_NOT_VERIFIED.
func TestProbeTrustsSupabaseRootOnSupabaseHosts(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"db.abcdefghijklmnopqrst.supabase.co", "aws-0-eu-central-1.pooler.supabase.com"} {
		a := setupcode.Address{Host: host, Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
		require.NoError(t, probeAt(t, a, host), host)
	}
	notVerified := func(a setupcode.Address, certHost string) {
		r, ok := ReachOf(probeAt(t, a, certHost))
		require.True(t, ok)
		require.Equal(t, ReasonTLSNotVerified, r.Reason, a.Host)
	}
	for _, host := range []string{"db.example.com", "db.evilsupabase.co"} {
		notVerified(setupcode.Address{Host: host, Port: 5432, Database: "postgres"}, host)
	}
	notVerified(setupcode.Address{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres"}, "db.otherprojectref000000.supabase.co")
}

// The agent's saved connection string, opened as the engine opens it,
// verifies a Supabase host's chain with the host name checked.
func TestSavedConnStringVerifiesSupabaseHost(t *testing.T) {
	t.Parallel()
	host := "db.abcdefghijklmnopqrst.supabase.co"
	a := setupcode.Address{Host: host, Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	login := func(certHost string) error {
		ca, cert := trustprofiletest.Chain(t, certHost)
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		return pgdial.Login(ctx, ConnString(a, setupcode.LoginUser(a, fixtureRole), "pw", true),
			trustprofiletest.Set(t, map[string][]*x509.Certificate{"supabase": {ca}}), "127.0.0.1", trustprofiletest.Serve(t, cert), nil)
	}
	var pg *pgconn.PgError
	require.ErrorAs(t, login(host), &pg)
	require.Equal(t, sqlstateInvalidPassword, pg.Code)
	require.Equal(t, ReasonTLSNotVerified, reasonOf(login("db.otherprojectref000000.supabase.co")))

	// In production the engine opens it with Supabase's real root.
	pool, err := pgdial.PoolConfig(ConnString(a, fixtureRole, "pw", false))
	require.NoError(t, err)
	cc := pool.ConnConfig.Copy()
	require.NoError(t, pool.BeforeConnect(context.Background(), cc))
	for _, root := range trustprofile.BuiltInSet().Named("supabase").Certificates() {
		_, err = root.Verify(x509.VerifyOptions{Roots: cc.TLSConfig.RootCAs})
		require.NoError(t, err)
	}
}
