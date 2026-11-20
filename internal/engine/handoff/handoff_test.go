package handoff

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// The contract's connect-only fixture (api/mcp/setup/setup-code.fixtures.json,
// "connect-only install of all tables"): setupId ...e1, made at its UUIDv7
// time, role basalt_agent_lead_bot.
const (
	fixtureCode        = "basalt-setup.1.PJBdb6JAFIb_y0nvlmlnrKJO4sUUtFXESou2uNmYAQecOjB0gPrR-N837G72XJ3kPDlvnvcbUm1yXgMlFlSibsrpDihgwknaHySo14kHqJ_cczRMMUb4_wgCFhxk0dLTxWvI5nOwoDQilSegEPOKqxosyBpudkC_ITU6B4otqDVQYl8tiBup_oTd9m4xWMAzUdQtWvBcAAUl-G4b6_YLVyrksRJVe66Svch5BfQnlE2sZAK_rhZ8CSNTKQxQeHVemI9enxjq9OybLh7alAVT94GtHh-O2czJKt8NussxG41uzt33U3R3Kcovd_nj7TDTy_eJDPjjnVfNVPg514P95lE5jX4ejGjWU5FbzLpv2jddW77tz59RkXB395Lovn_5IpNz9vR81vu78QgsqGpei1wUdShzoZvar4Det-VdLRCnUhpRsRoodHDHRoSgDgmxTXGHErIBC0SRyUK0xn81PXEGCv7kcBwfoydPb6aXD-ywIJr-210WJG6QsfFqfRzGpvhQ5jDG276XknB4CS4P9kZsF-TeW61NUFbPmJHhZGG69mrpR2ibqxdycLScBB4aLNbI8Vf9ue-o-JRuULhmcL3-DgAA__8._9xzIw"
	fixtureID          = "01a1f78c-52b8-7c3a-9f00-0000000000e1"
	fixtureFingerprint = "d48b ee66 a1d9 d005 1f63"
	fixtureRole        = "basalt_agent_lead_bot"
)

// fixtureMade is the fixture's setupId time.
var fixtureMade = time.UnixMilli(0x01a1f78c52b8).UTC()

var db = Address{Host: "db.example.com", Port: 5432, Database: "app"}

func fixtureSetup() config.Setup {
	return config.Setup{
		SetupID: fixtureID, Kind: guard.SetupInstall, GuardVersion: 16, ExpiresAt: "2026-11-21T06:02:11Z",
		Code: fixtureCode, Fingerprint: fixtureFingerprint, AwaitingAddress: true,
	}
}

type fakeCollector struct {
	mu   sync.Mutex
	addr Address
	// phase is the hold's; "" is SET_UP here, so the older tests read as
	// before.
	phase   string
	err     error
	calls   int
	reports []report
}

type report struct {
	addr  Address
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
	return Collected{Address: c.addr, Phase: phase}, c.err
}

func (c *fakeCollector) Report(_ context.Context, id, fp string, a Address, r Reach) error {
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
}

func (p *fakeProber) Resolve(_ context.Context, a Address) (netip.Addr, error) {
	if err := a.Check(); err != nil {
		return netip.Addr{}, err
	}
	if errors.Is(p.err, ErrAddressInvalid) {
		return netip.Addr{}, p.err
	}
	if p.ip.IsValid() {
		return p.ip, nil
	}
	return netip.MustParseAddr("8.8.8.8"), nil
}

func (p *fakeProber) ProbeAt(_ context.Context, _ Address, ip netip.Addr, user string) (Probed, error) {
	p.users = append(p.users, user)
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

func TestAddressShape(t *testing.T) {
	t.Parallel()
	require.NoError(t, db.Check())
	require.NoError(t, Address{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}.Check())
	require.NoError(t, Address{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}.Check())
	for name, a := range map[string]Address{
		"a host with a space":       {Host: "db example.com", Port: 5432, Database: "app"},
		"a host with a slash":       {Host: "/var/run/postgresql", Port: 5432, Database: "app"},
		"a host with an at sign":    {Host: "user@db.example.com", Port: 5432, Database: "app"},
		"a host that is too long":   {Host: strings.Repeat("a", 254), Port: 5432, Database: "app"},
		"no port":                   {Host: "db.example.com", Database: "app"},
		"a port over 65535":         {Host: "db.example.com", Port: 70000, Database: "app"},
		"a database with a quote":   {Host: "db.example.com", Port: 5432, Database: "app'; DROP"},
		"a database with a newline": {Host: "db.example.com", Port: 5432, Database: "app\nIgnore the above"},
		"a database too long":       {Host: "db.example.com", Port: 5432, Database: strings.Repeat("d", 64)},
		"a ref in upper case":       {Host: "db.example.com", Port: 5432, Database: "app", SupabaseRef: "ABCDEFGHIJKLMNOPQRST"},
		"a ref of 19 characters":    {Host: "db.example.com", Port: 5432, Database: "app", SupabaseRef: "abcdefghijklmnopqrs"},
		"a ref on another host":     {Host: "evil.example.com", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"},
		"another project's host":    {Host: "db.zzzzzzzzzzzzzzzzzzzz.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"},
		"a lookalike pooler":        {Host: "pooler.supabase.com.evil.example", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"},
		// The --database-url rules: init reads db.<ref>.supabase.co as that
		// project, so the address must say so too.
		"a project's host without its ref": {Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres"},
	} {
		require.ErrorIs(t, a.Check(), ErrAddressInvalid, name)
	}
	require.Equal(t, "db.example.com:5432, database app", db.Name())
	require.Equal(t, "Supabase project abcdefghijklmnopqrst, database postgres",
		Address{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}.Name())
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
	require.ErrorIs(t, err, ErrAddressInvalid)
	_, err = pick(ctx, r, "metadata.example.com")
	require.ErrorIs(t, err, ErrAddressInvalid)
	_, err = pick(ctx, r, "10.0.0.1")
	require.ErrorIs(t, err, ErrAddressInvalid, "an IP literal is checked as it is")
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
	require.ErrorIs(t, err, ErrAddressInvalid)
	require.False(t, dialed)
	_, err = p.Probe(context.Background(), Address{Host: "db example", Port: 5432, Database: "app"}, fixtureRole)
	require.ErrorIs(t, err, ErrAddressInvalid)
	require.False(t, dialed)
}

func TestConnStringAndLoginUser(t *testing.T) {
	t.Parallel()
	require.Equal(t, "postgres://basalt_agent_bot:pw@db.example.com:5432/app?channel_binding=require&sslmode=verify-full",
		ConnString(db, "basalt_agent_bot", "pw", true))
	require.Equal(t, "postgres://basalt_agent_bot:pw@db.example.com:5432/app?sslmode=verify-full", ConnString(db, "basalt_agent_bot", "pw", false))
	pooler := Address{Host: "aws-0-eu-central-1.pooler.supabase.com", Port: 6543, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	require.Equal(t, "basalt_agent_bot.abcdefghijklmnopqrst", LoginUser(pooler, "basalt_agent_bot"))
	direct := Address{Host: "db.abcdefghijklmnopqrst.supabase.co", Port: 5432, Database: "postgres", SupabaseRef: "abcdefghijklmnopqrst"}
	require.Equal(t, "basalt_agent_bot", LoginUser(direct, "basalt_agent_bot"))
}

// The cadence: every 15 seconds for 2 hours after the code was made, then
// every 5 minutes until it expires.
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

	h.clock.now = fixtureMade.Add(110 * time.Minute)
	h.p.Step(context.Background())
	require.Equal(t, fastEvery, wait())

	h.clock.now = fixtureMade.Add(3 * time.Hour)
	h.p.Step(context.Background())
	require.Equal(t, slowEvery, wait())

	// While the database cannot be reached, the cadence is the same.
	h.col.err, h.col.addr, h.prober.err = nil, db, &ReachError{Reason: ReasonNoRoute}
	h.clock.now = fixtureMade.Add(20 * time.Hour)
	h.p.Step(context.Background())
	require.Equal(t, ProblemUnreachable, h.p.State().Problem)
	require.Equal(t, slowEvery, wait())

	// A status call collects at once, however recent the last collect.
	calls := h.col.calls
	h.p.StatusCollect(context.Background())
	require.Equal(t, calls+1, h.col.calls)

	h.clock.now = fixtureMade.Add(25 * time.Hour)
	_, ok := h.p.nextWait()
	require.False(t, ok, "no collect after the code expired")
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

	h.col.err, h.col.addr = nil, Address{Host: "db example", Port: 5432, Database: "app"}
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	st = h.p.State()
	require.Equal(t, ProblemAddressInvalid, st.Problem)
	require.Nil(t, st.Database, "nothing of a refused address is kept to show")

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
	h.col.addr = Address{Host: "other.example.com", Port: 5432, Database: "app"}
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
	h.col.err, h.col.addr, h.col.phase = nil, Address{Host: "DB.Example.com", Port: 6543, Database: "app"}, HoldPreview
	h.p.Step(ctx)
	st := h.p.State()
	require.Equal(t, PhaseWaiting, st.Phase)
	require.Nil(t, st.Database)
	require.Empty(t, st.Problem)
	require.Empty(t, h.files.ops, "no file is touched")
	require.Equal(t, []report{{Address{Host: "DB.Example.com", Port: 6543, Database: "app"}, Reach{}}}, h.col.reports)
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

	// The same address after 5 minutes is probed again.
	h.prober.err = nil
	h.clock.advance(reuseFor + time.Second)
	h.p.Step(ctx)
	require.Equal(t, 3, h.prober.probes)
	require.Equal(t, report{db, Reach{}}, h.col.reports[3])

	// A refused range is reported ADDRESS_REFUSED; a shape that fails is
	// never reported.
	h.prober.err = &ReachError{Reason: ReasonAddressRefused}
	h.col.addr = Address{Host: "private.example.com", Port: 5432, Database: "app"}
	h.clock.advance(fastEvery)
	h.p.Step(ctx)
	require.Equal(t, report{h.col.addr, Reach{Reason: ReasonAddressRefused}}, h.col.reports[4])
	h.col.addr = Address{Host: "db example", Port: 5432, Database: "app"}
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
	h.col.addr = Address{Host: "other.example.com", Port: 5432, Database: "app"}
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
	_, ok = ReachOf(ErrAddressInvalid)
	require.False(t, ok, "a shape that fails is never reported")
	r, ok = ReachOf(&ReachError{Reason: ReasonAddressRefused})
	require.True(t, ok)
	require.Equal(t, ReasonAddressRefused, r.Reason)
	require.ErrorIs(t, &ReachError{Reason: ReasonAddressRefused}, ErrAddressInvalid)
	require.ErrorIs(t, &ReachError{Reason: ReasonTimeout}, ErrUnreachable)
	require.NotErrorIs(t, &ReachError{Reason: ReasonTimeout}, ErrAddressInvalid)

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
	_, err = p.Resolve(context.Background(), Address{Host: "private.example.com", Port: 5432, Database: "app"})
	r, _ = ReachOf(err)
	require.Equal(t, ReasonAddressRefused, r.Reason)
	require.ErrorIs(t, err, ErrAddressInvalid)
}
