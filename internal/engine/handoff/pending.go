package handoff

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// Phases of a connect-only setup on the engine.
const (
	// PhaseWaiting: no address passed the checks and the probe yet.
	PhaseWaiting = "WAITING"
	// PhaseConfirm: the probe passed; the person confirms the database.
	PhaseConfirm = "CONFIRM_DATABASE"
	// PhaseRefused: the person said the database is not theirs.
	PhaseRefused = "REFUSED"
	// PhaseConfirmed: the person said yes; the engine wrote the agent's
	// credential and restarts the agent on it.
	PhaseConfirmed = "CONFIRMED"
	// PhaseGone: engine.json no longer records this pending setup.
	PhaseGone = "GONE"
)

// Problems while waiting.
const (
	ProblemClockSkew      = "CLOCK_SKEW"
	ProblemAddressInvalid = "ADDRESS_INVALID"
	ProblemUnreachable    = "DATABASE_UNREACHABLE_FROM_BOT"
	// ProblemTrustRootMismatch: the database presents another certificate
	// authority to this machine than the one the person trusted on the
	// connect page; nothing is pinned.
	ProblemTrustRootMismatch = "TRUST_ROOT_MISMATCH"
	// ProblemEngineAsRoot: the engine runs as root without --user, so it
	// does not collect.
	ProblemEngineAsRoot = "ENGINE_AS_ROOT"
)

// ErrEngineAsRoot is the collector of an engine started as root without
// --user: it never collects a connect-only setup's address (problem
// ENGINE_AS_ROOT).
var ErrEngineAsRoot = errors.New("the engine runs as root without --user, so it does not collect the database's address")

// The collect cadence (CONTRACT.md, The engine and a connect-only code):
// every 15 seconds while the setup waits for an address or cannot reach
// it, for the code's life plus the connect service's 30-minute hold, and
// at once on status.
const fastEvery = 15 * time.Second

// reuseFor is how long a passed PREVIEW probe stands in for the SET_UP
// probe of the same address and resolved IP (CONTRACT.md, Connect, The
// reach check, Probes), and how long a PREVIEW address that was not
// reached waits before it is probed again.
const reuseFor = 5 * time.Minute

// Collector asks the connect service for the address and reports whether
// the engine reached a PREVIEW one: *Client.
type Collector interface {
	Collect(ctx context.Context, setupID, fingerprint string) (Collected, error)
	Report(ctx context.Context, setupID, fingerprint string, a Address, r Reach) error
}

// AddressProber probes an address with logins bound to fail: Prober.
// Resolve checks the address and resolves its host once; ProbeAt probes the
// address it resolved to.
type AddressProber interface {
	Resolve(ctx context.Context, a Address) (netip.Addr, error)
	// Approve checks, with the TLS handshake alone, the certificate
	// authority the person trusted on the connect page against the chain
	// the server presents to this machine.
	Approve(ctx context.Context, a Address, ip netip.Addr, approved string) (Pin, error)
	ProbeAt(ctx context.Context, a Address, ip netip.Addr, user string, pin Pin) (Probed, error)
}

// Files are the agent's files and its entry in engine.json, as the engine
// reaches them. Lock is the agent's lock, the one basalt init --remote
// takes; the other methods run under it.
type Files interface {
	Lock() (unlock func(), err error)
	// PendingSetup is the agent's pending setup in engine.json now; false
	// when none.
	PendingSetup() (config.Setup, bool, error)
	// ReadSecret reads the agent's .secret: the password init generated.
	ReadSecret() (string, error)
	// WriteCredential writes the agent's credential file, 0600 and
	// atomically; it refuses to replace one that exists.
	WriteCredential(dsn string) error
	// RemoveSecret removes .secret; a missing one is not an error.
	RemoveSecret() error
	// WritePin writes pin for host to trust.d, unless that pin is there
	// already; it refuses when another trust profile covers host by then.
	WritePin(host string, pin Pin) error
	// ConfirmSetup clears awaitingAddress from pending setup id.
	ConfirmSetup(id string) error
	// RefuseSetup replaces awaitingAddress with refused in pending setup id.
	RefuseSetup(id string) error
}

// State is what status reports about the connect-only setup.
type State struct {
	Setup config.Setup
	Phase string
	// Database is the probed database (CONFIRM_DATABASE), or the one that
	// could not be reached (problem DATABASE_UNREACHABLE_FROM_BOT).
	Database *Address
	// Problem is CLOCK_SKEW, ADDRESS_INVALID, TRUST_ROOT_MISMATCH or
	// DATABASE_UNREACHABLE_FROM_BOT while waiting, "" otherwise.
	Problem string
	// Expired: the code expired before an address passed the probe.
	Expired bool
}

// ErrNotWaiting is a confirm_database call for a setup or database that is
// not the one waiting for the person's answer.
var ErrNotWaiting = errors.New("no database waits for confirmation with this setupId and database: call status and use its setup.setupId and setup.database")

// Options build a Pending.
type Options struct {
	Agent     string
	Setup     config.Setup
	Collector Collector
	Prober    AddressProber
	Files     Files
	// Changed is called once the engine should build the agent anew: after
	// a YES, or when engine.json no longer records this pending setup.
	Changed func()
	Log     *slog.Logger
	Now     func() time.Time
	// Cache keeps the last PREVIEW probe and the RATE_LIMITED wait across
	// processes; nil keeps them in memory only.
	Cache ProbeCache
	// NoSetUpProbe is basalt status while the engine is down: a SET_UP
	// address is probed only by the engine, which asks the person next
	// (a passed PREVIEW probe it may reuse still counts).
	NoSetUpProbe bool
}

// Pending is one agent's connect-only setup on the engine: the collect,
// check and probe loop, and the person's answer. It never reads .secret
// before the person's YES, and no login it makes before then carries the
// agent's password.
type Pending struct {
	o       Options
	role    string
	made    time.Time
	expires time.Time

	// stepMu makes one step at a time: the loop's and status's.
	stepMu sync.Mutex

	mu sync.Mutex
	st State
	// probed is the probe that passed (CONFIRM_DATABASE), and pin the
	// certificate authority it passed with, which the person's yes writes.
	probed Probed
	pin    Pin
	// preview is the last PREVIEW address the engine probed and what it
	// found. It is never part of st: nothing of a PREVIEW address is shown.
	preview previewProbe
	// lastTry is when the address was last asked for; notBefore holds the
	// next try back after RATE_LIMITED.
	lastTry, notBefore time.Time
	changed            sync.Once
}

// New is the pending setup of o, or an error for a pending setup that is
// not a connect-only one this engine can collect for.
func New(o Options) (*Pending, error) {
	if o.Collector == nil || o.Prober == nil || o.Files == nil || o.Changed == nil || o.Log == nil || o.Now == nil {
		panic("handoff: a pending setup needs a collector, a prober, its files, a change hook, a logger and a clock")
	}
	p, err := setupcode.Decode(o.Setup.Code)
	if err != nil {
		return nil, fmt.Errorf("the pending setup code in engine.json cannot be read: %w", err)
	}
	if !p.ConnectOnly() || p.SetupID != o.Setup.SetupID || p.Agent == nil {
		return nil, errors.New("the pending setup in engine.json is not this agent's connect-only code")
	}
	made, err := p.CreatedAt()
	if err != nil {
		return nil, err
	}
	expires, err := o.Setup.Expires()
	if err != nil {
		return nil, err
	}
	out := &Pending{o: o, role: p.Role(), made: made, expires: expires}
	out.st = State{Setup: o.Setup, Phase: PhaseWaiting}
	if o.Cache != nil {
		if c, ok := o.Cache.Load(o.Setup.SetupID); ok {
			out.notBefore = c.NotBefore
			if !c.At.IsZero() {
				out.preview = previewProbe{key: c.AddressKey, ip: c.IP, at: c.At, reach: Reach{Reason: c.Reason}, probed: Probed{IP: c.IP, ChannelBinding: c.ChannelBinding}, pinned: c.Pinned}
			}
		}
	}
	if o.Setup.Refused {
		out.st.Phase = PhaseRefused
	}
	return out, nil
}

// previewProbe is a probe of a PREVIEW address: the address (canonical),
// the IP its host resolved to, when, and its outcome (passed with probed,
// or reach's reason).
type previewProbe struct {
	key    string
	ip     netip.Addr
	at     time.Time
	reach  Reach
	probed Probed
	// pinned is the SHA-256 of the pin it passed with, "" for none.
	pinned string
}

// pinnedOf is the SHA-256 of pin's top, "" for no pin.
func pinnedOf(pin Pin) string {
	if pin.Top == nil {
		return ""
	}
	return trustprofile.DERSHA256(pin.Top)
}

// passed reports whether the probe passed for key (probeKey) at ip within
// reuseFor of now: only then does the SET_UP probe reuse it.
func (v previewProbe) passed(key string, ip netip.Addr, now time.Time) bool {
	return !v.at.IsZero() && v.reach.Reason == "" && v.key == key && v.ip == ip && now.Sub(v.at) <= reuseFor
}

// probeKey is what a probe of a held under trustRoot is for: a probe that
// passed under one trusted certificate authority, or none, stands for no
// other.
func probeKey(a Address, trustRoot string) string {
	if trustRoot == "" {
		return a.key()
	}
	return a.key() + "\x00" + trustRoot
}

// State is the setup's state now: it reads engine.json first, so a pending
// setup that init replaced or removed drops the collected address at once.
func (p *Pending) State() State {
	p.recheckConfig()
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.st
	st.Expired = st.Phase == PhaseWaiting && !p.o.Now().Before(p.expires)
	if st.Database != nil {
		d := *st.Database
		st.Database = &d
	}
	return st
}

// StatusCollect is a status call: while waiting, it collects at once,
// then returns the state. When the loop's step is running, it does not
// wait for it and returns the state as it is.
func (p *Pending) StatusCollect(ctx context.Context) State {
	if p.stepMu.TryLock() {
		p.step(ctx)
		p.stepMu.Unlock()
	}
	return p.State()
}

// Run collects on the contract's cadence until ctx ends, the probe passed,
// the person answered or the code expired.
func (p *Pending) Run(ctx context.Context) {
	for {
		wait, ok := p.nextWait()
		if !ok {
			return
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		p.Step(ctx)
	}
}

// collectUntil is the last time the engine polls for this code's address:
// the code's life plus the 30-minute hold, measured from when it was made.
func (p *Pending) collectUntil() time.Time {
	return p.made.Add(setupcode.CollectWindow)
}

// nextWait is how long until the next collect, and false once there is
// none to make.
func (p *Pending) nextWait() (time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.o.Now()
	if p.st.Phase != PhaseWaiting || !now.Before(p.collectUntil()) {
		return 0, false
	}
	next := p.lastTry.Add(fastEvery)
	if p.notBefore.After(next) {
		next = p.notBefore
	}
	return max(next.Sub(now), 0), true
}

// Step is one collect, check and probe. It does nothing unless the setup
// waits for its address and the collect window has not ended. The one condition
// that stops it for good is a probe of a SET_UP address that passed: until
// then each step collects again, so an address the person changes on the
// page (running the same link again) is picked up and probed. A PREVIEW
// address is only checked, probed and reported (preview).
func (p *Pending) Step(ctx context.Context) {
	p.stepMu.Lock()
	defer p.stepMu.Unlock()
	p.step(ctx)
}

// step is Step with stepMu held.
func (p *Pending) step(ctx context.Context) {
	if !p.recheckConfig() {
		return
	}
	p.mu.Lock()
	now := p.o.Now()
	if p.st.Phase != PhaseWaiting || !now.Before(p.collectUntil()) || now.Before(p.notBefore) {
		p.mu.Unlock()
		return
	}
	p.lastTry = now
	setup := p.st.Setup
	p.mu.Unlock()

	got, err := p.o.Collector.Collect(ctx, setup.SetupID, setup.Fingerprint)
	if !p.collected(setup, err) {
		return
	}
	if !got.SetUp() {
		// A preview leaves status as before the address came.
		p.waiting("", nil)
		p.previewStep(ctx, setup, got)
		return
	}
	addr := got.Address
	ip, err := p.o.Prober.Resolve(ctx, addr)
	var (
		probed Probed
		pin    Pin
	)
	if err == nil {
		p.mu.Lock()
		reuse, v := p.preview.passed(probeKey(addr, got.TrustRoot), ip, p.o.Now()), p.preview
		p.mu.Unlock()
		switch {
		case p.o.NoSetUpProbe && !reuse:
			return
		case got.TrustRoot != "":
			// Read again even for a reused probe: the pin is never
			// cached, only the login that it let pass.
			pin, err = p.o.Prober.Approve(ctx, addr, ip, got.TrustRoot)
		}
		switch {
		case err != nil:
		case reuse && v.pinned == pinnedOf(pin):
			// The preview passed on the same trust: the same pin, or none.
			probed = v.probed
		case p.o.NoSetUpProbe:
			return
		default:
			probed, err = p.o.Prober.ProbeAt(ctx, addr, ip, LoginUser(addr, p.role), pin)
		}
	}
	switch {
	case errors.Is(err, ErrAddressInvalid):
		p.o.Log.Warn("the collected address is refused", "setupId", setup.SetupID)
		p.waiting(ProblemAddressInvalid, nil)
		return
	case errors.Is(err, ErrTrustRootMismatch):
		p.o.Log.Warn("the collected database presents another certificate authority than the one trusted on the connect page; nothing is pinned", "setupId", setup.SetupID)
		p.waiting(ProblemTrustRootMismatch, &addr)
		return
	case err != nil:
		p.o.Log.Warn("the collected database cannot be reached from this machine", "setupId", setup.SetupID, "err", err)
		p.waiting(ProblemUnreachable, &addr)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st.Phase != PhaseWaiting || p.st.Setup.SetupID != setup.SetupID {
		return
	}
	p.st.Phase, p.st.Database, p.st.Problem, p.probed, p.pin, p.preview = PhaseConfirm, &addr, "", probed, pin, previewProbe{}
	p.o.Log.Info("the collected database passed the probe; waiting for the person to confirm it", "setupId", setup.SetupID)
}

// collected handles a collect's refusal and reports whether an address
// came.
func (p *Pending) collected(setup config.Setup, err error) bool {
	var rl *RateLimitedError
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrNotHeld):
		p.waiting("", nil)
	case errors.Is(err, ErrClockSkew):
		p.waiting(ProblemClockSkew, nil)
	case errors.Is(err, ErrEngineAsRoot):
		p.waiting(ProblemEngineAsRoot, nil)
	case errors.As(err, &rl):
		p.mu.Lock()
		p.notBefore = p.o.Now().Add(rl.After)
		p.mu.Unlock()
		p.save()
	default:
		p.o.Log.Warn("collect the database's address", "setupId", setup.SetupID, "err", err)
	}
	return false
}

// previewStep is a PREVIEW address (CONTRACT.md, Connect, The reach
// check): the person has not approved, so the engine checks it, probes it
// with a wrong password, reports whether it reached it, and changes
// nothing else: the setup stays waiting, status shows nothing of it, and
// the collecting goes on. An address that fails the shape rules is not
// reported. The same address is reported again from its probe, without a
// new one, so a page that asks again (its Retry, a new preview hold with no
// report) gets an answer. An address that was reached is never probed
// again while it stays the same, so one flow leaves at most two failed
// logins (this probe and the SET_UP one); one that was not reached is
// probed again reuseFor after its probe, which logs no failed login there
// (no connection, no verified certificate, or a refused address).
func (p *Pending) previewStep(ctx context.Context, setup config.Setup, got Collected) {
	addr, key := got.Address, probeKey(got.Address, got.TrustRoot)
	now := p.o.Now()
	p.mu.Lock()
	v := p.preview
	p.mu.Unlock()
	if v.at.IsZero() || v.key != key || (v.reach.Reason != "" && now.Sub(v.at) > reuseFor) {
		v = previewProbe{key: key, at: now}
		ip, err := p.o.Prober.Resolve(ctx, addr)
		var pin Pin
		if err == nil && got.TrustRoot != "" {
			// Checked, used for this probe and dropped: a preview pins
			// nothing.
			pin, err = p.o.Prober.Approve(ctx, addr, ip, got.TrustRoot)
		}
		if err == nil {
			v.ip = ip
			v.probed, err = p.o.Prober.ProbeAt(ctx, addr, ip, LoginUser(addr, p.role), pin)
			v.pinned = pinnedOf(pin)
		}
		r, report := ReachOf(err)
		if !report {
			p.o.Log.Warn("a preview address is refused or could not be probed; nothing is reported", "setupId", setup.SetupID)
			return
		}
		v.reach = r
		p.mu.Lock()
		p.preview = v
		p.mu.Unlock()
		p.save()
	}
	err := p.o.Collector.Report(ctx, setup.SetupID, setup.Fingerprint, addr, v.reach)
	var rl *RateLimitedError
	switch {
	case errors.As(err, &rl):
		p.mu.Lock()
		p.notBefore = p.o.Now().Add(rl.After)
		p.mu.Unlock()
		p.save()
	case err != nil:
		p.o.Log.Warn("report whether the preview address was reached", "setupId", setup.SetupID, "err", err)
	}
}

// waiting records a step that left the setup waiting, with its problem.
func (p *Pending) waiting(problem string, db *Address) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st.Phase != PhaseWaiting {
		return
	}
	p.st.Problem, p.st.Database = problem, db
}

// recheckConfig reads the agent's pending setup in engine.json: when it is
// no longer this connect-only setup, the collected address is dropped and
// the engine builds the agent anew. False then, or when it cannot be read.
func (p *Pending) recheckConfig() bool {
	now, ok, err := p.o.Files.PendingSetup()
	if err != nil {
		p.o.Log.Warn("read the agent's pending setup in engine.json", "err", err)
		return false
	}
	p.mu.Lock()
	id, phase := p.st.Setup.SetupID, p.st.Phase
	p.mu.Unlock()
	if phase == PhaseConfirmed || phase == PhaseGone {
		return false
	}
	if ok && now.SetupID == id && now.ConnectOnly() {
		return true
	}
	p.mu.Lock()
	p.st.Phase, p.st.Database, p.st.Problem, p.probed, p.pin, p.preview = PhaseGone, nil, "", Probed{}, Pin{}, previewProbe{}
	p.mu.Unlock()
	p.o.Log.Info("engine.json no longer records the pending connect-only setup; the collected address is dropped", "setupId", id)
	p.done()
	return false
}

func (p *Pending) done() { p.changed.Do(p.o.Changed) }

// save writes the preview probe and the RATE_LIMITED wait to the cache.
func (p *Pending) save() {
	if p.o.Cache == nil {
		return
	}
	p.mu.Lock()
	v, c := p.preview, Cached{SetupID: p.st.Setup.SetupID, NotBefore: p.notBefore}
	p.mu.Unlock()
	c.AddressKey, c.IP, c.At, c.Reason, c.ChannelBinding, c.Pinned = v.key, v.ip, v.at, v.reach.Reason, v.probed.ChannelBinding, v.pinned
	if err := p.o.Cache.Save(c); err != nil {
		p.o.Log.Warn("keep the preview probe for the next process", "err", err)
	}
}

// Answer is what confirm_database did.
type Answer struct {
	// Confirmed is YES: the credential is written.
	Confirmed bool
	Database  Address
}

// Confirm records the person's answer for setup id and database db, which
// must be the ones waiting (ErrNotWaiting otherwise). YES, under the
// agent's lock: read .secret, write the pin the probe passed with (a
// certificate authority trusted on the connect page that the engine
// confirmed itself), write the credential for exactly the probed address,
// remove .secret, clear awaitingAddress; the engine then builds the agent
// anew on its credential. NO: remove .secret and record refused; nothing
// logged in there and nothing pinned.
func (p *Pending) Confirm(_ context.Context, id string, db Address, yes bool) (Answer, error) {
	p.recheckConfig()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st.Phase != PhaseConfirm || p.st.Setup.SetupID != id || p.st.Database == nil || *p.st.Database != db {
		return Answer{}, ErrNotWaiting
	}
	unlock, err := p.o.Files.Lock()
	if err != nil {
		return Answer{}, err
	}
	defer unlock()
	now, ok, err := p.o.Files.PendingSetup()
	if err != nil {
		return Answer{}, err
	}
	if !ok || now.SetupID != id || !now.AwaitingAddress {
		return Answer{}, ErrNotWaiting
	}
	if !yes {
		return p.refuse(id, db)
	}
	return p.confirm(id, db)
}

// confirm is YES. p.mu and the agent's lock are held.
func (p *Pending) confirm(id string, db Address) (Answer, error) {
	secret, err := p.o.Files.ReadSecret()
	if err != nil {
		return Answer{}, fmt.Errorf("read the agent's password: %w", err)
	}
	if p.pin.Profile != nil {
		if err := p.o.Files.WritePin(db.Host, p.pin); err != nil {
			return Answer{}, fmt.Errorf("pin the database's certificate authority: %w", err)
		}
	}
	dsn := ConnString(db, LoginUser(db, p.role), secret, p.probed.ChannelBinding)
	if err := p.o.Files.WriteCredential(dsn); err != nil {
		return Answer{}, fmt.Errorf("write the agent's credential: %w", err)
	}
	// Past the credential, a failure leaves the YES half done: the engine
	// builds the agent anew, and its start finishes what the YES began.
	if err := p.o.Files.RemoveSecret(); err != nil {
		go p.done()
		return Answer{}, err
	}
	if err := p.o.Files.ConfirmSetup(id); err != nil {
		go p.done()
		return Answer{}, err
	}
	p.st.Phase = PhaseConfirmed
	p.o.Log.Info("the person confirmed the database; the agent's credential is written", "setupId", id)
	go p.done()
	return Answer{Confirmed: true, Database: db}, nil
}

// refuse is NO. p.mu and the agent's lock are held.
func (p *Pending) refuse(id string, db Address) (Answer, error) {
	if err := p.o.Files.RemoveSecret(); err != nil {
		return Answer{}, err
	}
	if err := p.o.Files.RefuseSetup(id); err != nil {
		return Answer{}, err
	}
	p.st.Phase, p.st.Database, p.st.Problem, p.probed, p.pin, p.preview = PhaseRefused, nil, "", Probed{}, Pin{}, previewProbe{}
	p.st.Setup.AwaitingAddress, p.st.Setup.Refused = false, true
	p.o.Log.Info("the person refused the collected database; its address and the agent's password are forgotten", "setupId", id)
	return Answer{Database: db}, nil
}
