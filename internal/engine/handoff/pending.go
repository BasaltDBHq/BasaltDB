package handoff

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
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
)

// The collect cadence (CONTRACT.md, The engine and a connect-only code,
// Collecting): every 15 seconds for the first 30 minutes after the code
// was made, every 5 minutes for the next 2 hours, then only on status and
// at the hourly heartbeat until the code expires.
const (
	fastEvery    = 15 * time.Second
	fastFor      = 30 * time.Minute
	slowEvery    = 5 * time.Minute
	slowFor      = 2 * time.Hour
	heartbeat    = time.Hour
	statusMinGap = 10 * time.Second
)

// Collector asks the connect service for the address: *Client.
type Collector interface {
	Collect(ctx context.Context, setupID, fingerprint string) (Address, error)
}

// AddressProber probes an address with logins bound to fail: Prober.
type AddressProber interface {
	Probe(ctx context.Context, a Address, user string) (Probed, error)
}

// Files are the agent's files and its entry in engine.json, as the engine
// reaches them. Lock is the agent's lock, the one basalt init --remote
// takes; the other methods run under it.
type Files interface {
	Lock() (unlock func(), err error)
	// PendingSetup is the agent's pending setup in engine.json now, nil
	// when none.
	PendingSetup() (*config.Setup, error)
	// ReadSecret reads the agent's .secret: the password init generated.
	ReadSecret() (string, error)
	// WriteCredential writes the agent's credential file, 0600 and
	// atomically; it refuses to replace one that exists.
	WriteCredential(dsn string) error
	// RemoveSecret removes .secret; a missing one is not an error.
	RemoveSecret() error
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
	// Problem is CLOCK_SKEW, ADDRESS_INVALID or
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

	mu sync.Mutex
	st State
	// probed is the probe that passed (CONFIRM_DATABASE).
	probed Probed
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
	if o.Setup.Refused {
		out.st.Phase = PhaseRefused
	}
	return out, nil
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

// StatusCollect is a status call: while waiting, and at most every 10
// seconds, it collects (the only collecting once the cadence's first 2.5
// hours passed), then returns the state.
func (p *Pending) StatusCollect(ctx context.Context) State {
	p.mu.Lock()
	due := p.o.Now().Sub(p.lastTry) >= statusMinGap
	p.mu.Unlock()
	if due {
		p.Step(ctx)
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

// nextWait is how long until the next collect, and false once there is
// none to make.
func (p *Pending) nextWait() (time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.o.Now()
	if p.st.Phase != PhaseWaiting || !now.Before(p.expires) {
		return 0, false
	}
	every := heartbeat
	switch age := now.Sub(p.made); {
	case age < fastFor:
		every = fastEvery
	case age < fastFor+slowFor:
		every = slowEvery
	}
	next := p.lastTry.Add(every)
	if p.notBefore.After(next) {
		next = p.notBefore
	}
	return max(next.Sub(now), 0), true
}

// Step is one collect, check and probe. It does nothing unless the setup
// waits for its address and the code has not expired. The one condition
// that stops it for good is a probe that passed: until then each step
// collects again, so an address the person changes on the page (running
// the same link again) is picked up and probed.
func (p *Pending) Step(ctx context.Context) {
	if !p.recheckConfig() {
		return
	}
	p.mu.Lock()
	now := p.o.Now()
	if p.st.Phase != PhaseWaiting || !now.Before(p.expires) || now.Before(p.notBefore) {
		p.mu.Unlock()
		return
	}
	p.lastTry = now
	setup := p.st.Setup
	p.mu.Unlock()

	addr, err := p.o.Collector.Collect(ctx, setup.SetupID, setup.Fingerprint)
	var rl *RateLimitedError
	switch {
	case errors.Is(err, ErrNotHeld):
		p.waiting("", nil)
		return
	case errors.Is(err, ErrClockSkew):
		p.waiting(ProblemClockSkew, nil)
		return
	case errors.As(err, &rl):
		p.mu.Lock()
		p.notBefore = p.o.Now().Add(rl.After)
		p.mu.Unlock()
		return
	case err != nil:
		p.o.Log.Warn("collect the database's address", "setupId", setup.SetupID, "err", err)
		return
	}
	probed, err := p.o.Prober.Probe(ctx, addr, LoginUser(addr, p.role))
	switch {
	case errors.Is(err, ErrAddressInvalid):
		p.o.Log.Warn("the collected address is refused", "setupId", setup.SetupID)
		p.waiting(ProblemAddressInvalid, nil)
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
	p.st.Phase, p.st.Database, p.st.Problem, p.probed = PhaseConfirm, &addr, "", probed
	p.o.Log.Info("the collected database passed the probe; waiting for the person to confirm it", "setupId", setup.SetupID)
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
	now, err := p.o.Files.PendingSetup()
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
	if now != nil && now.SetupID == id && now.ConnectOnly() {
		return true
	}
	p.mu.Lock()
	p.st.Phase, p.st.Database, p.st.Problem, p.probed = PhaseGone, nil, "", Probed{}
	p.mu.Unlock()
	p.o.Log.Info("engine.json no longer records the pending connect-only setup; the collected address is dropped", "setupId", id)
	p.done()
	return false
}

func (p *Pending) done() { p.changed.Do(p.o.Changed) }

// Answer is what confirm_database did.
type Answer struct {
	// Confirmed is YES: the credential is written.
	Confirmed bool
	Database  Address
}

// Confirm records the person's answer for setup id and database db, which
// must be the ones waiting (ErrNotWaiting otherwise). YES, under the
// agent's lock: read .secret, write the credential for exactly the probed
// address, remove .secret, clear awaitingAddress; the engine then builds
// the agent anew on its credential. NO: remove .secret and record refused;
// nothing logged in there.
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
	now, err := p.o.Files.PendingSetup()
	if err != nil {
		return Answer{}, err
	}
	if now == nil || now.SetupID != id || !now.AwaitingAddress {
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
	dsn := ConnString(db, LoginUser(db, p.role), secret, p.probed.ChannelBinding)
	if err := p.o.Files.WriteCredential(dsn); err != nil {
		return Answer{}, fmt.Errorf("write the agent's credential: %w", err)
	}
	if err := p.o.Files.RemoveSecret(); err != nil {
		return Answer{}, err
	}
	if err := p.o.Files.ConfirmSetup(id); err != nil {
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
	p.st.Phase, p.st.Database, p.st.Problem, p.probed = PhaseRefused, nil, "", Probed{}
	p.st.Setup.AwaitingAddress, p.st.Setup.Refused = false, true
	p.o.Log.Info("the person refused the collected database; its address and the agent's password are forgotten", "setupId", id)
	return Answer{Database: db}, nil
}
