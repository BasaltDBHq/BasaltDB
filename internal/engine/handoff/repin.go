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
)

// A changed certificate on persona 2 (CONTRACT.md, Pinning from the connect
// page): the agent has a credential, its pinned host presents another chain
// top, and basalt init --remote made an AGENT code with no change, marked
// certificateChanged. The person trusts the new certificate on the connect
// page, whose service keeps a SET_UP hold of the code's target with that
// trustRoot. Repin collects that hold for the setupId through the collect
// window and replaces the engine's pin only when the hold names the
// credential's own database and the engine's own reading of the chain
// shows the trusted top. It asks no confirm_database: the database is the
// one the credential already names. The setup then finishes as any pending
// setup does.

// RepinProber resolves the credential's host and reads its chain: Prober.
type RepinProber interface {
	Resolve(ctx context.Context, a Address) (netip.Addr, error)
	// Repin checks approved against the chain the server presents to this
	// machine, the engine's own pin for the host left out.
	Repin(ctx context.Context, a Address, ip netip.Addr, approved string) (Pin, error)
}

// RepinFiles are the agent's entry in engine.json and the config's trust.d.
type RepinFiles interface {
	// PendingSetup is the agent's pending setup in engine.json now.
	PendingSetup() (config.Setup, bool, error)
	// ReplacePin replaces the engine's own pin for host with pin, under the
	// config lock; it refuses when another profile covers host.
	ReplacePin(host string, pin Pin) error
}

// RepinOptions build a Repin.
type RepinOptions struct {
	Setup config.Setup
	// Credential is the database the agent's credential file names.
	Credential Address
	Collector  Collector
	Prober     RepinProber
	Files      RepinFiles
	Log        *slog.Logger
	Now        func() time.Time
}

// Repin is one agent's certificateChanged setup on the engine.
type Repin struct {
	o    RepinOptions
	made time.Time
	mu   sync.Mutex
	done bool
	prob string
}

// ErrNotCertificateChanged is a pending setup Repin does not collect for.
var ErrNotCertificateChanged = errors.New("the pending setup in engine.json is not this agent's certificateChanged code")

// NewRepin is the certificateChanged setup of o.
func NewRepin(o RepinOptions) (*Repin, error) {
	if o.Collector == nil || o.Prober == nil || o.Files == nil || o.Log == nil || o.Now == nil {
		panic("handoff: a repin needs a collector, a prober, its files, a logger and a clock")
	}
	p, err := setupcode.Decode(o.Setup.Code)
	if err != nil {
		return nil, fmt.Errorf("the pending setup code in engine.json cannot be read: %w", err)
	}
	if !o.Setup.CertificateChanged || p.ConnectOnly() || p.SetupID != o.Setup.SetupID || p.Engine == nil {
		return nil, ErrNotCertificateChanged
	}
	made, err := p.CreatedAt()
	if err != nil {
		return nil, err
	}
	return &Repin{o: o, made: made}, nil
}

// Problem is TRUST_ROOT_MISMATCH after a hold whose certificate the
// engine's own reading did not show, "" otherwise.
func (r *Repin) Problem() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prob
}

// Done reports whether the pin was replaced.
func (r *Repin) Done() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done
}

// Run collects every 15 seconds until ctx ends, the pin is replaced, the
// collect window ends or engine.json no longer records this setup.
func (r *Repin) Run(ctx context.Context) {
	for {
		if !r.Step(ctx) {
			return
		}
		t := time.NewTimer(fastEvery)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// Step is one collect and check. It reports whether to go on collecting.
func (r *Repin) Step(ctx context.Context) bool {
	r.mu.Lock()
	done := r.done
	r.mu.Unlock()
	if done || !r.o.Now().Before(r.made.Add(setupcode.CollectWindow)) || !r.stillPending() {
		return false
	}
	got, err := r.o.Collector.Collect(ctx, r.o.Setup.SetupID, r.o.Setup.Fingerprint)
	var rl *RateLimitedError
	switch {
	case errors.Is(err, ErrNotHeld):
		return true
	case errors.As(err, &rl):
		r.wait(ctx, rl.After)
		return true
	case err != nil:
		r.o.Log.Warn("collect the certificate trusted on the connect page", "setupId", r.o.Setup.SetupID, "err", err)
		return true
	case !got.SetUp() || got.TrustRoot == "":
		return true // only a SET_UP hold with a trusted certificate counts
	case got.Address.Canonical() != r.o.Credential.Canonical():
		// Only the credential's own database: anything else pins nothing.
		r.o.Log.Warn("the connect service holds another database than the agent's credential names; nothing is pinned", "setupId", r.o.Setup.SetupID)
		return true
	}
	addr := r.o.Credential
	ip, err := r.o.Prober.Resolve(ctx, addr)
	if err != nil {
		r.o.Log.Warn("resolve the agent's database to read its certificate", "setupId", r.o.Setup.SetupID, "err", err)
		return true
	}
	pin, err := r.o.Prober.Repin(ctx, addr, ip, got.TrustRoot)
	if err != nil {
		r.mismatch(err)
		return true
	}
	if err := r.o.Files.ReplacePin(addr.Host, pin); err != nil {
		r.o.Log.Warn("replace the engine's pin", "setupId", r.o.Setup.SetupID, "err", err)
		return true
	}
	r.mu.Lock()
	r.done, r.prob = true, ""
	r.mu.Unlock()
	r.o.Log.Info("the engine's own reading matched the certificate trusted on the connect page; its pin is replaced", "setupId", r.o.Setup.SetupID)
	return false
}

// mismatch records a reading that did not show the trusted certificate:
// nothing is pinned and the setup stays pending.
func (r *Repin) mismatch(err error) {
	reason := ""
	if rr, ok := ReachOf(err); ok {
		reason = rr.Reason
	}
	r.o.Log.Warn("the database presents another certificate authority to this machine than the one trusted on the connect page; nothing is pinned",
		"setupId", r.o.Setup.SetupID, "reason", reason)
	if reason == ReasonTrustRootMismatch {
		r.mu.Lock()
		r.prob = ProblemTrustRootMismatch
		r.mu.Unlock()
	}
}

// stillPending reports whether engine.json still records this setup.
func (r *Repin) stillPending() bool {
	now, ok, err := r.o.Files.PendingSetup()
	if err != nil {
		r.o.Log.Warn("read the agent's pending setup in engine.json", "err", err)
		return true
	}
	return ok && now.SetupID == r.o.Setup.SetupID && now.CertificateChanged
}

func (r *Repin) wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
