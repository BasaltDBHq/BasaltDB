package handoff

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// The removal hand-off on the engine (CONTRACT.md, Connect, The removal
// hand-off): basalt init --remove made a removal link for the agent, an
// AGENT code with no change that names the credential's database and
// carries the engine's key, and engine.json records it as the agent's
// pending removal. The person removes BasaltDB from that database on the
// connect page, whose service then keeps a REMOVED hold for the code's
// setupId. SelfRemove reads engine.json at every tick, so a removal link
// made while the engine runs is collected without a restart, and collects
// the pending removal's hold through its collect window. It asks the
// engine to remove itself only when all of these hold:
//
//   - the hold is for the removal engine.json records now (its setupId,
//     signed for with the engine's key), so a hold of an older link or of
//     another code is never acted on;
//   - its phase is REMOVED and it names the credential's own database;
//   - a fresh login with the agent's credential is refused, so the
//     database itself shows the agent's role is gone. A login that works,
//     whatever the service says, removes nothing.
//
// It removes nothing itself: Confirmed hands the decision to the engine,
// which stops, deletes its folders and sends ReportRemoved.

// SelfRemoveOptions build a SelfRemove.
type SelfRemoveOptions struct {
	Agent string
	// Credential is the database the agent's credential file names.
	Credential setupcode.Address
	Collector  Collector
	// Login logs in once with the agent's credential, on a connection of
	// its own: nil when the database accepts it, ErrLoginRefused when it
	// refuses it, another error when it cannot be reached.
	Login func(ctx context.Context) error
	// Pending is the agent's pending removal in engine.json now; false when
	// none.
	Pending func() (config.Removal, bool, error)
	// Confirmed asks the engine to remove itself; it is called once.
	Confirmed func(ctx context.Context, r Removed)
	Log       *slog.Logger
	Now       func() time.Time
}

// Removed is a removal SelfRemove confirmed: the engine removes itself,
// then reports with Report.
type Removed struct {
	Agent, SetupID, Fingerprint string
	// Report sends ReportRemoved with the engine's key in memory.
	Report func(ctx context.Context, result, reason string) error
}

// SelfRemove is one agent's removal watch on the engine.
type SelfRemove struct {
	o    SelfRemoveOptions
	mu   sync.Mutex
	done bool
	// checked is the last pending removal read, by setupId: when its code
	// was made, or why it is not collected for.
	checked struct {
		id   string
		made time.Time
		err  error
	}
}

// ErrNotARemoval is a pending removal whose code SelfRemove does not
// collect for: not an AGENT code with a target and an engine key, not the
// setupId engine.json records, or another database than the credential's.
var ErrNotARemoval = errors.New("the pending removal in engine.json is not a removal link of this agent")

// NewSelfRemove is the removal watch of o.
func NewSelfRemove(o SelfRemoveOptions) *SelfRemove {
	if o.Collector == nil || o.Login == nil || o.Pending == nil || o.Confirmed == nil || o.Log == nil || o.Now == nil {
		panic("handoff: a self-removal needs a collector, a login, its pending removal, a confirm, a logger and a clock")
	}
	return &SelfRemove{o: o}
}

// CheckRemoval is when rm's code was made, or ErrNotARemoval when it is not
// a removal link for credential.
func CheckRemoval(rm config.Removal, credential setupcode.Address) (time.Time, error) {
	p, err := setupcode.Decode(rm.Code)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: its code cannot be read: %w", ErrNotARemoval, err)
	}
	if p.ConnectOnly() || p.SetupID != rm.SetupID || p.Engine == nil || p.Kind != setupcode.KindAgent ||
		setupcode.Address(*p.Target).Canonical() != credential.Canonical() {
		return time.Time{}, ErrNotARemoval
	}
	return p.CreatedAt()
}

// Done reports whether the removal was confirmed.
func (r *SelfRemove) Done() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done
}

// Run reads engine.json and collects every 15 seconds until ctx ends or a
// removal is confirmed.
func (r *SelfRemove) Run(ctx context.Context) {
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

// pending is the removal to collect for now, or false: none recorded, its
// code refused, or its collect window over.
func (r *SelfRemove) pending() (config.Removal, bool) {
	rm, ok, err := r.o.Pending()
	if err != nil {
		r.o.Log.Warn("read the agent's pending removal in engine.json", "err", err)
		return config.Removal{}, false
	}
	if !ok {
		return config.Removal{}, false
	}
	if r.checked.id != rm.SetupID {
		r.checked.id = rm.SetupID
		r.checked.made, r.checked.err = CheckRemoval(rm, r.o.Credential)
		if r.checked.err != nil {
			r.o.Log.Warn("the pending removal is not collected", "setupId", rm.SetupID, "err", r.checked.err)
		}
	}
	if r.checked.err != nil || !r.o.Now().Before(r.checked.made.Add(setupcode.CollectWindow)) {
		return config.Removal{}, false
	}
	return rm, true
}

// Step is one read of engine.json and, with a removal pending, one collect
// and check. It reports whether to go on.
func (r *SelfRemove) Step(ctx context.Context) bool {
	if r.Done() {
		return false
	}
	rm, ok := r.pending()
	if !ok {
		return true
	}
	id := rm.SetupID
	got, err := r.o.Collector.Collect(ctx, id, rm.Fingerprint)
	var rl *RateLimitedError
	switch {
	case errors.Is(err, ErrNotHeld):
		return true
	case errors.As(err, &rl):
		r.wait(ctx, rl.After)
		return true
	case err != nil:
		r.o.Log.Warn("collect the removal from the connect page", "setupId", id, "err", err)
		return true
	case !got.Removed():
		return true // only a REMOVED hold counts
	case got.Address.Canonical() != r.o.Credential.Canonical():
		r.o.Log.Warn("the connect service holds a removal of another database than the agent's credential names; nothing is removed", "setupId", id)
		return true
	}
	// The database decides, not the service: the agent's role must be gone.
	err = r.o.Login(ctx)
	switch {
	case err == nil:
		r.o.Log.Warn("the connect service says BasaltDB was removed, but the agent's role still logs in; nothing is removed", "setupId", id)
		return true
	case !errors.Is(err, ErrLoginRefused):
		r.o.Log.Warn("check that the agent's role is gone before removing BasaltDB from this machine", "setupId", id, "err", err)
		return true
	}
	r.mu.Lock()
	r.done = true
	r.mu.Unlock()
	r.o.Log.Info("BasaltDB was removed from the agent's database on the connect page; the engine removes itself from this machine", "setupId", id)
	c, ok := r.o.Collector.(RemovedReporter)
	report := func(context.Context, string, string) error { return nil }
	if ok {
		report = func(ctx context.Context, result, reason string) error {
			return c.ReportRemoved(ctx, id, rm.Fingerprint, result, reason)
		}
	}
	r.o.Confirmed(ctx, Removed{Agent: r.o.Agent, SetupID: id, Fingerprint: rm.Fingerprint, Report: report})
	return false
}

// RemovedReporter sends ReportRemoved: *Client.
type RemovedReporter interface {
	ReportRemoved(ctx context.Context, setupID, fingerprint, result, reason string) error
}

func (r *SelfRemove) wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
