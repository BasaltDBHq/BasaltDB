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
// setupId. SelfRemove collects that hold through the collect window and
// asks the engine to remove itself only when all of these hold:
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
	Agent   string
	Removal config.Removal
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
	Confirmed func(Removed)
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

// SelfRemove is one agent's pending removal on the engine.
type SelfRemove struct {
	o    SelfRemoveOptions
	made time.Time
	mu   sync.Mutex
	done bool
}

// ErrNotARemoval is a pending removal whose code SelfRemove does not
// collect for: not an AGENT code with a target and an engine key, or not
// the setupId engine.json records.
var ErrNotARemoval = errors.New("the pending removal in engine.json is not a removal link of this agent")

// NewSelfRemove is the pending removal of o.
func NewSelfRemove(o SelfRemoveOptions) (*SelfRemove, error) {
	if o.Collector == nil || o.Login == nil || o.Pending == nil || o.Confirmed == nil || o.Log == nil || o.Now == nil {
		panic("handoff: a self-removal needs a collector, a login, its pending removal, a confirm, a logger and a clock")
	}
	p, err := setupcode.Decode(o.Removal.Code)
	if err != nil {
		return nil, fmt.Errorf("the pending removal code in engine.json cannot be read: %w", err)
	}
	if p.ConnectOnly() || p.SetupID != o.Removal.SetupID || p.Engine == nil || p.Kind != setupcode.KindAgent {
		return nil, ErrNotARemoval
	}
	if setupcode.Address(*p.Target).Canonical() != o.Credential.Canonical() {
		return nil, ErrNotARemoval
	}
	made, err := p.CreatedAt()
	if err != nil {
		return nil, err
	}
	return &SelfRemove{o: o, made: made}, nil
}

// Done reports whether the removal was confirmed.
func (r *SelfRemove) Done() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done
}

// Run collects every 15 seconds until ctx ends, the removal is confirmed,
// the collect window ends or engine.json no longer records this removal.
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

// Step is one collect and check. It reports whether to go on collecting.
func (r *SelfRemove) Step(ctx context.Context) bool {
	if r.Done() || !r.o.Now().Before(r.made.Add(setupcode.CollectWindow)) || !r.stillPending() {
		return false
	}
	id := r.o.Removal.SetupID
	got, err := r.o.Collector.Collect(ctx, id, r.o.Removal.Fingerprint)
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
			return c.ReportRemoved(ctx, id, r.o.Removal.Fingerprint, result, reason)
		}
	}
	r.o.Confirmed(Removed{Agent: r.o.Agent, SetupID: id, Fingerprint: r.o.Removal.Fingerprint, Report: report})
	return false
}

// RemovedReporter sends ReportRemoved: *Client.
type RemovedReporter interface {
	ReportRemoved(ctx context.Context, setupID, fingerprint, result, reason string) error
}

// stillPending reports whether engine.json still records this removal.
func (r *SelfRemove) stillPending() bool {
	now, ok, err := r.o.Pending()
	if err != nil {
		r.o.Log.Warn("read the agent's pending removal in engine.json", "err", err)
		return true
	}
	return ok && now.SetupID == r.o.Removal.SetupID
}

func (r *SelfRemove) wait(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
