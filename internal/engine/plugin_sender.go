package engine

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// pluginSenderQueue is how many calls wait per entry (CONTRACT.md, Notifier
// messages, Limits and numbers: at most 100 notices wait per entry).
const pluginSenderQueue = 100

// Why a pluginSender did not take or make a call.
var (
	errSenderFull    = errors.New("plugin: the entry's queue is full")
	errSenderStopped = errors.New("plugin: the entry is no longer served")
	errCallExpired   = errors.New("plugin: the call was not made before it expired")
)

// pluginCall is one hook call a pluginSender makes to its entry.
type pluginCall struct {
	// run makes the call to entry k through h, with one of the host's hook
	// calls (plugin.Host.ObserveFeedOn, DeliverApproval), which keep the
	// listed agent, the entry's 4 call slots and its timeoutMs. ctx is the
	// sender's: it ends when the sender stops.
	run func(ctx context.Context, h *plugin.Host, k plugin.EntryKey) error
	// notAfter: a call still waiting at this time is dropped, never sent.
	// Zero is no limit.
	notAfter time.Time
	// done gets the call's outcome once, on the sender's goroutine: nil, a
	// failure of the call (plugin.CallError, plugin.ErrAgentNotListed), or
	// errCallExpired or errSenderStopped. It must not block. nil ignores it.
	done func(error)
}

// pluginSender makes the hook calls of one plugin entry (the notifier hooks:
// feed.observe, approval.deliver). Calls wait in a bounded queue; at most
// protocol.MaxInFlight are made at once, each through the host, which keeps
// the entry's call cap and timeoutMs. Whoever hands it a call never waits
// on the plugin: Send returns at once, and a full queue refuses the call.
type pluginSender struct {
	host *plugin.Host
	key  plugin.EntryKey
	now  func() time.Time

	queue chan pluginCall
	// notices are the approval.deliver calls, apart from the feed's batches:
	// a full feed queue never refuses a notice, workers take notices first,
	// and one worker takes nothing else, so feed calls that hang never hold
	// every worker.
	notices chan pluginCall
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	mu sync.Mutex
	// stopped: Stop ran; Send queues nothing.
	stopped bool
}

// newPluginSender starts the sender of entry k on host.
func newPluginSender(host *plugin.Host, k plugin.EntryKey, now func() time.Time) *pluginSender {
	if host == nil || now == nil {
		panic("engine: a plugin sender needs a host and a clock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &pluginSender{
		host: host, key: k, now: now, queue: make(chan pluginCall, pluginSenderQueue),
		notices: make(chan pluginCall, pluginSenderQueue), ctx: ctx, cancel: cancel,
	}
	s.wg.Go(s.workNotices)
	for range protocol.MaxInFlight - 1 {
		s.wg.Go(s.work)
	}
	return s
}

// Send queues c and returns at once. It refuses c, sending nothing and
// never calling c.done, when ctx is done, the queue is full
// (errSenderFull) or the sender stopped (errSenderStopped). The call is made
// on the sender's own context, not ctx: it outlives the caller's request,
// and ends when the sender stops.
func (s *pluginSender) Send(ctx context.Context, c pluginCall) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errSenderStopped
	}
	select {
	case s.queue <- c:
		return nil
	default:
		return errSenderFull
	}
}

// SendNotice is Send for an approval.deliver call: it waits in the notices'
// own queue, which the feed's batches never fill.
func (s *pluginSender) SendNotice(c pluginCall) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errSenderStopped
	}
	select {
	case s.notices <- c:
		return nil
	default:
		return errSenderFull
	}
}

// Stop ends the calls in flight, drops the waiting ones (each done gets
// errSenderStopped) and returns once every worker has returned.
func (s *pluginSender) Stop() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
	for {
		select {
		case c := <-s.queue:
			finish(c, errSenderStopped)
		case c := <-s.notices:
			finish(c, errSenderStopped)
		default:
			return
		}
	}
}

func (s *pluginSender) work() {
	for {
		// A waiting notice goes before a feed batch.
		select {
		case <-s.ctx.Done():
			return
		case c := <-s.notices:
			s.do(c)
			continue
		default:
		}
		select {
		case <-s.ctx.Done():
			return
		case c := <-s.notices:
			s.do(c)
		case c := <-s.queue:
			s.do(c)
		}
	}
}

// workNotices is the worker that takes only notices.
func (s *pluginSender) workNotices() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case c := <-s.notices:
			s.do(c)
		}
	}
}

func (s *pluginSender) do(c pluginCall) {
	if !c.notAfter.IsZero() && !s.now().Before(c.notAfter) {
		finish(c, errCallExpired)
		return
	}
	err := c.run(s.ctx, s.host, s.key)
	if err != nil && s.ctx.Err() != nil {
		err = errSenderStopped
	}
	finish(c, err)
}

func finish(c pluginCall, err error) {
	if c.done != nil {
		c.done(err)
	}
}

// pluginSenders are the senders of the entries the engine serves that
// declare a notifier hook, one per entry, started and stopped with the
// entries (sync).
type pluginSenders struct {
	host *plugin.Host
	now  func() time.Time

	mu sync.Mutex
	m  map[plugin.EntryKey]*pluginSender
}

func newPluginSenders(host *plugin.Host, now func() time.Time) *pluginSenders {
	return &pluginSenders{host: host, now: now, m: map[plugin.EntryKey]*pluginSender{}}
}

// sync keeps a sender for each of keys and stops the others.
func (r *pluginSenders) sync(keys []plugin.EntryKey) {
	r.mu.Lock()
	var stop []*pluginSender
	for k, s := range r.m {
		if !slices.Contains(keys, k) {
			stop = append(stop, s)
			delete(r.m, k)
		}
	}
	for _, k := range keys {
		if r.m[k] == nil {
			r.m[k] = newPluginSender(r.host, k, r.now)
		}
	}
	r.mu.Unlock()
	stopAll(stop)
}

// sender is entry k's sender, nil when the engine serves no such entry.
func (r *pluginSenders) sender(k plugin.EntryKey) *pluginSender {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[k]
}

// stop stops every sender.
func (r *pluginSenders) stop() {
	r.mu.Lock()
	stop := slices.Collect(maps.Values(r.m))
	clear(r.m)
	r.mu.Unlock()
	stopAll(stop)
}

func stopAll(senders []*pluginSender) {
	var wg sync.WaitGroup
	for _, s := range senders {
		wg.Go(s.Stop)
	}
	wg.Wait()
}
