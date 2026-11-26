package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// The numbers of approval.deliver (CONTRACT.md, Notifier messages, Limits
// and numbers).
const (
	// deliverWaiting is how many notices wait per entry: one made while
	// that many wait is dropped.
	deliverWaiting = 100
	// deliverIntake is how many notices wait to be handed to their
	// entries. DeliverLink never blocks: past this, a notice is dropped.
	deliverIntake = 1024
	// deliverInstallTimeout bounds the read of an agent's install id.
	deliverInstallTimeout = 5 * time.Second
	// deliverDropKeep is how long a dropped notice counts in status.
	deliverDropKeep = 24 * time.Hour
)

// deliverTries is when a notice is tried, counted from when it was made.
var deliverTries = []time.Duration{0, 5 * time.Second, 20 * time.Second, 60 * time.Second}

// deliverTiming is the delivery's numbers; tests shrink them.
type deliverTiming struct {
	tries   []time.Duration
	install time.Duration
	keep    time.Duration
}

var defaultDeliverTiming = deliverTiming{tries: deliverTries, install: deliverInstallTimeout, keep: deliverDropKeep}

// The notices' event types and fixed words (deliver.schema.json).
const (
	noticeTypeApproval = feedTypePrefix + "approval.requested"
	noticeTypeRevert   = feedTypePrefix + "revert.requested"
	noticeTypeReplaced = feedTypePrefix + "link.replaced"

	linkOpensAnywhere = "ANYWHERE"
	linkOpensEngine   = "ENGINE_COMPUTER"

	localLinkPrefix = "http://localhost:"
)

// noticeInstructions is what the person does, by the item (a held write or
// a revert) and where its link opens ("" for no link).
var noticeInstructions = map[bool]map[string]string{
	true: {
		linkOpensAnywhere: "Open the link to review the held write and approve it with your passkey.",
		linkOpensEngine:   "Open the link on the computer Basalt runs on to review the held write and approve it with your passkey.",
		"":                "Ask the agent for the link to review the held write and approve it with your passkey.",
	},
	false: {
		linkOpensAnywhere: "Open the link to review the revert and sign it with your passkey.",
		linkOpensEngine:   "Open the link on the computer Basalt runs on to review the revert and sign it with your passkey.",
		"":                "Ask the agent for the link to review the revert and sign it with your passkey.",
	},
}

// noticeLink is the shape of a link a notice may carry: a short or a long
// link to an approval or revert page at one of the two page origins.
var noticeLink = regexp.MustCompile(`^(?:https://portal\.basaltvault\.app|http://localhost:[0-9]{1,5})/(approvals|reverts)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})#(?:s=[A-Za-z0-9_-]{22}|2\.[A-Za-z0-9_.-]+)$`)

// noticeEvent is one CloudEvent of deliver/1, in its JSON form.
type noticeEvent struct {
	SpecVersion     string     `json:"specversion"`
	ID              string     `json:"id"`
	Source          string     `json:"source"`
	Type            string     `json:"type"`
	Time            string     `json:"time"`
	Subject         string     `json:"subject"`
	DataContentType string     `json:"datacontenttype"`
	Data            noticeData `json:"data"`
}

// noticeData is a notice's data. It has no field for a statement, an
// intent, a parameter or a row.
type noticeData struct {
	Kind        string `json:"kind"`
	Agent       string `json:"agent"`
	ApprovalID  string `json:"approvalId,omitempty"`
	RevertID    string `json:"revertId,omitempty"`
	Headline    string `json:"headline"`
	ExpiresAt   string `json:"expiresAt"`
	Link        string `json:"link,omitempty"`
	LinkOpens   string `json:"linkOpens,omitempty"`
	Instruction string `json:"instruction"`
}

// madeNotice is a notice as the engine made it, when the agent's answer was
// built: its id and time never change between tries.
type madeNotice struct {
	id    uuid.UUID
	at    time.Time
	agent string
	n     linksvc.LinkNotice
}

// event is the notice's CloudEvent for the database of install id install,
// encoded as the transports encode it. The link is n's, byte for byte, or
// left out when it is not a link a notice may carry.
func (m madeNotice) event(install uuid.UUID) (json.RawMessage, error) {
	n := m.n
	held := n.ApprovalID != uuid.Nil
	d := noticeData{
		Kind: string(n.Kind), Agent: approval.AgentName(m.agent), Headline: n.Headline,
		ExpiresAt: n.ExpiresAt.UTC().Format(feedTimeLayout),
	}
	var typ string
	switch n.Kind {
	case linksvc.NoticeApprovalRequested:
		typ = noticeTypeApproval
	case linksvc.NoticeRevertRequested:
		typ = noticeTypeRevert
	case linksvc.NoticeLinkReplaced:
		typ = noticeTypeReplaced
	default:
		return nil, errors.New("plugin: a notice of an unknown kind")
	}
	page, id := "reverts", n.RevertID
	if held {
		page, id = "approvals", n.ApprovalID
		d.ApprovalID = id.String()
	} else {
		d.RevertID = id.String()
	}
	if parts := noticeLink.FindStringSubmatch(n.Link); len(parts) == 3 && parts[1] == page && parts[2] == id.String() {
		d.Link, d.LinkOpens = n.Link, linkOpensAnywhere
		if strings.HasPrefix(n.Link, localLinkPrefix) {
			d.LinkOpens = linkOpensEngine
		}
	}
	d.Instruction = noticeInstructions[held][d.LinkOpens]
	return pluginproto.Marshal(noticeEvent{
		SpecVersion: cloudEventsSpecVersion, ID: m.id.String(), Source: feedSource(install), Type: typ,
		Time: m.at.UTC().Format(feedTimeLayout), Subject: d.Agent, DataContentType: feedDataContentType, Data: d,
	})
}

// pluginDelivery delivers approval notices to approval.deliver entries
// (CONTRACT.md, Notifier messages). A notice is taken from the agent's
// call without waiting on anything (agentDeliverer.DeliverLink), handed to
// every entry that declares the hook and is served to that agent, and
// tried a few times through the entry's sender; then it is dropped and
// counted. It is held in memory only. It carries the link of the agent's
// answer and issues none. Nothing an agent does waits on it.
type pluginDelivery struct {
	host    *Host
	served  func() []pluginmodel.Entry
	senders *pluginSenders
	now     func() time.Time
	clock   Clock
	timing  deliverTiming
	log     *slog.Logger

	// intake holds the notices made and not yet handed to their entries.
	intake chan madeNotice

	mu sync.Mutex
	// waiting counts, per entry, the notices made and not yet delivered or
	// dropped.
	waiting map[pluginmodel.EntryKey]int
	// drops are the times of the notices dropped, per agent and entry.
	drops map[string]map[pluginmodel.EntryKey][]time.Time

	// installs lets one read of an agent's install id run at a time, and
	// readInstall reads it: through the agent's own connection, unless a
	// test replaced it.
	installMu   sync.Mutex
	installs    map[string]chan struct{}
	readInstall func(ctx context.Context, agent string) (uuid.UUID, error)
}

func newPluginDelivery(host *Host, served func() []pluginmodel.Entry, senders *pluginSenders, now func() time.Time,
	clock Clock, log *slog.Logger,
) *pluginDelivery {
	if host == nil || served == nil || senders == nil || now == nil || clock == nil || log == nil {
		panic("engine: the plugin delivery needs a host, the served entries, senders, clocks and a log")
	}
	return &pluginDelivery{
		host: host, served: served, senders: senders, now: now, clock: clock, timing: defaultDeliverTiming, log: log,
		intake: make(chan madeNotice, deliverIntake), waiting: map[pluginmodel.EntryKey]int{},
		drops: map[string]map[pluginmodel.EntryKey][]time.Time{}, installs: map[string]chan struct{}{},
	}
}

// agentDeliverer is the delivery as one agent's service sees it.
type agentDeliverer struct {
	d     *pluginDelivery
	agent string
}

// forAgent is the agent.LinkDeliverer of the agent named name in
// engine.json.
func (d *pluginDelivery) forAgent(name string) linksvc.LinkDeliverer {
	return agentDeliverer{d: d, agent: name}
}

// DeliverLink takes the notice of an answer the agent is about to get, or of
// a write just held whose call waits for the person. It
// only stamps it and puts it in a buffer: no lock, no read, no call, so it
// returns at once whatever the plugins and the database do. A full buffer
// drops the notice; the agent's answer has the link all the same.
func (a agentDeliverer) DeliverLink(n linksvc.LinkNotice) {
	id, err := uuid.NewV7() //nolint:forbidigo // baseline: move to internal/lib/uniqueid
	if err != nil {
		return
	}
	select {
	case a.d.intake <- madeNotice{id: id, at: a.d.now(), agent: a.agent, n: n}:
	default:
	}
}

// run hands notices to their entries until ctx is done, then waits for the
// tries under way to end. ledgers are the agents' own connections, for
// their install ids.
func (d *pluginDelivery) run(ctx context.Context, ledgers map[string]AgentLedger) {
	if d.readInstall == nil {
		d.readInstall = func(ctx context.Context, name string) (uuid.UUID, error) {
			l, ok := ledgers[name]
			if !ok || l.db == nil {
				return uuid.Nil, guardmodel.ErrNoInstall
			}
			return l.ports.Guard.InstallID(ctx, l.db)
		}
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-d.intake:
			for _, k := range d.targets(m.agent) {
				if !d.admit(k) {
					d.drop(m.agent, k, "too many notices wait for the plugin")
					continue
				}
				wg.Go(func() {
					defer d.release(k)
					d.deliver(ctx, m, k)
				})
			}
		}
	}
}

// targets are the entries a notice of agent goes to: those the engine
// serves to that agent now that declare approval.deliver. An entry not
// served to the agent gets nothing, and nothing is counted for it.
func (d *pluginDelivery) targets(agentName string) []pluginmodel.EntryKey {
	var out []pluginmodel.EntryKey
	for _, e := range d.served() {
		if _, ok := e.Manifest.Hooks[string(HookApprovalDeliver)]; ok && slices.Contains(e.Agents, agentName) {
			out = append(out, e.Key)
		}
	}
	return out
}

func (d *pluginDelivery) admit(k pluginmodel.EntryKey) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.waiting[k] >= deliverWaiting {
		return false
	}
	d.waiting[k]++
	return true
}

func (d *pluginDelivery) release(k pluginmodel.EntryKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.waiting[k]--; d.waiting[k] <= 0 {
		delete(d.waiting, k)
	}
}

// errNoticeDropped ends a notice's tries at once.
var errNoticeDropped = errors.New("plugin: the notice is dropped")

// deliver tries m on entry k at each of the tries' times, until one is
// answered, the notice expires or the tries are used up. A notice still
// waiting when the engine stops is dropped uncounted.
func (d *pluginDelivery) deliver(ctx context.Context, m madeNotice, k pluginmodel.EntryKey) {
	var raw json.RawMessage
	for _, after := range d.timing.tries {
		if wait := m.at.Add(after).Sub(d.now()); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-d.clock.After(wait):
			}
		}
		if ctx.Err() != nil {
			return
		}
		if d.expired(m) {
			d.drop(m.agent, k, "it expired before it could be delivered")
			return
		}
		err := d.try(ctx, m, k, &raw)
		if err == nil || ctx.Err() != nil {
			return
		}
		if errors.Is(err, errCallExpired) {
			d.drop(m.agent, k, "it expired before it could be delivered")
			return
		}
		if errors.Is(err, errNoticeDropped) {
			d.drop(m.agent, k, "the agent's database reports no install id")
			return
		}
	}
	d.drop(m.agent, k, "every try failed")
}

func (d *pluginDelivery) expired(m madeNotice) bool { return !d.now().Before(m.n.ExpiresAt) }

// try is one try of m on entry k. *raw is the notice's bytes, built at the
// first try that could read the install id and sent unchanged after.
func (d *pluginDelivery) try(ctx context.Context, m madeNotice, k pluginmodel.EntryKey, raw *json.RawMessage) error {
	s := d.senders.sender(k)
	if s == nil || d.host.State(k) != StateReady {
		return &pluginmodel.CallError{Entry: k, Class: pluginmodel.ClassUnavailable}
	}
	if *raw == nil {
		install, err := d.installID(ctx, m.agent)
		if errors.Is(err, guardmodel.ErrNoInstall) {
			return errNoticeDropped
		}
		if err != nil {
			return err
		}
		if *raw, err = m.event(install); err != nil {
			return errNoticeDropped
		}
	}
	event := *raw
	outcome := make(chan error, 1)
	err := s.SendNotice(pluginCall{
		run: func(ctx context.Context, h *Host, k pluginmodel.EntryKey) error {
			// Checked again here, after any wait for a worker, and the
			// call itself ends at the expiry: nothing leaves after it.
			left := m.n.ExpiresAt.Sub(d.now())
			if left <= 0 {
				return errCallExpired
			}
			ctx, cancel := context.WithTimeout(ctx, left)
			defer cancel()
			return h.DeliverApproval(ctx, k, m.agent, event)
		},
		notAfter: m.n.ExpiresAt,
		done:     func(err error) { outcome <- err },
	})
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-outcome:
		return err
	}
}

// installID reads the install id of agent's database, one read at a time
// per agent and within the timing's bound; the agent's connection is
// released before any plugin call.
func (d *pluginDelivery) installID(ctx context.Context, agentName string) (uuid.UUID, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timing.install)
	defer cancel()
	d.installMu.Lock()
	turn := d.installs[agentName]
	if turn == nil {
		turn = make(chan struct{}, 1)
		d.installs[agentName] = turn
	}
	d.installMu.Unlock()
	select {
	case turn <- struct{}{}:
		defer func() { <-turn }()
	case <-ctx.Done():
		return uuid.Nil, ctx.Err()
	}
	return d.readInstall(ctx, agentName)
}

// drop counts a notice of agent that entry k did not get, and logs it with
// the entry, the agent and why in fixed words: never what it was about.
func (d *pluginDelivery) drop(agentName string, k pluginmodel.EntryKey, why string) {
	now := d.now()
	d.mu.Lock()
	byEntry := d.drops[agentName]
	if byEntry == nil {
		byEntry = map[pluginmodel.EntryKey][]time.Time{}
		d.drops[agentName] = byEntry
	}
	byEntry[k] = append(d.recent(byEntry[k], now), now)
	d.mu.Unlock()
	d.log.Warn("approval notice dropped: "+why, "plugin", k.String(), "agent", agentName)
}

// recent is times without those older than the timing's keep.
func (d *pluginDelivery) recent(times []time.Time, now time.Time) []time.Time {
	return slices.DeleteFunc(times, func(t time.Time) bool { return now.Sub(t) >= d.timing.keep })
}

// droppedNotices is how many notices of one agent an entry dropped.
type droppedNotices struct {
	key   pluginmodel.EntryKey
	count int
}

// dropped are the entries that dropped notices of agent in the last 24
// hours, with how many, in entry order.
func (d *pluginDelivery) dropped(agentName string) []droppedNotices {
	if d == nil {
		return nil
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []droppedNotices
	for k, times := range d.drops[agentName] {
		times = d.recent(times, now)
		if len(times) == 0 {
			delete(d.drops[agentName], k)
			continue
		}
		d.drops[agentName][k] = times
		out = append(out, droppedNotices{key: k, count: len(times)})
	}
	slices.SortFunc(out, func(a, b droppedNotices) int { return compareEntryKeys(a.key, b.key) })
	return out
}
