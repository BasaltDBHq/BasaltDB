//go:build unix

package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/dial"
)

// fedSeqs are the seqs every test plugin process received for agent, over
// JSON-RPC, each request checked against feed.schema.json.
func (f *pluginFixture) fedSeqs(sch *jsonschema.Schema, agent string) []int64 {
	f.t.Helper()
	files, err := filepath.Glob(filepath.Join(f.report, "*.feed"))
	require.NoError(f.t, err)
	var out []int64
	for _, name := range files {
		raw, err := os.ReadFile(name)
		require.NoError(f.t, err)
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(nil, 4<<20)
		for sc.Scan() {
			var req struct {
				Params json.RawMessage `json:"params"`
			}
			require.NoError(f.t, json.Unmarshal(sc.Bytes(), &req))
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(req.Params))
			require.NoError(f.t, err)
			require.NoError(f.t, sch.Validate(inst), string(req.Params))
			var p struct {
				Agent  string     `json:"agent"`
				Events []gotEvent `json:"events"`
			}
			require.NoError(f.t, json.Unmarshal(req.Params, &p))
			if p.Agent != agent {
				continue
			}
			for _, e := range p.Events {
				out = append(out, e.seq())
			}
		}
	}
	slices.Sort(out)
	return out
}

// The engine as it runs: an approved feed.observe plugin, a real process
// over JSON-RPC, is fed what the agent does; turned off, it gets nothing,
// and approved again it starts at the PLUGIN_ENABLED the engine wrote
// then, so nothing from while it was off reaches it.
func TestFeedFollowsTheRunningEngine(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.installApproval(feedHooks, "product_a")
	l := newPluginLedgers(t, f)
	pk := l.person(t)
	l.approve(t, pk, p, "product_a")
	f.writeConfig()
	cfg, err := config.Load(f.configPath)
	require.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	state := t.TempDir()
	timing := fastFeed
	ep := NewFor(cfg, f.configPath, Options{Ports: testPorts, Dialer: dial.Dialer{}, SocketBase: f.sockBase, euid: os.Geteuid(), stateDir: state, feedTiming: &timing}, log)
	ledgers := l.pools(t)
	ctx, cancel := context.WithCancel(context.Background())
	RecordEvents(ctx, cfg, f.configPath, ep, ledgers, log)
	done := make(chan struct{})
	go func() { ep.Serve(ctx, cfg, f.configPath, ledgers); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	fe := &feedEnv{t: t, l: l, stateDir: state}
	sch := feedSchema(t)
	waitReady(t, ep, p.Key())
	fe.started(p.Key(), "product_a")
	require.NotNil(t, ep.senders.sender(p.Key()), "the entry's sender, for the notifier hooks")
	a := fe.applied("product_a")
	require.Eventually(t, func() bool { return slices.Equal(f.fedSeqs(sch, "product_a"), []int64{a}) }, 20*time.Second, 20*time.Millisecond)

	f.cfg.Plugins[0].Enabled = false
	f.writeConfig()
	require.Eventually(t, func() bool {
		rows := l.events(t, "product_a")
		return len(servedTo(ep, p.Key())) == 0 && rows[len(rows)-1].Kind == "PLUGIN_DISABLED"
	}, 20*time.Second, 20*time.Millisecond)
	require.Eventually(t, func() bool { return ep.senders.sender(p.Key()) == nil }, 10*time.Second, 20*time.Millisecond,
		"its sender stops with it")
	off := fe.applied("product_a")

	f.cfg.Plugins[0].Enabled = true
	f.writeConfig()
	l.approve(t, pk, p, "product_a")
	require.Eventually(t, func() bool {
		return ep.host.State(p.Key()) == plugin.StateReady && slices.Equal(servedTo(ep, p.Key()), []string{"product_a"})
	}, 20*time.Second, 20*time.Millisecond)
	b := fe.applied("product_a")
	require.Eventually(t, func() bool { return slices.Contains(f.fedSeqs(sch, "product_a"), b) }, 20*time.Second, 20*time.Millisecond)
	require.Equal(t, []int64{a, b}, f.fedSeqs(sch, "product_a"), "nothing from while it was off (%d)", off)
}
