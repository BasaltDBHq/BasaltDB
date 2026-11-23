package testnotifier_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/adaptertest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/child"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/connect"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/dial"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/jsonrpc"
	tn "github.com/basaltdbhq/basaltdb/internal/adapter/outbound/plugintransport/testnotifier"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

var bin string

// TestMain builds the plugin once, as an engine test would.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "testnotifier")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin, err = tn.Build(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

const timeout = 300 * time.Millisecond

func entry(hooks ...string) pluginmodel.Entry {
	decl := map[string]pluginproto.HookDecl{}
	for _, h := range hooks {
		decl[h] = pluginproto.HookDecl{Contract: map[string]string{tn.HookFeedObserve: "feed/1", tn.HookApprovalDeliver: "deliver/1"}[h]}
	}
	return pluginmodel.Entry{
		Key: pluginmodel.EntryKey{Name: tn.Name, Instance: "default"},
		Manifest: pluginmodel.Manifest{
			ManifestVersion: 1, Name: tn.Name, Version: tn.Version, Publisher: "t",
			Protocol: []string{pluginproto.Version1}, Hooks: decl,
			Endpoint: pluginmodel.Endpoint{Local: &pluginmodel.LocalEndpoint{Transport: "jsonrpc-stdio", Command: "bin/" + tn.Binary}},
		},
		Agents: []string{"product_a"}, Timeout: timeout,
	}
}

type started struct {
	h       *plugin.Host
	key     pluginmodel.EntryKey
	record  string
	control string
}

// start spawns the plugin over stdio with o and registers it, as the engine
// does. Record and Control are filled in when empty.
func start(t *testing.T, o tn.Options) *started {
	t.Helper()
	dir := t.TempDir()
	if o.Record == "" {
		o.Record = filepath.Join(dir, "received.jsonl")
	}
	if o.Control == "" {
		o.Control = filepath.Join(dir, "mode")
	}
	tr, err := jsonrpc.Spawn(context.Background(), child.Spec{Path: bin, Args: o.Args(), Dir: dir})
	require.NoError(t, err)
	hooks := o.Hooks
	if len(hooks) == 0 {
		hooks = []string{tn.HookFeedObserve, tn.HookApprovalDeliver}
	}
	e := entry(hooks...)
	h := plugin.NewHost()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, h.Register(ctx, e, tr))
	t.Cleanup(func() { h.Unregister(e.Key) })
	return &started{h: h, key: e.Key, record: o.Record, control: o.Control}
}

func (s *started) observe(seqs ...int64) (int64, error) {
	evs := make([]string, len(seqs))
	for i, q := range seqs {
		evs[i] = adaptertest.FeedEvent(q)
	}
	return s.h.ObserveFeed(context.Background(), s.key, "product_a", adaptertest.Batch(evs...))
}

func (s *started) deliver() error {
	return s.h.DeliverApproval(context.Background(), s.key, "product_a", json.RawMessage(adaptertest.Notice))
}

func (s *started) records(t *testing.T) []tn.Record {
	t.Helper()
	r, err := tn.ReadRecords(s.record)
	require.NoError(t, err)
	return r
}

func classOf(err error) pluginmodel.FailureClass {
	var c *pluginmodel.CallError
	if errors.As(err, &c) {
		return c.Class
	}
	return ""
}

// TestOKRecordsWhatItReceived: it answers both hooks and records each call
// with the exact bytes it got.
func TestOKRecordsWhatItReceived(t *testing.T) {
	s := start(t, tn.Options{})
	got, err := s.observe(3, 8)
	require.NoError(t, err)
	require.Equal(t, int64(8), got)
	require.NoError(t, s.deliver())

	r := s.records(t)
	require.Len(t, r, 2)
	require.Equal(t, tn.Record{
		Hook: tn.HookFeedObserve, Agent: "product_a", Mode: tn.ModeOK,
		Events: []json.RawMessage{json.RawMessage(adaptertest.FeedEvent(3)), json.RawMessage(adaptertest.FeedEvent(8))},
	}, r[0])
	require.Contains(t, string(r[0].Events[0]), "a<b&c>", "recorded unescaped")
	require.Equal(t, tn.HookApprovalDeliver, r[1].Hook)
	require.Equal(t, adaptertest.Notice, string(r[1].Event))
}

// TestFaultModes: each mode fails the call the way it says, and records the
// call first.
func TestFaultModes(t *testing.T) {
	for _, tc := range []struct {
		mode tn.Mode
		feed pluginmodel.FailureClass
		dlvr pluginmodel.FailureClass // "" when deliver succeeds
	}{
		{tn.ModeLate, pluginmodel.ClassTimeout, pluginmodel.ClassTimeout},
		{tn.ModeHang, pluginmodel.ClassTimeout, pluginmodel.ClassTimeout},
		{tn.ModeBadSeq, pluginmodel.ClassBadResponse, ""},
		{tn.ModeBadJSON, pluginmodel.ClassBadResponse, pluginmodel.ClassBadResponse},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			o := tn.Options{Mode: tc.mode, Delay: 2 * timeout}
			s := start(t, o)
			begin := time.Now()
			_, err := s.observe(5)
			require.Equal(t, tc.feed, classOf(err), "%v", err)
			require.Less(t, time.Since(begin), 2*time.Second)
			r := s.records(t)
			require.Len(t, r, 1)
			require.Equal(t, tc.mode, r[0].Mode)

			// A fresh process for the notice: a line that is not JSON ends
			// the JSON-RPC connection, so later calls on it fail UNAVAILABLE.
			s = start(t, o)
			err = s.deliver()
			if tc.dlvr == "" {
				require.NoError(t, err)
			} else {
				require.Equal(t, tc.dlvr, classOf(err), "%v", err)
			}
			require.Len(t, s.records(t), 1)
		})
	}
	t.Run("crash", func(t *testing.T) {
		s := start(t, tn.Options{Mode: tn.ModeCrash})
		_, err := s.observe(5)
		require.Equal(t, pluginmodel.ClassExited, classOf(err), "%v", err)
		require.Len(t, s.records(t), 1)
		require.Equal(t, plugin.StateUnavailable, s.h.State(s.key))
	})
	t.Run("not-ready", func(t *testing.T) {
		s := start(t, tn.Options{Mode: tn.ModeNotReady})
		var h pluginproto.HealthResponse
		require.NoError(t, s.h.Control(context.Background(), s.key, pluginproto.MethodHealth, pluginproto.HealthRequest{}, &h))
		require.Equal(t, pluginproto.HealthNotReady, h.Status)
	})
}

// TestControlFileSwitchesModesWhileItRuns: a test can make the plugin hang,
// then answer again, without restarting it.
func TestControlFileSwitchesModesWhileItRuns(t *testing.T) {
	s := start(t, tn.Options{})
	_, err := s.observe(1)
	require.NoError(t, err)
	require.NoError(t, tn.SetMode(s.control, tn.ModeLate))
	_, err = s.observe(2)
	require.Equal(t, pluginmodel.ClassTimeout, classOf(err))
	require.NoError(t, tn.SetMode(s.control, tn.ModeOK))
	// The late call's handler still holds a slot for its delay (5s by
	// default here); the next call takes another.
	got, err := s.observe(3)
	require.NoError(t, err)
	require.Equal(t, int64(3), got)
	recs := s.records(t)
	modes := make([]tn.Mode, 0, len(recs))
	for _, r := range recs {
		modes = append(modes, r.Mode)
	}
	require.Equal(t, []tn.Mode{tn.ModeOK, tn.ModeLate, tn.ModeOK}, modes)
}

// TestHooksOption: it declares only the hooks it is given, so it matches a
// manifest with one hook.
func TestHooksOption(t *testing.T) {
	s := start(t, tn.Options{Hooks: []string{tn.HookFeedObserve}})
	_, err := s.observe(1)
	require.NoError(t, err)
	err = s.h.Call(context.Background(), s.key, []string{"product_a"}, pluginproto.MethodApprovalDeliver,
		pluginproto.ApprovalDeliverRequest{Agent: "product_a", Event: json.RawMessage(adaptertest.Notice)}, nil)
	require.Error(t, err, "approval.deliver is not served")
}

// TestConnectRPCTransport: the SDK modes work over ConnectRPC on a socket.
func TestConnectRPCTransport(t *testing.T) {
	dir, err := os.MkdirTemp("", "tn")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	rec := filepath.Join(dir, "rec.jsonl")
	cmd, err := child.Start(child.Spec{Path: bin, Args: tn.Options{Record: rec, Transport: "connectrpc"}.Args(), Dir: dir, Env: []string{"BASALT_PLUGIN_SOCKET=" + sock}})
	require.NoError(t, err)
	t.Cleanup(func() { cmd.Stop() })
	require.Eventually(t, func() bool { _, err := os.Stat(sock); return err == nil }, 5*time.Second, 10*time.Millisecond)
	tr, err := connect.DialLocal(context.Background(), sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Close() })
	var res pluginproto.FeedObserveResponse
	require.NoError(t, tr.Call(context.Background(), pluginproto.MethodFeedObserve,
		pluginproto.FeedObserveRequest{Agent: "product_a", Events: adaptertest.Batch(adaptertest.FeedEvent(7))}, &res))
	require.Equal(t, int64(7), res.LastSeq)
	r, err := tn.ReadRecords(rec)
	require.NoError(t, err)
	require.Len(t, r, 1)
}

// TestRawModeOverAUnixSocket: the modes the SDK refuses to serve work on
// jsonrpc-unix too, through the engine's host.
func TestRawModeOverAUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "tn")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	rec := filepath.Join(dir, "rec.jsonl")
	cmd, err := child.Start(child.Spec{Path: bin, Args: tn.Options{Mode: tn.ModeBadSeq, Record: rec}.Args(), Dir: dir, Env: []string{"BASALT_PLUGIN_SOCKET=" + sock}})
	require.NoError(t, err)
	t.Cleanup(cmd.Stop)
	require.Eventually(t, func() bool { _, err := os.Stat(sock); return err == nil }, 5*time.Second, 10*time.Millisecond)
	tr, err := jsonrpc.Dial(context.Background(), sock)
	require.NoError(t, err)
	e := entry(tn.HookFeedObserve, tn.HookApprovalDeliver)
	h := plugin.NewHost()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, h.Register(ctx, e, tr))
	t.Cleanup(func() { h.Unregister(e.Key) })
	s := &started{h: h, key: e.Key, record: rec}

	_, err = s.observe(4)
	require.Equal(t, pluginmodel.ClassBadResponse, classOf(err), "%v", err)
	require.NoError(t, s.deliver())
	r := s.records(t)
	require.Len(t, r, 2)
	require.Equal(t, "product_a", r[1].Agent)
	require.Equal(t, adaptertest.Notice, string(r[1].Event))
}

// TestManifestMatchesTheOptions: WriteDir writes a manifest the engine reads,
// with the binary's hash and the settings in args.
func TestManifestMatchesTheOptions(t *testing.T) {
	dir := t.TempDir()
	o := tn.Options{Mode: tn.ModeHang, Record: "/r", Control: "/c", Hooks: []string{tn.HookApprovalDeliver}, Transport: "jsonrpc-unix"}
	require.NoError(t, tn.WriteDir(dir, bin, o))
	b, err := os.ReadFile(filepath.Join(dir, plugin.ManifestFile))
	require.NoError(t, err)
	m, err := plugin.ParseManifest(b)
	require.NoError(t, err)
	require.Equal(t, tn.Name, m.Name)
	require.Equal(t, map[string]pluginproto.HookDecl{tn.HookApprovalDeliver: {Contract: "deliver/1"}}, m.Hooks)
	require.Equal(t, "jsonrpc-unix", m.Endpoint.Local.Transport)
	require.Equal(t, o.Args(), m.Endpoint.Local.Args)
	require.True(t, strings.HasPrefix(m.Files["bin/"+tn.Binary], "sha256:"))
}

// capped calls a transport as the engine does: at most MaxInFlight calls open
// at once. The suite sends more at a time than the engine ever does, and an
// SDK plugin answers calls past its waiting cap busy instead of queueing them.
type capped struct {
	pluginmodel.Transport
	slots chan struct{}
}

func engineCapped(tr pluginmodel.Transport) pluginmodel.Transport {
	return capped{Transport: tr, slots: make(chan struct{}, pluginproto.MaxInFlight)}
}

func (c capped) Call(ctx context.Context, method string, params, result any) error {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	return c.Transport.Call(ctx, method, params, result)
}

// TestSDKNotifierPassesTheNotifierSuite: the engine's adapters carry both
// hooks to a plugin built from the Go SDK module go.mod pins, in a child
// process, on every transport. It is the wire check between the engine and
// the SDK: a version of the SDK that no longer speaks the engine's protocol
// fails here.
func TestSDKNotifierPassesTheNotifierSuite(t *testing.T) {
	t.Run("jsonrpc-stdio", func(t *testing.T) {
		adaptertest.RunNotifier(t, func(t *testing.T) pluginmodel.Transport {
			tr, err := jsonrpc.Spawn(context.Background(), child.Spec{Path: bin, Dir: t.TempDir()})
			require.NoError(t, err)
			t.Cleanup(func() { _ = tr.Close() })
			return engineCapped(tr)
		})
	})
	for _, tc := range []struct {
		name string
		opts tn.Options
		dial func(context.Context, string) (pluginmodel.Transport, error)
	}{
		{"jsonrpc-unix", tn.Options{}, jsonrpc.Dial},
		{"connectrpc", tn.Options{Transport: "connectrpc"}, connect.DialLocal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adaptertest.RunNotifier(t, func(t *testing.T) pluginmodel.Transport {
				dir, err := os.MkdirTemp("", "tn")
				require.NoError(t, err)
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				sock := filepath.Join(dir, "p.sock")
				cmd := exec.Command(bin, tc.opts.Args()...)
				cmd.Dir = dir
				cmd.Env = []string{dial.SocketEnv + "=" + sock}
				require.NoError(t, cmd.Start())
				t.Cleanup(func() {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				})
				require.Eventually(t, func() bool {
					c, err := net.Dial("unix", sock)
					if err != nil {
						return false
					}
					_ = c.Close()
					return true
				}, 5*time.Second, 5*time.Millisecond)
				tr, err := tc.dial(context.Background(), sock)
				require.NoError(t, err)
				t.Cleanup(func() { _ = tr.Close() })
				return engineCapped(tr)
			})
		})
	}
}
