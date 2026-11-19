//go:build unix

package engine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// testPluginFlag makes this test binary a JSON-RPC test plugin.
const testPluginFlag = "--engine-test-plugin"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == testPluginFlag {
		testPluginMain(os.Args[2:])
	}
	os.Exit(m.Run())
}

// testPluginMain never returns. Its argument "report=DIR" names where it
// writes "<pid>.start" when it starts and "<pid>.shutdown" when asked to
// shut down. It refuses to answer anything, and exits 3, unless its
// environment is exactly what the engine must give it (nothing for stdio,
// the socket variable alone for a socket) and its working directory is its
// installed copy.
func testPluginMain(args []string) {
	var report string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "report="); ok {
			report = v
		}
	}
	exe, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	copyDir := filepath.Dir(filepath.Dir(exe))
	raw, err := os.ReadFile(filepath.Join(copyDir, plugin.ManifestFile))
	if err != nil {
		os.Exit(1)
	}
	m, err := plugin.ParseManifest(raw)
	if err != nil {
		os.Exit(1)
	}
	sock := os.Getenv(dial.SocketEnv)
	wantEnv := []string{}
	if sock != "" {
		wantEnv = []string{dial.SocketEnv + "=" + sock}
	}
	cwd, _ := os.Getwd()
	if !slices.Equal(os.Environ(), wantEnv) || !sameDir(cwd, copyDir) {
		os.Exit(3)
	}
	pid := strconv.Itoa(os.Getpid())
	_, _ = os.Stderr.WriteString(pluginStderrMarker + "\n")
	_ = os.WriteFile(filepath.Join(report, pid+".start"), nil, 0o600)
	onShutdown := func() { _ = os.WriteFile(filepath.Join(report, pid+".shutdown"), nil, 0o600) }
	keep := func(suffix string) func(line []byte) {
		return func(line []byte) {
			f, err := os.OpenFile(filepath.Join(report, pid+suffix), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				os.Exit(1)
			}
			_, _ = f.Write(line)
			_ = f.Close()
		}
	}
	onFeed := testPluginKeeps{feed: keep(".feed"), notice: keep(".deliver")}
	if sock == "" {
		serveTestPlugin(os.Stdin, os.Stdout, m, onShutdown, onFeed)
		os.Exit(0)
	}
	l, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			os.Exit(1)
		}
		go serveTestPlugin(c, c, m, onShutdown, onFeed)
	}
}

// pluginStderrMarker is what the test plugin writes on its stderr.
const pluginStderrMarker = "PLUGIN-STDERR-MAY-HOLD-VALUES"

func sameDir(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

// testPluginKeeps are where the test plugin keeps the request lines of its
// notifier hooks.
type testPluginKeeps struct {
	feed, notice func(line []byte)
}

// serveTestPlugin answers initialize from the manifest, health READY,
// feed.observe with the last seq of its batch, and shutdown (then exits),
// one line each.
func serveTestPlugin(r io.Reader, w io.Writer, m plugin.Manifest, onShutdown func(), onFeed testPluginKeeps) {
	in := bufio.NewReader(r)
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Events []struct {
					Data struct {
						Seq int64 `json:"seq"`
					} `json:"data"`
				} `json:"events"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &req) != nil {
			os.Exit(1)
		}
		var result any = struct{}{}
		switch req.Method {
		case protocol.MethodFeedObserve:
			// Answers the last event of a batch, and keeps the request's
			// line in <report>/<pid>.feed for the test to read.
			if n := len(req.Params.Events); n > 0 {
				result = map[string]int64{"lastSeq": req.Params.Events[n-1].Data.Seq}
				onFeed.feed(line)
			}
		case protocol.MethodApprovalDeliver:
			// Keeps the request's line in <report>/<pid>.deliver.
			onFeed.notice(line)
		case protocol.MethodInitialize:
			result = protocol.InitializeResponse{Protocol: protocol.Version1, Name: m.Name, Version: m.Version, Hooks: m.Hooks}
		case protocol.MethodHealth:
			result = protocol.HealthResponse{Status: protocol.HealthReady}
		case protocol.MethodShutdown:
			onShutdown()
		}
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
		if err != nil {
			os.Exit(1)
		}
		_, _ = w.Write(append(b, '\n'))
		if req.Method == protocol.MethodShutdown {
			os.Exit(0)
		}
	}
}

// pluginFixture is a same-user engine under t.TempDir(): a config
// directory with its plugin root and a trust store holding one key, and a
// signed test plugin installed per entry.
type pluginFixture struct {
	t          *testing.T
	configPath string
	root       string
	trust      plugin.TrustStore
	report     string
	sockBase   string
	cfg        config.Config
}

func newPluginFixture(t *testing.T) *pluginFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	configDir := filepath.Join(base, "config")
	require.NoError(t, os.Mkdir(configDir, 0o700))
	f := &pluginFixture{t: t, configPath: filepath.Join(configDir, "engine.json"), report: filepath.Join(base, "report")}
	require.NoError(t, os.Mkdir(f.report, 0o700))
	f.root, err = plugin.Root(plugin.ModeSameUser, runtime.GOOS, configDir)
	require.NoError(t, err)
	f.trust, err = plugin.NewTrustStore(plugin.ModeSameUser, runtime.GOOS, configDir)
	require.NoError(t, err)
	// Socket paths must be short; t.TempDir() is too long on macOS.
	f.sockBase, err = os.MkdirTemp("", "bs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(f.sockBase) })
	f.cfg = config.Config{Agents: []config.Agent{{Name: "product_a", OSUser: "a"}, {Name: "client_x", OSUser: "x"}}}
	return f
}

// install adds an enabled entry of the test plugin for agents, over
// transport, signed by a new trusted key.
func (f *pluginFixture) install(instance, transport string, agents ...string) config.Plugin {
	f.t.Helper()
	t := f.t
	key, err := plugin.GenerateKey()
	require.NoError(t, err)
	pemBytes, err := plugin.MarshalPublicKey(&key.PublicKey)
	require.NoError(t, err)
	_, _, err = f.trust.Add(pemBytes)
	require.NoError(t, err)

	src := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(src, "bin"), 0o755))
	exe, err := os.ReadFile(os.Args[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(src, "bin", "p"), exe, 0o755))
	args, err := json.Marshal([]string{testPluginFlag, "report=" + f.report})
	require.NoError(t, err)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": "1.4.0", "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "feed.observe": { "contract": "feed/1" } },
  "endpoint": { "local": { "transport": %q, "command": "bin/p", "args": %s } },
  "files": { "bin/p": "sha256:%x" },
  "network": { "egress": [] }
}
`, transport, args, sha256.Sum256(exe))
	require.NoError(t, os.WriteFile(filepath.Join(src, plugin.ManifestFile), []byte(manifest), 0o644))
	sig, err := plugin.SignManifest([]byte(manifest), key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(src, plugin.SignatureFile), sig, 0o644))
	v, err := plugin.Install(src, f.root, instance, f.trust, plugin.ModeSameUser)
	require.NoError(t, err)
	p := config.Plugin{Name: "acme-ner", Instance: instance, ManifestSHA256: v.ManifestSHA256, Enabled: true, Agents: agents, TimeoutMs: config.MaxPluginTimeoutMs}
	f.cfg.Plugins = append(f.cfg.Plugins, p)
	return p
}

// installedFile is entry p's installed binary.
func (f *pluginFixture) installedFile(p config.Plugin) string {
	return filepath.Join(f.root, p.Name, p.Key().Instance, p.ManifestSHA256, "bin", "p")
}

func (f *pluginFixture) plugins(clock plugin.Clock) *enginePlugins {
	f.t.Helper()
	return f.pluginsWith(pluginOptions{euid: os.Geteuid(), clock: clock}, slog.New(slog.DiscardHandler))
}

func (f *pluginFixture) pluginsWith(o pluginOptions, log *slog.Logger) *enginePlugins {
	f.t.Helper()
	o.SocketBase = f.sockBase
	return newEnginePlugins(f.cfg, f.configPath, o, log)
}

// runPlugins runs ep until the returned stop is called (or the test ends).
func runPlugins(t *testing.T, ep *enginePlugins) func() time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ep.run(ctx); close(done) }()
	stop := func() time.Duration {
		start := time.Now()
		cancel()
		<-done
		return time.Since(start)
	}
	t.Cleanup(func() { stop() })
	return stop
}

func waitReady(t *testing.T, ep *enginePlugins, k plugin.EntryKey) {
	t.Helper()
	require.Eventually(t, func() bool { return ep.host.State(k) == plugin.StateReady }, 60*time.Second, 10*time.Millisecond, "%s never READY", k)
}

// reported lists the pids the test plugins wrote with suffix.
func (f *pluginFixture) reported(suffix string) []int {
	f.t.Helper()
	des, err := os.ReadDir(f.report)
	require.NoError(f.t, err)
	var pids []int
	for _, de := range des {
		if s, ok := strings.CutSuffix(de.Name(), suffix); ok {
			pid, err := strconv.Atoi(s)
			require.NoError(f.t, err)
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

func codes(ps []agent.PluginProblem) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Code)
	}
	return out
}

// Two instances of one plugin run as separate processes with separate
// socket directories; stopping client_x leaves default READY, and status
// shows client_x's problem to its own agent only. Each child gets only the
// socket variable and runs in its installed copy (the test plugin refuses
// to start otherwise), gets shutdown before it is closed, and the engine
// stops every plugin within 5 s, leaving no socket directory behind.
func TestInstancesAreSeparate(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	def := f.install("default", dial.TransportUnix, "product_a")
	cx := f.install("client_x", dial.TransportUnix, "client_x")
	ep := f.plugins(nil)
	require.NotNil(t, ep)
	stop := runPlugins(t, ep)
	waitReady(t, ep, def.Key())
	waitReady(t, ep, cx.Key())
	require.Empty(t, ep.PluginProblems("product_a"))
	require.Empty(t, ep.PluginProblems("client_x"))
	require.Len(t, f.reported(".start"), 2, "one process per entry")
	dirs, err := os.ReadDir(f.sockBase)
	require.NoError(t, err)
	require.Len(t, dirs, 2, "one socket directory per entry")
	for _, d := range dirs {
		fi, err := os.Lstat(filepath.Join(f.sockBase, d.Name()))
		require.NoError(t, err)
		require.True(t, fi.IsDir())
		require.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
		require.Equal(t, uint32(os.Geteuid()), fi.Sys().(*syscall.Stat_t).Uid)
	}

	ep.sup.Stop(cx.Key())
	require.Equal(t, plugin.StateReady, ep.host.State(def.Key()))
	require.Empty(t, ep.PluginProblems("product_a"), "another instance's stop shows nothing to product_a")
	require.Equal(t, []string{agent.ProblemPluginUnavailable}, codes(ep.PluginProblems("client_x")))
	require.Len(t, f.reported(".shutdown"), 1, "client_x got shutdown")
	dirs, err = os.ReadDir(f.sockBase)
	require.NoError(t, err)
	require.Len(t, dirs, 1, "client_x's socket directory is gone")

	took := stop()
	require.Less(t, took, plugin.StopWait)
	require.Equal(t, f.reported(".start"), f.reported(".shutdown"), "every plugin got shutdown")
	dirs, err = os.ReadDir(f.sockBase)
	require.NoError(t, err)
	require.Empty(t, dirs)
	for _, pid := range f.reported(".start") {
		require.Eventually(t, func() bool { return syscall.Kill(pid, 0) != nil }, 5*time.Second, 10*time.Millisecond, "pid %d stopped", pid)
	}
}

// A stdio plugin gets an empty environment (the test plugin exits without
// answering otherwise) and is reached.
func TestStdioPluginStarts(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	ep := f.plugins(nil)
	stop := runPlugins(t, ep)
	waitReady(t, ep, p.Key())
	stop()
	require.Len(t, f.reported(".shutdown"), 1)
}

// An installed copy that does not verify is never started, and the agents
// it lists see PLUGIN_NOT_TRUSTED naming the entry; an agent it does not
// list sees nothing.
func TestUntrustedPluginIsNotStarted(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	bin := f.installedFile(p)
	require.NoError(t, os.Chmod(bin, 0o755))
	fh, err := os.OpenFile(bin, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)
	_, err = fh.WriteString("x")
	require.NoError(t, err)
	require.NoError(t, fh.Close())

	ep := f.plugins(nil)
	require.Empty(t, ep.entries, "nothing to start")
	runPlugins(t, ep)()
	require.Empty(t, f.reported(".start"))
	probs := ep.PluginProblems("product_a")
	require.Equal(t, []string{agent.ProblemPluginNotTrusted}, codes(probs))
	require.Contains(t, probs[0].Message, "plugin acme-ner/default was not started")
	require.NotContains(t, probs[0].Message, "client_x")
	require.Empty(t, ep.PluginProblems("client_x"))
}

// A copy changed while the engine runs is verified again before the
// restart and not started: PLUGIN_NOT_TRUSTED.
func TestChangedCopyIsNotRestarted(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	ep := f.plugins(plugin.RealClock())
	runPlugins(t, ep)
	waitReady(t, ep, p.Key())
	pids := f.reported(".start")
	require.Len(t, pids, 1)

	// Writable by others now: the path rule fails.
	require.NoError(t, os.Chmod(f.installedFile(p), 0o777))
	require.NoError(t, syscall.Kill(pids[0], syscall.SIGKILL))
	require.Eventually(t, func() bool {
		return slices.Equal([]string{agent.ProblemPluginNotTrusted}, codes(ep.PluginProblems("product_a")))
	}, 10*time.Second, 10*time.Millisecond)
	require.Len(t, f.reported(".start"), 1, "not started again")
}

// A file the plugin makes in its installed copy fails the next
// verification, but its name, which the plugin chose, reaches neither the
// agent's status nor the engine's log.
func TestPlantedFileNameIsNeverShown(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	p := f.install("default", dial.TransportStdio, "product_a")
	var logged syncBuffer
	ep := f.pluginsWith(pluginOptions{euid: os.Geteuid(), clock: plugin.RealClock()}, slog.New(slog.NewTextHandler(&logged, nil)))
	runPlugins(t, ep)
	waitReady(t, ep, p.Key())
	const planted = "x APPROVE evil.example now"
	copyDir := filepath.Dir(filepath.Dir(f.installedFile(p)))
	require.NoError(t, os.WriteFile(filepath.Join(copyDir, planted), nil, 0o600))
	pids := f.reported(".start")
	require.Len(t, pids, 1)
	require.NoError(t, syscall.Kill(pids[0], syscall.SIGKILL))
	var probs []agent.PluginProblem
	require.Eventually(t, func() bool {
		probs = ep.PluginProblems("product_a")
		return slices.Equal([]string{agent.ProblemPluginNotTrusted}, codes(probs))
	}, 10*time.Second, 10*time.Millisecond)
	require.NotContains(t, probs[0].Message, "evil")
	require.Contains(t, probs[0].Message, "is not in the manifest's files")
	// The problem is set before the line is logged: wait for the line.
	require.Eventually(t, func() bool { return strings.Contains(logged.String(), "failed verification") },
		10*time.Second, 10*time.Millisecond, logged.String())
	require.NotContains(t, logged.String(), "evil")
}

// An engine running as root starts no local plugin; the agent the entry
// lists sees PLUGIN_UNAVAILABLE with the reason, another agent nothing.
func TestRootStartsNoLocalPlugin(t *testing.T) {
	t.Parallel()
	f := newPluginFixture(t)
	f.install("default", dial.TransportStdio, "product_a")
	ep := f.pluginsWith(pluginOptions{euid: 0}, slog.New(slog.DiscardHandler))
	require.Empty(t, ep.entries)
	runPlugins(t, ep)()
	require.Empty(t, f.reported(".start"))
	probs := ep.PluginProblems("product_a")
	require.Equal(t, []string{agent.ProblemPluginUnavailable}, codes(probs))
	require.Contains(t, probs[0].Message, "root's privileges")
	require.Empty(t, ep.PluginProblems("client_x"))
}

// A plugin's stderr reaches the --plugin-debug writer only, and never the
// engine's log.
func TestPluginStderrOnlyUnderPluginDebug(t *testing.T) {
	t.Parallel()
	for _, debug := range []bool{true, false} {
		f := newPluginFixture(t)
		p := f.install("default", dial.TransportStdio, "product_a")
		var stderr, logged syncBuffer
		o := pluginOptions{euid: os.Geteuid()}
		if debug {
			o.Stderr = &stderr
		}
		ep := f.pluginsWith(o, slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
		stop := runPlugins(t, ep)
		waitReady(t, ep, p.Key())
		stop()
		require.Equal(t, debug, strings.Contains(stderr.String(), pluginStderrMarker))
		require.NotContains(t, logged.String(), pluginStderrMarker)
	}
}

// With no enabled plugin entry nothing is read or started, and the agents'
// status has no plugin source.
func TestNoPluginsChangeNothing(t *testing.T) {
	t.Parallel()
	opts := pluginOptions{euid: os.Geteuid()}
	discard := slog.New(slog.DiscardHandler)
	missing := filepath.Join(t.TempDir(), "missing", "engine.json")
	require.Nil(t, newEnginePlugins(config.Config{}, missing, opts, discard))
	off := config.Config{Plugins: []config.Plugin{
		{Name: "acme-ner", ManifestSHA256: strings.Repeat("a", 64), Enabled: false, Agents: []string{"a"}},
		{Name: "acme-ner", Instance: "none", ManifestSHA256: strings.Repeat("a", 64), Enabled: true, Agents: []string{}},
	}}
	require.Nil(t, newEnginePlugins(off, missing, opts, discard))
	_, err := os.Stat(filepath.Dir(missing))
	require.True(t, os.IsNotExist(err), "nothing was made on disk")
}

// A local plugin never runs with the engine's privileges: refused as root,
// and in service mode without its own unit; a remote one is not.
func TestLocalPluginRefusedInServiceModeAndAsRoot(t *testing.T) {
	t.Parallel()
	local := plugin.Verified{Dir: "/x", Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Local: &plugin.LocalEndpoint{Transport: dial.TransportStdio, Command: "bin/p"}}}}
	remote := plugin.Verified{Manifest: plugin.Manifest{Endpoint: plugin.Endpoint{Remote: &plugin.RemoteEndpoint{Transport: dial.TransportConnect, URL: "https://ner.example"}}}}
	p := config.Plugin{Name: "acme-ner", Enabled: true, Agents: []string{"product_a"}}
	service := serviceEngine(svcConfig(), &fakeUnits{}, 1000)
	root := &enginePlugins{mode: plugin.ModeSameUser, o: pluginOptions{euid: 0}}
	user := &enginePlugins{mode: plugin.ModeSameUser, o: pluginOptions{euid: 1000}}
	require.Equal(t, whyNoUnit, service.localRefusal(p, local))
	require.Equal(t, whyLocalAsRoot, root.localRefusal(p, local))
	require.Empty(t, user.localRefusal(p, local))
	for _, ep := range []*enginePlugins{service, root, user} {
		require.Empty(t, ep.localRefusal(p, remote))
	}
}

// --plugin-debug reaches a foreground engine's stderr only.
func TestPluginDebugOnlyInTheForeground(t *testing.T) {
	t.Parallel()
	discard := slog.New(slog.DiscardHandler)
	var w strings.Builder
	require.Equal(t, io.Writer(&w), pluginDebugWriter(config.Config{}, &w, discard))
	require.Nil(t, pluginDebugWriter(config.Config{Mode: config.ModeService}, &w, discard))
	require.Nil(t, pluginDebugWriter(config.Config{}, nil, discard))
}

// A same-user engine reaps the plugin run records under its state
// directory before it records new ones; a service engine and an engine run
// as root start no local plugin process, so they record nothing.
// TestPluginRunsUnlessRoot: an engine records and reaps the local plugin
// processes it starts, in same-user mode and, for its approved engine-kept
// entries, in service mode; an engine running as root starts none.
func TestPluginRunsUnlessRoot(t *testing.T) {
	t.Parallel()
	discard := slog.New(slog.DiscardHandler)
	state := t.TempDir()
	stale := filepath.Join(t.TempDir(), "bp1")
	require.NoError(t, os.Mkdir(stale, 0o700))
	runs := filepath.Join(state, pluginRunsDirName)
	require.NoError(t, os.Mkdir(runs, 0o700))
	rec := fmt.Sprintf(`{"pid":99999999,"start":"gone","socketDir":%q,"enginePid":99999998,"engineStart":"gone"}`, stale)
	require.NoError(t, os.WriteFile(filepath.Join(runs, "99999999.json"), []byte(rec), 0o600))

	require.Nil(t, pluginRuns(config.Config{Mode: config.ModeService}, state, 0, discard))
	require.Nil(t, pluginRuns(config.Config{}, state, 0, discard))
	_, err := os.Lstat(stale)
	require.NoError(t, err, "nothing reaped by an engine that records nothing")

	r := pluginRuns(config.Config{Mode: config.ModeService}, state, os.Geteuid(), discard)
	require.NotNil(t, r)
	require.Equal(t, runs, r.Dir)
	_, err = os.Lstat(stale)
	require.ErrorIs(t, err, os.ErrNotExist, "the earlier run's socket directory is removed")
	left, err := os.ReadDir(runs)
	require.NoError(t, err)
	require.Empty(t, left)
}
