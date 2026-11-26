//go:build unix

package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// Uids of the kept-plugin cases: the person, and an agent's own OS user.
// Neither is this process's (the server refuses its own uid).
var keptPerson, keptAgentUID, keptOtherUID = func() (uint32, uint32, uint32) {
	self := uint32(os.Getuid())
	var out []uint32
	for uid := uint32(2001); len(out) < 3; uid++ {
		if uid != self {
			out = append(out, uid)
		}
	}
	return out[0], out[1], out[2]
}()

// keptFixture is a service engine's person socket serving the plugin
// methods for agents on one real guard, with the uid of each connection
// set by the test.
type keptFixture struct {
	t          *testing.T
	base       string
	state      string
	configPath string
	d          *guardtest.DB
	roles      map[string]*guardtest.Agent
	agents     map[string]KeptAgent
	s          *KeptPlugins
	pk         *passkeytest.Authenticator
	client     keptClient
	peer       atomic.Uint32
	cfg        config.Config
}

// newKeptFixture serves agents names on one database. The agents in
// scoped run as keptAgentUID, the others as keptOtherUID, so keptPerson is
// the person, no agent's osUser.
func newKeptFixture(t *testing.T, names []string, scoped ...string) *keptFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "bk")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	base, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	f := &keptFixture{
		t: t, base: base, state: filepath.Join(base, "state"), configPath: filepath.Join(base, "config", "engine.json"),
		roles: map[string]*guardtest.Agent{}, agents: map[string]KeptAgent{},
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(f.configPath), 0o700))
	f.d = guardtest.New(t).WithDemo(t)
	me, err := user.Current()
	require.NoError(t, err)
	f.cfg = config.Config{Mode: config.ModeService, StateDir: f.state, SocketDir: filepath.Join(base, "run")}
	uids := map[string]uint32{}
	for _, name := range names {
		a := f.d.NewAgent(t, name, []string{"public.leads"}, nil)
		f.roles[name] = a
		pool, err := pgxpool.New(context.Background(), a.URL)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		cc := pool.Config().ConnConfig
		f.agents[name] = KeptAgent{db: pool, host: cc.Host, port: cc.Port, database: cc.Database}
		f.cfg.Agents = append(f.cfg.Agents, config.Agent{Name: name, OSUser: me.Username})
		uids[name] = keptOtherUID
		if slices.Contains(scoped, name) {
			uids[name] = keptAgentUID
		}
	}
	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, 0o600))
	store, err := NewPluginhost(testFiles, f.state, time.Now)
	require.NoError(t, err)
	f.s = &KeptPlugins{
		ports: testPorts,
		store: store, cfg: f.cfg, configPath: f.configPath, agents: f.agents, euid: os.Geteuid(), goos: runtimeGOOS(),
		log: slog.New(slog.DiscardHandler),
	}
	f.pk, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), f.d.Admin, f.pk.Credential(), "app"))

	f.peer.Store(keptPerson)
	f.client = keptClient{s: f.s, uid: f.peer.Load}
	return f
}

// source is an unsigned local plugin acme-ner at version: its files as the
// command uploads them, and the executables it names.
func source(version string) ([]UploadFile, []string) {
	exe := []byte("#!/bin/sh\nexit 0\n" + version)
	manifest := fmt.Sprintf(`{
  "manifestVersion": 1, "name": "acme-ner", "version": %q, "publisher": "Acme",
  "protocol": ["basalt-plugin/1"],
  "hooks": { "wire.detect": { "contract": "detector/1", "roles": ["VALUE"], "entityTypes": ["PERSON_NAME"] } },
  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/acme-ner" } },
  "files": { "bin/acme-ner": "sha256:%x", "share/model.txt": "sha256:%x" },
  "network": { "egress": [] }
}
`, version, sha256.Sum256(exe), sha256.Sum256([]byte("model")))
	return []UploadFile{
		{Path: ManifestFile, Data: []byte(manifest)},
		{Path: "bin/acme-ner", Data: exe},
		{Path: "share/model.txt", Data: []byte("model")},
	}, []string{"bin/acme-ner"}
}

// add uploads source("1.0.0") and opens it for agents.
func (f *keptFixture) add(instance string, agents ...string) (PluginOpenResult, error) {
	f.t.Helper()
	files, exec := source("1.0.0")
	id, err := f.client.PluginUpload(context.Background(), files)
	require.NoError(f.t, err)
	return f.client.PluginOpen(context.Background(), PluginOpenParams{
		UploadID: &id, Name: "acme-ner", Instance: instance, Agents: agents, Executables: exec,
	})
}

// sign signs approval a with the person's passkey and submits it through
// the agent that opened it (the one whose row carries the binding text),
// as the approval page does.
func (f *keptFixture) sign(a PluginOpenedApproval) {
	f.t.Helper()
	require.NotNil(f.t, a.ApprovalID, a.Refused)
	as, err := f.pk.Sign(passkeytest.Challenge(a.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(f.t, err)
	ctx := context.Background()
	for _, name := range slices.Sorted(maps.Keys(f.agents)) {
		r, ok, err := guard.ReadPluginApproval(ctx, pgxOf(f.agents[name].db), *a.ApprovalID)
		if err != nil || !ok || r.BindingText == "" {
			continue
		}
		_, err = guard.SubmitPluginApproval(ctx, pgxOf(f.agents[name].db), guardmodel.PluginApprovalResponse{ApprovalID: *a.ApprovalID, Assertion: as})
		require.NoError(f.t, err)
		r, ok, err = guard.ReadPluginApproval(ctx, pgxOf(f.agents[name].db), *a.ApprovalID)
		require.NoError(f.t, err)
		require.True(f.t, ok)
		require.Equal(f.t, guardmodel.PluginApprovalStatusApproved, r.Status)
		return
	}
	f.t.Fatalf("no agent opened plugin approval %s", *a.ApprovalID)
}

func (f *keptFixture) entries() []config.Plugin {
	f.t.Helper()
	es, err := f.s.store.Entries(f.cfg)
	require.NoError(f.t, err)
	return es
}

func (f *keptFixture) state0(agentName string, k pluginmodel.EntryKey) string {
	f.t.Helper()
	r := newKeptApprovalReader(context.Background(), f.s, nil, []config.Plugin{{Name: k.Name, Instance: k.Instance, Agents: []string{agentName}}})
	return r.stateOf(agentName, k).State
}

func requirePersonError(t *testing.T, err error, code Code, reason string) {
	t.Helper()
	var pe *PersonError
	require.True(t, errors.As(err, &pe), "an engine-kept plugin error: %v", err)
	require.Equal(t, code, pe.Code, pe.Message)
	require.Equal(t, reason, pe.Reason, pe.Message)
}

// snapshot is every path below dir but skip, with its mode and bytes.
func snapshot(t *testing.T, dir, skip string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if p == skip {
			return filepath.SkipDir
		}
		fi, err := d.Info()
		require.NoError(t, err)
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			require.NoError(t, err)
			v += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		out[p] = v
		return nil
	}))
	return out
}

// personSchema compiles api/plugin's schemas, for the results the
// methods return.
func personSchema(t *testing.T, def string) *jsonschema.Schema {
	t.Helper()
	const base = "https://basaltvault.app/schemas/plugin/"
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	for _, f := range []string{"manifest.schema.json", "config.schema.json", "events.schema.json", "approval/person.schema.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "api", "plugin", f))
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NoError(t, c.AddResource(base+f, doc))
	}
	s, err := c.Compile(base + "approval/person.schema.json#/$defs/" + def)
	require.NoError(t, err)
	return s
}

func requireSchema(t *testing.T, def string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	require.NoError(t, err)
	require.NoError(t, personSchema(t, def).Validate(inst), string(raw))
}

// TestServiceModeAddOpensApproval: an add over the person socket, run as
// the person (no sudo), stages and checks the copy inside the engine,
// keeps the entry with approval REQUIRED, opens one approval per database
// with files NONE, and writes nothing outside the state directory.
func TestServiceModeAddOpensApproval(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a", "product_b"})
	before := snapshot(t, f.base, f.state)

	res, err := f.add("default", "product_a", "product_b")
	require.NoError(t, err)
	requireSchema(t, "openResult", res)
	require.False(t, res.Narrowed)
	require.Equal(t, "1.0.0", res.Version)
	require.Len(t, res.Approvals, 1, "both agents are on one database")
	a := res.Approvals[0]
	require.Nil(t, a.Refused)
	require.Equal(t, []string{"product_a", "product_b"}, a.Agents)
	b, err := approval.ParsePluginBinding(a.BindingText)
	require.NoError(t, err)
	require.Equal(t, "UNKNOWN", b.Signer)
	require.JSONEq(t, `{"files":"NONE","network":"NOT_ENFORCED"}`, string(b.Isolation))

	es := f.entries()
	require.Len(t, es, 1)
	require.Equal(t, config.PluginApprovalRequired, es[0].Approval)
	require.True(t, es[0].Enabled)
	require.Equal(t, "default", es[0].Instance)
	copyDir := filepath.Join(f.state, "plugins", "acme-ner", "default", es[0].ManifestSHA256)
	fi, err := os.Stat(filepath.Join(copyDir, "bin", "acme-ner"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fi.Mode().Perm(), "the executable keeps its execute bit")
	fi, err = os.Stat(filepath.Join(copyDir, "share", "model.txt"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
	fi, err = os.Stat(filepath.Join(f.state, EntriesFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	des, err := os.ReadDir(filepath.Join(f.state, UploadsDir))
	require.NoError(t, err)
	require.Empty(t, des, "the upload's directory is gone once used")
	require.Zero(t, f.s.store.Open(), "the upload is gone once used")

	require.Equal(t, before, snapshot(t, f.base, f.state), "nothing outside the state directory changed")
	require.Equal(t, "PENDING", f.state0("product_a", pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}))

	list, err := f.client.PluginList(context.Background())
	require.NoError(t, err)
	requireSchema(t, "listResult", list)
	require.Len(t, list.Plugins, 1)
	require.Equal(t, SourceEngine, list.Plugins[0].Source)
	require.True(t, list.Plugins[0].Approval.Required)
	require.Equal(t, "PENDING", list.Plugins[0].Approval.Agents[0].State)
	require.Equal(t, HealthNotStarted, list.Plugins[0].Health, "not approved yet, so the engine has not started it")
	require.JSONEq(t, `{"files":"NONE","network":"NOT_ENFORCED"}`, string(list.Plugins[0].Isolation))

	f.sign(a)
	require.Equal(t, "APPROVED", f.state0("product_b", pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}))
}

// TestFilesOverSocketRespectLimits: every limit of the upload and of the
// engine's storage, through the person socket.
func TestFilesOverSocketRespectLimits(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	f.s.store.WithLimits(Limits{PartBytes: 16, UploadBytes: 40, StorageBytes: 60, UploadPaths: 3, OpenUploads: 2})
	begin := func() uuid.UUID {
		r, err := f.client.PluginUploadBegin(context.Background())
		require.NoError(t, err)
		requireSchema(t, "uploadBeginResult", r)
		return r.UploadID
	}
	part := func(id uuid.UUID, p string, off int64, n int) error {
		_, err := f.client.PluginUploadPart(context.Background(), PluginUploadPartParams{UploadID: id, Path: p, Offset: off, Data: b64(bytes.Repeat([]byte("x"), n))})
		return err
	}
	tooLarge := func(err error) {
		t.Helper()
		requirePersonError(t, err, CodePluginRefused, ReasonTooLarge)
	}

	id := begin()
	tooLarge(part(id, "a", 0, 17))
	requirePersonError(t, part(id, "a", 0, 1), CodeNotFound, "")

	id = begin()
	for _, p := range []string{"a", "b", "c"} {
		require.NoError(t, part(id, p, 0, 1))
	}
	tooLarge(part(id, "d", 0, 1))

	id = begin()
	require.NoError(t, part(id, "a", 0, 16))
	require.NoError(t, part(id, "a", 16, 16))
	tooLarge(part(id, "a", 32, 9))

	id, id2 := begin(), begin()
	requirePersonError(t, func() error { _, err := f.client.PluginUploadBegin(context.Background()); return err }(), CodePluginRefused, ReasonTooManyUploads)
	require.NoError(t, part(id, "a", 0, 16))
	require.NoError(t, part(id, "a", 16, 16))
	require.NoError(t, part(id2, "a", 0, 16))
	tooLarge(part(id2, "a", 16, 16))

	f.s.store.WithLimits(DefaultLimits())
	id = begin()
	tooLarge(part(id, SignatureFile, 0, MaxSignatureFileBytes+1))
	id = begin()
	tooLarge(part(id, "a", 0, MaxPartBytes+1))

	// A seventeenth entry is refused before anything is written.
	require.NoError(t, f.s.store.Update(f.cfg, func([]config.Plugin) ([]config.Plugin, error) {
		es := make([]config.Plugin, 0, config.MaxKeptPlugins)
		for i := range config.MaxKeptPlugins {
			es = append(es, config.Plugin{
				Name: fmt.Sprintf("p-%02d", i), Instance: "default", ManifestSHA256: zeroSHA,
				Agents: []string{"product_a"}, Approval: config.PluginApprovalRequired,
			})
		}
		return es, nil
	}))
	_, err := f.add("default", "product_a")
	tooLarge(err)
	require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner"))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestNameClashWithConfigRefused: a (name, instance) engine.json holds is
// never an engine-kept entry, also one written to engine.json after the
// engine started; the methods on it name the sudo command.
func TestNameClashWithConfigRefused(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	held := config.Plugin{Name: "acme-ner", Instance: "default", ManifestSHA256: strings.Repeat("a", 64), Enabled: true, Agents: []string{"product_a"}}
	// Written to engine.json while the engine runs: the clash is read from
	// disk.
	cfg := f.cfg
	cfg.Plugins = []config.Plugin{held}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, 0o600))

	_, err = f.add("default", "product_a")
	requirePersonError(t, err, CodePluginRefused, reasonNameTaken)
	_, err = f.client.PluginOpen(context.Background(), PluginOpenParams{Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}})
	requirePersonError(t, err, CodePluginRefused, reasonConfigEntry)
	_, err = f.client.PluginDisable(context.Background(), PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, CodePluginRefused, reasonConfigEntry)
	_, err = f.client.PluginRemove(context.Background(), PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, CodePluginRefused, reasonConfigEntry)
	require.Empty(t, f.entries())
	require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner"))

	// Another instance is not a clash.
	res, err := f.add("other", "product_a")
	require.NoError(t, err)
	require.Len(t, res.Approvals, 1)

	// Each row's health is asked of the engine for that row's own kind.
	f.s.health = func(_ pluginmodel.EntryKey, kept bool) string {
		if kept {
			return HealthUnavailable
		}
		return HealthReady
	}
	list, err := f.client.PluginList(context.Background())
	require.NoError(t, err)
	requireSchema(t, "listResult", list)
	sources := make([]string, 0, len(list.Plugins))
	for _, p := range list.Plugins {
		sources = append(sources, p.Instance+":"+p.Source+":"+p.Health)
	}
	slices.Sort(sources)
	require.Equal(t, []string{"default:CONFIG:READY", "other:ENGINE:UNAVAILABLE"}, sources)
}

// TestScopedCallerReachesOnlyItsOwnAgents: a caller scoped to its own
// agents (an agent asking through request_plugin) can add for those alone,
// and can neither disable, remove nor widen an entry the person made for more.
func TestScopedCallerReachesOnlyItsOwnAgents(t *testing.T) {
	f2 := newKeptFixture(t, []string{"product_a", "product_b"}, "product_a")
	srvScoped := keptClient{s: f2.s, uid: func() uint32 { return keptAgentUID }, scope: Scope{"product_a": true}}
	_, err := f2.addVia(srvScoped, "1.0.0", "default", "product_a", "product_b")
	requirePersonError(t, err, CodeAgentNotAllowed, "")
	require.Empty(t, f2.entries(), "nothing was written")
	require.Equal(t, 1, f2.s.store.Open(), "a request refused for its scope does not use up its upload")

	// The person adds for both; the scoped caller can neither disable nor
	// remove it, nor enable it, and sees only its own agent.
	_, err = f2.add("default", "product_a", "product_b")
	require.NoError(t, err)
	_, err = srvScoped.PluginDisable(context.Background(), PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, CodeAgentNotAllowed, "")
	_, err = srvScoped.PluginRemove(context.Background(), PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, CodeAgentNotAllowed, "")
	_, err = srvScoped.PluginOpen(context.Background(), PluginOpenParams{Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}})
	requirePersonError(t, err, CodeAgentNotAllowed, "")
	list, err := srvScoped.PluginList(context.Background())
	require.NoError(t, err)
	require.Len(t, list.Plugins, 1)
	require.Equal(t, []string{"product_a"}, list.Plugins[0].Agents)
	require.True(t, f2.entries()[0].Enabled)

	// Its own agent alone: allowed.
	res, err := f2.addVia(srvScoped, "1.0.0", "mine", "product_a")
	require.NoError(t, err)
	require.Len(t, res.Approvals, 1)
}

func (f *keptFixture) addVia(c keptClient, version, instance string, agents ...string) (PluginOpenResult, error) {
	f.t.Helper()
	files, exec := source(version)
	id, err := c.PluginUpload(context.Background(), files)
	require.NoError(f.t, err)
	return c.PluginOpen(context.Background(), PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: instance, Agents: agents, Executables: exec})
}

// failingDB fails every exec of record_plugin_event while fail is set: a
// database that does not take an approval's end.
type failingDB struct {
	guard.Querier
	fail *atomic.Bool
}

func (d failingDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if d.fail.Load() && strings.Contains(sql, "record_plugin_event") {
		return pgconn.CommandTag{}, errors.New("the database does not answer")
	}
	return d.Querier.Exec(ctx, sql, args...)
}

// TestDisableThenEnableNeedsNewApproval: an engine-kept entry turned off
// never comes back on its old signed approval: disable ends it; when the
// end cannot be written at disable, the enable writes it first, and when
// it still cannot, the enable is refused with nothing written.
func TestDisableThenEnableNeedsNewApproval(t *testing.T) {
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	enable := func(f *keptFixture) (PluginOpenResult, error) {
		return f.client.PluginOpen(context.Background(), PluginOpenParams{Name: k.Name, Instance: k.Instance, Agents: []string{"product_a"}})
	}

	t.Run("disable ends the signed approval", func(t *testing.T) {
		f := newKeptFixture(t, []string{"product_a"})
		res, err := f.add("default", "product_a")
		require.NoError(t, err)
		f.sign(res.Approvals[0])
		require.Equal(t, "APPROVED", f.state0("product_a", k))
		off, err := f.client.PluginDisable(context.Background(), PluginEntryParams{Name: k.Name, Instance: k.Instance})
		require.NoError(t, err)
		requireSchema(t, "disableResult", off)
		require.Equal(t, "ENDED", f.state0("product_a", k), "signed, never served, and ended at once")
		require.False(t, f.entries()[0].Enabled)
		again, err := enable(f)
		require.NoError(t, err)
		require.Len(t, again.Approvals, 1)
		require.NotEqual(t, *res.Approvals[0].ApprovalID, *again.Approvals[0].ApprovalID)
		require.Equal(t, "PENDING", f.state0("product_a", k), "a new approval waits for a person")
		require.True(t, f.entries()[0].Enabled)
	})

	t.Run("an end not written at disable is written by the enable", func(t *testing.T) {
		f := newKeptFixture(t, []string{"product_a"})
		res, err := f.add("default", "product_a")
		require.NoError(t, err)
		f.sign(res.Approvals[0])
		fail := &atomic.Bool{}
		a := f.agents["product_a"]
		a.db = failingDB{Querier: pgxOf(a.db), fail: fail}
		f.agents["product_a"] = a
		fail.Store(true)
		_, err = f.client.PluginDisable(context.Background(), PluginEntryParams{Name: k.Name, Instance: k.Instance})
		require.NoError(t, err, "the disable answers; its end is owed")
		require.Equal(t, "APPROVED", f.state0("product_a", k), "the end could not be written")

		// Still failing: the enable is refused, the entry stays off.
		_, err = enable(f)
		requirePersonError(t, err, CodePluginRefused, reasonDatabaseUnreachable)
		require.False(t, f.entries()[0].Enabled)
		require.Equal(t, "APPROVED", f.state0("product_a", k))

		fail.Store(false)
		again, err := enable(f)
		require.NoError(t, err)
		require.Len(t, again.Approvals, 1)
		old, ok, err := guard.ReadPluginApproval(context.Background(), f.roles["product_a"].Connect(t), *res.Approvals[0].ApprovalID)
		require.NoError(t, err)
		require.True(t, ok)
		require.True(t, old.Ended(), "the old approval ended before the new one was opened")
		require.Equal(t, "PENDING", f.state0("product_a", k))
	})

	t.Run("an end not written at disable is written at the next start", func(t *testing.T) {
		f := newKeptFixture(t, []string{"product_a"})
		res, err := f.add("default", "product_a")
		require.NoError(t, err)
		f.sign(res.Approvals[0])
		fail := &atomic.Bool{}
		a := f.agents["product_a"]
		a.db = failingDB{Querier: pgxOf(a.db), fail: fail}
		f.agents["product_a"] = a
		fail.Store(true)
		_, err = f.client.PluginDisable(context.Background(), PluginEntryParams{Name: k.Name, Instance: k.Instance})
		require.NoError(t, err)
		require.Equal(t, "APPROVED", f.state0("product_a", k))
		fail.Store(false)
		f.s.EndDisabled(context.Background())
		require.Equal(t, "ENDED", f.state0("product_a", k))
	})

	t.Run("remove ends it too, and a new add needs a new approval", func(t *testing.T) {
		f := newKeptFixture(t, []string{"product_a"})
		res, err := f.add("default", "product_a")
		require.NoError(t, err)
		f.sign(res.Approvals[0])
		gone, err := f.client.PluginRemove(context.Background(), PluginEntryParams{Name: k.Name, Instance: k.Instance})
		require.NoError(t, err)
		requireSchema(t, "removeResult", gone)
		require.Empty(t, f.entries())
		require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner", "default"))
		require.Equal(t, "ENDED", f.state0("product_a", k))
		_, err = f.add("default", "product_a")
		require.NoError(t, err)
		require.Equal(t, "PENDING", f.state0("product_a", k))
	})
}

// TestKeptOpenRefusals: the refusals before anything is written.
func TestKeptOpenRefusals(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	_, err := f.add("default", "nobody")
	requirePersonError(t, err, CodePluginRefused, reasonUnknownAgent)
	_, err = f.client.PluginOpen(context.Background(), PluginOpenParams{Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}})
	requirePersonError(t, err, CodeNotFound, "")

	// The manifest's name, an unlisted file, a missing one.
	files, exec := source("1.0.0")
	id, err := f.client.PluginUpload(context.Background(), files)
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), PluginOpenParams{UploadID: &id, Name: "other-name", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, CodePluginRefused, ReasonBadManifest)
	id, err = f.client.PluginUpload(context.Background(), append(slices.Clone(files), UploadFile{Path: "extra", Data: []byte("x")}))
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, CodePluginRefused, ReasonBadManifest)
	id, err = f.client.PluginUpload(context.Background(), files[:2])
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, CodePluginRefused, ReasonBadManifest)
	// A file whose hash is not the manifest's.
	bad := slices.Clone(files)
	bad[2] = UploadFile{Path: "share/model.txt", Data: []byte("other")}
	id, err = f.client.PluginUpload(context.Background(), bad)
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, CodePluginRefused, ReasonNotTrusted)
	// An engine running as root refuses a local plugin.
	f.s.euid = 0
	_, err = f.add("default", "product_a")
	requirePersonError(t, err, CodePluginRefused, reasonEngineIsRoot)
	f.s.euid = os.Geteuid()

	require.Empty(t, f.entries())
	require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner"))
	require.Zero(t, f.s.store.Open(), "every upload is gone once PLUGIN_OPEN took it")

	// An empty file is uploaded as one empty part.
	files, exec = source("1.0.0")
	empty := fmt.Sprintf(`"files": { "bin/acme-ner": "sha256:%x", "share/model.txt": "sha256:%x", "pkg/__init__.py": "sha256:%x" },`,
		sha256.Sum256(files[1].Data), sha256.Sum256([]byte("model")), sha256.Sum256(nil))
	manifest := strings.Replace(string(files[0].Data), fmt.Sprintf(`"files": { "bin/acme-ner": "sha256:%x", "share/model.txt": "sha256:%x" },`,
		sha256.Sum256(files[1].Data), sha256.Sum256([]byte("model"))), empty, 1)
	files[0].Data = []byte(manifest)
	id, err = f.client.PluginUpload(context.Background(), append(files, UploadFile{Path: "pkg/__init__.py"}))
	require.NoError(t, err)
	res, err := f.client.PluginOpen(context.Background(), PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	require.NoError(t, err)
	require.Len(t, res.Approvals, 1)
	require.FileExists(t, filepath.Join(f.state, "plugins", "acme-ner", "default", f.entries()[0].ManifestSHA256, "pkg", "__init__.py"))
}

// failingOpen fails every open_plugin_approval while fail is set: an open
// refused after the entry is written.
type failingOpen struct {
	guard.Querier
	fail *atomic.Bool
}

func (d failingOpen) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if d.fail.Load() && strings.Contains(sql, "open_plugin_approval") {
		return errRow{}
	}
	return d.Querier.QueryRow(ctx, sql, args...)
}

type errRow struct{}

func (errRow) Scan(...any) error { return errors.New("the database does not answer") }

// TestNarrowThenWidenNeedsNewApproval: an agent removed from an enabled
// entry has its approval ended, and an agent added never comes back on an
// old signed approval, even when the new approval cannot be opened.
func TestNarrowThenWidenNeedsNewApproval(t *testing.T) {
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	open := func(f *keptFixture, agents ...string) (PluginOpenResult, error) {
		return f.client.PluginOpen(context.Background(), PluginOpenParams{Name: k.Name, Instance: k.Instance, Agents: agents})
	}
	f := newKeptFixture(t, []string{"product_a", "product_b"})
	res, err := f.add("default", "product_a", "product_b")
	require.NoError(t, err)
	f.sign(res.Approvals[0])

	narrowed, err := open(f, "product_a")
	require.NoError(t, err)
	requireSchema(t, "openResult", narrowed)
	require.True(t, narrowed.Narrowed)
	require.Empty(t, narrowed.Approvals)
	require.True(t, f.entries()[0].Enabled)
	require.Equal(t, "APPROVED", f.state0("product_a", k))
	require.Equal(t, "ENDED", f.state0("product_b", k), "the agent removed has its approval ended")

	// Widened again while the open fails after the write.
	fail := &atomic.Bool{}
	a := f.agents["product_a"]
	a.db = failingOpen{Querier: pgxOf(a.db), fail: fail}
	f.agents["product_a"] = a
	fail.Store(true)
	widened, err := open(f, "product_a", "product_b")
	require.NoError(t, err)
	require.NotNil(t, widened.Approvals[0].Refused)
	require.Equal(t, "ENDED", f.state0("product_b", k), "the old approval does not come back")

	// A disabled entry is never narrowed: turning it on opens an approval.
	fail.Store(false)
	_, err = f.client.PluginDisable(context.Background(), PluginEntryParams{Name: k.Name, Instance: k.Instance})
	require.NoError(t, err)
	again, err := open(f, "product_a")
	require.NoError(t, err)
	require.False(t, again.Narrowed)
	require.Len(t, again.Approvals, 1)
}

// TestRemoveThenAddWiderNeedsNewApproval: an end a remove could not write
// is written before an agent is added to a new entry of the same name.
func TestRemoveThenAddWiderNeedsNewApproval(t *testing.T) {
	k := pluginmodel.EntryKey{Name: "acme-ner", Instance: "default"}
	f := newKeptFixture(t, []string{"product_a", "product_b"})
	res, err := f.add("default", "product_a", "product_b")
	require.NoError(t, err)
	f.sign(res.Approvals[0])
	fail := &atomic.Bool{}
	b := f.agents["product_b"]
	b.db = failingDB{Querier: pgxOf(b.db), fail: fail}
	f.agents["product_b"] = b
	fail.Store(true)
	_, err = f.client.PluginRemove(context.Background(), PluginEntryParams{Name: k.Name, Instance: k.Instance})
	require.NoError(t, err)
	require.Equal(t, "APPROVED", f.state0("product_b", k), "its end could not be written")
	fail.Store(false)
	_, err = f.add("default", "product_a")
	require.NoError(t, err)
	require.Equal(t, "APPROVED", f.state0("product_b", k), "a new entry for product_a alone owes product_b nothing yet")
	// The widen's own open fails after the write: only the end written for
	// the agent it adds keeps the old approval from serving it.
	failOpen := &atomic.Bool{}
	a := f.agents["product_a"]
	a.db = failingOpen{Querier: pgxOf(a.db), fail: failOpen}
	f.agents["product_a"] = a
	failOpen.Store(true)
	widened, err := f.client.PluginOpen(context.Background(), PluginOpenParams{Name: k.Name, Instance: k.Instance, Agents: []string{"product_a", "product_b"}})
	require.NoError(t, err)
	require.NotNil(t, widened.Approvals[0].Refused)
	require.Equal(t, "ENDED", f.state0("product_b", k), "the old approval ended before product_b was added")
	old, ok, err := guard.ReadPluginApproval(context.Background(), f.roles["product_b"].Connect(t), *res.Approvals[0].ApprovalID)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, old.Ended())
}
