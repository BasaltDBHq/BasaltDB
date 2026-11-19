//go:build unix

package engine

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
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/keptplugins"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
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
	agents     map[string]keptAgent
	s          *keptPlugins
	pk         *passkeytest.Authenticator
	client     person.Client
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
		roles: map[string]*guardtest.Agent{}, agents: map[string]keptAgent{},
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
		f.agents[name] = keptAgent{db: pool, host: cc.Host, port: cc.Port, database: cc.Database, role: cc.User}
		f.cfg.Agents = append(f.cfg.Agents, config.Agent{Name: name, OSUser: me.Username})
		uids[name] = keptOtherUID
		if slices.Contains(scoped, name) {
			uids[name] = keptAgentUID
		}
	}
	raw, err := json.Marshal(f.cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, 0o600))
	store, err := keptplugins.New(f.state, time.Now)
	require.NoError(t, err)
	f.s = &keptPlugins{
		store: store, cfg: f.cfg, configPath: f.configPath, agents: f.agents, euid: os.Geteuid(), goos: runtimeGOOS(),
		log: slog.New(slog.DiscardHandler),
	}
	f.pk, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), f.d.Admin, f.pk.Credential(), "app"))

	f.peer.Store(keptPerson)
	srv := person.NewServer(person.Options{
		Allow: []uint32{keptPerson}, AgentUIDs: uids, Plugins: f.s, Log: slog.New(slog.DiscardHandler),
		PeerUID: func(*net.UnixConn) (uint32, error) { return f.peer.Load(), nil },
	})
	sock := filepath.Join(base, "p.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	f.client = person.Client{Path: sock}
	return f
}

// source is an unsigned local plugin acme-ner at version: its files as the
// command uploads them, and the executables it names.
func source(version string) ([]person.PluginFile, []string) {
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
	return []person.PluginFile{
		{Path: plugin.ManifestFile, Data: []byte(manifest)},
		{Path: "bin/acme-ner", Data: exe},
		{Path: "share/model.txt", Data: []byte("model")},
	}, []string{"bin/acme-ner"}
}

// add uploads source("1.0.0") and opens it for agents.
func (f *keptFixture) add(instance string, agents ...string) (person.PluginOpenResult, error) {
	f.t.Helper()
	files, exec := source("1.0.0")
	id, err := f.client.PluginUpload(context.Background(), files)
	require.NoError(f.t, err)
	return f.client.PluginOpen(context.Background(), person.PluginOpenParams{
		UploadID: &id, Name: "acme-ner", Instance: instance, Agents: agents, Executables: exec,
	})
}

// sign signs approval a with the person's passkey and relays it over the
// socket.
func (f *keptFixture) sign(a person.PluginOpenedApproval) {
	f.t.Helper()
	require.NotNil(f.t, a.ApprovalID, a.Refused)
	as, err := f.pk.Sign(approval.Challenge(a.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(f.t, err)
	res, err := f.client.PluginApprove(context.Background(), person.NewPluginApproveParams(*a.ApprovalID, as))
	require.NoError(f.t, err)
	require.Equal(f.t, "APPROVED", res.Status)
}

func (f *keptFixture) entries() []config.Plugin {
	f.t.Helper()
	es, err := f.s.store.Entries(f.cfg)
	require.NoError(f.t, err)
	return es
}

func (f *keptFixture) state0(agentName string, k plugin.EntryKey) string {
	f.t.Helper()
	r := newKeptApprovalReader(context.Background(), f.s, nil, []config.Plugin{{Name: k.Name, Instance: k.Instance, Agents: []string{agentName}}})
	return r.stateOf(agentName, k).State
}

func requirePersonError(t *testing.T, err error, code person.Code, reason string) {
	t.Helper()
	var pe *person.Error
	require.True(t, errors.As(err, &pe), "a person socket error: %v", err)
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
	fi, err = os.Stat(filepath.Join(f.state, keptplugins.EntriesFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	require.NoDirExists(t, filepath.Join(f.state, keptplugins.UploadsDir, "x"), "")
	require.Zero(t, f.s.store.Open(), "the upload is gone once used")

	require.Equal(t, before, snapshot(t, f.base, f.state), "nothing outside the state directory changed")
	require.Equal(t, "PENDING", f.state0("product_a", plugin.EntryKey{Name: "acme-ner", Instance: "default"}))

	list, err := f.client.PluginList(context.Background())
	require.NoError(t, err)
	requireSchema(t, "listResult", list)
	require.Len(t, list.Plugins, 1)
	require.Equal(t, person.SourceEngine, list.Plugins[0].Source)
	require.True(t, list.Plugins[0].Approval.Required)
	require.Equal(t, "PENDING", list.Plugins[0].Approval.Agents[0].State)

	f.sign(a)
	require.Equal(t, "APPROVED", f.state0("product_b", plugin.EntryKey{Name: "acme-ner", Instance: "default"}))
}

// TestFilesOverSocketRespectLimits: every limit of the upload and of the
// engine's storage, through the person socket.
func TestFilesOverSocketRespectLimits(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a"})
	f.s.store.WithLimits(keptplugins.Limits{PartBytes: 16, UploadBytes: 40, StorageBytes: 60, UploadPaths: 3, OpenUploads: 2})
	begin := func() uuid.UUID {
		r, err := f.client.PluginUploadBegin(context.Background())
		require.NoError(t, err)
		requireSchemaLoose(t, r)
		return r.UploadID
	}
	part := func(id uuid.UUID, p string, off int64, n int) error {
		_, err := f.client.PluginUploadPart(context.Background(), person.PluginUploadPartParams{UploadID: id, Path: p, Offset: off, Data: b64(bytes.Repeat([]byte("x"), n))})
		return err
	}
	tooLarge := func(err error) {
		t.Helper()
		requirePersonError(t, err, person.CodePluginRefused, keptplugins.ReasonTooLarge)
	}

	id := begin()
	tooLarge(part(id, "a", 0, 17))
	requirePersonError(t, part(id, "a", 0, 1), person.CodeNotFound, "")

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
	requirePersonError(t, func() error { _, err := f.client.PluginUploadBegin(context.Background()); return err }(), person.CodePluginRefused, keptplugins.ReasonTooManyUploads)
	require.NoError(t, part(id, "a", 0, 16))
	require.NoError(t, part(id, "a", 16, 16))
	require.NoError(t, part(id2, "a", 0, 16))
	tooLarge(part(id2, "a", 16, 16))

	f.s.store.WithLimits(keptplugins.DefaultLimits())
	id = begin()
	tooLarge(part(id, plugin.SignatureFile, 0, plugin.MaxSignatureFileBytes+1))
	id = begin()
	require.Error(t, part(id, "a", 0, keptplugins.MaxPartBytes+1), "a part over 64 KiB does not even fit the schema's line")

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

// requireSchemaLoose checks a begin result against its schema's limits.
func requireSchemaLoose(t *testing.T, r person.PluginUploadBeginResult) {
	t.Helper()
	require.NotEqual(t, uuid.Nil, r.UploadID)
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
	requirePersonError(t, err, person.CodePluginRefused, reasonNameTaken)
	_, err = f.client.PluginOpen(context.Background(), person.PluginOpenParams{Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}})
	requirePersonError(t, err, person.CodePluginRefused, reasonConfigEntry)
	_, err = f.client.PluginDisable(context.Background(), person.PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, person.CodePluginRefused, reasonConfigEntry)
	_, err = f.client.PluginRemove(context.Background(), person.PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, person.CodePluginRefused, reasonConfigEntry)
	require.Empty(t, f.entries())
	require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner"))

	// Another instance is not a clash.
	res, err := f.add("other", "product_a")
	require.NoError(t, err)
	require.Len(t, res.Approvals, 1)

	list, err := f.client.PluginList(context.Background())
	require.NoError(t, err)
	requireSchema(t, "listResult", list)
	sources := make([]string, 0, len(list.Plugins))
	for _, p := range list.Plugins {
		sources = append(sources, p.Instance+":"+p.Source)
	}
	sort.Strings(sources)
	require.Equal(t, []string{"default:CONFIG", "other:ENGINE"}, sources)
}

// TestAgentOsUserThatIsNotAPersonRefused: an agent's own OS user that is
// not in personUids is refused at the greeting and reaches nothing; a
// person uid that is also an agent's osUser is scoped to its agents.
func TestAgentOsUserThatIsNotAPersonRefused(t *testing.T) {
	f := newKeptFixture(t, []string{"product_a", "product_b"}, "product_a")

	f.peer.Store(keptAgentUID) // product_a's osUser, not a person
	_, err := f.client.PluginUploadBegin(context.Background())
	require.ErrorIs(t, err, person.ErrUIDNotAllowed)
	_, err = f.client.PluginList(context.Background())
	require.ErrorIs(t, err, person.ErrUIDNotAllowed)
	require.NoDirExists(t, filepath.Join(f.state, keptplugins.UploadsDir))
	require.Zero(t, f.s.store.Open())

	// The same uid recorded as a person too: scoped to product_a.
	f2 := newKeptFixture(t, []string{"product_a", "product_b"}, "product_a")
	srvScoped := scopedServer(t, f2)
	_, err = f2.addVia(srvScoped, "1.0.0", "default", "product_a", "product_b")
	requirePersonError(t, err, person.CodeAgentNotAllowed, "")
	require.Empty(t, f2.entries(), "nothing was written")

	// The person adds for both; the scoped peer can neither disable nor
	// remove it, nor enable it, and sees only its own agent.
	_, err = f2.add("default", "product_a", "product_b")
	require.NoError(t, err)
	_, err = srvScoped.PluginDisable(context.Background(), person.PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, person.CodeAgentNotAllowed, "")
	_, err = srvScoped.PluginRemove(context.Background(), person.PluginEntryParams{Name: "acme-ner", Instance: "default"})
	requirePersonError(t, err, person.CodeAgentNotAllowed, "")
	_, err = srvScoped.PluginOpen(context.Background(), person.PluginOpenParams{Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}})
	requirePersonError(t, err, person.CodeAgentNotAllowed, "")
	list, err := srvScoped.PluginList(context.Background())
	require.NoError(t, err)
	require.Len(t, list.Plugins, 1)
	require.Equal(t, []string{"product_a"}, list.Plugins[0].Agents)
	require.True(t, f2.entries()[0].Enabled)

	// Its own agent alone: allowed.
	res, err := f2.addVia(srvScoped, "1.0.0", "mine", "product_a")
	require.NoError(t, err)
	require.Len(t, res.Approvals, 1)

	// A top-level agent is refused on every plugin method.
	raw, err := rawCall(f2.client.Path, `{"method":"PLUGIN_LIST","agent":"product_a","params":{}}`)
	require.NoError(t, err)
	require.Contains(t, raw, `"INVALID_ARGUMENT"`)
	raw, err = rawCall(f2.client.Path, `{"method":"PLUGIN_UPLOAD_BEGIN","agent":"","params":{}}`)
	require.NoError(t, err)
	require.Contains(t, raw, `"INVALID_ARGUMENT"`)
}

// scopedServer serves f's methods on a second socket whose every peer is
// keptAgentUID recorded as a person as well: the SM-4 scope applies.
func scopedServer(t *testing.T, f *keptFixture) person.Client {
	t.Helper()
	srv := person.NewServer(person.Options{
		Allow: []uint32{keptPerson, keptAgentUID}, AgentUIDs: map[string]uint32{"product_a": keptAgentUID, "product_b": keptOtherUID},
		Plugins: f.s, Log: slog.New(slog.DiscardHandler),
		PeerUID: func(*net.UnixConn) (uint32, error) { return keptAgentUID, nil },
	})
	sock := filepath.Join(f.base, "s.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return person.Client{Path: sock}
}

func (f *keptFixture) addVia(c person.Client, version, instance string, agents ...string) (person.PluginOpenResult, error) {
	f.t.Helper()
	files, exec := source(version)
	id, err := c.PluginUpload(context.Background(), files)
	require.NoError(f.t, err)
	return c.PluginOpen(context.Background(), person.PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: instance, Agents: agents, Executables: exec})
}

// rawCall writes one request line and returns the response line.
func rawCall(sock, line string) (string, error) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return "", err
	}
	defer c.Close()
	buf := make([]byte, 4096)
	n, err := c.Read(buf) // the greeting
	if err != nil || !bytes.Contains(buf[:n], []byte(`"ok":true`)) {
		return string(buf[:n]), err
	}
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		return "", err
	}
	var out []byte
	for {
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil || bytes.HasSuffix(out, []byte("\n")) {
			return string(out), nil
		}
	}
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
	k := plugin.EntryKey{Name: "acme-ner", Instance: "default"}
	enable := func(f *keptFixture) (person.PluginOpenResult, error) {
		return f.client.PluginOpen(context.Background(), person.PluginOpenParams{Name: k.Name, Instance: k.Instance, Agents: []string{"product_a"}})
	}

	t.Run("disable ends the signed approval", func(t *testing.T) {
		f := newKeptFixture(t, []string{"product_a"})
		res, err := f.add("default", "product_a")
		require.NoError(t, err)
		f.sign(res.Approvals[0])
		require.Equal(t, "APPROVED", f.state0("product_a", k))
		off, err := f.client.PluginDisable(context.Background(), person.PluginEntryParams{Name: k.Name, Instance: k.Instance})
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
		a.db = failingDB{Querier: a.db, fail: fail}
		f.agents["product_a"] = a
		fail.Store(true)
		_, err = f.client.PluginDisable(context.Background(), person.PluginEntryParams{Name: k.Name, Instance: k.Instance})
		require.NoError(t, err, "the disable answers; its end is owed")
		require.Equal(t, "APPROVED", f.state0("product_a", k), "the end could not be written")

		// Still failing: the enable is refused, the entry stays off.
		_, err = enable(f)
		requirePersonError(t, err, person.CodePluginRefused, reasonDatabaseUnreachable)
		require.False(t, f.entries()[0].Enabled)
		require.Equal(t, "APPROVED", f.state0("product_a", k))

		fail.Store(false)
		again, err := enable(f)
		require.NoError(t, err)
		require.Len(t, again.Approvals, 1)
		recs, err := guard.ReadPluginApprovals(context.Background(), f.roles["product_a"].Connect(t))
		require.NoError(t, err)
		for _, r := range recs {
			if r.ApprovalID == *res.Approvals[0].ApprovalID {
				require.True(t, r.Ended(), "the old approval ended before the new one was opened")
			}
		}
		require.Equal(t, "PENDING", f.state0("product_a", k))
	})

	t.Run("an end not written at disable is written at the next start", func(t *testing.T) {
		f := newKeptFixture(t, []string{"product_a"})
		res, err := f.add("default", "product_a")
		require.NoError(t, err)
		f.sign(res.Approvals[0])
		fail := &atomic.Bool{}
		a := f.agents["product_a"]
		a.db = failingDB{Querier: a.db, fail: fail}
		f.agents["product_a"] = a
		fail.Store(true)
		_, err = f.client.PluginDisable(context.Background(), person.PluginEntryParams{Name: k.Name, Instance: k.Instance})
		require.NoError(t, err)
		require.Equal(t, "APPROVED", f.state0("product_a", k))
		fail.Store(false)
		f.s.endDisabled(context.Background())
		require.Equal(t, "ENDED", f.state0("product_a", k))
	})

	t.Run("remove ends it too, and a new add needs a new approval", func(t *testing.T) {
		f := newKeptFixture(t, []string{"product_a"})
		res, err := f.add("default", "product_a")
		require.NoError(t, err)
		f.sign(res.Approvals[0])
		gone, err := f.client.PluginRemove(context.Background(), person.PluginEntryParams{Name: k.Name, Instance: k.Instance})
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
	requirePersonError(t, err, person.CodePluginRefused, reasonUnknownAgent)
	_, err = f.client.PluginOpen(context.Background(), person.PluginOpenParams{Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}})
	requirePersonError(t, err, person.CodeNotFound, "")

	// The manifest's name, an unlisted file, a missing one.
	files, exec := source("1.0.0")
	id, err := f.client.PluginUpload(context.Background(), files)
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), person.PluginOpenParams{UploadID: &id, Name: "other-name", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, person.CodePluginRefused, keptplugins.ReasonBadManifest)
	id, err = f.client.PluginUpload(context.Background(), append(slices.Clone(files), person.PluginFile{Path: "extra", Data: []byte("x")}))
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), person.PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, person.CodePluginRefused, keptplugins.ReasonBadManifest)
	id, err = f.client.PluginUpload(context.Background(), files[:2])
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), person.PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, person.CodePluginRefused, keptplugins.ReasonBadManifest)
	// A file whose hash is not the manifest's.
	bad := slices.Clone(files)
	bad[2] = person.PluginFile{Path: "share/model.txt", Data: []byte("other")}
	id, err = f.client.PluginUpload(context.Background(), bad)
	require.NoError(t, err)
	_, err = f.client.PluginOpen(context.Background(), person.PluginOpenParams{UploadID: &id, Name: "acme-ner", Instance: "default", Agents: []string{"product_a"}, Executables: exec})
	requirePersonError(t, err, person.CodePluginRefused, keptplugins.ReasonNotTrusted)
	// auth is no setting of an engine-kept entry.
	raw, err := rawCall(f.client.Path, `{"method":"PLUGIN_OPEN","params":{"name":"acme-ner","instance":"default","agents":["product_a"],"settings":{"auth":{"credentialFile":"/etc/passwd"}}}}`)
	require.NoError(t, err)
	require.Contains(t, raw, `"INVALID_ARGUMENT"`)
	// An engine running as root refuses a local plugin.
	f.s.euid = 0
	_, err = f.add("default", "product_a")
	requirePersonError(t, err, person.CodePluginRefused, reasonEngineIsRoot)
	f.s.euid = os.Geteuid()

	require.Empty(t, f.entries())
	require.NoDirExists(t, filepath.Join(f.state, "plugins", "acme-ner"))
	require.Zero(t, f.s.store.Open(), "every upload is gone once PLUGIN_OPEN took it")

	// A narrowing opens nothing and keeps the entry enabled.
	res, err := f.add("default", "product_a")
	require.NoError(t, err)
	require.Len(t, res.Approvals, 1)
}
