package main

// The address hand-off end to end (CONTRACT.md, Setup from your laptop, The
// engine and a connect-only code; Connect, The address hand-off): basalt
// init --remote makes a connect-only code with no --database-url, the
// connect page's calls run it in a real Postgres behind a TLS proxy that
// records every login, and an engine in this process collects the address,
// probes it, asks, and writes its credential only after confirm_database.
// The proxy is where the tests see the wire: no login carries the agent's
// real password before the person's YES, and none at all after a NO.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/platform/keyfile"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
	"github.com/basaltdbhq/basaltdb/internal/testkit/connecttest"
)

// dbHost is the name the person's database has in these tests: the proxy's
// certificate is for it, and the engine's resolver maps it to a global
// unicast address that its dialer sends to the proxy.
const dbHost = "db.example.com"

// publicIP is what dbHost resolves to for the engine: an address the
// engine's own rules allow.
var publicIP = netip.MustParseAddr("8.8.8.8")

// fixedResolver resolves every name in it, and nothing else.
type fixedResolver map[string][]netip.Addr

func (r fixedResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

// handoffFixture is a connect-only code made by init, its database behind a
// recording proxy, the connect service and the person.
type handoffFixture struct {
	t        *testing.T
	d        *guardtest.DB
	cfg      string
	install  remoteRun
	password string
	role     string
	proxy    *connecttest.Proxy
	// proxies are the databases the connect service reaches, by host.
	proxies map[string]*connecttest.Proxy
	srv     *connecttest.Server
	page    page
	person  *passkeytest.Authenticator
}

func newHandoffFixture(t *testing.T) handoffFixture {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	cfg := connectOnlyConfig(t)
	install := connectOnlyWithPrefix(t, cfg, d.Names.Prefix)
	require.True(t, install.res.ConnectOnly)
	proxy := connecttest.StartProxy(t, dbHost, upstreamOf(t, d))
	proxies := map[string]*connecttest.Proxy{dbHost: proxy}
	srv, base := connecttest.StartWith(t, connecttest.Options{Dial: func(ctx context.Context, pasted string) (*pgx.Conn, error) {
		u, err := url.Parse(pasted)
		if err != nil {
			return nil, err
		}
		p, ok := proxies[u.Hostname()]
		if !ok {
			return nil, errors.New("no such database")
		}
		return p.Connect(ctx, pasted)
	}})
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	return handoffFixture{
		t: t, d: d, cfg: cfg, install: install, password: secretOf(t, cfg), role: install.payload.Role(),
		proxy: proxy, proxies: proxies, srv: srv, page: page{t, base}, person: person,
	}
}

// upstreamOf is the test database's host and port.
func upstreamOf(t *testing.T, d *guardtest.DB) string {
	t.Helper()
	c := d.Admin.Config()
	return net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port)))
}

// pasted is the admin connection string the person pastes on the page: the
// test database's, at dbHost, with a verified certificate.
func pastedFor(t *testing.T, d *guardtest.DB, host string) string {
	t.Helper()
	u, err := url.Parse(d.URL)
	require.NoError(t, err)
	u.Host = net.JoinHostPort(host, "5432")
	q := u.Query()
	q.Set("sslmode", "verify-full")
	u.RawQuery = q.Encode()
	return u.String()
}

// runOnPage is the page's three calls with the person's passkey and the
// pasted string; it returns RunSetup's answer.
func (f handoffFixture) runOnPage(pasted string) *connectv1.RunSetupResponse {
	f.t.Helper()
	code := f.install.res.Code
	var desc connectv1.DescribeSetupResponse
	f.page.ok("DescribeSetup", map[string]any{"code": code}, &desc)
	require.Nil(f.t, desc.GetSummary().GetTarget(), "a connect-only code names no database")
	var chk connectv1.CheckSetupResponse
	f.page.ok("CheckSetup", map[string]any{"code": code, "databaseUrl": pasted}, &chk)
	require.Equal(f.t, dbHost, chk.GetDatabase().GetHost(), "the page names the pasted database first")
	require.NotEmpty(f.t, chk.GetTables())
	ch := desc.GetChallenge()
	var run connectv1.RunSetupResponse
	f.page.ok("RunSetup", map[string]any{
		"code": code, "databaseUrl": pasted, "challenge": challengeJSON(ch), "passkey": passkeyOf(f.t, f.person, ch),
		"includedTables": chk.GetTables(),
	}, &run)
	require.NotEmpty(f.t, run.GetTicket())
	return &run
}

// carried is how many logins through the proxy carried the agent's real
// password.
func (f handoffFixture) carried() int { return f.proxy.CarriedFor(f.role, f.password) }

// handoffEngine is an engine in this process on the config init wrote, its
// connect service and database reached through the test's resolver, dialer
// and roots. A reload runs it again on the config as it is then.
type handoffEngine struct {
	socket  string
	reloads chan struct{}
}

func startHandoffEngine(t *testing.T, cfgPath string, o app.HandoffOptions) handoffEngine {
	t.Helper()
	sameUserConfig(t, cfgPath)
	e := handoffEngine{reloads: make(chan struct{}, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		for {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				done <- err
				return
			}
			err = app.RunWith(ctx, cfg, cfgPath, slog.New(slog.DiscardHandler), app.RestartOptions{Handoff: o})
			if !errors.Is(err, app.ErrReload) || ctx.Err() != nil {
				done <- err
				return
			}
			e.reloads <- struct{}{}
		}
	}()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	e.socket = config.SocketPath(cfg.SocketDir, "bot")
	e.waitServing(t)
	return e
}

// sameUserConfig makes the config init wrote one for a same-user engine
// of this test's OS user, with a short socket directory and the Vault off.
func sameUserConfig(t *testing.T, cfgPath string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "bho") // short: macOS bounds socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	me, err := user.Current()
	require.NoError(t, err)
	// The state directory stays: the engine signs with the key init put
	// in the code. The Vault is off, so the test dials nothing else.
	if m["stateDir"] == nil {
		m["stateDir"] = filepath.Join(filepath.Dir(cfgPath), stateDirName)
	}
	m["socketDir"], m["pagesAddr"], m["mode"], m["vault"] = filepath.Join(dir, "run"), "off", "SAME_USER", "OFF"
	m["agents"].([]any)[0].(map[string]any)["osUser"] = me.Username
	raw, err = json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfgPath, raw))
}

func (e handoffEngine) waitServing(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", e.socket)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 30*time.Second, 20*time.Millisecond)
}

// call is a tools/call with args on the engine's socket: the result's
// text, and whether it is an error.
func (e handoffEngine) call(t *testing.T, tool string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	conn, err := net.Dial("unix", e.socket)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(60*time.Second)))
	rawArgs, err := json.Marshal(args)
	require.NoError(t, err)
	_, err = fmt.Fprintf(conn, "%s\n%s\n", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+string(rawArgs)+`}}`)
	require.NoError(t, err)
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	var resp struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &resp), line)
	require.Len(t, resp.Result.Content, 1, line)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &out), line)
	return out, resp.Result.IsError
}

func setupOf(t *testing.T, status map[string]any) map[string]any {
	t.Helper()
	s, ok := status["setup"].(map[string]any)
	require.True(t, ok, "%v", status)
	return s
}

func problemCodes(status map[string]any) []string {
	var out []string
	ps, _ := status["problems"].([]any)
	for _, p := range ps {
		if m, ok := p.(map[string]any); ok {
			out = append(out, fmt.Sprint(m["code"]))
		}
	}
	return out
}

// waitForState calls status until setup.state is state (status collects
// at most every 10 seconds, and the loop every 15).
func (e handoffEngine) waitForState(t *testing.T, state string) map[string]any {
	t.Helper()
	var st map[string]any
	require.Eventually(t, func() bool {
		st, _ = e.call(t, "status", map[string]any{})
		return setupOf(t, st)["state"] == state
	}, 45*time.Second, 500*time.Millisecond, "setup.state never became %s", state)
	return st
}

func (f handoffFixture) engineOptions(resolver handoff.Resolver) app.HandoffOptions {
	return app.HandoffOptions{
		ServiceURL: f.page.base,
		Prober:     handoff.Prober{Resolver: resolver, Dial: f.proxy.Dial, Roots: f.proxy.Roots},
	}
}

var publicDB = fixedResolver{dbHost: {publicIP}}

// confirmArgs are confirm_database's arguments from status's CALL_TOOL step
// with the person's answer.
func confirmArgs(t *testing.T, status map[string]any, answer string) map[string]any {
	t.Helper()
	for _, p := range status["problems"].([]any) {
		m := p.(map[string]any)
		if m["code"] != "CONFIRM_DATABASE" {
			continue
		}
		steps := m["nextSteps"].([]any)
		call := steps[len(steps)-1].(map[string]any)
		require.Equal(t, "confirm_database", call["tool"])
		args := call["arguments"].(map[string]any)
		require.NotContains(t, args, "answer", "the engine never fills in the answer")
		args["answer"] = answer
		return args
	}
	t.Fatalf("no CONFIRM_DATABASE problem: %v", status)
	return nil
}

func TestConnectOnlySetupEndToEnd(t *testing.T) {
	t.Parallel()
	f := newHandoffFixture(t)
	e := startHandoffEngine(t, f.cfg, f.engineOptions(publicDB))

	// Before the page: the engine waits, serves only status, and holds no
	// connection to anything.
	st, isErr := e.call(t, "status", map[string]any{})
	require.False(t, isErr)
	require.Equal(t, "PENDING", setupOf(t, st)["state"])
	require.Equal(t, true, setupOf(t, st)["connectOnly"])
	require.Contains(t, problemCodes(st), "SETUP_NOT_RUN")
	body, isErr := e.call(t, "list_runs", map[string]any{})
	require.True(t, isErr)
	require.Equal(t, "SETUP_PENDING", body["reason"])

	// The page runs the setup; the service holds the address.
	run := f.runOnPage(pastedFor(t, f.d, dbHost))
	held, ok := f.srv.Held(f.install.res.SetupID)
	require.True(t, ok)
	require.Equal(t, dbHost, held.Host)

	// The engine collects, checks and probes, then asks.
	st = e.waitForState(t, "CONFIRM_DATABASE")
	db := setupOf(t, st)["database"].(map[string]any)
	require.Equal(t, dbHost, db["host"])
	require.Equal(t, f.d.Admin.Config().Database, db["database"])
	require.Contains(t, problemCodes(st), "CONFIRM_DATABASE")
	var hs connectv1.HandoffStatusResponse
	f.page.ok("HandoffStatus", map[string]any{"ticket": run.GetTicket()}, &hs)
	require.Equal(t, "COLLECTED", hs.GetState(), "the page sees the pick-up")
	probes := 0
	for _, l := range f.proxy.Logins() {
		if l.User == f.role {
			probes++
		}
	}
	require.NotZero(t, probes, "the probe reached the database as the agent's role")
	require.Zero(t, f.carried(), "no login before the person's answer carried the real password")
	require.FileExists(t, secretPathOf(f.cfg))
	require.NoFileExists(t, f.install.credFile)
	body, isErr = e.call(t, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isErr)
	require.Equal(t, "DATABASE_NOT_CONFIRMED", body["reason"])

	// YES: the credential for exactly that database, .secret gone,
	// awaitingAddress cleared, and the engine serves its config again.
	res, isErr := e.call(t, "confirm_database", confirmArgs(t, st, "YES"))
	require.False(t, isErr, "%v", res)
	require.Equal(t, "CONFIRMED", res["state"])
	select {
	case <-e.reloads:
	case <-time.After(30 * time.Second):
		t.Fatal("the engine did not serve its config again after the YES")
	}
	e.waitServing(t)
	require.NoFileExists(t, secretPathOf(f.cfg))
	dsn := credentialDSN(t, f.install.credFile)
	u, err := url.Parse(dsn)
	require.NoError(t, err)
	require.Equal(t, dbHost, u.Hostname())
	require.Equal(t, "verify-full", u.Query().Get("sslmode"))
	pw, _ := u.User.Password()
	require.Equal(t, f.password, pw, "the password init generated, never sent before the YES")
	cfg, err := config.Load(f.cfg)
	require.NoError(t, err)
	require.False(t, cfg.Agents[0].Setup.AwaitingAddress)
	require.Zero(t, f.carried(), "the YES itself sends nothing")

	// The positive control: a login with the written credential carries
	// the real password, and the proxy sees it. It finds the setup.
	conn, err := f.proxy.Connect(context.Background(), dsn)
	require.NoError(t, err)
	recorded, err := guard.SetupRecorded(context.Background(), conn, uuid.MustParse(f.install.res.SetupID))
	require.NoError(t, conn.Close(context.Background()))
	require.NoError(t, err)
	require.True(t, recorded)
	require.Equal(t, 1, f.carried(), "the recorder sees a real login once one is made")
}

func TestConnectOnlySetupRefused(t *testing.T) {
	t.Parallel()
	f := newHandoffFixture(t)
	e := startHandoffEngine(t, f.cfg, f.engineOptions(publicDB))
	f.runOnPage(pastedFor(t, f.d, dbHost))
	st := e.waitForState(t, "CONFIRM_DATABASE")

	res, isErr := e.call(t, "confirm_database", confirmArgs(t, st, "NO"))
	require.False(t, isErr, "%v", res)
	require.Equal(t, "REFUSED", res["state"])
	require.NotEmpty(t, res["personMessage"])
	require.NoFileExists(t, secretPathOf(f.cfg), "the password is gone")
	require.NoFileExists(t, f.install.credFile)
	cfg, err := config.Load(f.cfg)
	require.NoError(t, err)
	require.True(t, cfg.Agents[0].Setup.Refused)
	require.False(t, cfg.Agents[0].Setup.AwaitingAddress)

	st = e.waitForState(t, "REFUSED")
	require.Contains(t, problemCodes(st), "DATABASE_REFUSED")
	body, isErr := e.call(t, "list_runs", map[string]any{})
	require.True(t, isErr)
	require.Equal(t, "SETUP_PENDING", body["reason"])
	require.Zero(t, f.carried(), "a NO leaves no real login anywhere")
}

func TestConnectOnlyHostileHandoffs(t *testing.T) {
	t.Parallel()

	t.Run("a collector with another key", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		f.runOnPage(pastedFor(t, f.d, dbHost))
		other, err := channel.GenerateEngineKeys(time.Now)
		require.NoError(t, err)
		c := handoff.NewClient(nil, f.page.base, other, time.Now)
		_, err = c.Collect(context.Background(), f.install.res.SetupID, f.install.res.Fingerprint)
		require.ErrorIs(t, err, handoff.ErrNotHeld)
		// The real key, with the other's signature: the same answer.
		key := engineKeysOf(t, f.cfg)
		_, err = handoff.NewClient(nil, f.page.base, keyWithSigner{Signer: other, spki: key.PublicKeySPKI()}, time.Now).
			Collect(context.Background(), f.install.res.SetupID, f.install.res.Fingerprint)
		require.ErrorIs(t, err, handoff.ErrNotHeld)
		addr, err := handoff.NewClient(nil, f.page.base, key, time.Now).Collect(context.Background(), f.install.res.SetupID, f.install.res.Fingerprint)
		require.NoError(t, err)
		require.Equal(t, dbHost, addr.Address.Host)
	})

	t.Run("a replayed collect", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		f.runOnPage(pastedFor(t, f.d, dbHost))
		key := engineKeysOf(t, f.cfg)
		at := time.Now()
		c := handoff.NewClient(nil, f.page.base, key, func() time.Time { return at })
		first, err := c.Collect(context.Background(), f.install.res.SetupID, f.install.res.Fingerprint)
		require.NoError(t, err)
		again, err := c.Collect(context.Background(), f.install.res.SetupID, f.install.res.Fingerprint)
		require.NoError(t, err)
		require.Equal(t, first, again, "within the window a replay gets the same answer")
		f.srv.Advance(6 * time.Minute)
		_, err = c.Collect(context.Background(), f.install.res.SetupID, f.install.res.Fingerprint)
		require.ErrorIs(t, err, handoff.ErrClockSkew, "outside it, the time is refused first")
	})

	t.Run("a forged ticket", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		run := f.runOnPage(pastedFor(t, f.d, dbHost))
		forged := []byte(run.GetTicket())
		forged[len(forged)-2] ^= 1
		f.page.refused("HandoffStatus", map[string]any{"ticket": string(forged)}, "not_found", "HANDOFF_UNKNOWN")
		f.srv.Restart()
		f.page.refused("OfferAddress", map[string]any{"ticket": string(forged)}, "not_found", "HANDOFF_UNKNOWN")
		_, ok := f.srv.Held(f.install.res.SetupID)
		require.False(t, ok, "a forged ticket puts nothing back")
		var off connectv1.OfferAddressResponse
		f.page.ok("OfferAddress", map[string]any{"ticket": run.GetTicket()}, &off)
		_, ok = f.srv.Held(f.install.res.SetupID)
		require.True(t, ok, "the real ticket puts the hold back after a restart")
	})

	t.Run("a second database for the same code", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		e := startHandoffEngine(t, f.cfg, f.engineOptions(publicDB))
		f.runOnPage(pastedFor(t, f.d, dbHost))

		// Someone else's database, behind its own recording proxy, pasted
		// with the same code while the hold lives: refused after the login
		// there succeeded, and nothing runs.
		other := guardtest.New(t).WithDemo(t)
		otherProxy := connecttest.StartProxy(t, "other.example.com", upstreamOf(t, other))
		f.proxies["other.example.com"] = otherProxy
		var desc connectv1.DescribeSetupResponse
		f.page.ok("DescribeSetup", map[string]any{"code": f.install.res.Code}, &desc)
		ch := desc.GetChallenge()
		f.page.refused("RunSetup", map[string]any{
			"code": f.install.res.Code, "databaseUrl": pastedFor(t, other, "other.example.com"),
			"challenge": challengeJSON(ch), "passkey": passkeyOf(t, f.person, ch),
		}, "failed_precondition", "RUN_ELSEWHERE")
		require.Zero(t, installedVersion(t, other), "nothing ran there")
		held, ok := f.srv.Held(f.install.res.SetupID)
		require.True(t, ok)
		require.Equal(t, dbHost, held.Host, "the hold still names the first database")

		st := e.waitForState(t, "CONFIRM_DATABASE")
		require.Equal(t, dbHost, setupOf(t, st)["database"].(map[string]any)["host"], "the engine asks about the first database only")
		require.Zero(t, otherProxy.CarriedFor(f.role, f.password))
		require.Zero(t, f.carried())
	})

	t.Run("an address that resolves to a private range", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		private := fixedResolver{dbHost: {netip.MustParseAddr("10.0.0.5")}}
		e := startHandoffEngine(t, f.cfg, f.engineOptions(private))
		f.runOnPage(pastedFor(t, f.d, dbHost))
		var st map[string]any
		require.Eventually(t, func() bool {
			st, _ = e.call(t, "status", map[string]any{})
			return slicesContains(problemCodes(st), "ADDRESS_INVALID")
		}, 45*time.Second, 500*time.Millisecond)
		require.Equal(t, "PENDING", setupOf(t, st)["state"])
		raw, err := json.Marshal(st)
		require.NoError(t, err)
		require.NotContains(t, string(raw), dbHost, "nothing of a refused address is shown")
		for _, l := range f.proxy.Logins() {
			require.NotEqual(t, f.role, l.User, "the engine never connected to it")
		}
	})
}

func slicesContains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// engineKeysOf loads the engine key init made for cfg.
func engineKeysOf(t *testing.T, cfg string) *channel.EngineKeys {
	t.Helper()
	k, err := keyfile.LoadKeys(filepath.Join(filepath.Dir(cfg), stateDirName, "channel.json"))
	require.NoError(t, err)
	return k
}

// keyWithSigner signs with Signer but names another key.
type keyWithSigner struct {
	handoff.Signer
	spki []byte
}

func (k keyWithSigner) PublicKeySPKI() []byte { return k.spki }

// checkOnPage is the page's first two calls: DescribeSetup and CheckSetup,
// before the person approves. It returns CheckSetup's answer.
func (f handoffFixture) checkOnPage(pasted string) *connectv1.CheckSetupResponse {
	f.t.Helper()
	var desc connectv1.DescribeSetupResponse
	f.page.ok("DescribeSetup", map[string]any{"code": f.install.res.Code}, &desc)
	var chk connectv1.CheckSetupResponse
	f.page.ok("CheckSetup", map[string]any{"code": f.install.res.Code, "databaseUrl": pasted}, &chk)
	return &chk
}

// waitForReach polls HandoffStatus with ticket, as the page does, until the
// engine's reach report is there.
func (f handoffFixture) waitForReach(ticket string) *connectv1.HandoffStatusResponse {
	f.t.Helper()
	var hs connectv1.HandoffStatusResponse
	require.Eventually(f.t, func() bool {
		hs = connectv1.HandoffStatusResponse{}
		f.page.ok("HandoffStatus", map[string]any{"ticket": ticket}, &hs)
		return hs.GetReach() != nil
	}, 45*time.Second, 200*time.Millisecond, "the engine never reported")
	return &hs
}

// roleLogins is how many logins through the proxy were the agent's role's.
func (f handoffFixture) roleLogins() int {
	n := 0
	for _, l := range f.proxy.Logins() {
		if l.User == f.role {
			n++
		}
	}
	return n
}

// The reach check end to end (CONTRACT.md, Connect, The reach check): the
// page's CheckSetup makes a PREVIEW hold, the engine probes it with a wrong
// password and reports, and shows nothing of it; after RunSetup the SET_UP
// probe reuses the preview's, and the engine asks as before. No login
// carries the agent's real password before the person's YES.
func TestConnectOnlyReachCheck(t *testing.T) {
	t.Parallel()
	f := newHandoffFixture(t)
	e := startHandoffEngine(t, f.cfg, f.engineOptions(publicDB))
	pasted := pastedFor(t, f.d, dbHost)

	chk := f.checkOnPage(pasted)
	require.NotEmpty(t, chk.GetTicket(), "a connect-only INSTALL code gets a preview ticket")
	require.Equal(t, "PREVIEW", f.srv.HeldPhase(f.install.res.SetupID))
	hs := f.waitForReach(chk.GetTicket())
	require.Equal(t, "PREVIEW", hs.GetPhase())
	require.Equal(t, "REACHABLE", hs.GetReach().GetResult())
	require.Empty(t, hs.GetReach().GetReason())

	// The engine shows nothing of the preview address and stays waiting.
	st, _ := e.call(t, "status", map[string]any{})
	require.Equal(t, "PENDING", setupOf(t, st)["state"])
	require.Contains(t, problemCodes(st), "SETUP_NOT_RUN")
	raw, err := json.Marshal(st)
	require.NoError(t, err)
	require.NotContains(t, string(raw), dbHost, "status shows nothing of a PREVIEW address")
	cfgRaw, err := os.ReadFile(f.cfg)
	require.NoError(t, err)
	require.NotContains(t, string(cfgRaw), dbHost, "engine.json keeps nothing of it")
	require.NoFileExists(t, f.install.credFile)
	require.FileExists(t, secretPathOf(f.cfg))
	body, isErr := e.call(t, "query", map[string]any{"sql": "SELECT 1"})
	require.True(t, isErr)
	require.Equal(t, "SETUP_PENDING", body["reason"])
	probed := f.roleLogins()
	require.NotZero(t, probed, "the preview probe reached the database as the agent's role")
	require.Zero(t, f.carried(), "the preview probe sends a wrong password")

	// The person approves: the SET_UP hold, the reused probe, the question.
	f.runOnPage(pasted)
	require.Equal(t, "SET_UP", f.srv.HeldPhase(f.install.res.SetupID))
	st = e.waitForState(t, "CONFIRM_DATABASE")
	require.Equal(t, dbHost, setupOf(t, st)["database"].(map[string]any)["host"])
	require.Equal(t, probed, f.roleLogins(), "the SET_UP probe reuses the preview's: one flow, one probe here")
	require.Zero(t, f.carried())

	// NO: still nothing real anywhere.
	res, isErr := e.call(t, "confirm_database", confirmArgs(t, st, "NO"))
	require.False(t, isErr, "%v", res)
	require.Zero(t, f.carried(), "no valid proof after a NO either")
}

// A preview address the engine cannot use is reported with its reason, and
// still shows nothing in status.
func TestConnectOnlyReachCheckUnreachable(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		resolver fixedResolver
		reason   string
	}{
		"a private address":            {fixedResolver{dbHost: {netip.MustParseAddr("10.0.0.5")}}, "ADDRESS_REFUSED"},
		"a host that does not resolve": {fixedResolver{}, "NO_ROUTE"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newHandoffFixture(t)
			e := startHandoffEngine(t, f.cfg, f.engineOptions(c.resolver))
			chk := f.checkOnPage(pastedFor(t, f.d, dbHost))
			hs := f.waitForReach(chk.GetTicket())
			require.Equal(t, "UNREACHABLE", hs.GetReach().GetResult())
			require.Equal(t, c.reason, hs.GetReach().GetReason())
			st, _ := e.call(t, "status", map[string]any{})
			require.Equal(t, "PENDING", setupOf(t, st)["state"])
			require.Equal(t, []string{"SETUP_NOT_RUN"}, problemCodes(st), "a preview shows no problem")
			require.Zero(t, f.roleLogins(), "the engine never connected to it")
		})
	}
}

// The hold's phases rank as the contract says, and a report is checked as
// a collect is.
func TestConnectOnlyHostileReachCheck(t *testing.T) {
	t.Parallel()

	t.Run("a report with another key, a forged result, or for another address", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		chk := f.checkOnPage(pastedFor(t, f.d, dbHost))
		ctx := context.Background()
		addr := handoff.Address{Host: dbHost, Port: 5432, Database: f.d.Admin.Config().Database}
		other, err := channel.GenerateEngineKeys(time.Now)
		require.NoError(t, err)
		err = handoff.NewClient(nil, f.page.base, other, time.Now).Report(ctx, f.install.res.SetupID, f.install.res.Fingerprint, addr, handoff.Reach{})
		require.ErrorIs(t, err, handoff.ErrNotHeld)
		key := engineKeysOf(t, f.cfg)
		err = handoff.NewClient(nil, f.page.base, keyWithSigner{Signer: other, spki: key.PublicKeySPKI()}, time.Now).
			Report(ctx, f.install.res.SetupID, f.install.res.Fingerprint, addr, handoff.Reach{})
		require.ErrorIs(t, err, handoff.ErrNotHeld)
		c := handoff.NewClient(nil, f.page.base, key, time.Now)
		require.ErrorIs(t, c.Report(ctx, f.install.res.SetupID, f.install.res.Fingerprint, addr, handoff.Reach{Reason: "BECAUSE"}), handoff.ErrNotHeld)
		_, ok := f.srv.Reached(f.install.res.SetupID)
		require.False(t, ok, "nothing refused is kept")

		// Another address is accepted and ignored.
		require.NoError(t, c.Report(ctx, f.install.res.SetupID, f.install.res.Fingerprint, handoff.Address{Host: "other.example.com", Port: 5432, Database: "app"}, handoff.Reach{}))
		_, ok = f.srv.Reached(f.install.res.SetupID)
		require.False(t, ok)
		// The hold's own, in another case, is kept.
		upper := addr
		upper.Host = "DB.EXAMPLE.COM"
		require.NoError(t, c.Report(ctx, f.install.res.SetupID, f.install.res.Fingerprint, upper, handoff.Reach{Reason: handoff.ReasonTimeout}))
		var hs connectv1.HandoffStatusResponse
		f.page.ok("HandoffStatus", map[string]any{"ticket": chk.GetTicket()}, &hs)
		require.Equal(t, "TIMEOUT", hs.GetReach().GetReason())
	})

	t.Run("a preview never replaces a set-up hold", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		pasted := pastedFor(t, f.d, dbHost)
		preview := f.checkOnPage(pasted)
		require.NotEmpty(t, preview.GetTicket())
		run := f.runOnPage(pasted)
		require.Equal(t, "SET_UP", f.srv.HeldPhase(f.install.res.SetupID))

		// After a restart, the preview ticket puts back a PREVIEW hold, and
		// the set-up ticket then replaces it; the preview ticket never
		// replaces it back.
		f.srv.Restart()
		var off connectv1.OfferAddressResponse
		f.page.ok("OfferAddress", map[string]any{"ticket": preview.GetTicket()}, &off)
		require.Equal(t, "PREVIEW", f.srv.HeldPhase(f.install.res.SetupID))
		var hs connectv1.HandoffStatusResponse
		f.page.ok("HandoffStatus", map[string]any{"ticket": run.GetTicket()}, &hs)
		require.Equal(t, "UNKNOWN", hs.GetState(), "a set-up ticket reads a PREVIEW hold as none")
		f.page.ok("OfferAddress", map[string]any{"ticket": run.GetTicket()}, &off)
		require.Equal(t, "SET_UP", f.srv.HeldPhase(f.install.res.SetupID))
		f.page.ok("OfferAddress", map[string]any{"ticket": preview.GetTicket()}, &off)
		require.Equal(t, "SET_UP", f.srv.HeldPhase(f.install.res.SetupID), "a preview ticket never replaces a SET_UP hold")
	})

	t.Run("someone else's preview of another database refuses nothing", func(t *testing.T) {
		t.Parallel()
		f := newHandoffFixture(t)
		other := guardtest.New(t).WithDemo(t)
		f.proxies["other.example.com"] = connecttest.StartProxy(t, "other.example.com", upstreamOf(t, other))
		chk := f.checkOnPage(pastedFor(t, other, "other.example.com"))
		require.NotEmpty(t, chk.GetTicket())
		f.runOnPage(pastedFor(t, f.d, dbHost))
		held, ok := f.srv.Held(f.install.res.SetupID)
		require.True(t, ok)
		require.Equal(t, dbHost, held.Host, "RunSetup holds its own address, never the preview's")
	})
}

// The connect page's ticks and labels through the service: CheckSetup
// lists the columns with their classes, a label whose class changed is
// CLASSES_CHANGED, and RunSetup grants the ticked tables only and writes
// the labels.
func TestConnectPageTicksAndLabels(t *testing.T) {
	t.Parallel()
	f := newHandoffFixture(t)
	pasted := pastedFor(t, f.d, dbHost)
	chk := f.checkOnPage(pasted)
	require.NotEmpty(t, chk.GetColumns())
	for _, c := range chk.GetColumns() {
		require.Equal(t, "UNCLASSIFIED", c.GetClass(), "no guard yet")
	}
	var desc connectv1.DescribeSetupResponse
	f.page.ok("DescribeSetup", map[string]any{"code": f.install.res.Code}, &desc)
	ch := desc.GetChallenge()
	body := func(was string) map[string]any {
		return map[string]any{
			"code": f.install.res.Code, "databaseUrl": pasted, "challenge": challengeJSON(ch), "passkey": passkeyOf(t, f.person, ch),
			"includedTables": []string{"public.leads"},
			"columnClasses": []map[string]any{{
				"table": "public.leads", "column": "name", "class": "IDENTIFIER", "entityType": "PERSON_NAME", "was": map[string]any{"class": was},
			}},
			"restPublic": true,
		}
	}
	f.page.refused("RunSetup", body("PUBLIC"), "failed_precondition", "CLASSES_CHANGED")
	require.Zero(t, installedVersion(t, f.d), "nothing changed")
	var run connectv1.RunSetupResponse
	f.page.ok("RunSetup", body("UNCLASSIFIED"), &run)
	role := f.d.Names.Prefix + "_agent_bot"
	var leads, payroll bool
	require.NoError(t, f.d.Admin.QueryRow(context.Background(),
		`SELECT has_table_privilege($1, 'public.leads', 'UPDATE'), has_table_privilege($1, 'public.payroll', 'SELECT')`, role).Scan(&leads, &payroll))
	require.True(t, leads)
	require.False(t, payroll, "an unticked table is not granted")
	labels, err := guard.ReadLabels(context.Background(), f.d.Admin, f.d.Names, []string{"public.leads"})
	require.NoError(t, err)
	for _, l := range labels {
		if l.Column == "name" {
			require.Equal(t, guardmodel.Label{Class: "IDENTIFIER", EntityType: "PERSON_NAME"}, l.Label)
		} else {
			require.Equal(t, "PUBLIC", l.Class, l.Column)
		}
	}
}

// The shape rules of the page's table list, then the re-run of the same
// code: CheckSetup says it already ran, and RunSetup reconnects without the
// tables, the labels or a passkey.
func TestConnectOnlyPageRerun(t *testing.T) {
	t.Parallel()
	f := newHandoffFixture(t)
	pasted := pastedFor(t, f.d, dbHost)
	code := f.install.res.Code
	var desc connectv1.DescribeSetupResponse
	f.page.ok("DescribeSetup", map[string]any{"code": code}, &desc)
	require.NotEmpty(t, desc.GetSummary().GetAllTablesSchemas(), "a connect-only code gives all tables")
	chk := f.checkOnPage(pasted)
	require.False(t, chk.GetAlreadyRan())
	require.NotEmpty(t, chk.GetTicket(), "a preview ticket for the reach check")
	all := chk.GetTables()
	require.NotEmpty(t, all)
	ch := desc.GetChallenge()
	body := func(included []string) map[string]any {
		b := map[string]any{"code": code, "databaseUrl": pasted, "challenge": challengeJSON(ch), "passkey": passkeyOf(t, f.person, ch)}
		if included != nil {
			b["includedTables"] = included
		}
		return b
	}
	for name, c := range map[string]struct {
		included     []string
		code, reason string
	}{
		"no list":              {nil, "failed_precondition", "NO_TABLES"},
		"a table twice":        {append([]string{all[0]}, all...), "invalid_argument", "ANSWERS_INVALID"},
		"not schema-qualified": {[]string{"leads"}, "invalid_argument", "ANSWERS_INVALID"},
		"a table since gone":   {append(slices.Clone(all), "public.gone"), "failed_precondition", "TABLES_CHANGED"},
	} {
		f.page.refused("RunSetup", body(c.included), c.code, c.reason)
		require.Zero(t, installedVersion(t, f.d), "%s: nothing ran", name)
	}

	var run connectv1.RunSetupResponse
	f.page.ok("RunSetup", body(all), &run)
	require.NotEmpty(t, run.GetTicket())
	require.False(t, run.GetReconnected())

	again := f.checkOnPage(pasted)
	require.True(t, again.GetAlreadyRan())
	require.Equal(t, dbHost, again.GetDatabase().GetHost())
	require.Empty(t, again.GetTicket(), "no preview hold over a SET_UP one")
	var rerun connectv1.RunSetupResponse
	f.page.ok("RunSetup", map[string]any{"code": code, "databaseUrl": pasted}, &rerun)
	require.True(t, rerun.GetReconnected())
	require.NotEmpty(t, rerun.GetTicket())
	require.Empty(t, rerun.GetPasskeys(), "a re-run registers no passkey")
}
