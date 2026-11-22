package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// agentUsers has the agent's OS user alice (uid 4242) and an engine (uid
// 4000) whose group alice is not in.
type agentUsers struct{}

func (agentUsers) Lookup(name string) (*user.User, error) {
	if name != "alice" {
		return nil, user.UnknownUserError(name)
	}
	return &user.User{Username: "alice", Uid: "4242", Gid: "4242"}, nil
}

func (agentUsers) LookupID(uid string) (*user.User, error) {
	return &user.User{Uid: uid, Gid: "4000"}, nil
}
func (agentUsers) GroupIDs(*user.User) ([]string, error) { return nil, nil }
func (agentUsers) Self() int                             { return 4000 }

func postJSON(t *testing.T, base, origin, path string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out bytes.Buffer
	_, err = out.ReadFrom(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out.Bytes()
}

// The whole first install through the routes: check, the passkey, run.
// The engine writes its own files, the run's answer arrives in full, and
// the waiting ends with the listener handed on.
func TestFirstInstallThroughTheSetupRoutes(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	if u, err := url.Parse(d.URL); err != nil || u.User == nil {
		t.Skip("the test server's admin string has no password")
	} else if _, ok := u.User.Password(); !ok {
		t.Skip("the test server's admin string has no password")
	}
	addr := freeAddr(t)
	origin := pageOrigin(addr)
	configPath := filepath.Join(t.TempDir(), "engine.json")
	type waited struct {
		ln  net.Listener
		err error
	}
	done := make(chan waited, 1)
	go func() {
		o := waitOptions(addr, configPath)
		o.Users, o.Prefix = agentUsers{}, d.Names.Prefix
		ln, err := engine.WaitForConfig(context.Background(), o)
		done <- waited{ln, err}
	}()
	waitUp(t, addr)
	base := "http://" + addr

	job := localsetup.Request{Job: localsetup.JobInstall, Agent: "demo_bot", OSUser: "alice", Demo: true, DatabaseURL: d.URL}
	code, raw := postJSON(t, base, origin, "/api/v1/setup/check", job)
	require.Equal(t, http.StatusOK, code, string(raw))
	var checked localsetup.CheckAnswer
	require.NoError(t, json.Unmarshal(raw, &checked))
	require.True(t, checked.PasskeyNeeded)

	rp, err := passkey.Local(origin)
	require.NoError(t, err)
	auth, err := passkeytest.New(rp)
	require.NoError(t, err)
	c := *checked.Challenge
	rr, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	require.NoError(t, err)
	reg, err := auth.Register(rr, nil)
	require.NoError(t, err)
	run := job
	run.Challenge, run.Passkey = &c, &localsetup.Passkey{RegistrationResponse: reg, Label: "laptop"}
	code, raw = postJSON(t, base, origin, "/api/v1/setup/run", run)
	require.Equal(t, http.StatusOK, code, string(raw))
	var ran localsetup.RunAnswer
	require.NoError(t, json.Unmarshal(raw, &ran))
	require.Equal(t, "demo_bot", ran.Agent)
	require.Len(t, ran.Passkeys, 1)

	var w waited
	select {
	case w = <-done:
		require.NoError(t, w.err)
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not see the config the setup wrote")
	}
	require.NoError(t, w.ln.Close())
	cfg, err := config.Load(configPath)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	require.Equal(t, "demo_bot", cfg.Agents[0].Name)
}

// registerFor is the browser's part: a passkey made with a check's challenge.
func registerFor(t *testing.T, origin string, c localsetup.Challenge) *localsetup.Passkey {
	t.Helper()
	rp, err := passkey.Local(origin)
	require.NoError(t, err)
	auth, err := passkeytest.New(rp)
	require.NoError(t, err)
	rr, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	require.NoError(t, err)
	reg, err := auth.Register(rr, nil)
	require.NoError(t, err)
	return &localsetup.Passkey{RegistrationResponse: reg, Label: "laptop"}
}

// The install of a real database through the routes, as the page drives
// it: the listing, a check with the picks, a check with the labels, the
// passkey, and a run of exactly what that check showed. The agent gets the
// picked tables with their access and nothing else, and the label lands.
func TestRealInstallThroughTheSetupRoutes(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	if u, err := url.Parse(d.URL); err != nil || u.User == nil {
		t.Skip("the test server's admin string has no password")
	} else if _, ok := u.User.Password(); !ok {
		t.Skip("the test server's admin string has no password")
	}
	d.Exec(t, `CREATE TABLE public.orders (id bigint PRIMARY KEY, email text);
INSERT INTO public.orders SELECT g, 'buyer' || g || '@example.com' FROM generate_series(1, 20) g;
CREATE TABLE public.logs (line text);
INSERT INTO public.logs VALUES ('started');
CREATE TABLE public.vault (id bigint PRIMARY KEY, v text);
INSERT INTO public.vault VALUES (1, 'a');
ALTER TABLE public.vault ENABLE ROW LEVEL SECURITY;
CREATE TABLE public.secrets (id bigint PRIMARY KEY, v text)`)
	addr := freeAddr(t)
	origin := pageOrigin(addr)
	configPath := filepath.Join(t.TempDir(), "engine.json")
	type waited struct {
		ln  net.Listener
		err error
	}
	done := make(chan waited, 1)
	go func() {
		o := waitOptions(addr, configPath)
		o.Users, o.Prefix = agentUsers{}, d.Names.Prefix
		ln, err := engine.WaitForConfig(context.Background(), o)
		done <- waited{ln, err}
	}()
	waitUp(t, addr)
	base := "http://" + addr
	check := func(req localsetup.Request) localsetup.CheckAnswer {
		t.Helper()
		code, raw := postJSON(t, base, origin, "/api/v1/setup/check", req)
		require.Equal(t, http.StatusOK, code, string(raw))
		var a localsetup.CheckAnswer
		require.NoError(t, json.Unmarshal(raw, &a))
		return a
	}

	// 1: the listing.
	job := localsetup.Request{Job: localsetup.JobInstall, Agent: "bot", OSUser: "alice", DatabaseURL: d.URL}
	listing := check(job)
	require.Nil(t, listing.Challenge)
	require.Contains(t, listing.Tables, localsetup.ListedTable{Table: "public.orders", CanWrite: true})
	require.Contains(t, listing.Tables, localsetup.ListedTable{Table: "public.logs", CanWrite: false})
	require.Contains(t, listing.Tables, localsetup.ListedTable{Table: "public.secrets", CanWrite: true})

	// 2: the picks; secrets stays unticked.
	picked := job
	picked.Tables = []localsetup.TablePick{
		{Table: "public.orders", Access: localsetup.AccessWrite},
		{Table: "public.logs", Access: localsetup.AccessRead},
		{Table: "public.vault", Access: localsetup.AccessRead},
	}
	full := check(picked)
	require.NotNil(t, full.Challenge)
	require.Len(t, full.Questions, 1)
	require.Equal(t, "public.vault", full.Questions[0].Table)
	var email *localsetup.ColumnInfo
	for i := range full.Columns {
		if full.Columns[i].Table == "public.orders" && full.Columns[i].Column == "email" {
			email = &full.Columns[i]
		}
	}
	require.NotNil(t, email)
	require.Equal(t, "IDENTIFIER", email.SuggestedClass, "the page shows the classifier's suggestion")

	// 3: the person accepts the suggestion; the page checks again for the
	// challenge that binds the label.
	labeled := picked
	labeled.ColumnClasses = []localsetup.ColumnClass{{Table: "public.orders", Column: "email", Class: "IDENTIFIER", EntityType: "EMAIL", Was: localsetup.Label{Class: "UNCLASSIFIED"}}}
	withLabels := check(labeled)
	require.NotNil(t, withLabels.Challenge)
	require.Contains(t, withLabels.SQL, "column labels")
	answers := []localsetup.Answer{{Table: "public.vault", Choice: "ALL_ROWS"}}

	// A run of anything else than what that check showed is refused.
	for name, edit := range map[string]func(*localsetup.Request){
		"another access": func(r *localsetup.Request) {
			r.Tables = append([]localsetup.TablePick{{Table: "public.orders", Access: localsetup.AccessRead}}, r.Tables[1:]...)
		},
		"another table": func(r *localsetup.Request) {
			r.Tables = append(r.Tables, localsetup.TablePick{Table: "public.secrets", Access: localsetup.AccessRead})
		},
		"no labels": func(r *localsetup.Request) { r.ColumnClasses = nil },
		"the first check": func(r *localsetup.Request) {
			r.Challenge, r.Passkey = full.Challenge, registerFor(t, origin, *full.Challenge)
		},
		"no challenge":       func(r *localsetup.Request) { r.Challenge, r.Passkey = nil, nil },
		"another RLS answer": func(r *localsetup.Request) { r.Answers = []localsetup.Answer{{Table: "public.vault", Choice: "NONE"}} },
	} {
		run := labeled
		run.Answers = answers
		run.Challenge, run.Passkey = withLabels.Challenge, registerFor(t, origin, *withLabels.Challenge)
		edit(&run)
		code, raw := postJSON(t, base, origin, "/api/v1/setup/run", run)
		require.Equal(t, http.StatusBadRequest, code, "%s: %s", name, raw)
		require.Contains(t, string(raw), `"code":"`+localsetup.CodeChallengeInvalid+`"`, name)
	}

	// 4: the run of what was checked.
	run := labeled
	run.Answers = answers
	run.Challenge, run.Passkey = withLabels.Challenge, registerFor(t, origin, *withLabels.Challenge)
	code, raw := postJSON(t, base, origin, "/api/v1/setup/run", run)
	require.Equal(t, http.StatusOK, code, string(raw))
	var ran localsetup.RunAnswer
	require.NoError(t, json.Unmarshal(raw, &ran))
	require.Equal(t, "bot", ran.Agent)
	require.Len(t, ran.Passkeys, 1)
	require.Equal(t, "basalt mcp --agent bot", ran.MCPCommand)

	var w waited
	select {
	case w = <-done:
		require.NoError(t, w.err)
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not see the config the setup wrote")
	}
	require.NoError(t, w.ln.Close())
	cfg, err := config.Load(configPath)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	require.Equal(t, "bot", cfg.Agents[0].Name)

	ctx := context.Background()
	dsn, err := config.ReadCredential(filepath.Join(filepath.Dir(configPath), "agents", "bot.url"))
	require.NoError(t, err)
	conn, err := pgdial.Connect(ctx, dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	for _, table := range []string{"public.orders", "public.logs", "public.vault"} {
		var n int
		require.NoError(t, conn.QueryRow(ctx, fmt.Sprintf(`SELECT count(*)::int FROM %s`, table)).Scan(&n), table)
		require.Positive(t, n, "%s: the agent sees every row (ALL_ROWS)", table)
	}
	_, err = conn.Exec(ctx, `SELECT 1 FROM public.secrets`)
	require.Error(t, err, "an unticked table is never granted")
	var canWrite bool
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege($1, 'public.logs', 'INSERT')`, d.Names.Prefix+"_agent_bot").Scan(&canWrite))
	require.False(t, canWrite, "a READ table is read only")
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege($1, 'public.orders', 'UPDATE')`, d.Names.Prefix+"_agent_bot").Scan(&canWrite))
	require.True(t, canWrite, "a WRITE table can be changed")
	var class, entity string
	require.NoError(t, d.Admin.QueryRow(ctx, `SELECT class::text, coalesce(entity_type::text, '') FROM basalt_meta.pii_columns
		WHERE table_schema = 'public' AND table_name = 'orders' AND column_name = 'email'`).Scan(&class, &entity))
	require.Equal(t, [2]string{"IDENTIFIER", "EMAIL"}, [2]string{class, entity})
}
