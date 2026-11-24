package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
)

const homeOrigin = "http://localhost:8787"

// homeService is an agent's service whose guard is at state and which has n
// passkeys on the local pages.
func homeService(t *testing.T, state string, n int) *Service {
	t.Helper()
	d := deps()
	d.Status.Probe = &fakeProbe{st: guardAt(state, nil, nil)}
	setApprovals(&d, keys{n: n})
	return NewService(d)
}

func homeConn(host, database string) *pgx.ConnConfig {
	cc := &pgx.ConnConfig{}
	cc.Host, cc.Port, cc.Database, cc.User = host, 5432, database, "basalt_agent_x"
	return cc
}

// homeGet is the answer of the pages to GET path, with a home source of
// agents.
func homeGet(t *testing.T, agents []homeAgent, path string) (int, string) {
	t.Helper()
	srv := newPages(homeOrigin, slog.New(slog.DiscardHandler))
	if agents != nil {
		srv.SetHome(newHomeSource(agents, slog.New(slog.DiscardHandler)))
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, homeOrigin+path, nil))
	return w.Code, w.Body.String()
}

func homeAnswer(t *testing.T, agents []homeAgent) pageserver.Home {
	t.Helper()
	code, body := homeGet(t, agents, pageserver.HomeDataPath)
	require.Equal(t, http.StatusOK, code, body)
	var h pageserver.Home
	require.NoError(t, json.Unmarshal([]byte(body), &h), body)
	return h
}

func TestHomeCountsOneAgentOnSupabase(t *testing.T) {
	h := homeAnswer(t, []homeAgent{{svc: homeService(t, guardmodel.GuardOK, 1), db: homeDBOf(homeConn("db.abcdefghijklmnop.supabase.co", "postgres"))}})
	require.Equal(t, pageserver.HomeRunning, h.State)
	require.Equal(t, 1, h.Agents)
	require.Equal(t, 1, h.Databases)
	require.Equal(t, []string{pageserver.ProviderSupabase}, h.Providers)
	require.Equal(t, pageserver.HomeGuardCurrent, h.Guard)
	require.NotNil(t, h.Passkeys)
	require.Equal(t, 1, *h.Passkeys)
}

func TestHomeCountsTwoAgentsOnTwoDatabases(t *testing.T) {
	rds := homeDBOf(homeConn("main.abc123.eu-west-1.rds.amazonaws.com", "app"))
	own := homeDBOf(homeConn("pg.internal.example", "app"))
	h := homeAnswer(t, []homeAgent{
		{svc: homeService(t, guardmodel.GuardOK, 2), db: rds},
		{svc: homeService(t, guardmodel.GuardOutdated, 1), db: own},
	})
	require.Equal(t, 2, h.Agents)
	require.Equal(t, 2, h.Databases)
	require.Equal(t, []string{pageserver.ProviderAmazonRDS, pageserver.ProviderPostgres}, h.Providers)
	require.Equal(t, pageserver.HomeGuardNeedsUpdate, h.Guard, "one database needs an update")
	require.Equal(t, 1, *h.Passkeys, "the database with the fewest devices")
}

func TestHomeCountsTwoAgentsOnOneDatabaseOnce(t *testing.T) {
	db := homeDBOf(homeConn("pg.internal.example", "app"))
	h := homeAnswer(t, []homeAgent{{svc: homeService(t, guardmodel.GuardOK, 1), db: db, link: "a"}, {svc: homeService(t, guardmodel.GuardOK, 1), db: db, link: "b"}})
	require.Equal(t, 2, h.Agents)
	require.Equal(t, 1, h.Databases)
	require.Equal(t, []pageserver.HomeCheck{{Provider: pageserver.ProviderPostgres, Href: "a"}}, h.Checks, "one button per database")
}

func TestHomeAnAgentWaitingForItsDatabaseCountsAsAnAgentOnly(t *testing.T) {
	h := homeAnswer(t, []homeAgent{{}})
	require.Equal(t, 1, h.Agents)
	require.Equal(t, 0, h.Databases)
	require.Equal(t, pageserver.HomeUnknown, h.Guard)
	require.Nil(t, h.Passkeys)
}

type brokenPasskeys struct{ keys }

func (brokenPasskeys) Passkeys(context.Context) ([]passkey.Credential, error) {
	return nil, errors.New("password authentication failed for user basalt_agent_x at db.secret-host.example")
}

func TestHomeRowsThatCannotBeReadAreUnknownAndSayNothingOfWhy(t *testing.T) {
	d := deps()
	d.Status.Probe = &fakeProbe{err: errors.New("could not connect to db.secret-host.example")}
	setApprovals(&d, brokenPasskeys{})
	code, body := homeGet(t, []homeAgent{{svc: NewService(d), db: homeDBOf(homeConn("pg.internal.example", "app"))}}, pageserver.HomeDataPath)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, body, `"guard":"UNKNOWN"`)
	require.Contains(t, body, `"passkeys":null`)
	require.NotContains(t, body, "secret-host")
	require.NotContains(t, body, "basalt_agent_x")
}

func TestHomeAnEngineNotServingYetIsStarting(t *testing.T) {
	code, body := homeGet(t, nil, pageserver.HomeDataPath)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, body, `"state":"STARTING"`)
	code, _ = homeGet(t, nil, "/")
	require.Equal(t, http.StatusOK, code)
}

func TestHomeProviderIsTheKindOnly(t *testing.T) {
	require.Equal(t, pageserver.ProviderSupabase, providerOf("aws-0-eu-west-1.pooler.supabase.com"))
	require.Equal(t, pageserver.ProviderSupabase, providerOf("db.abcdefghijklmnop.supabase.co"))
	require.Equal(t, pageserver.ProviderAmazonRDS, providerOf("x.cluster-abc.us-east-1.rds.amazonaws.com"))
	require.Equal(t, pageserver.ProviderPostgres, providerOf("localhost"))
	require.Equal(t, pageserver.ProviderPostgres, providerOf("/var/run/postgresql"))
}

func TestHomeCheckLinkNeedsTheEngineToServeTheCheckUp(t *testing.T) {
	a := config.Agent{Name: "orders_bot", OSUser: "deploy"}
	require.Empty(t, agentEnv{}.checkLink(a))
	link := agentEnv{setupOrigin: homeOrigin}.checkLink(a)
	require.True(t, strings.HasPrefix(link, homeOrigin+"/setup/#1."), link)
}

// The distinctive names of a setup the home page must never show.
var homeSecrets = []string{
	"zebra_ledger_bot", "quokka_os_user", "db.kumquat-host.supabase.co", "kumquat-host", "walrus_database",
	"narwhal_schema", "pangolin_table", "basalt_agent_zebra", "ocelot-profile", "axolotl passkey",
}

var hrefAttr = regexp.MustCompile(`href="(http://localhost:8787/setup/#1\.[^"]*)"`)

// TestHomeNeverNamesAnAgentOrADatabase: the page and the route it calls are
// readable by every program on the computer. Built through the real
// assembly, with names that cannot occur by chance, the only place an agent
// name may appear is the fragment of a check-up link.
func TestHomeNeverNamesAnAgentOrADatabase(t *testing.T) {
	cc := homeConn("db.kumquat-host.supabase.co", "walrus_database")
	cc.User = "basalt_agent_zebra"
	env := agentEnv{setupOrigin: homeOrigin}
	a := config.Agent{Name: "zebra_ledger_bot", OSUser: "quokka_os_user", Store: config.PostgresStore("/etc/basalt/narwhal_schema.pangolin_table.url")}
	d := deps()
	d.Core.Name = a.Name
	d.Status.Probe = &fakeProbe{st: guardAt(guardmodel.GuardOK, nil, nil)}
	setApprovals(&d, keys{n: 1})
	agents := []homeAgent{{svc: NewService(d), db: homeDBOf(cc), link: env.checkLink(a)}}

	for _, path := range []string{"/", pageserver.HomeDataPath} {
		code, body := homeGet(t, agents, path)
		require.Equal(t, http.StatusOK, code, path)
		require.NotEmpty(t, body)
		stripped := body
		if path == pageserver.HomeDataPath {
			var h pageserver.Home
			require.NoError(t, json.Unmarshal([]byte(body), &h))
			require.Len(t, h.Checks, 1)
			stripped = strings.ReplaceAll(body, h.Checks[0].Href, "")
			checkFragmentHoldsOnlyTheLink(t, h.Checks[0].Href)
		}
		for _, secret := range homeSecrets {
			require.NotContains(t, stripped, secret, "%s names %q", path, secret)
		}
	}
	// The page itself is a file: it carries no data at all.
	_, page := homeGet(t, agents, "/")
	require.Empty(t, hrefAttr.FindAllString(page, -1))
}

// checkFragmentHoldsOnlyTheLink decodes the link's fragment: the job, the
// agent and its OS user, nothing else of the setup.
func checkFragmentHoldsOnlyTheLink(t *testing.T, href string) {
	t.Helper()
	_, frag, ok := strings.Cut(href, "#1.")
	require.True(t, ok, href)
	raw, err := base64.RawURLEncoding.DecodeString(frag)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Equal(t, map[string]any{"job": "UPDATE", "agent": "zebra_ledger_bot", "osUser": "quokka_os_user", "demo": false}, fields)
	for _, secret := range []string{"kumquat", "walrus", "narwhal", "pangolin", "basalt_agent_zebra", "ocelot", "axolotl"} {
		require.NotContains(t, string(raw), secret)
	}
}
