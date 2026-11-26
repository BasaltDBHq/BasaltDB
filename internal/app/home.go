package app

import (
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The home page's data (CONTRACT.md, Local pages, The home page). The page
// has no login, so everything here becomes a count, an enum or a check-up
// link before it leaves: never a name, a host, an error text or a label.

// homeDB is what the home page knows of an agent's database.
type homeDB struct {
	// key tells databases apart; it is never sent.
	key string
	// provider is the kind: a pageserver.Provider* value.
	provider string
}

// homeDBOf is the database cc connects to, as the home page counts it.
func homeDBOf(cc *pgx.ConnConfig) homeDB {
	return homeDB{key: handoff.ConnectDatabaseName(cc.Host, cc.Port, cc.Database), provider: providerOf(cc.Host)}
}

// providerOf is the kind of database host is: the built-in trust profile
// that applies to it names Supabase and Amazon RDS; any other host, and a
// host an operator's profile covers, is Postgres.
func providerOf(host string) string {
	p := pgdial.Trust().For(host)
	if p == nil || p.Origin != trustprofile.BuiltIn {
		return pageserver.ProviderPostgres
	}
	switch p.Name {
	case "supabase":
		return pageserver.ProviderSupabase
	case "aws-rds":
		return pageserver.ProviderAmazonRDS
	}
	return pageserver.ProviderPostgres
}

// homeAgent is one served agent as the home page counts it.
type homeAgent struct {
	// svc is nil for a connect-only agent that waits for its database.
	svc *Service
	db  homeDB
	// link is the setup page's UPDATE link for the agent; empty when this
	// engine does not serve the check-up.
	link string
}

// newHomeSource is the home page's source for agents.
func newHomeSource(agents []homeAgent) pageserver.HomeSource {
	out := make([]pageserver.HomeAgent, 0, len(agents))
	for _, a := range agents {
		h := pageserver.HomeAgent{DBKey: a.db.key, Provider: a.db.provider, Link: a.link}
		if a.svc != nil {
			h.Health = a.svc.status.HomeHealth
		}
		out = append(out, h)
	}
	return pageserver.NewAgentsHome(out)
}
