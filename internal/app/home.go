package app

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/pageserver"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// The home page's data (CONTRACT.md, Local pages, The home page). The page
// has no login, so everything here becomes a count, an enum or a check-up
// link before it leaves: never a name, a host, an error text or a label.

const (
	// homeReadTimeout bounds the reads one answer makes of the databases.
	homeReadTimeout = 3 * time.Second
	// homeTTL is how long an answer is kept, so a page that reloads does not
	// read each agent's database every time.
	homeTTL = 5 * time.Second
)

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

// homeSource answers the home page for the engine's agents.
type homeSource struct {
	agents []homeAgent
	log    *slog.Logger
	now    func() time.Time

	mu   sync.Mutex
	at   time.Time
	last pageserver.Home
}

func newHomeSource(agents []homeAgent, log *slog.Logger) *homeSource {
	return &homeSource{agents: agents, log: log, now: time.Now}
}

// Home implements pageserver.HomeSource.
func (h *homeSource) Home(ctx context.Context) pageserver.Home {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.at.IsZero() && h.now().Sub(h.at) < homeTTL {
		return h.last
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), homeReadTimeout)
	defer cancel()
	h.last, h.at = h.read(ctx), h.now()
	return h.last
}

func (h *homeSource) read(ctx context.Context) pageserver.Home {
	out := pageserver.Home{
		State: pageserver.HomeRunning, Version: buildinfo.Version, Agents: len(h.agents),
		Guard: pageserver.HomeUnknown, Providers: []string{}, Checks: []pageserver.HomeCheck{},
	}
	seen := map[string]bool{}
	guards, passkeys := []string{}, []*int{}
	for _, a := range h.agents {
		if a.db.key != "" && !seen[a.db.key] {
			seen[a.db.key] = true
			out.Databases++
			if !slices.Contains(out.Providers, a.db.provider) {
				out.Providers = append(out.Providers, a.db.provider)
			}
			if a.link != "" {
				out.Checks = append(out.Checks, pageserver.HomeCheck{Provider: a.db.provider, Href: a.link})
			}
		}
		if a.svc != nil {
			g, p := a.svc.status.HomeHealth(ctx)
			guards, passkeys = append(guards, pageserver.HomeGuardOf(g)), append(passkeys, p)
		}
	}
	slices.Sort(out.Providers)
	out.Guard = worstGuard(guards)
	out.Passkeys = fewestPasskeys(passkeys)
	return out
}

// worstGuard is NEEDS_UPDATE when any agent's guard needs one, else UNKNOWN
// when any could not be read (or none was asked), else CURRENT.
func worstGuard(guards []string) string {
	switch {
	case slices.Contains(guards, pageserver.HomeGuardNeedsUpdate):
		return pageserver.HomeGuardNeedsUpdate
	case len(guards) == 0 || slices.Contains(guards, pageserver.HomeUnknown):
		return pageserver.HomeUnknown
	}
	return pageserver.HomeGuardCurrent
}

// fewestPasskeys is the smallest count, the database that has the fewest
// devices that can approve; nil when none was asked or any could not be
// read.
func fewestPasskeys(counts []*int) *int {
	var least *int
	for _, c := range counts {
		if c == nil {
			return nil
		}
		if least == nil || *c < *least {
			least = c
		}
	}
	return least
}
