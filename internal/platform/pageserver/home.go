package pageserver

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/web"
)

// The home page at the root of the local pages (CONTRACT.md, Local pages,
// The home page): it answers "is BasaltDB working?" with counts and health.
// It has no login, so it and the route it reads carry counts, enum states
// and the check-up links only: no database host or name, no schema, no
// table and no run or approval data. An agent's name appears only inside a
// check-up link's fragment.
const (
	HomePath     = "/{$}"
	HomeDataPath = "/api/v1/home"
	homePageFile = "home/index.html"
)

// Home states (Home.State).
const (
	// HomeNotSetUp: the engine has no config yet.
	HomeNotSetUp = "NOT_SET_UP"
	// HomeStarting: it has one and is not serving its agents yet.
	HomeStarting = "STARTING"
	// HomeRunning: it serves its agents.
	HomeRunning = "RUNNING"
)

// Home guard states (Home.Guard).
const (
	HomeGuardCurrent     = "CURRENT"
	HomeGuardNeedsUpdate = "NEEDS_UPDATE"
	// HomeUnknown is a row that could not be read.
	HomeUnknown = "UNKNOWN"
)

// HomeGuardOf is the guard's state in the home page's words: anything a
// database update would change needs one, and a guard that could not be read
// (nil) is UNKNOWN.
func HomeGuardOf(st *guardmodel.Status) string {
	if st == nil {
		return HomeUnknown
	}
	switch st.State {
	case guardmodel.GuardOK, guardmodel.GuardNewer:
		return HomeGuardCurrent
	case guardmodel.GuardUpgradeAvailable, guardmodel.GuardOutdated, guardmodel.GuardMissing:
		return HomeGuardNeedsUpdate
	}
	return HomeUnknown
}

// Database kinds (Home.Providers, HomeCheck.Provider): the kind only.
const (
	ProviderSupabase  = "SUPABASE"
	ProviderAmazonRDS = "AMAZON_RDS"
	ProviderPostgres  = "POSTGRES"
)

// Home is what GET /api/v1/home answers. Every field is a count, an enum or
// a link, so nothing a database or an agent called itself can reach it.
type Home struct {
	State   string `json:"state"`
	Version string `json:"version"`
	Agents  int    `json:"agents"`
	// Databases counts the distinct databases the agents use.
	Databases int `json:"databases"`
	// Providers are the kinds of those databases, each once, sorted.
	Providers []string `json:"providers"`
	Guard     string   `json:"guard"`
	// Passkeys is how many devices can approve; nil when it cannot be read.
	Passkeys *int `json:"passkeys"`
	// Checks has one check-up link per database, when this engine serves the
	// check-up.
	Checks []HomeCheck `json:"checks"`
}

// HomeCheck is the check-up button of one database. Href is the setup
// page's UPDATE link of one of its agents; the link is not a secret.
type HomeCheck struct {
	Provider string `json:"provider"`
	Href     string `json:"href"`
}

// HomeSource reads the home page's data.
type HomeSource interface {
	Home(ctx context.Context) Home
}

// NotSetUpHome is the source of an engine with no config.
type NotSetUpHome struct{}

// Home implements HomeSource.
func (NotSetUpHome) Home(context.Context) Home {
	return emptyHome(HomeNotSetUp)
}

func emptyHome(state string) Home {
	return Home{State: state, Version: buildinfo.Version, Guard: HomeUnknown, Providers: []string{}, Checks: []HomeCheck{}}
}

// HomePage serves the home page file.
func HomePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, web.Files, homePageFile)
}

// HomeData serves src's answer as JSON.
func HomeData(src HomeSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := src.Home(r.Context())
		if h.Providers == nil {
			h.Providers = []string{}
		}
		if h.Checks == nil {
			h.Checks = []HomeCheck{}
		}
		WriteJSON(w, http.StatusOK, h)
	}
}

// SetHome sets where the home page reads its data, once the agents serve.
// Until then it says the engine is starting.
func (s *Server) SetHome(src HomeSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home = src
}

// Home implements HomeSource for the server's own routes.
func (s *Server) Home(ctx context.Context) Home {
	s.mu.RLock()
	src := s.home
	s.mu.RUnlock()
	if src == nil {
		return emptyHome(HomeStarting)
	}
	return src.Home(ctx)
}

// HomeAgent is one served agent as the home page counts it.
type HomeAgent struct {
	// DBKey tells databases apart; it is never sent. Empty for an agent
	// that waits for its database.
	DBKey string
	// Provider is the database's kind: a Provider* value.
	Provider string
	// Link is the setup page's UPDATE link for the agent; empty when the
	// engine does not serve the check-up.
	Link string
	// Health reads the agent's guard (nil when it could not be read) and
	// how many passkeys can sign on the pages (nil likewise); nil for an
	// agent that waits for its database.
	Health func(ctx context.Context) (guard *guardmodel.Status, passkeys *int)
}

const (
	// homeReadTimeout bounds the reads one answer makes of the databases.
	homeReadTimeout = 3 * time.Second
	// homeTTL is how long an answer is kept, so a page that reloads does not
	// read each agent's database every time.
	homeTTL = 5 * time.Second
)

// AgentsHome answers the home page for the engine's agents, keeping each
// answer for a short time.
type AgentsHome struct {
	agents []HomeAgent
	now    func() time.Time

	mu   sync.Mutex
	at   time.Time
	last Home
}

// NewAgentsHome is the home page's source for agents.
func NewAgentsHome(agents []HomeAgent) *AgentsHome {
	return &AgentsHome{agents: agents, now: time.Now}
}

// Home implements HomeSource.
func (h *AgentsHome) Home(ctx context.Context) Home {
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

func (h *AgentsHome) read(ctx context.Context) Home {
	out := Home{
		State: HomeRunning, Version: buildinfo.Version, Agents: len(h.agents),
		Guard: HomeUnknown, Providers: []string{}, Checks: []HomeCheck{},
	}
	seen := map[string]bool{}
	guards, passkeys := []string{}, []*int{}
	for _, a := range h.agents {
		if a.DBKey != "" && !seen[a.DBKey] {
			seen[a.DBKey] = true
			out.Databases++
			if !slices.Contains(out.Providers, a.Provider) {
				out.Providers = append(out.Providers, a.Provider)
			}
			if a.Link != "" {
				out.Checks = append(out.Checks, HomeCheck{Provider: a.Provider, Href: a.Link})
			}
		}
		if a.Health != nil {
			g, p := a.Health(ctx)
			guards, passkeys = append(guards, HomeGuardOf(g)), append(passkeys, p)
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
	case slices.Contains(guards, HomeGuardNeedsUpdate):
		return HomeGuardNeedsUpdate
	case len(guards) == 0 || slices.Contains(guards, HomeUnknown):
		return HomeUnknown
	}
	return HomeGuardCurrent
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
