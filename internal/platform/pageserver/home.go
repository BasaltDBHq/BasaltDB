package pageserver

import (
	"context"
	"net/http"

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
