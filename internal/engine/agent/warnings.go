package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// maxTableChars is the most of a table's name a personMessage quotes.
const maxTableChars = 100

// RLSChecker says whether row-level security hides every row of a table
// from the agent role. It returns the table's name as the database writes it
// (quoted where needed), or "" when the table is not hidden. The engine's is
// a BlindCache; the default says no table is hidden.
type RLSChecker interface {
	Hides(ctx context.Context, table string) (string, error)
}

type noRLS struct{}

func (noRLS) Hides(context.Context, string) (string, error) { return "", nil }

// BlindCache answers RLSChecker from the database's catalog, once per table
// until Refresh: a statement that returns no rows asks, and a busy agent
// does not ask again for the same table. The upkeep cycle calls Refresh, so
// a policy added or dropped by the person shows within one cycle.
type BlindCache struct {
	// ask returns which of tables (as written in a statement) the role is
	// blind to, named as the database writes them.
	ask func(ctx context.Context, tables []string) ([]string, error)

	mu    sync.Mutex
	known map[string]string
	// generation counts refreshes: an answer asked before a refresh is not stored.
	generation int
}

// NewBlindCache returns a cache that asks through ask. It panics without one.
func NewBlindCache(ask func(ctx context.Context, tables []string) ([]string, error)) *BlindCache {
	if ask == nil {
		panic("agent: blind cache needs a query")
	}
	return &BlindCache{ask: ask, known: map[string]string{}}
}

// Hides returns the database's name for table when it is hidden from the
// agent role, else "".
func (c *BlindCache) Hides(ctx context.Context, table string) (string, error) {
	c.mu.Lock()
	name, ok := c.known[table]
	asked := c.generation
	c.mu.Unlock()
	if ok {
		return name, nil
	}
	blind, err := c.ask(ctx, []string{table})
	if err != nil {
		return "", err
	}
	name = ""
	if len(blind) > 0 {
		name = blind[0]
	}
	c.mu.Lock()
	if c.generation == asked {
		c.known[table] = name
	}
	c.mu.Unlock()
	return name, nil
}

// Refresh forgets every answer, so the next statement asks again.
func (c *BlindCache) Refresh() {
	c.mu.Lock()
	clear(c.known)
	c.generation++
	c.mu.Unlock()
}

// UpgradeChecker says whether the guard misses only non-breaking migrations,
// so everything works and basalt upgrade adds them. The default asks the
// service's Probe.
type UpgradeChecker interface {
	UpgradeAvailable(ctx context.Context) (bool, error)
}

// rlsWarnings is the RLS_HIDES_ROWS warning for each of tables that row-level
// security hides from the agent, when the statement returned or changed no
// row: an empty result there says nothing about the data. A check that fails
// is logged and gives no warning: the call itself worked.
func (s *Service) rlsWarnings(ctx context.Context, tables []string, rows int) []mcp.Warning {
	if rows > 0 {
		return nil
	}
	var out []mcp.Warning
	for _, table := range tables {
		name, err := s.RLS.Hides(ctx, table)
		if err != nil {
			s.Log.Error("check row-level security", "table", table, "err", err)
			continue
		}
		if name == "" {
			continue
		}
		w, err := s.rlsWarning(name)
		if err != nil {
			s.Log.Error("cannot build the row-level security warning", "table", table, "err", err)
			continue
		}
		out = append(out, w)
	}
	return out
}

func (s *Service) rlsWarning(dbName string) (mcp.Warning, error) {
	table := shown(dbName, maxTableChars)
	command := s.Commands.Init("--agent-rls=all-rows")
	steps, err := NewSteps().
		AskPerson("Tell the person row-level security hides every row of this table from you, and ask whether you may see its rows.").
		RunCommand(command, "To let the agent see all rows, run this: init asks for the admin connection string itself.").
		TellAgent("Tell the agent once it is done.").
		Build()
	if err != nil {
		return mcp.Warning{}, err
	}
	return mcp.Warning{
		Code:  mcp.WarningRLSHidesRows,
		Table: dbName,
		Message: fmt.Sprintf("row-level security hides every row of %s from this agent, so an empty result says nothing about its data; "+
			"do not conclude the table is empty", table),
		PersonMessage: fmt.Sprintf("Row-level security hides every row of %s from the agent, so it sees no rows there. To let it see them, "+
			"run: %s then tell the agent. Leave it as it is if the agent should not see that table.", table, command),
		NextSteps: steps,
	}, nil
}

// upgradeWarnings is the GUARD_UPGRADE_AVAILABLE warning of run_start, when
// only non-breaking guard migrations are missing.
func (s *Service) upgradeWarnings(ctx context.Context) []mcp.Warning {
	available, err := s.Upgrade.UpgradeAvailable(ctx)
	if err != nil {
		s.Log.Error("check for a guard upgrade", "err", err)
		return nil
	}
	if !available {
		return nil
	}
	b := NewSteps()
	person := upgradeSteps(b, s.Commands)
	steps, err := b.Build()
	if err != nil {
		s.Log.Error("cannot build the guard upgrade warning", "err", err)
		return nil
	}
	return []mcp.Warning{{
		Code:          mcp.WarningGuardUpgradeAvailable,
		Message:       "the guard in this database misses non-breaking migrations; everything works, the person can upgrade when it suits them",
		PersonMessage: person,
		NextSteps:     steps,
	}}
}

// upgradeSteps: the person adds the missing non-breaking migrations when it
// suits them, in a warning and in status.
func upgradeSteps(b *Steps, cmds Commands) string {
	command := cmds.Upgrade()
	b.RunCommand(command, "Run this to add the missing guard migrations: nothing stops, and the agent needs no restart.")
	return fmt.Sprintf("The guard in this database can be upgraded. Everything works as it is; when it suits you, run: %s", command)
}
