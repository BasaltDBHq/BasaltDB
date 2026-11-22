package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
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
// so everything works and the setup page's update adds them. The default asks the
// service's Probe.
type UpgradeChecker interface {
	UpgradeAvailable(ctx context.Context) (bool, error)
}

// rlsWarnings is the RLS_HIDES_ROWS warning for each of tables that row-level
// security hides from the agent, when the statement returned or changed no
// row: an empty result there says nothing about the data. A check that fails
// is logged and gives no warning: the call itself worked.
func (s *Service) rlsWarnings(ctx context.Context, tables []string, rows int) []toolresult.Warning {
	if rows > 0 {
		return nil
	}
	var out []toolresult.Warning
	for _, table := range tables {
		name, err := s.deps.Write.RLS.Hides(ctx, table)
		if err != nil {
			s.deps.Core.Log.Error("check row-level security", "table", table, "err", err)
			continue
		}
		if name == "" {
			continue
		}
		w, err := s.rlsWarning(name)
		if err != nil {
			s.deps.Core.Log.Error("cannot build the row-level security warning", "table", table, "err", err)
			continue
		}
		out = append(out, w)
	}
	return out
}

func (s *Service) rlsWarning(dbName string) (toolresult.Warning, error) {
	table := shown(dbName, maxTableChars)
	b := NewSteps().AskPerson("Tell the person row-level security hides every row of this table from you, and ask whether you may see its rows.")
	b.AgentRunCommand(s.deps.Core.Commands.Init(), "On the person's yes, run this and show them the link it prints, where they answer the row-level security question.")
	if !s.deps.Core.Commands.AgentOperated() {
		b.TellAgent("Tell the agent once it is done.")
	}
	person := fmt.Sprintf("Row-level security hides every row of %s from the agent, so it sees no rows there. To let it see them, "+
		"tell the agent: it gives you a link where you answer the row-level security question for that table. "+
		"Leave it as it is if the agent should not see that table.", table)
	steps, err := b.Build()
	if err != nil {
		return toolresult.Warning{}, err
	}
	return toolresult.Warning{
		Code:  toolresult.WarningRLSHidesRows,
		Table: dbName,
		Message: fmt.Sprintf("row-level security hides every row of %s from this agent, so an empty result says nothing about its data; "+
			"do not conclude the table is empty", table),
		PersonMessage: person,
		NextSteps:     steps,
	}, nil
}

// upgradeWarnings is the GUARD_UPGRADE_AVAILABLE warning of run_start, when
// only non-breaking guard migrations are missing.
func (s *Service) upgradeWarnings(ctx context.Context) []toolresult.Warning {
	available, err := s.deps.Status.Upgrade.UpgradeAvailable(ctx)
	if err != nil {
		s.deps.Core.Log.Error("check for a guard upgrade", "err", err)
		return nil
	}
	if !available {
		return nil
	}
	b := NewSteps()
	person := upgradeSteps(b, s.deps.Core.Commands)
	steps, err := b.Build()
	if err != nil {
		s.deps.Core.Log.Error("cannot build the guard upgrade warning", "err", err)
		return nil
	}
	return []toolresult.Warning{{
		Code:          toolresult.WarningGuardUpgradeAvailable,
		Message:       "the guard in this database misses non-breaking migrations; everything works, the person can upgrade when it suits them",
		PersonMessage: person,
		NextSteps:     steps,
	}}
}

// upgradeSteps: the person adds the missing non-breaking migrations when it
// suits them, in a warning and in status, on the page basalt init links to.
func upgradeSteps(b *Steps, cmds Commands) string {
	b.AskPerson("Tell the person the guard can be updated when it suits them, and ask whether to do it now.")
	if cmds.UpdateLinkURL() != "" && !cmds.AgentOperated() {
		b.OpenLink(cmds.UpdateLinkURL(), "On the person's yes, show them this link: nothing stops, and the agent needs no restart.")
		return "The guard in this database can be updated. Everything works as it is; when it suits you, open the link the agent gives you to update it."
	}
	b.AgentRunCommand(cmds.Init(), "On the person's yes, run this and show them the link it prints: nothing stops, and the agent needs no restart.")
	return "The guard in this database can be updated. Everything works as it is; when it suits you, tell the agent: it gives you a link to update it."
}
