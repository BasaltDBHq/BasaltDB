package agent

import (
	"context"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// rlsWarnings is the RLS_HIDES_ROWS warning for each of tables that the
// store's Visibility (row-level security) hides from the agent, whatever
// the row count: an empty result, a count of 0 and a write that changed
// nothing all say nothing about the data. Visibility answers once per table
// (BlindCache), so a call pays at most one catalog check per table, and none
// for a table already checked. A check that fails is logged and gives no warning: the
// call itself worked. A store without Visibility hides nothing.
func (wc *Service) rlsWarnings(ctx context.Context, tables []string) []toolresult.Warning {
	if wc.store.Visibility == nil {
		return nil
	}
	var out []toolresult.Warning
	for _, table := range tables {
		name, err := wc.store.Visibility.Hides(ctx, table)
		if err != nil {
			wc.core.Log.Error("check row-level security", "table", table, "err", err)
			continue
		}
		if name == "" {
			continue
		}
		w, err := wc.rlsWarning(name)
		if err != nil {
			wc.core.Log.Error("cannot build the row-level security warning", "table", table, "err", err)
			continue
		}
		out = append(out, w)
	}
	return out
}

func (wc *Service) rlsWarning(dbName string) (toolresult.Warning, error) {
	table := guidance.Shown(dbName, guidance.MaxTableChars)
	b := guidance.NewSteps().AskPerson("Tell the person row-level security hides every row of this resource from you, and ask whether you may see its rows.")
	b.AgentRunCommand(wc.core.Commands.Init(), "On the person's yes, run this and show them the link it prints, where they answer the row-level security question.")
	if !wc.core.Commands.AgentOperated() {
		b.TellAgent("Tell the agent once it is done.")
	}
	person := fmt.Sprintf("Row-level security hides every row of %s from the agent, so it sees no rows there. To let it see them, "+
		"tell the agent: it gives you a link where you answer the row-level security question for that resource. "+
		"Leave it as it is if the agent should not see that resource.", table)
	steps, err := b.Build()
	if err != nil {
		return toolresult.Warning{}, err
	}
	return toolresult.Warning{
		Code:     toolresult.WarningRLSHidesRows,
		Resource: dbName,
		Message: fmt.Sprintf("row-level security hides every row of %s from this agent, so an empty result or a count of 0 says nothing about its data; "+
			"do not conclude the resource is empty", table),
		PersonMessage: person,
		NextSteps:     steps,
	}, nil
}

// rlsRefusedSteps are the steps for a write that row-level security refused
// (PERMISSION_DENIED): the same question as RLS_HIDES_ROWS, answered on the
// page `basalt init` links to. table is the resource the store named, or ""
// when it named none.
func (wc *Service) rlsRefusedSteps(b *guidance.Steps, table string) string {
	b.Stop("Row-level security refused this write for the agent: do not retry or look for another route.")
	b.AskPerson("Tell the person row-level security blocks you on this resource, and ask whether you may write to it.")
	b.TellAgent("Tell the agent to add the access once you decide it should have it.")
	b.EndTurn("End your turn: the person decides.")
	b.AgentRunCommand(wc.core.Commands.Init(), "On the person's yes, run this and show them the link it prints, where they answer the row-level security question.")
	what := "the resource"
	if table != "" {
		what = guidance.Shown(table, guidance.MaxTableChars)
	}
	return fmt.Sprintf("Row-level security blocks the agent from writing to %s, so the database refused its write. If it should write there, "+
		"tell the agent: it gives you a link where you answer the row-level security question for that resource. "+
		"Leave it as it is if the agent should not.", what)
}
