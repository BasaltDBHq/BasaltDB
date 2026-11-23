package agent

import (
	"context"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

// rlsWarnings is the RLS_HIDES_ROWS warning for each of tables that row-level
// security hides from the agent, when the statement returned or changed no
// row: an empty result there says nothing about the data. A check that fails
// is logged and gives no warning: the call itself worked.
func (wc *Service) rlsWarnings(ctx context.Context, tables []string, rows int) []toolresult.Warning {
	if rows > 0 {
		return nil
	}
	var out []toolresult.Warning
	for _, table := range tables {
		name, err := wc.write.RLS.Hides(ctx, table)
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
	b := guidance.NewSteps().AskPerson("Tell the person row-level security hides every row of this table from you, and ask whether you may see its rows.")
	b.AgentRunCommand(wc.core.Commands.Init(), "On the person's yes, run this and show them the link it prints, where they answer the row-level security question.")
	if !wc.core.Commands.AgentOperated() {
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
