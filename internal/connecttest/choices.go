package connecttest

import (
	"regexp"
	"slices"
	"strings"

	"connectrpc.com/connect"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// The page's choices on RunSetup (CONTRACT.md, Connect, Tables on the
// connect page and Column labels on the connect page): includedTables,
// columnClasses and restPublic. The setup package does not take them yet,
// so the fake, like the hosted service until it does, enforces their shape
// and refuses any choice it cannot apply instead of dropping it: a table
// left out, a label, restPublic. A run with every table ticked and no label
// is the one it runs, and it is the same database as the laptop command's.

// tableEntry is a plain lowercase schema.table.
var tableEntry = regexp.MustCompile(`^[a-z_][a-z0-9_$]*\.[a-z_][a-z0-9_$]*$`)

func answersInvalid(message string) error {
	return refusal(connect.CodeInvalidArgument, "ANSWERS_INVALID", message)
}

// choices checks the page's choices against the code and the listing
// Check read, before the setup runs.
func choices(d setup.Description, checked setup.Checked, m *connectv1.RunSetupRequest) error {
	if len(m.GetColumnClasses()) > 0 || m.GetRestPublic() {
		return answersInvalid("This service cannot write column labels yet.")
	}
	included := m.GetIncludedTables()
	ticks := d.Kind == setup.KindInstall && len(d.AllTablesSchemas) > 0 && checked.NothingToDo == nil
	if !ticks {
		if len(included) > 0 {
			return answersInvalid("This setup takes no list of tables.")
		}
		return nil
	}
	if len(included) == 0 {
		return refusal(connect.CodeFailedPrecondition, setup.CodeNoTables, "There is no table to give "+d.Agent+". Nothing changed.")
	}
	seen := map[string]bool{}
	for _, t := range included {
		schema, _, _ := strings.Cut(t, ".")
		if !tableEntry.MatchString(t) || seen[t] || !slices.Contains(d.AllTablesSchemas, schema) {
			return answersInvalid("The list of tables is not valid for this setup.")
		}
		seen[t] = true
	}
	for t := range seen {
		if !slices.Contains(checked.Tables, t) {
			return refusal(connect.CodeFailedPrecondition, "TABLES_CHANGED", "The tables changed since they were listed. Nothing changed.")
		}
	}
	if len(seen) != len(checked.Tables) {
		return answersInvalid("This service cannot leave a table out yet.")
	}
	return nil
}
