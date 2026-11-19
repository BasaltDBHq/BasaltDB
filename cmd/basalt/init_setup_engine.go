package main

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// pinAddURL is the portal page where each device pins the engine
// (CONTRACT.md, Direct transport).
const pinAddURL = "https://portal.basaltvault.app/engines/add"

// engineSummary prints the engine lines of the summary (step 5) and asks,
// for each other engine at the address given, whether to revoke it. It
// returns the engine ids the person chose to revoke. With --yes or
// --dry-run none is revoked, and init says so.
func (l *laptopSetup) engineSummary(checked setup.Checked) ([]string, error) {
	c := l.c
	for _, line := range checked.EngineLines {
		fprintSafef(c.stdout, "%s\n", line)
	}
	var revoke []string
	for _, q := range checked.Questions.Revoke {
		if l.f.yes || l.f.dryRun {
			fmt.Fprintf(c.stderr, "basalt: %s Not revoked (--yes or --dry-run); basalt engine revoke %s revokes it.\n", q.Text, q.EngineID)
			continue
		}
		ok, err := c.confirm(q.Text)
		if err != nil {
			return nil, err
		}
		if ok {
			revoke = append(revoke, q.EngineID)
		}
	}
	return revoke, nil
}
