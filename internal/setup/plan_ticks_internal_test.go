package setup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// A setup whose tables are ticked is never planned without its ticks,
// whatever its kind: plan refuses before it reads the database, so it
// never grants every listed table.
func TestPlanRefusesATickedSetupWithoutTicks(t *testing.T) {
	t.Parallel()
	allTables := &setupcode.Agent{Name: "bot", AllTables: &setupcode.AllTables{Schemas: []string{"public"}}}
	keepsGrants := &setupcode.Agent{Name: "bot", Write: []string{}, Read: []string{}}
	for name, s := range map[string]*Setup{
		"an INSTALL code with allTables":                     {P: setupcode.Payload{Kind: setupcode.KindInstall, Agent: allTables}},
		"an AGENT code that runs as an INSTALL":              {P: setupcode.Payload{Kind: setupcode.KindAgent, Agent: allTables}, asInstall: true},
		"an AGENT code for a role with no grants":            {P: setupcode.Payload{Kind: setupcode.KindAgent, Agent: keepsGrants}, noGrants: true},
		"an AGENT code that keeps grants, run as an INSTALL": {P: setupcode.Payload{Kind: setupcode.KindAgent, Agent: keepsGrants}, asInstall: true},
	} {
		require.True(t, s.Ticked(), name)
		_, err := (&Prepared{Setup: s}).plan(context.Background(), nil)
		require.ErrorIs(t, err, errPlannedUnticked, name)
	}
}
