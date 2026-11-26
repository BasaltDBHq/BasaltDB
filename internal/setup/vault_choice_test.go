package setup_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

func TestChooseVault(t *testing.T) {
	t.Parallel()
	const personWhy = "default for --operated-by=person; --vault=on to turn it on"
	const agentWhy = "default for --operated-by=agent; --vault=off to turn it off"
	for _, tc := range []struct {
		name       string
		given      setup.VaultMode
		operatedBy setup.OperatedBy
		pages      string
		want       setup.VaultChoice
	}{
		{"agent default", "", setup.OperatedByAgent, links.Portal, setup.VaultChoice{Given: "", Def: setup.VaultModeOn, Why: agentWhy}},
		{"person default", "", setup.OperatedByPerson, links.Portal, setup.VaultChoice{Given: "", Def: setup.VaultModeOff, Why: personWhy}},
		{"person on the portal", setup.VaultModeOn, setup.OperatedByPerson, links.Portal, setup.VaultChoice{Given: setup.VaultModeOn, Def: setup.VaultModeOff, Why: personWhy}},
		{"agent turns it off", setup.VaultModeOff, setup.OperatedByAgent, links.Portal, setup.VaultChoice{Given: setup.VaultModeOff, Def: setup.VaultModeOn, Why: agentWhy}},
		{"off with local pages", setup.VaultModeOff, setup.OperatedByPerson, links.DefaultLocal, setup.VaultChoice{Given: setup.VaultModeOff, Def: setup.VaultModeOff, Why: personWhy}},
	} {
		got, err := setup.ChooseVault(tc.given, tc.operatedBy, tc.pages, personWhy)
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, got, tc.name)
	}

	byAgent := setup.VaultChoice{Given: "", Def: setup.VaultModeOn, Why: agentWhy}
	require.Equal(t, "basalt: vault: on (default for --operated-by=agent; --vault=off to turn it off)\n",
		byAgent.Line(config.VaultWritten{Vault: config.VaultOn}), "the contract's line")
	require.Equal(t, "basalt: vault: off (kept from engine.json; --vault=on to change)\n",
		byAgent.Line(config.VaultWritten{Vault: config.VaultOff, Kept: true}))
	require.Equal(t, "basalt: vault: off (--vault=off)\n",
		setup.VaultChoice{Given: setup.VaultModeOff, Def: setup.VaultModeOn, Why: agentWhy}.Line(config.VaultWritten{Vault: config.VaultOff}))

	for _, pages := range []string{links.DefaultLocal, "http://localhost:7777"} {
		_, err := setup.ChooseVault(setup.VaultModeOn, setup.OperatedByPerson, pages, personWhy)
		require.ErrorIs(t, err, setup.ErrUsage, "--vault=on needs the portal's pages, not %s", pages)
	}
}
