package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

const linkBudgetAgent = `"agents": [{"name": "a", "osUser": "u", "store": {"kind": "POSTGRES", "credentialFile": "/c"}}]`

func TestLinkBudget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, json string
		want       int
	}{
		{name: "default", json: `{"socketDir": "/s", ` + linkBudgetAgent + `}`, want: 1800},
		{name: "set", json: `{"socketDir": "/s", "linkBudget": 900, ` + linkBudgetAgent + `}`, want: 900},
		{name: "one is a positive integer", json: `{"socketDir": "/s", "linkBudget": 1, ` + linkBudgetAgent + `}`, want: 1},
	} {
		c, err := config.Load(write(t, "engine.json", tc.json, 0o600))
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, c.LinkBudgetOrDefault(), tc.name)
	}
}

func TestLoadRefusesALinkBudgetThatIsNotAPositiveInteger(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"0", "-5", "1.5", `"1800"`, "1e3", "true"} {
		_, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "linkBudget": `+value+`, `+linkBudgetAgent+`}`, 0o600))
		require.Error(t, err, "linkBudget %s", value)
		require.ErrorContains(t, err, "linkBudget", "linkBudget %s", value)
	}
}
