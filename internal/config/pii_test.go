package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

func TestPIIConfig(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, json string
		want       config.PII
	}{
		{name: "defaults", json: `{"socketDir": "/s", ` + linkBudgetAgent + `}`, want: config.PII{MaxMemoryMB: 512, ScanRowsPerSecond: 20000}},
		{name: "set", json: `{"socketDir": "/s", "pii": {"maxMemoryMB": 64, "scanRowsPerSecond": 500}, ` + linkBudgetAgent + `}`, want: config.PII{MaxMemoryMB: 64, ScanRowsPerSecond: 500}},
		{name: "one set", json: `{"socketDir": "/s", "pii": {"maxMemoryMB": 1024}, ` + linkBudgetAgent + `}`, want: config.PII{MaxMemoryMB: 1024, ScanRowsPerSecond: 20000}},
	} {
		c, err := config.Load(write(t, "engine.json", tc.json, 0o600))
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.want, c.PIIOrDefault(), tc.name)
	}
	require.Equal(t, int64(512)<<20, config.Config{}.PIIOrDefault().MaxMemoryBytes())

	c, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "pii": {"maxMemoryMB": 65536}, `+linkBudgetAgent+`}`, 0o600))
	require.NoError(t, err, "the largest budget")
	require.Equal(t, int64(config.MaxPIIMemoryMB)<<20, c.PIIOrDefault().MaxMemoryBytes())

	for _, bad := range []string{
		`{"maxMemoryMB": -1}`, `{"scanRowsPerSecond": -5}`, `{"unknown": 1}`,
		`{"maxMemoryMB": 65537}`,
		`{"maxMemoryMB": 9223372036854775807}`, // would overflow MaxMemoryBytes into a negative
	} {
		_, err := config.Load(write(t, "engine.json", `{"socketDir": "/s", "pii": `+bad+`, `+linkBudgetAgent+`}`, 0o600))
		require.Error(t, err, bad)
	}
}
