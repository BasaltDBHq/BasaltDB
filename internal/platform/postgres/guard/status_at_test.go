package guard_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
)

// StatusAt judges a guard by its newest version with the same rules as
// AgentStatus: breaking and non-breaking gaps, newer, missing.
func TestStatusAt(t *testing.T) {
	t.Parallel()
	migs := []guardmodel.Migration{
		{Version: 1, Breaking: true},
		{Version: 2, Breaking: false},
		{Version: 3, Breaking: true},
		{Version: 4, Breaking: false},
	}
	tests := []struct {
		name          string
		installed     int
		state         string
		breaking      []int
		nonBreaking   []int
		wantInstalled int
	}{
		{"none", 0, guardmodel.GuardMissing, nil, nil, 0},
		{"one behind, breaking", 2, guardmodel.GuardOutdated, []int{3}, []int{4}, 2},
		{"one behind, non-breaking", 3, guardmodel.GuardUpgradeAvailable, nil, []int{4}, 3},
		{"current", 4, guardmodel.GuardOK, nil, nil, 4},
		{"newer", 5, guardmodel.GuardNewer, nil, nil, 5},
		{"huge", 1 << 30, guardmodel.GuardNewer, nil, nil, 1 << 30},
		{"negative", -3, guardmodel.GuardOutdated, []int{1, 3}, []int{2, 4}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			st := guard.StatusAt(tt.installed, migs)
			require.Equal(t, tt.state, st.State)
			require.Equal(t, tt.breaking, st.MissingBreaking)
			require.Equal(t, tt.nonBreaking, st.MissingNonBreaking)
			require.Equal(t, tt.wantInstalled, st.Installed)
			require.Equal(t, 4, st.Build)
		})
	}
}
