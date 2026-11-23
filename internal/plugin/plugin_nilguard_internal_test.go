package plugin

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// An agent with no database connection (the zero AgentLedger: no handle, no
// guard) is served status only: every served entry is withheld as
// unreachable, nothing is decided (not transient), and no guard is touched.
func TestAgentWithNoConnectionIsUnreachableNotTransient(t *testing.T) {
	t.Parallel()
	a := pluginmodel.EntryKey{Name: "a", Instance: "one"}
	b := pluginmodel.EntryKey{Name: "b", Instance: "one"}
	want := pluginWant{served: map[string]map[pluginmodel.EntryKey]guardmodel.PluginDetail{
		"product_a": {a: {}, b: {}},
	}}
	pass := writeAgentPluginEvents(context.Background(), "product_a", want, AgentLedger{}, slog.New(slog.DiscardHandler))
	require.Len(t, pass.withheld, 2)
	for _, e := range pass.withheld {
		require.Equal(t, whyUnreachable, e.why, e.key.String())
		require.False(t, e.transient, e.key.String())
	}
}

// Every helper that reads a database error through the guard answers as it
// did before the guard was asked: with no guard, and with no error.
func TestErrorHelpersNeedNoGuardForNoError(t *testing.T) {
	t.Parallel()
	other := errors.New("the connection broke")

	require.Equal(t, whyUnreachable, unrecordedWhy(nil, nil))
	require.Equal(t, whyUnreachable, unrecordedWhy(nil, other))
	require.Equal(t, whyNotAdmitted, unrecordedWhy(nil, ErrNotAdmitted))

	require.False(t, transientErr(nil, nil))
	require.False(t, transientErr(nil, ErrNotAdmitted))
	require.False(t, transientErr(nil, other))

	require.Equal(t, "UNREADABLE", *dbFailure(nil, nil))
	require.Equal(t, "UNREADABLE", *dbFailure(nil, other))

	err := unreachable(nil, "product_a", other)
	require.ErrorContains(t, err, "it does not answer")

	r := keptOpenRefusal(nil, other, 7)
	require.Equal(t, reasonDatabaseUnreachable, r.Reason)
	require.Equal(t, "the database does not answer", r.Message)
}
