package ledger

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// A failed plugin read is one named problem, not a failed health check.
func TestPluginsHealthFailsOnItsOwn(t *testing.T) {
	t.Parallel()
	ps, more, problem := pluginsHealth(context.Background(), nil,
		func(context.Context, guard.Querier) (guardmodel.PluginRecords, error) {
			return guardmodel.PluginRecords{}, errors.New("relation is gone")
		})
	require.Nil(t, ps)
	require.Zero(t, more)
	require.Equal(t, "relation is gone", problem)
}

// More entries than the cap: the first MaxPluginsListed are listed and the
// rest counted.
func TestPluginsHealthCapsTheList(t *testing.T) {
	t.Parallel()
	var recs guardmodel.PluginRecords
	for i := range MaxPluginsListed + 5 {
		recs.Entries = append(recs.Entries, guardmodel.PluginRecord{
			Kind:   guardmodel.PluginEnabled,
			Detail: guardmodel.PluginDetail{Name: fmt.Sprintf("p%03d", i), Instance: "default", Endpoint: guardmodel.PluginEndpoint{Kind: guardmodel.PluginEndpointRemote}},
		})
	}
	ps, more, problem := pluginsHealth(context.Background(), nil,
		func(context.Context, guard.Querier) (guardmodel.PluginRecords, error) { return recs, nil })
	require.Empty(t, problem)
	require.Len(t, ps, MaxPluginsListed)
	require.Equal(t, 5, more)
	require.Equal(t, "p000", ps[0].Name)
}
