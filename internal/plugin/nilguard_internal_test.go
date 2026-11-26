package plugin

import (
	"context"
	"errors"
	"fmt"
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

	require.Equal(t, whyUnreachable, unrecordedWhy(nil))
	require.Equal(t, whyUnreachable, unrecordedWhy(other))
	require.Equal(t, whyNotAdmitted, unrecordedWhy(ErrNotAdmitted))

	require.False(t, transientErr(nil, nil))
	require.False(t, transientErr(nil, ErrNotAdmitted))
	require.False(t, transientErr(nil, other))

	require.Equal(t, "UNREADABLE", *dbFailure(nil, nil))
	require.Equal(t, "UNREADABLE", *dbFailure(nil, other))

	err := unreachable("product_a", other)
	require.ErrorContains(t, err, "it does not answer")

	r := keptOpenRefusal(other, 7)
	require.Equal(t, reasonDatabaseUnreachable, r.Reason)
	require.Equal(t, "the database does not answer", r.Message)
}

// The host decides on the store's typed answer alone: each reason gives the
// status, open refusal and feed class it gave when the host read the
// database's codes, and any store answer is never transient.
func TestStoreAnswersDecideByReason(t *testing.T) {
	t.Parallel()
	answer := func(r pluginmodel.StoreReason) error {
		return fmt.Errorf("record: %w", &pluginmodel.StoreError{Reason: r, Code: "C0DE1", Message: "the store's text", Err: errors.New("raw")})
	}
	whys := map[pluginmodel.StoreReason]string{
		pluginmodel.StoreGuardOutdated:  whyNoPluginEvents,
		pluginmodel.StoreGuardMissing:   whyNoGuard,
		pluginmodel.StoreRefused:        whyRefused,
		pluginmodel.StoreTooManyPending: whyRefused,
		pluginmodel.StoreUnknownAgent:   whyRefused,
		pluginmodel.StoreAnswered:       whyUnreachable,
	}
	for r, why := range whys {
		err := answer(r)
		require.Equal(t, why, unrecordedWhy(err), r)
		require.False(t, transientErr(nil, err), r)
		require.Equal(t, "STORE_CODE C0DE1", *dbFailure(nil, err), r)
		require.ErrorContains(t, unreachable("product_a", err), "it refused: the store's text", r)
	}

	opens := map[pluginmodel.StoreReason]PluginOpenRefusal{
		pluginmodel.StoreTooManyPending: {Reason: reasonTooManyPending, Message: "8 plugin approvals already wait in this database"},
		pluginmodel.StoreUnknownAgent:   {Reason: reasonUnknownAgent, Message: "a listed agent is not an agent role of this database"},
		pluginmodel.StoreGuardOutdated:  {Reason: reasonGuardOutdated, Message: "the guard is older than schema version 7"},
		pluginmodel.StoreRefused:        {Reason: reasonDatabaseUnreachable, Message: "the store's text"},
		pluginmodel.StoreGuardMissing:   {Reason: reasonDatabaseUnreachable, Message: "the store's text"},
		pluginmodel.StoreAnswered:       {Reason: reasonDatabaseUnreachable, Message: "the store's text"},
	}
	for r, want := range opens {
		require.Equal(t, want, *keptOpenRefusal(answer(r), 7), r)
	}
}
