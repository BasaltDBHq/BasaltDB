package plugin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// entryEvents is a feed snapshot that holds one entry's ledger records.
type entryEvents struct {
	guardmodel.FeedSnapshot
	events []guardmodel.PluginEntryEvent
}

func (s entryEvents) PluginEntryEvents(context.Context, string, string) ([]guardmodel.PluginEntryEvent, error) {
	return s.events, nil
}

// An entry is served from its newest PLUGIN_ENABLED after the cursor, or
// from a PLUGIN_CHANGED that adds an egress host, moves the endpoint, or
// cannot be decoded; a change that narrows does not start serving again.
func TestServedFrom(t *testing.T) {
	enabled, changed, disabled := string(guardmodel.PluginEnabled), string(guardmodel.PluginChanged), string(guardmodel.PluginDisabled)
	local := guardmodel.PluginEndpoint{Kind: "LOCAL"}
	remote := guardmodel.PluginEndpoint{Kind: "REMOTE", Host: "ner.example"}
	snap := entryEvents{events: []guardmodel.PluginEntryEvent{
		{Seq: 3, Kind: enabled, Endpoint: local, Egress: []string{"a:443"}},
		{Seq: 5, Kind: changed, Endpoint: local, Egress: []string{}},          // narrows
		{Seq: 7, Kind: changed, Endpoint: local, Egress: []string{"b:443"}},   // adds a host
		{Seq: 9, Kind: changed, Endpoint: remote, Egress: []string{"b:443"}},  // moves the endpoint
		{Seq: 11, Kind: changed, Endpoint: remote, Egress: []string{"b:443"}}, // the same
		{Seq: 13, Kind: changed, DecodeErr: true},                             // cannot be read
		{Seq: 15, Kind: disabled},
	}}
	for _, c := range []struct {
		after int64
		from  int64
		ok    bool
	}{{0, 13, true}, {3, 13, true}, {13, 0, false}, {20, 0, false}} {
		from, ok, err := servedFrom(context.Background(), snap, "acme-ner", "default", c.after)
		require.NoError(t, err)
		require.Equal(t, c.ok, ok, "after %d", c.after)
		require.Equal(t, c.from, from, "after %d", c.after)
	}
	require.False(t, widens(snap.events[0], snap.events[1]), "a narrower egress")
	require.True(t, widens(snap.events[1], snap.events[2]), "a new host")
	require.True(t, widens(snap.events[2], snap.events[3]), "a moved endpoint")
	require.False(t, widens(snap.events[3], snap.events[4]), "nothing changed")
	require.True(t, widens(snap.events[4], snap.events[5]), "a detail that does not decode")
}
