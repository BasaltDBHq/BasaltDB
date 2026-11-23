package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// endGuard is a guard that holds an agent's plugin records and approvals
// and keeps the events written to it.
type endGuard struct {
	Guard
	recs    guardmodel.PluginRecords
	apps    []guardmodel.PluginApprovalRecord
	written []guardmodel.PluginDetail
}

func (g *endGuard) ReadPluginRecords(context.Context, Querier) (guardmodel.PluginRecords, error) {
	return g.recs, nil
}

func (g *endGuard) ReadPluginApprovals(context.Context, Querier) ([]guardmodel.PluginApprovalRecord, error) {
	return g.apps, nil
}

func (g *endGuard) RecordPluginEntryEvent(_ context.Context, _ Querier, kind guardmodel.PluginEventKind, d guardmodel.PluginDetail) error {
	if kind != guardmodel.PluginDisabled {
		panic("only PLUGIN_DISABLED is written here")
	}
	g.written = append(g.written, d)
	return nil
}

// An agent owes a PLUGIN_DISABLED for an entry its ledger records as served,
// else for its newest signed, unended approval naming it; none for a
// pending or ended approval, or one that does not name it.
func TestEndPluginApproval(t *testing.T) {
	ctx := context.Background()
	signed := time.Now()
	served := guardmodel.PluginDetail{Name: "acme-ner", Instance: "default", Version: "1.0.0"}
	bound := guardmodel.PluginApprovalBound{Name: "acme-ner", Instance: "default", Version: "2.0.0"}
	approval := func(status guardmodel.PluginApprovalStatus, names bool, approvedAt, endedAt *time.Time) guardmodel.PluginApprovalRecord {
		return guardmodel.PluginApprovalRecord{
			Name: "acme-ner", Instance: "default", Status: status, NamesCaller: names,
			ApprovedAt: approvedAt, EndedAt: endedAt, Bound: bound,
		}
	}
	for _, c := range []struct {
		name string
		g    *endGuard
		want []guardmodel.PluginDetail
	}{
		{"served on the record", &endGuard{recs: guardmodel.PluginRecords{Entries: []guardmodel.PluginRecord{
			{Kind: guardmodel.PluginEnabled, Detail: served},
		}}}, []guardmodel.PluginDetail{served}},
		{"disabled on the record, nothing approved", &endGuard{recs: guardmodel.PluginRecords{Entries: []guardmodel.PluginRecord{
			{Kind: guardmodel.PluginDisabled, Detail: served},
		}}}, nil},
		{
			"a signed approval naming the caller", &endGuard{apps: []guardmodel.PluginApprovalRecord{
				approval(guardmodel.PluginApprovalStatusApproved, true, &signed, nil),
			}},
			[]guardmodel.PluginDetail{{Name: "acme-ner", Instance: "default", Version: "2.0.0"}},
		},
		{
			"an approval that does not name the caller is skipped", &endGuard{apps: []guardmodel.PluginApprovalRecord{
				approval(guardmodel.PluginApprovalStatusApproved, false, &signed, nil),
				approval(guardmodel.PluginApprovalStatusApproved, true, &signed, nil),
			}},
			[]guardmodel.PluginDetail{{Name: "acme-ner", Instance: "default", Version: "2.0.0"}},
		},
		{"an ended approval", &endGuard{apps: []guardmodel.PluginApprovalRecord{
			approval(guardmodel.PluginApprovalStatusApproved, true, &signed, &signed),
		}}, nil},
		{"an approval not signed yet", &endGuard{apps: []guardmodel.PluginApprovalRecord{
			approval(guardmodel.PluginApprovalStatusApproved, true, nil, nil),
		}}, nil},
		{"a pending approval", &endGuard{apps: []guardmodel.PluginApprovalRecord{
			approval(guardmodel.PluginApprovalStatusPending, true, &signed, nil),
		}}, nil},
		{"served on the record wins over a signed approval", &endGuard{
			recs: guardmodel.PluginRecords{Entries: []guardmodel.PluginRecord{{Kind: guardmodel.PluginEnabled, Detail: served}}},
			apps: []guardmodel.PluginApprovalRecord{approval(guardmodel.PluginApprovalStatusApproved, true, &signed, nil)},
		}, []guardmodel.PluginDetail{served}},
		{"nothing", &endGuard{}, nil},
	} {
		require.NoError(t, endPluginApproval(ctx, c.g, nil, "acme-ner", "default"), c.name)
		require.Equal(t, c.want, c.g.written, c.name)
	}
}
