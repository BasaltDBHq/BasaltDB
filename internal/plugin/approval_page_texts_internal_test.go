package plugin

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// onePluginApproval serves one pending plugin approval the role opened.
type onePluginApproval struct {
	PluginApprovalStore
	r guardmodel.PluginApprovalRecord
}

func (s onePluginApproval) ReadPluginApproval(context.Context, uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	return s.r, true, nil
}

// The engine relays only texts that follow the text rules (CONTRACT.md,
// Stores, Text rules): the plugin page's request refuses a binding or
// settings from the store that break them.
func TestPluginApprovalRequestRefusesTextsOutOfTheRules(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../api/plugin/approval/vectors.json")
	require.NoError(t, err)
	var v struct {
		Vectors []struct{ Binding, Settings string } `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Vectors)
	binding, settings := v.Vectors[0].Binding, v.Vectors[0].Settings
	record := func(binding, settings string) guardmodel.PluginApprovalRecord {
		return guardmodel.PluginApprovalRecord{
			ApprovalID: uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a1"), Status: guardmodel.PluginApprovalStatusPending,
			ExpiresAt: time.Now().Add(time.Hour), BindingText: binding, SettingsText: settings,
		}
	}
	ok := record(binding, settings)
	_, err = newService(t, "linux", "", withApprovals(onePluginApproval{r: ok})).PluginApprovalRequest(context.Background(), ok.ApprovalID)
	require.NoError(t, err, "texts in the rules are relayed")

	for name, r := range map[string]guardmodel.PluginApprovalRecord{
		"binding": record(strings.Replace(binding, `{"kind": `, `{"kind":`, 1), settings),
		"line":    record(binding, `{"a":1}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pc := newService(t, "linux", "", withApprovals(onePluginApproval{r: r}))
			_, err := pc.PluginApprovalRequest(context.Background(), r.ApprovalID)
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, name)
		})
	}
}
