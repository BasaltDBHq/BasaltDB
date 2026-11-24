package plugin

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// owedPluginEnd is the PLUGIN_DISABLED the agent of q owes for the entry
// (name, instance), false when it owes none: its ledger records the entry as
// served (the detail last recorded), or its newest plugin approval naming
// it is signed and not ended (the detail that approval binds). Writing it
// ends the approval for that agent (CONTRACT.md, Plugin approval, Turning
// off ends it). It needs schema version PluginApprovalsVersion.
func owedPluginEnd(ctx context.Context, g Guard, q Querier, name, instance string) (guardmodel.PluginDetail, bool, error) {
	recs, err := g.ReadPluginRecords(ctx, q)
	if err != nil {
		return guardmodel.PluginDetail{}, false, err
	}
	for _, r := range recs.Entries {
		if r.Detail.Name == name && r.Detail.Instance == instance && r.Enabled() {
			return r.Detail, true, nil
		}
	}
	apps, err := g.ReadPluginApprovals(ctx, q)
	if err != nil {
		return guardmodel.PluginDetail{}, false, err
	}
	for _, a := range apps {
		if a.Name != name || a.Instance != instance || !a.NamesCaller {
			continue
		}
		if a.Status != guardmodel.PluginApprovalStatusApproved || a.ApprovedAt == nil || a.Ended() {
			return guardmodel.PluginDetail{}, false, nil
		}
		b := a.Bound
		return guardmodel.PluginDetail{
			Name: b.Name, Instance: b.Instance, Version: b.Version, ManifestSHA256: b.ManifestSHA256,
			Hooks: b.Hooks, Roles: b.Roles, Egress: b.Egress, Endpoint: b.Endpoint, Isolation: b.Isolation,
			Signer: b.Signer, SignerKeyID: b.SignerKeyID,
		}, true, nil
	}
	return guardmodel.PluginDetail{}, false, nil
}

// endPluginApproval records the PLUGIN_DISABLED the agent of q owes for
// (name, instance), if any (owedPluginEnd).
func endPluginApproval(ctx context.Context, g Guard, q Querier, name, instance string) error {
	d, owed, err := owedPluginEnd(ctx, g, q, name, instance)
	if err != nil || !owed {
		return err
	}
	return g.RecordPluginEntryEvent(ctx, q, guardmodel.PluginDisabled, d)
}
