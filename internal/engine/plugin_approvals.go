package engine

import (
	"context"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Why an entry that requires approval is not served to one agent
// (CONTRACT.md, Plugins, Plugin approvals at engine start). The approval
// reasons carry their own problem code; the others are PLUGIN_UNAVAILABLE
// and write nothing.
const (
	whyNoApproval = "no plugin approval names this agent yet; " +
		"open one with basalt plugin enable --approve-with-passkey and have a person sign it, then restart the engine"
	whyApprovalReplaced = "no plugin approval names this agent: the newest one for it was replaced by a newer approval that does not name this agent; " +
		"open one with basalt plugin enable --approve-with-passkey, then restart the engine once a person signed it"
	whyApprovalEnded = "its plugin approval ended when it was turned off or removed for this agent; " +
		"turning it on again needs a new approval: open one with basalt plugin enable --approve-with-passkey"
	whyApprovalsOldGuard = "this agent's guard is older than schema version 5, so it holds no plugin approvals; " +
		"run basalt upgrade for this agent (on an agent-operated engine, an UPGRADE setup code), then restart the engine"
	whyApprovalsUnread = "its plugin approvals could not be read from this agent's database; " +
		"restart the engine once the database answers"
)

// withheldWhy is why an entry is not served to one agent: code is the
// status problem (agent.ProblemPluginUnavailable when empty), why the
// message's reason.
type withheldWhy struct {
	code string
	why  string
}

// approvalReason reports whether code is one of the approval reasons:
// awaiting, expired or mismatch. A withhold for one of them ends the
// approval (PLUGIN_DISABLED, when the ledger records the entry served); any
// other withhold writes nothing.
func approvalReason(code string) bool {
	switch code {
	case agent.ProblemPluginAwaitingApproval, agent.ProblemPluginApprovalExpired, agent.ProblemPluginApprovalMismatch:
		return true
	}
	return false
}

// agentApprovals is one agent's plugin approvals, read at most once per
// start through the agent's own connection, and only when an entry served
// to it requires approval.
type agentApprovals struct {
	db   guard.Querier
	read bool
	// unavailable is why they could not be read, "" when they were.
	unavailable string
	// newest is, per entry, the newest approval that names the agent's
	// role (guard.ReadPluginApprovals).
	newest map[plugin.EntryKey]guard.PluginApprovalRecord
}

func (a *agentApprovals) load(ctx context.Context) {
	if a.read {
		return
	}
	a.read = true
	v, err := guard.AgentVersion(ctx, a.db)
	switch {
	case err != nil:
		a.unavailable = whyApprovalsUnread
		return
	case v < guard.PluginApprovalsVersion:
		a.unavailable = whyApprovalsOldGuard
		return
	}
	recs, err := guard.ReadPluginApprovals(ctx, a.db)
	if err != nil {
		a.unavailable = whyApprovalsUnread
		return
	}
	a.newest = make(map[plugin.EntryKey]guard.PluginApprovalRecord, len(recs))
	for _, r := range recs {
		if r.NamesCaller {
			a.newest[plugin.EntryKey{Name: r.Name, Instance: r.Instance}] = r
		}
	}
}

// check decides whether entry k, recorded as d and with settings s, is
// served to the agent: only when the newest approval naming the agent is
// signed, not ended, and equals in every matched field what the engine
// derives from the installed copy and engine.json. Anything else withholds
// it, with why. An error reading the approvals or hashing the settings is
// PLUGIN_UNAVAILABLE.
func (a *agentApprovals) check(ctx context.Context, k plugin.EntryKey, d guard.PluginDetail, s guard.PluginSettings) (withheldWhy, bool) {
	a.load(ctx)
	if a.unavailable != "" {
		return withheldWhy{why: a.unavailable}, false
	}
	r, ok := a.newest[k]
	if !ok {
		return withheldWhy{code: agent.ProblemPluginAwaitingApproval, why: whyNoApproval}, false
	}
	switch r.Status {
	case guard.PluginApprovalStatusPending:
		return withheldWhy{code: agent.ProblemPluginAwaitingApproval, why: "its plugin approval is waiting for a person to sign it (it expires " +
			r.ExpiresAt.UTC().Format("2006-01-02 15:04") + " UTC); restart the engine once it is signed"}, false
	case guard.PluginApprovalStatusCancelled:
		return withheldWhy{code: agent.ProblemPluginAwaitingApproval, why: whyApprovalReplaced}, false
	case guard.PluginApprovalStatusExpired:
		return withheldWhy{code: agent.ProblemPluginApprovalExpired, why: "its plugin approval expired unsigned at " +
			r.ExpiresAt.UTC().Format("2006-01-02 15:04") + " UTC; open a new one with basalt plugin enable --approve-with-passkey, or remove the plugin"}, false
	case guard.PluginApprovalStatusApproved:
	default:
		return withheldWhy{why: whyApprovalsUnread}, false
	}
	if r.Ended() || r.ApprovedAt == nil {
		return withheldWhy{code: agent.ProblemPluginAwaitingApproval, why: whyApprovalEnded}, false
	}
	sum, err := guard.PluginSettingsSHA256(ctx, a.db, s)
	if err != nil {
		return withheldWhy{why: whyApprovalsUnread}, false
	}
	if diff := approvalMismatch(r.Bound, approvalBound(d, sum)); len(diff) > 0 {
		return withheldWhy{code: agent.ProblemPluginApprovalMismatch, why: "it does not match what a person approved; these differ: " +
			strings.Join(diff, ", ") + ". Ask the person whether the change was theirs, then open a new approval or disable the plugin"}, false
	}
	return withheldWhy{}, true
}

// approvalBound is what an approval of entry d with settings hash
// settingsSHA256 must bind to be served: every matched field, derived from
// the installed copy as recorded and from engine.json.
func approvalBound(d guard.PluginDetail, settingsSHA256 string) guard.PluginApprovalBound {
	return guard.PluginApprovalBound{
		Name: d.Name, Instance: d.Instance, Version: d.Version, ManifestSHA256: d.ManifestSHA256,
		SettingsSHA256: settingsSHA256, Hooks: d.Hooks, Roles: d.Roles, Egress: d.Egress,
		Endpoint: d.Endpoint, Isolation: d.Isolation, Signer: d.Signer, SignerKeyID: d.SignerKeyID,
	}
}

// approvalMismatch names the matched fields in which an approval's bound
// detail and what the engine derives differ, in the binding's terms and a
// fixed order; none when they are equal. It names fields, never a value.
func approvalMismatch(approved, derived guard.PluginApprovalBound) []string {
	var out []string
	add := func(field string, differs bool) {
		if differs {
			out = append(out, field)
		}
	}
	add("name", approved.Name != derived.Name)
	add("instance", approved.Instance != derived.Instance)
	add("version", approved.Version != derived.Version)
	add("manifestSha256", approved.ManifestSHA256 != derived.ManifestSHA256)
	add("settingsSha256", approved.SettingsSHA256 != derived.SettingsSHA256)
	add("hooks", !slices.Equal(approved.Hooks, derived.Hooks))
	add("roles", !slices.Equal(approved.Roles, derived.Roles))
	add("endpoint", approved.Endpoint != derived.Endpoint)
	add("egress", !slices.Equal(approved.Egress, derived.Egress))
	add("isolation", !sameIsolation(approved.Isolation, derived.Isolation))
	add("signer", approved.Signer != derived.Signer)
	add("signerKeyId", approved.SignerKeyID != derived.SignerKeyID)
	return out
}

func sameIsolation(a, b *guard.PluginIsolation) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// withSigner is d as recorded for an entry that requires approval: with
// the copy's signer state, and its key id only for a KNOWN signer
// (CONTRACT.md, In the ledger, signer).
func withSigner(d guard.PluginDetail, v plugin.Verified) guard.PluginDetail {
	d.Signer, d.SignerKeyID = string(v.Signer), ""
	if v.Signer == plugin.SignerKnown {
		d.SignerKeyID = v.SignerKeyID
	}
	return d
}
