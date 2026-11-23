package plugin

import (
	"context"
	"runtime"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// Why an entry that requires approval is not served to one agent
// (CONTRACT.md, Plugins, Plugin approvals at engine start). The approval
// reasons carry their own problem code; the others are PLUGIN_UNAVAILABLE
// and write nothing.
const (
	whyNoApproval = "no plugin approval names this agent yet; " +
		"the agent opens one with request_plugin and a person signs it: the engine starts the plugin within seconds"
	whyApprovalReplaced = "no plugin approval names this agent: the newest one for it was replaced by a newer approval that does not name this agent; " +
		"the agent opens one with request_plugin: the engine starts the plugin once a person signed it"
	whyApprovalEnded = "its plugin approval ended when it was turned off or removed for this agent; " +
		"turning it on again needs a new approval, which the agent opens with request_plugin"
	whyApprovalsOldGuard = "this agent's guard is older than schema version 5, so it holds no plugin approvals; " +
		"update it through the link basalt init prints for this agent: the engine checks again on its own"
	whyApprovalsUnread = "its plugin approvals could not be read from this agent's database; " +
		"the engine checks again once the database answers"
)

// withheldWhy is why an entry is not served to one agent: code is the
// status problem (problemPluginUnavailable when empty), why the
// message's reason.
type withheldWhy struct {
	code string
	why  string
	// transient: the database did not answer (transientErr), so nothing was
	// decided. While the engine runs, what runs then stays as it is.
	transient bool
	// approvalID is the approval that matched, when one did.
	approvalID uuid.UUID
}

// approvalReason reports whether code is one of the approval reasons:
// awaiting, expired or mismatch. A withhold for one of them ends the
// approval (PLUGIN_DISABLED, when the ledger records the entry served); any
// other withhold writes nothing.
func approvalReason(code string) bool {
	switch code {
	case problemPluginAwaitingApproval, problemPluginApprovalExpired, problemPluginApprovalMismatch:
		return true
	}
	return false
}

// agentApprovals is one agent's plugin approvals, read at most once per
// start through the agent's own connection, and only when an entry served
// to it requires approval.
type agentApprovals struct {
	db    Querier
	ports Ports
	read  bool
	// unavailable is why they could not be read, "" when they were;
	// transient when the database did not answer.
	unavailable string
	transient   bool
	// newest is, per entry, the newest approval that names the agent's
	// role (guard.ReadPluginApprovals).
	newest map[pluginmodel.EntryKey]guardmodel.PluginApprovalRecord
}

func (a *agentApprovals) load(ctx context.Context) {
	if a.read {
		return
	}
	a.read = true
	v, err := a.ports.Guard.AgentVersion(ctx, a.db)
	switch {
	case err != nil:
		a.unavailable, a.transient = whyApprovalsUnread, transientErr(err)
		return
	case v < a.ports.approvalsVersion():
		a.unavailable = whyApprovalsOldGuard
		return
	}
	recs, err := a.ports.Guard.ReadPluginApprovals(ctx, a.db)
	if err != nil {
		a.unavailable, a.transient = whyApprovalsUnread, transientErr(err)
		return
	}
	a.newest = make(map[pluginmodel.EntryKey]guardmodel.PluginApprovalRecord, len(recs))
	for _, r := range recs {
		if r.NamesCaller {
			a.newest[pluginmodel.EntryKey{Name: r.Name, Instance: r.Instance}] = r
		}
	}
}

// check decides whether entry k, recorded as d and with settings s, is
// served to the agent: only when the newest approval naming the agent is
// signed, not ended, and equals in every matched field what the engine
// derives from the installed copy and engine.json. Anything else withholds
// it, with why. An error reading the approvals or hashing the settings is
// PLUGIN_UNAVAILABLE.
func (a *agentApprovals) check(ctx context.Context, k pluginmodel.EntryKey, d guardmodel.PluginDetail, s guardmodel.PluginSettings) (withheldWhy, bool) {
	a.load(ctx)
	if a.unavailable != "" {
		return withheldWhy{why: a.unavailable, transient: a.transient}, false
	}
	r, ok := a.newest[k]
	if !ok {
		return withheldWhy{code: problemPluginAwaitingApproval, why: whyNoApproval}, false
	}
	switch r.Status {
	case guardmodel.PluginApprovalStatusPending:
		return withheldWhy{code: problemPluginAwaitingApproval, why: "its plugin approval is waiting for a person to sign it (it expires " +
			r.ExpiresAt.UTC().Format("2006-01-02 15:04") + " UTC); the engine starts the plugin within seconds of the signature"}, false
	case guardmodel.PluginApprovalStatusCancelled:
		return withheldWhy{code: problemPluginAwaitingApproval, why: whyApprovalReplaced}, false
	case guardmodel.PluginApprovalStatusExpired:
		return withheldWhy{code: problemPluginApprovalExpired, why: "its plugin approval expired unsigned at " +
			r.ExpiresAt.UTC().Format("2006-01-02 15:04") + " UTC; the agent opens a new one with request_plugin, or removes the plugin"}, false
	case guardmodel.PluginApprovalStatusApproved:
	default:
		return withheldWhy{why: whyApprovalsUnread}, false
	}
	if r.ApprovedAt == nil {
		return withheldWhy{code: problemPluginAwaitingApproval, why: whyApprovalEnded}, false
	}
	sum, err := a.ports.Guard.PluginSettingsSHA256(ctx, a.db, s)
	if err != nil {
		return withheldWhy{why: whyApprovalsUnread, transient: transientErr(err)}, false
	}
	// A mismatch is named while it lasts, also once the withhold ended the
	// approval: the person sees what differs, not only that it ended.
	if diff := approvalMismatch(r.Bound, approvalBound(d, sum)); len(diff) > 0 {
		return withheldWhy{code: problemPluginApprovalMismatch, why: "it does not match what a person approved; these differ: " +
			strings.Join(diff, ", ") + ". Ask the person whether the change was theirs, then open a new approval or disable the plugin"}, false
	}
	if r.Ended() {
		return withheldWhy{code: problemPluginAwaitingApproval, why: whyApprovalEnded}, false
	}
	return withheldWhy{approvalID: r.ApprovalID}, true
}

// approvalBound is what an approval of entry d with settings hash
// settingsSHA256 must bind to be served: every matched field, derived from
// the installed copy as recorded and from engine.json.
func approvalBound(d guardmodel.PluginDetail, settingsSHA256 string) guardmodel.PluginApprovalBound {
	return guardmodel.PluginApprovalBound{
		Name: d.Name, Instance: d.Instance, Version: d.Version, ManifestSHA256: d.ManifestSHA256,
		SettingsSHA256: settingsSHA256, Hooks: d.Hooks, Roles: d.Roles, Egress: d.Egress,
		Endpoint: d.Endpoint, Isolation: d.Isolation, Signer: d.Signer, SignerKeyID: d.SignerKeyID,
	}
}

// approvalMismatch names the matched fields in which an approval's bound
// detail and what the engine derives differ, in the binding's terms and a
// fixed order; none when they are equal. It names fields, never a value.
func approvalMismatch(approved, derived guardmodel.PluginApprovalBound) []string {
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

func sameIsolation(a, b *guardmodel.PluginIsolation) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// PluginApprovalDetail is the detail basalt plugin opens a plugin approval
// with for verified copy v of entry k (verified with
// RequireApproval(true)), naming roles. It is built by the same code
// the engine derives the matched fields with at start (pluginDetail,
// withSigner, in same-user mode: the engine runs an entry that requires
// approval itself, as its own child, in either mode), so an honest approval
// always matches what the engine serves.
func PluginApprovalDetail(k pluginmodel.EntryKey, v pluginmodel.Verified, roles []string) guardmodel.PluginApprovalDetail {
	d := withSigner(pluginDetail(k, v, pluginmodel.ModeSameUser, runtime.GOOS, nil), v)
	return guardmodel.PluginApprovalDetail{
		Agents: slices.Clone(roles), Name: d.Name, Instance: d.Instance, Version: d.Version,
		ManifestSHA256: d.ManifestSHA256, Hooks: d.Hooks, Roles: d.Roles, Egress: d.Egress,
		Endpoint: d.Endpoint, Isolation: d.Isolation, Signer: d.Signer, SignerKeyID: d.SignerKeyID,
	}
}

// withSigner is d as recorded for an entry that requires approval: with
// the copy's signer state, and its key id only for a KNOWN signer
// (CONTRACT.md, In the ledger, signer).
func withSigner(d guardmodel.PluginDetail, v pluginmodel.Verified) guardmodel.PluginDetail {
	d.Signer, d.SignerKeyID = string(v.Signer), ""
	if v.Signer == pluginmodel.SignerKnown {
		d.SignerKeyID = v.SignerKeyID
	}
	return d
}
