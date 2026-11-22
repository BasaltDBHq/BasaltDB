package store

import (
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The service speaks internal/core/action; the guard's functions take their own
// types. These map one to the other at the store's edge, field for field.

func guardIntent(in action.Intent) guard.Intent {
	return guard.Intent{RunID: in.RunID, TaskID: in.TaskID, Text: in.Text}
}

func guardRead(r action.Read) guard.Read {
	return guard.Read{
		RunID: r.RunID, Statement: r.Statement, Params: r.Params, Tables: r.Tables,
		Rows: r.Rows, Duration: r.Duration, Versions: guardVersions(r.Versions),
	}
}

func guardVersions(vs []action.RowVersion) []guard.RowVersion {
	if vs == nil {
		return nil
	}
	out := make([]guard.RowVersion, len(vs))
	for i, v := range vs {
		out[i] = guard.RowVersion{TableOID: v.TableOID, Key: v.Key, Version: v.Version}
	}
	return out
}

func guardRefusal(r action.Refusal) guard.Refusal {
	return guard.Refusal{
		Intent: guardIntent(r.Intent), Op: string(r.Op), Statement: r.Statement, Params: r.Params,
		Code: r.Code, Reason: r.Reason, Duration: r.Duration,
	}
}

func previewPageOf(p guardmodel.PreviewPage) action.PreviewPage {
	return action.PreviewPage{
		Lines: p.Lines, Restore: p.Restore, AllAlreadyReverted: p.AllAlreadyReverted, CursorFound: p.CursorFound,
		Page: mapSlice(p.Page, func(l guardmodel.PreviewLine) action.PreviewLine { return action.PreviewLine(l) }),
		More: p.More,
	}
}

func batchResultOf(b guardmodel.BatchResult) action.BatchResult {
	return action.BatchResult{
		RevertID: b.RevertID, Batch: b.Batch, Status: b.Status,
		Restored: b.Restored, Skipped: b.Skipped, Pending: b.Pending,
		Items: mapSlice(b.Items, func(it guardmodel.BatchItem) action.BatchItem { return action.BatchItem(it) }),
	}
}

func rescopedOf(r guardmodel.RescopedRevert) action.RescopedRevert {
	return action.RescopedRevert{
		RevertID: r.RevertID, BindingText: r.BindingText, ExpiresAt: r.ExpiresAt, Lines: r.Lines,
		RescopeNonce: r.RescopeNonce, Catalog: catalogOf(r.Catalog), ScopeToken: r.ScopeToken,
	}
}

func catalogOf(c *guardmodel.RevertCatalog) *action.RevertCatalog {
	if c == nil {
		return nil
	}
	return &action.RevertCatalog{
		Agents:       mapSlice(c.Agents, func(a guardmodel.CatalogAgent) action.CatalogAgent { return action.CatalogAgent(a) }),
		Runs:         mapSlice(c.Runs, func(r guardmodel.CatalogRun) action.CatalogRun { return action.CatalogRun(r) }),
		Tables:       mapSlice(c.Tables, func(t guardmodel.CatalogTable) action.CatalogTable { return action.CatalogTable(t) }),
		ChangeAgents: c.ChangeAgents,
	}
}

// mapSlice maps each element of in with f, keeping a nil slice nil (JSON
// null, not []).
func mapSlice[T, U any](in []T, f func(T) U) []U {
	if in == nil {
		return nil
	}
	out := make([]U, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
