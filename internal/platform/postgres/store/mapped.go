package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgcatalog"
)

// The exported store methods map their errors (MapError), so the service
// sees contract errors, never a driver error. Each calls the method of the
// same name with Raw appended. A new exported method that can fail gets
// its wrapper here.

// Relations is pgcatalog.Relations.
func (c *Catalog) Relations(ctx context.Context) ([]pgcatalog.Relation, int, error) {
	r0, r1, err := c.relationsRaw(ctx)
	return r0, r1, MapError(err)
}

// Find is pgcatalog.FindRelation.
func (c *Catalog) Find(ctx context.Context, schema string, name string) (pgcatalog.Relation, bool, error) {
	r0, r1, err := c.findRaw(ctx, schema, name)
	return r0, r1, MapError(err)
}

// Describe is pgcatalog.DescribeRelation, every read of it in one snapshot
// (read is REPEATABLE READ).
func (c *Catalog) Describe(ctx context.Context, oid uint32) (pgcatalog.Detail, error) {
	r0, err := c.describeRaw(ctx, oid)
	return r0, MapError(err)
}

// Guarded reports whether oid is in basalt_meta.agent_guarded_tables. A
// guard older than that view, or a database without it, guards nothing
// describe can report: false, not an error.
func (c *Catalog) Guarded(ctx context.Context, oid uint32) (bool, error) {
	r0, err := c.guardedRaw(ctx, oid)
	return r0, MapError(err)
}

// Search is pgcatalog.Search.
func (c *Catalog) Search(ctx context.Context, q string, exclude []pgcatalog.ColumnKey, after *pgcatalog.SearchCursor, limit int) ([]pgcatalog.Match, error) {
	r0, err := c.searchRaw(ctx, q, exclude, after, limit)
	return r0, MapError(err)
}

// Structure is pgcatalog.StructureLines.
func (c *Catalog) Structure(ctx context.Context) ([]string, error) {
	r0, err := c.structureRaw(ctx)
	return r0, MapError(err)
}

// ColumnOrder maps each table to its columns in table order.
func (c *ColumnOrder) ColumnOrder(ctx context.Context, tables []string) (map[string][]string, error) {
	r0, err := c.columnOrderRaw(ctx, tables)
	return r0, MapError(err)
}

// GuardStatus reads schema_version.
func (p Probe) GuardStatus(ctx context.Context) (guardmodel.Status, error) {
	r0, err := p.guardStatusRaw(ctx)
	return r0, MapError(err)
}

// SetupRecorded reports whether setup id is recorded.
func (p Probe) SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error) {
	r0, err := p.setupRecordedRaw(ctx, id)
	return r0, MapError(err)
}

// LatestSetup is the agent's newest recorded setup.
func (p Probe) LatestSetup(ctx context.Context) (guardmodel.AgentSetup, bool, error) {
	r0, r1, err := p.latestSetupRaw(ctx)
	return r0, r1, MapError(err)
}

// LedgerBytes is the size of basalt_meta.
func (p Probe) LedgerBytes(ctx context.Context) (int64, error) {
	r0, err := p.ledgerBytesRaw(ctx)
	return r0, MapError(err)
}

// Reinstalls reads agent_reinstalls with the kept copy merged in.
func (p Probe) Reinstalls(ctx context.Context) (guard.Reinstalls, error) {
	r0, err := p.reinstallsRaw(ctx)
	return r0, MapError(err)
}

// Read runs one SELECT in a read-only transaction within the time limit,
// and cancels it once it returns more than the row limit. For the
// statement's row sources (its Handle, the []sqlguard.RowSource of the
// check) that are guarded tables the agent can read, it also returns the version
// of each row: the statement runs with version columns added through the
// parse tree (sqlguard.WithRowVersions), which are stripped from the rows.
// If that statement fails to plan, the original runs as given and the read
// carries no versions.
func (r *Reader) Read(ctx context.Context, sql string, params []any, stmt action.Statement) (action.ReadResult, error) {
	r0, err := r.readRaw(ctx, sql, params, stmt)
	return r0, MapError(err)
}

// Preview previews a held write. It refuses a write whose values change
// between runs (*action.RefusalError NOT_REPEATABLE), works out the columns
// whose new values the approval binds (holdColumns, which may read the
// catalog), then runs the write in a preview transaction (basalt.mode =
// PREVIEW) on the agent's credential that always rolls back, and returns
// the columns with the preview lines. An error of the preview run is marked
// *action.PreviewFailedError; a catalog read's error is not.
func (s *Store) Preview(ctx context.Context, in action.Intent, req agentstore.Request) (action.HeldPreview, error) {
	assigned, err := s.holdColumns(ctx, req.Text, req.Params)
	if err != nil {
		return action.HeldPreview{}, err
	}
	lines, err := s.previewRaw(ctx, in, req.Text, req.Params, assigned)
	if err != nil {
		return action.HeldPreview{}, &action.PreviewFailedError{Err: MapError(err)}
	}
	return action.HeldPreview{Assigned: assigned, Lines: lines}, nil
}

// RevealHeld checks the person's reveal proof for a held write
// (basalt_meta.open_reveal, in its own transaction), then re-runs the held
// request in a preview transaction exactly as an apply runs it (the
// statement with its parameters, then finish_change, so the change records
// them), and reads the held approval's hidden rows with the reveal's ticket
// (basalt_meta.reveal_approval_rows). The ticket lives in this call only;
// the transaction always rolls back.
func (s *Store) RevealHeld(ctx context.Context, id uuid.UUID, run action.HeldRun, proof passkey.Assertion, key []byte) ([]approval.RevealedRow, error) {
	r0, err := s.revealHeldRaw(ctx, id, run, proof, key)
	return r0, revealApprovalRefusal(MapError(err))
}

// Hold stores a held write for the person's approval.
func (s *Store) Hold(ctx context.Context, in action.Intent, r action.HoldRequest) (action.Held, error) {
	r0, err := s.holdRaw(ctx, in, r)
	return r0, MapError(err)
}

// TableColumns returns the columns an INSERT without a column list assigns:
// every non-generated column of table, in order, resolved as the agent's
// session would.
func (s *Store) TableColumns(ctx context.Context, table string) ([]string, error) {
	r0, err := s.tableColumnsRaw(ctx, table)
	return r0, MapError(err)
}

// SubmitApproval relays the person's signed approval to Postgres.
func (s *Store) SubmitApproval(ctx context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	r0, err := s.submitApprovalRaw(ctx, id, a)
	return r0, MapError(err)
}

// ReadPluginApproval returns one plugin approval the agent's role may see
// (basalt_meta.agent_plugin_approvals), and false when there is none.
func (s *Store) ReadPluginApproval(ctx context.Context, id uuid.UUID) (guardmodel.PluginApprovalRecord, bool, error) {
	r0, r1, err := s.readPluginApprovalRaw(ctx, id)
	return r0, r1, MapError(err)
}

// SubmitPluginApproval relays the person's signed plugin approval to
// Postgres (basalt_meta.submit_plugin_approval).
func (s *Store) SubmitPluginApproval(ctx context.Context, r guardmodel.PluginApprovalResponse) (time.Time, error) {
	r0, err := s.submitPluginApprovalRaw(ctx, r)
	return r0, MapError(err)
}

// FindApproval returns one of the agent's approvals.
func (s *Store) FindApproval(ctx context.Context, id uuid.UUID) (action.Approval, error) {
	r0, err := s.findApprovalRaw(ctx, id)
	return r0, findApprovalRefusal(MapError(err))
}

// ListApprovals returns one page of the agent's open approvals.
func (s *Store) ListApprovals(ctx context.Context, p action.ApprovalListParams) (pagination.Page[action.Approval], error) {
	r0, err := s.listApprovalsRaw(ctx, p)
	return r0, MapError(err)
}

// ListOpenReverts returns one page of the agent's reverts waiting for the
// person's signature or for its batches (ledger.ListOpenReverts).
func (s *Store) ListOpenReverts(ctx context.Context, p action.RevertListParams) (pagination.Page[action.Revert], error) {
	r0, err := s.listOpenRevertsRaw(ctx, p)
	return r0, MapError(err)
}

// Passkeys returns the registered passkeys' public data.
func (s *Store) Passkeys(ctx context.Context) ([]passkey.Credential, error) {
	r0, err := s.passkeysRaw(ctx)
	return r0, MapError(err)
}

// PreviewRevert returns one page of the preview of scope (basalt_meta
// preview_revert) on the agent's credential, after the line whose hash is
// after, with the preview's totals (guard.PreviewRevertPage). The guard
// runs the revert on trial and undoes it; this transaction is read-write
// for that, and is rolled back anyway.
func (s *Store) PreviewRevert(ctx context.Context, scope action.Scope, after string, limit int) (action.PreviewPage, error) {
	r0, err := s.previewRevertRaw(ctx, scope, after, limit)
	return r0, prepareRefusal(MapError(err))
}

// PrepareRevert stores a revert of scope for the person to sign
// (basalt_meta.prepare_revert) on the agent's credential, in its own
// transaction with the statement timeout set to timeout instead of the
// agent's limit. A proposal with no line is rolled back and answered
// action.ErrEmptyProposal: through MCP it is NOTHING_TO_REVERT (RS-6).
func (s *Store) PrepareRevert(ctx context.Context, scope action.Scope, intent string, timeout time.Duration) (action.PreparedRevert, error) {
	r0, err := s.prepareRevertRaw(ctx, scope, intent, timeout)
	return r0, prepareRefusal(MapError(err))
}

// RescopeRevert changes the scope of a revert the agent's role prepared
// (basalt_meta.rescope_revert), for the person on the revert page, in its
// own transaction with the statement timeout set to timeout instead of the
// agent's limit. Past it Postgres cancels the rescope (57014) and nothing
// changes.
func (s *Store) RescopeRevert(ctx context.Context, req action.RescopeRequest, timeout time.Duration) (action.RescopedRevert, error) {
	r0, err := s.rescopeRevertRaw(ctx, req, timeout)
	return r0, rescopeRevertRefusal(MapError(err))
}

// ResetRevert puts a widened revert the agent's role prepared back to its
// proposal (basalt_meta.reset_revert), for the agent's reissueLink, under
// the same time limit as a rescope.
func (s *Store) ResetRevert(ctx context.Context, id uuid.UUID, timeout time.Duration) (action.RescopedRevert, error) {
	r0, err := s.resetRevertRaw(ctx, id, timeout)
	return r0, MapError(err)
}

// HasChange reports whether the agent's view of the change record shows
// change id: one of its own changes, or a revert's change that covered it.
func (s *Store) HasChange(ctx context.Context, id uuid.UUID) (bool, error) {
	r0, err := s.hasChangeRaw(ctx, id)
	return r0, MapError(err)
}

// HasTaskRun reports whether the agent has a run with task id id, read
// through its agent_runs view (RS-1: a task the agent ran in is its own
// scope; any run with that task id counts).
func (s *Store) HasTaskRun(ctx context.Context, id uuid.UUID) (bool, error) {
	r0, err := s.hasTaskRunRaw(ctx, id)
	return r0, MapError(err)
}

// RevertedBy returns the change record of the latest revert that covered
// scope in the agent's view of the ledger, or uuid.Nil when none did. A change
// scope is the change itself; a run or task scope is any of its changes. The
// revert's change is what request_revert takes to redo the reverted work.
func (s *Store) RevertedBy(ctx context.Context, scope action.Scope) (uuid.UUID, error) {
	r0, err := s.revertedByRaw(ctx, scope)
	return r0, MapError(err)
}

// FindRevert returns a revert the agent's role prepared.
func (s *Store) FindRevert(ctx context.Context, id uuid.UUID) (action.Revert, error) {
	r0, err := s.findRevertRaw(ctx, id)
	return r0, findRevertRefusal(MapError(err))
}

// RevertLines returns one page of a batched plan's lines, with values too
// large for the agent left out (CONTRACT.md, Large values).
func (s *Store) RevertLines(ctx context.Context, p action.RevertLineParams) (pagination.Page[action.RevertLine], error) {
	r0, err := s.revertLinesRaw(ctx, p)
	return r0, MapError(err)
}

// ApplyRevertBatch applies lines of a signed plan in one transaction on the
// agent's credential (basalt_meta.apply_revert_batch), under the agent's
// statement timeout.
func (s *Store) ApplyRevertBatch(ctx context.Context, id uuid.UUID, lines []int) (action.BatchResult, error) {
	r0, err := s.applyRevertBatchRaw(ctx, id, lines)
	return r0, MapError(err)
}

// ApplyRevert relays the person's signed revert (basalt_meta.apply_revert)
// on the agent's credential, for the revert page: Postgres verifies the
// passkey assertion and runs the revert, or for a large plan records the
// signature. It runs in its own transaction with the engine's timeouts
// (guard.SetTimeouts), so the agent role's own defaults cannot fail the
// person's revert.
func (s *Store) ApplyRevert(ctx context.Context, id uuid.UUID, a passkey.Assertion) (action.AppliedRevert, error) {
	r0, err := s.applyRevertRaw(ctx, id, a)
	return r0, applyRevertRefusal(MapError(err))
}

// RevertNonce reads the rescope nonce of a revert the agent's role prepared
// (basalt_meta.revert_nonce).
func (s *Store) RevertNonce(ctx context.Context, id uuid.UUID) ([]byte, error) {
	r0, err := s.revertNonceRaw(ctx, id)
	return r0, MapError(err)
}

// RejectRevert marks a pending revert the agent's role prepared REJECTED
// for the person on the revert page (basalt_meta.reject_revert), with the
// scope token the engine holds for a widened revert's rotated link.
func (s *Store) RejectRevert(ctx context.Context, id uuid.UUID, note string, token []byte) (action.RejectedRevert, error) {
	r0, err := s.rejectRevertRaw(ctx, id, note, token)
	return r0, rejectRevertRefusal(MapError(err))
}

// RevealNonce reads the reveal nonce of an approval (approval.KindApprove)
// or revert (approval.KindRevert) the agent's role holds
// (basalt_meta.reveal_nonce).
func (s *Store) RevealNonce(ctx context.Context, kind string, id uuid.UUID) ([]byte, error) {
	r0, err := s.revealNonceRaw(ctx, kind, id)
	return r0, MapError(err)
}

// RevealRevertRows asks Postgres for the values of a pending revert's
// redacted lines with the person's reveal proof and the key derived from
// the page's reveal secret (basalt_meta.reveal_revert_rows), in its own
// pinned transaction: it rebuilds the lines' rows to match their hashes.
func (s *Store) RevealRevertRows(ctx context.Context, id uuid.UUID, proof passkey.Assertion, key []byte) (action.RevealedRevert, error) {
	r0, err := s.revealRevertRowsRaw(ctx, id, proof, key)
	return r0, revealRevertRowsRefusal(MapError(err))
}

// ListRuns returns one page of the agent's own runs, read through the
// guard's agent views (agent_runs filters on session_user in Postgres).
// Keyset on run_id; the time filters narrow the same keyset.
func (s *Store) ListRuns(ctx context.Context, p action.RunListParams) (pagination.Page[action.RunSummary], error) {
	r0, err := s.listRunsRaw(ctx, p)
	return r0, MapError(err)
}

// Read runs one read on the store's pool (Reader.Read).
func (s *Store) Read(ctx context.Context, sql string, params []any, stmt action.Statement) (action.ReadResult, error) {
	r0, err := s.readRaw(ctx, sql, params, stmt)
	return r0, MapError(err)
}

// FindRun returns the agent's run id, read through the guard's agent view.
func (s *Store) FindRun(ctx context.Context, id uuid.UUID) (action.Run, error) {
	r0, err := s.findRunRaw(ctx, id)
	return r0, MapError(err)
}

// StartRun records a run and its RUN_STARTED ledger row.
func (s *Store) StartRun(ctx context.Context, in action.Intent) error {
	return MapError(s.startRunRaw(ctx, in))
}

// Write runs one INSERT, UPDATE or DELETE in a guarded transaction (the
// engine session protocol): the time limit and the intent set
// transaction-local, the statement as given with its parameters, then the
// change stamped with statement, parameters and duration before COMMIT. Any
// error rolls the whole action back.
func (s *Store) Write(ctx context.Context, in action.Intent, op action.Op, sql string, params []any) (action.WriteResult, error) {
	r0, err := s.writeRaw(ctx, in, op, sql, params)
	return r0, MapError(err)
}

// WriteApproved is Write under a signed approval (basalt.approval_id). The
// guard commits it only if it is the write the person approved.
func (s *Store) WriteApproved(ctx context.Context, in action.Intent, approvalID uuid.UUID, op action.Op, sql string, params []any) (action.WriteResult, error) {
	r0, err := s.writeApprovedRaw(ctx, in, approvalID, op, sql, params)
	return r0, MapError(err)
}

// RecordRead records a read the reader ran (a SELECT change record, the
// READ ledger row and the run's row versions) in its own transaction, and
// returns its change id.
func (s *Store) RecordRead(ctx context.Context, r action.Read) (uuid.UUID, error) {
	r0, err := s.recordReadRaw(ctx, r)
	return r0, MapError(err)
}

// RecordRefusal writes a REFUSED change record in its own transaction.
func (s *Store) RecordRefusal(ctx context.Context, r action.Refusal) error {
	return MapError(s.recordRefusalRaw(ctx, r))
}

// History reads one page of change records through the agent views, with
// values too large for the agent left out (CONTRACT.md, Large values).
func (s *Store) History(ctx context.Context, p action.ChangeListParams) (action.History[action.Change, action.RowChange], error) {
	r0, err := s.historyRaw(ctx, p)
	return r0, MapError(err)
}
