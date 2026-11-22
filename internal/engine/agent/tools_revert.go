package agent

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/action"
	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// --- preview_revert ---

// previewRevertArgs is the preview_revert tool's input
// (api/mcp/tools/preview_revert.json).
type previewRevertArgs struct {
	pagination.Params
	scopeIDs
}

// scopeIDs are the scope arguments preview_revert and request_revert share:
// exactly one of the ids names the change, run or task to revert, and the
// optional runs and tables filters narrow it to some of the agent's own
// work in it (RS-1).
type scopeIDs struct {
	ChangeID string   `json:"changeId" validate:"omitempty,uuid"`
	RunID    string   `json:"runId" validate:"omitempty,uuid"`
	TaskID   string   `json:"taskId" validate:"omitempty,uuid"`
	Runs     []string `json:"runs" validate:"omitempty,unique,dive,uuid"`
	Tables   []string `json:"tables" validate:"omitempty,unique"`
}

// filterTable is a schema.table name as the tools' tables filter takes it:
// no whitespace, no semicolon, one dot.
var filterTable = regexp.MustCompile(`^[^.\s;]+\.[^.\s;]+$`)

// hasFilters reports whether the arguments carry a runs or tables filter.
func (a scopeIDs) hasFilters() bool { return a.Runs != nil || a.Tables != nil }

// filtered narrows scope by the runs and tables filters. It refuses what
// the arguments alone show is outside the agent's own work or over the cap;
// whether each run and table is the agent's own Postgres checks, and the
// engine maps its refusal (scopeRefused).
func (a scopeIDs) filtered(scope action.Scope) (action.Scope, error) {
	if a.Runs != nil && scope.Kind != revert.ScopeTask {
		return action.Scope{}, &ArgumentError{Reason: ReasonScopeFilter, Message: "invalid arguments: runs goes only with " +
			"taskId, nothing was prepared: a change or a run is one run already. Narrow it with tables"}
	}
	if len(a.Runs) > revert.MaxFilter || len(a.Tables) > revert.MaxFilter {
		return action.Scope{}, scopeFilterCapped()
	}
	if (a.Runs != nil && len(a.Runs) == 0) || (a.Tables != nil && len(a.Tables) == 0) {
		return action.Scope{}, &ArgumentError{Message: "invalid arguments: runs and tables list at least one entry; leave " +
			"a filter out for all of your work in the scope"}
	}
	for _, t := range a.Tables {
		if !filterTable.MatchString(t) {
			return action.Scope{}, &ArgumentError{Message: "invalid arguments: tables are schema.table names, such as public.leads"}
		}
	}
	for _, id := range a.Runs {
		scope.Runs = append(scope.Runs, uuid.MustParse(id))
	}
	scope.Tables = a.Tables
	return scope, nil
}

// named returns the scopes the arguments name.
func (a scopeIDs) named() []action.Scope {
	var out []action.Scope
	for _, s := range []struct {
		kind revert.Scope
		id   string
	}{{revert.ScopeChange, a.ChangeID}, {revert.ScopeRun, a.RunID}, {revert.ScopeTask, a.TaskID}} {
		if s.id != "" {
			out = append(out, action.Scope{Kind: s.kind, ID: uuid.MustParse(s.id)})
		}
	}
	return out
}

// scope returns the one scope the arguments name.
func (a previewRevertArgs) scope() (action.Scope, error) {
	out := a.named()
	if len(out) != 1 {
		return action.Scope{}, &ArgumentError{Message: "name exactly one of changeId, runId, taskId"}
	}
	return a.filtered(out[0])
}

type revertPreviewResult struct {
	Scope         string          `json:"scope"`
	ScopeID       string          `json:"scopeId"`
	Rows          int             `json:"rows"`
	Skipped       int             `json:"skipped"`
	Items         []revertLineDTO `json:"items"`
	NextCursor    string          `json:"nextCursor,omitempty"`
	PersonMessage string          `json:"personMessage,omitempty"`
	NextSteps     []mcp.NextStep  `json:"nextSteps,omitempty"`
}

// revertLineDTO is one revert line as the tool returns it: the line's
// fields as objects, not the signed text.
type revertLineDTO struct {
	Action    string          `json:"action"`
	Op        string          `json:"op"`
	Table     string          `json:"table"`
	Key       json.RawMessage `json:"key,omitempty"`
	Now       json.RawMessage `json:"now,omitempty"`
	Set       json.RawMessage `json:"set,omitempty"`
	Conflict  string          `json:"conflict,omitempty"`
	SQLState  string          `json:"sqlState,omitempty"`
	Cascaded  bool            `json:"cascaded"`
	Redacted  bool            `json:"redacted,omitempty"`
	RowHash   string          `json:"rowHash,omitempty"`
	ChangeIDs []string        `json:"changeIds"`
	// LargeValues and MoreChangeIDs: what an agent's read left out
	// (CONTRACT.md, Large values).
	LargeValues   []largevalue.Entry `json:"largeValues,omitempty"`
	MoreChangeIDs int                `json:"moreChangeIds,omitempty"`
}

func revertLineFromDomain(l revert.Line) revertLineDTO {
	d := revertLineDTO{
		Action: l.Action, Op: l.Op, Table: l.Table, Key: l.Key, Now: l.Now, Set: l.Set,
		Cascaded: l.Cascaded, Redacted: l.Redacted, RowHash: l.RowHash, ChangeIDs: make([]string, 0, len(l.ChangeIDs)),
		LargeValues: l.LargeValues, MoreChangeIDs: l.MoreChangeIDs,
	}
	if l.Conflict != nil {
		d.Conflict = *l.Conflict
	}
	if l.SQLState != nil {
		d.SQLState = *l.SQLState
	}
	for _, id := range l.ChangeIDs {
		d.ChangeIDs = append(d.ChangeIDs, id.String())
	}
	return d
}

func (h handlers) previewRevert(ctx context.Context, raw json.RawMessage) (any, error) {
	var args previewRevertArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Sort != "" {
		return nil, &ArgumentError{Message: "invalid arguments: preview_revert has no sort; lines come in their signed order"}
	}
	scope, err := args.scope()
	if err != nil {
		return nil, err
	}
	params := PreviewRevertParams{Params: args.Params, Scope: scope}
	params.ApplyDefaultsAndClamp()
	p, err := h.svc.PreviewRevert(ctx, params)
	if err != nil {
		return nil, err
	}
	out := revertPreviewResult{
		Scope: string(p.Scope.Kind), ScopeID: p.Scope.ID.String(), Rows: p.Rows, Skipped: p.Skipped,
		Items: make([]revertLineDTO, 0, len(p.Page.Items)), NextCursor: p.Page.NextCursor,
		PersonMessage: p.PersonMessage, NextSteps: p.NextSteps,
	}
	for _, l := range p.Page.Items {
		out.Items = append(out.Items, revertLineFromDomain(l))
	}
	return out, nil
}

// --- request_revert ---

// requestRevertArgs is the request_revert tool's input
// (api/mcp/tools/request_revert.json): the request form (one scope and an
// intent) or the wait form (revertId).
type requestRevertArgs struct {
	scopeIDs
	Intent           string `json:"intent" validate:"omitempty,max=500"`
	RevertID         string `json:"revertId" validate:"omitempty,uuid"`
	WaitForSignature *int   `json:"waitForSignature" validate:"omitempty,min=0,max=110"`
	ReissueLink      *bool  `json:"reissueLink"`
	Signature        string `json:"signature" validate:"omitempty,max=8192"`
}

// requestScope returns the request form's one scope, checking the
// argument combinations the schema cannot express.
func (a requestRevertArgs) requestScope() (action.Scope, error) {
	if a.WaitForSignature != nil || a.ReissueLink != nil || a.Signature != "" {
		return action.Scope{}, &ArgumentError{Message: "invalid arguments: waitForSignature, reissueLink and signature go only with " +
			"revertId; a new request returns the link at once, for you to show the person before anyone can sign"}
	}
	out := a.named()
	if len(out) != 1 {
		return action.Scope{}, &ArgumentError{Message: "invalid arguments: name exactly one of changeId, runId, taskId (with intent), " +
			"or only revertId"}
	}
	if a.Intent == "" {
		return action.Scope{}, &ArgumentError{Message: "invalid arguments: intent is required with changeId, runId or taskId: why the person " +
			"reverts, in their words, in 1 to 500 characters; it is shown on the revert page they sign"}
	}
	return a.filtered(out[0])
}

// awaitParams is the wait form's arguments as the service takes them. A
// signature or a new link returns at once, so neither takes
// waitForSignature; a signature takes no reissueLink.
func (a requestRevertArgs) awaitParams() (AwaitRevertParams, error) {
	if len(a.named()) > 0 || a.hasFilters() || a.Intent != "" {
		return AwaitRevertParams{}, &ArgumentError{Message: "invalid arguments: revertId takes no changeId, runId, taskId, runs, " +
			"tables or intent; the revert already has them"}
	}
	reissue := a.ReissueLink != nil && *a.ReissueLink
	if a.WaitForSignature != nil && (a.Signature != "" || reissue) {
		return AwaitRevertParams{}, &ArgumentError{Message: "invalid arguments: waitForSignature does not go with signature or " +
			"reissueLink: both return at once (show a new link before waiting for it)"}
	}
	if a.Signature != "" && reissue {
		return AwaitRevertParams{}, &ArgumentError{Message: "invalid arguments: signature does not go with reissueLink"}
	}
	out := AwaitRevertParams{RevertID: uuid.MustParse(a.RevertID), Wait: DefaultRevertWait, Reissue: reissue}
	if a.WaitForSignature != nil {
		out.Wait = time.Duration(*a.WaitForSignature) * time.Second
	}
	if a.Signature == "" {
		return out, nil
	}
	code, err := revert.ParseResponse(a.Signature)
	if err != nil {
		return AwaitRevertParams{}, &ArgumentError{Message: "invalid arguments: signature is not a basalt-revert.1. code the " +
			"revert page shows (" + err.Error() + "); ask the person to copy the whole code. An approval code goes to write's approval"}
	}
	out.Signature = &code
	return out, nil
}

type requestRevertResult struct {
	RevertID      string             `json:"revertId"`
	Status        string             `json:"status"`
	Scope         string             `json:"scope,omitempty"`
	ScopeID       string             `json:"scopeId,omitempty"`
	Widened       bool               `json:"widened,omitempty"`
	Intent        string             `json:"intent"`
	Batched       bool               `json:"batched"`
	Rows          int                `json:"rows"`
	Skipped       int                `json:"skipped"`
	ExpiresAt     string             `json:"expiresAt"`
	RevertURL     string             `json:"revertUrl,omitempty"`
	RequestFile   *links.RequestFile `json:"requestFile,omitempty"`
	PersonMessage string             `json:"personMessage"`
	Links         []mcp.Link         `json:"links,omitempty"`
	ChangeID      string             `json:"changeId,omitempty"`
	ApplyBy       string             `json:"applyBy,omitempty"`
	Progress      *revertProgressDTO `json:"progress,omitempty"`
	RejectedAt    string             `json:"rejectedAt,omitempty"`
	Note          string             `json:"note,omitempty"`
	Receipt       string             `json:"receipt,omitempty"`
	NoReceipt     string             `json:"noReceipt,omitempty"`
	NextSteps     []mcp.NextStep     `json:"nextSteps,omitempty"`
}

type revertProgressDTO struct {
	Restored int `json:"restored"`
	Skipped  int `json:"skipped"`
	Pending  int `json:"pending"`
	Batches  int `json:"batches"`
}

func requestRevertFromDomain(r RequestedRevert) requestRevertResult {
	rv := r.Revert
	out := requestRevertResult{
		RevertID: rv.ID.String(), Status: rv.Status, Scope: rv.Scope, ScopeID: rv.ScopeID.String(),
		Intent: rv.Intent, Batched: rv.Batched, Rows: rv.Rows, Skipped: rv.Skipped,
		ExpiresAt: timeText(rv.ExpiresAt), RevertURL: r.RevertURL, RequestFile: r.RequestFile, PersonMessage: r.PersonMessage, Links: r.Links, NextSteps: r.NextSteps,
	}
	if rv.ChangeID != nil {
		out.ChangeID = rv.ChangeID.String()
	}
	if rv.ApplyBy != nil {
		out.ApplyBy = timeText(*rv.ApplyBy)
	}
	if rv.Widened {
		// Status and totals only: the person's scope is theirs (RS-5).
		out.Widened, out.Scope, out.ScopeID, out.RevertURL, out.RequestFile, out.Links = true, "", "", "", nil, nil
	}
	if rv.RejectedAt != nil {
		out.RejectedAt, out.Note = timeText(*rv.RejectedAt), rv.RejectNote
	}
	if r.Receipt != nil {
		out.Receipt, out.NoReceipt = r.Receipt.Token, r.Receipt.Missing
	}
	if rv.Batched && rv.SignedAt != nil {
		out.Progress = &revertProgressDTO{
			Restored: rv.Progress.Restored, Skipped: rv.Progress.Skipped, Pending: rv.Progress.Pending, Batches: rv.Batches,
		}
	}
	return out
}

// requestRevert serves both forms; a bad argument carries its next step.
func (h handlers) requestRevert(ctx context.Context, raw json.RawMessage) (any, error) {
	return h.requestRevertForm(ctx, raw)
}

func (h handlers) requestRevertForm(ctx context.Context, raw json.RawMessage) (any, error) {
	var args requestRevertArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.RevertID != "" {
		return h.awaitRevert(ctx, args)
	}
	scope, err := args.requestScope()
	if err != nil {
		return nil, err
	}
	r, err := h.svc.RequestRevert(ctx, RequestRevertParams{Scope: scope, Intent: args.Intent})
	if err != nil {
		return nil, err
	}
	return requestRevertFromDomain(r), nil
}

// awaitRevert is request_revert's wait form.
func (h handlers) awaitRevert(ctx context.Context, args requestRevertArgs) (any, error) {
	p, err := args.awaitParams()
	if err != nil {
		return nil, err
	}
	r, err := h.svc.AwaitRevert(ctx, p)
	if err != nil {
		return nil, err
	}
	return requestRevertFromDomain(r), nil
}

// --- revert_plan ---

// revertPlanArgs is the revert_plan tool's input
// (api/mcp/tools/revert_plan.json).
type revertPlanArgs struct {
	pagination.Params
	RevertID string `json:"revertId" validate:"required,uuid"`
	Pending  bool   `json:"pending"`
}

type revertPlanResult struct {
	RevertID      string              `json:"revertId"`
	Status        string              `json:"status"`
	Scope         string              `json:"scope,omitempty"`
	ScopeID       string              `json:"scopeId,omitempty"`
	Widened       bool                `json:"widened,omitempty"`
	Lines         int                 `json:"lines"`
	Restored      int                 `json:"restored"`
	Skipped       int                 `json:"skipped"`
	Pending       int                 `json:"pending"`
	ExpiresAt     string              `json:"expiresAt"`
	ApplyBy       string              `json:"applyBy,omitempty"`
	MaxBatch      int                 `json:"maxBatch"`
	RevertURL     string              `json:"revertUrl,omitempty"`
	RequestFile   *links.RequestFile  `json:"requestFile,omitempty"`
	PersonMessage string              `json:"personMessage,omitempty"`
	Links         []mcp.Link          `json:"links,omitempty"`
	Items         []revertPlanItemDTO `json:"items"`
	NextCursor    string              `json:"nextCursor,omitempty"`
	NextSteps     []mcp.NextStep      `json:"nextSteps,omitempty"`
}

// revertPlanItemDTO is one line of a batched plan: its number, what
// happened to it, and the signed line as an object.
type revertPlanItemDTO struct {
	Line     int            `json:"line"`
	Outcome  string         `json:"outcome"`
	Batch    *int           `json:"batch,omitempty"`
	Conflict string         `json:"conflict,omitempty"`
	SQLState string         `json:"sqlState,omitempty"`
	Plan     *revertLineDTO `json:"plan,omitempty"`
}

func revertPlanFromDomain(p RevertPlan) revertPlanResult {
	r := p.Revert
	out := revertPlanResult{
		RevertID: r.ID.String(), Status: r.Status, Scope: r.Scope, ScopeID: r.ScopeID.String(),
		Lines: r.Rows + r.Skipped, Restored: r.Progress.Restored, Skipped: r.Progress.Skipped, Pending: r.Progress.Pending,
		ExpiresAt: timeText(r.ExpiresAt), MaxBatch: revert.MaxBatch,
		Items: make([]revertPlanItemDTO, 0, len(p.Page.Items)), NextCursor: p.Page.NextCursor,
		RevertURL: p.RevertURL, RequestFile: p.RequestFile, PersonMessage: p.PersonMessage, Links: p.Links, NextSteps: p.NextSteps,
	}
	if r.ApplyBy != nil {
		out.ApplyBy = timeText(*r.ApplyBy)
	}
	if r.Widened {
		// Status and totals only: the person's scope is theirs (RS-5).
		out.Widened, out.Scope, out.ScopeID, out.RevertURL, out.RequestFile, out.Links = true, "", "", "", nil, nil
	}
	for _, l := range p.Page.Items {
		item := revertPlanItemDTO{Line: l.No, Outcome: l.Outcome, Batch: l.Batch, Conflict: l.Conflict, SQLState: l.SQLState}
		if l.Plan != nil {
			d := revertLineFromDomain(*l.Plan)
			item.Plan = &d
		}
		out.Items = append(out.Items, item)
	}
	return out
}

func (h handlers) revertPlan(ctx context.Context, raw json.RawMessage) (any, error) {
	var args revertPlanArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Sort != "" {
		return nil, &ArgumentError{Message: "invalid arguments: revert_plan has no sort; lines come in execution order"}
	}
	params := RevertPlanParams{Params: args.Params, RevertID: uuid.MustParse(args.RevertID)}
	if args.Pending {
		params.Outcome = ledger.OutcomePending
	}
	params.ApplyDefaultsAndClamp()
	p, err := h.svc.RevertPlan(ctx, params)
	if err != nil {
		return nil, err
	}
	return revertPlanFromDomain(p), nil
}

// --- apply_revert_batch ---

// applyRevertBatchArgs is the apply_revert_batch tool's input
// (api/mcp/tools/apply_revert_batch.json).
type applyRevertBatchArgs struct {
	RevertID string `json:"revertId" validate:"required,uuid"`
	Lines    []int  `json:"lines" validate:"required,min=1,max=200,unique,dive,min=1"`
}

type batchResultDTO struct {
	RevertID      string             `json:"revertId"`
	Batch         int                `json:"batch"`
	Status        string             `json:"status"`
	Restored      int                `json:"restored"`
	Skipped       int                `json:"skipped"`
	Pending       int                `json:"pending"`
	Items         []action.BatchItem `json:"items"`
	PersonMessage string             `json:"personMessage,omitempty"`
	NextSteps     []mcp.NextStep     `json:"nextSteps,omitempty"`
}

func (h handlers) applyRevertBatch(ctx context.Context, raw json.RawMessage) (any, error) {
	var args applyRevertBatchArgs
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	res, err := h.svc.ApplyRevertBatch(ctx, ApplyRevertBatchParams{RevertID: uuid.MustParse(args.RevertID), Lines: args.Lines})
	if err != nil {
		return nil, err
	}
	return batchResultDTO{
		RevertID: res.RevertID.String(), Batch: res.Batch, Status: res.Status,
		Restored: res.Restored, Skipped: res.Skipped, Pending: res.Pending, Items: res.Items,
		PersonMessage: res.PersonMessage, NextSteps: res.NextSteps,
	}, nil
}
