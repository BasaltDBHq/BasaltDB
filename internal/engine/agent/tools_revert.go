package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// --- preview_revert ---

// previewRevertArgs is the preview_revert tool's input
// (api/mcp/tools/preview_revert.json).
type previewRevertArgs struct {
	pagination.Params
	ChangeID string `json:"changeId" validate:"omitempty,uuid"`
	RunID    string `json:"runId" validate:"omitempty,uuid"`
	TaskID   string `json:"taskId" validate:"omitempty,uuid"`
}

// scope returns the one scope the arguments name.
func (a previewRevertArgs) scope() (guard.RevertScope, error) {
	var out []guard.RevertScope
	for _, s := range []struct {
		kind revert.Scope
		id   string
	}{{revert.ScopeChange, a.ChangeID}, {revert.ScopeRun, a.RunID}, {revert.ScopeTask, a.TaskID}} {
		if s.id != "" {
			out = append(out, guard.RevertScope{Kind: s.kind, ID: uuid.MustParse(s.id)})
		}
	}
	if len(out) != 1 {
		return guard.RevertScope{}, &ArgumentError{Message: "name exactly one of changeId, runId, taskId"}
	}
	return out[0], nil
}

type revertPreviewResult struct {
	Scope      string          `json:"scope"`
	ScopeID    string          `json:"scopeId"`
	Rows       int             `json:"rows"`
	Skipped    int             `json:"skipped"`
	Command    string          `json:"command"`
	Items      []revertLineDTO `json:"items"`
	NextCursor string          `json:"nextCursor,omitempty"`
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
}

func revertLineFromDomain(l revert.Line) revertLineDTO {
	d := revertLineDTO{
		Action: l.Action, Op: l.Op, Table: l.Table, Key: l.Key, Now: l.Now, Set: l.Set,
		Cascaded: l.Cascaded, Redacted: l.Redacted, RowHash: l.RowHash, ChangeIDs: make([]string, 0, len(l.ChangeIDs)),
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
		Scope: string(p.Scope.Kind), ScopeID: p.Scope.ID.String(), Rows: p.Rows, Skipped: p.Skipped, Command: p.Command,
		Items: make([]revertLineDTO, 0, len(p.Page.Items)), NextCursor: p.Page.NextCursor,
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
	ChangeID         string `json:"changeId" validate:"omitempty,uuid"`
	RunID            string `json:"runId" validate:"omitempty,uuid"`
	Intent           string `json:"intent" validate:"omitempty,max=500"`
	RevertID         string `json:"revertId" validate:"omitempty,uuid"`
	WaitForSignature *int   `json:"waitForSignature" validate:"omitempty,min=0,max=110"`
	ReissueLink      *bool  `json:"reissueLink"`
	Signature        string `json:"signature" validate:"omitempty,max=8192"`
}

// requestScope returns the request form's one scope, checking the
// argument combinations the schema cannot express.
func (a requestRevertArgs) requestScope() (guard.RevertScope, error) {
	if a.WaitForSignature != nil || a.ReissueLink != nil || a.Signature != "" {
		return guard.RevertScope{}, &ArgumentError{Message: "invalid arguments: waitForSignature, reissueLink and signature go only with " +
			"revertId; a new request returns the link at once, for you to show the person before anyone can sign"}
	}
	var out []guard.RevertScope
	for _, s := range []struct {
		kind revert.Scope
		id   string
	}{{revert.ScopeChange, a.ChangeID}, {revert.ScopeRun, a.RunID}} {
		if s.id != "" {
			out = append(out, guard.RevertScope{Kind: s.kind, ID: uuid.MustParse(s.id)})
		}
	}
	if len(out) != 1 {
		return guard.RevertScope{}, &ArgumentError{Message: "invalid arguments: name exactly one of changeId, runId (with intent), or only revertId"}
	}
	if a.Intent == "" {
		return guard.RevertScope{}, &ArgumentError{Message: "invalid arguments: intent is required with changeId or runId: why the person " +
			"reverts, in their words, in 1 to 500 characters; it is shown on the revert page they sign"}
	}
	return out[0], nil
}

// awaitParams is the wait form's arguments as the service takes them. A
// signature or a new link returns at once, so neither takes
// waitForSignature; a signature takes no reissueLink.
func (a requestRevertArgs) awaitParams() (AwaitRevertParams, error) {
	if a.ChangeID != "" || a.RunID != "" || a.Intent != "" {
		return AwaitRevertParams{}, &ArgumentError{Message: "invalid arguments: revertId takes no changeId, runId or intent; the revert already has them"}
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
	Scope         string             `json:"scope"`
	ScopeID       string             `json:"scopeId"`
	Intent        string             `json:"intent"`
	Batched       bool               `json:"batched"`
	Rows          int                `json:"rows"`
	Skipped       int                `json:"skipped"`
	ExpiresAt     string             `json:"expiresAt"`
	RevertURL     string             `json:"revertUrl,omitempty"`
	PersonMessage string             `json:"personMessage"`
	ChangeID      string             `json:"changeId,omitempty"`
	ApplyBy       string             `json:"applyBy,omitempty"`
	Progress      *revertProgressDTO `json:"progress,omitempty"`
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
		ExpiresAt: timeText(rv.ExpiresAt), RevertURL: r.RevertURL, PersonMessage: r.PersonMessage, NextSteps: r.NextSteps,
	}
	if rv.ChangeID != nil {
		out.ChangeID = rv.ChangeID.String()
	}
	if rv.ApplyBy != nil {
		out.ApplyBy = timeText(*rv.ApplyBy)
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
		if hasTaskID(raw) {
			return nil, &ArgumentError{Message: "invalid arguments: " + taskScopeRefused}
		}
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

// hasTaskID reports whether the arguments name a taskId, which
// request_revert refuses with its reason (N12-R7).
func hasTaskID(raw json.RawMessage) bool {
	var probe struct {
		TaskID *json.RawMessage `json:"taskId"`
	}
	return json.Unmarshal(raw, &probe) == nil && probe.TaskID != nil
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
	Scope         string              `json:"scope"`
	ScopeID       string              `json:"scopeId"`
	Lines         int                 `json:"lines"`
	Restored      int                 `json:"restored"`
	Skipped       int                 `json:"skipped"`
	Pending       int                 `json:"pending"`
	ExpiresAt     string              `json:"expiresAt"`
	ApplyBy       string              `json:"applyBy,omitempty"`
	MaxBatch      int                 `json:"maxBatch"`
	RevertURL     string              `json:"revertUrl,omitempty"`
	PersonMessage string              `json:"personMessage,omitempty"`
	Items         []revertPlanItemDTO `json:"items"`
	NextCursor    string              `json:"nextCursor,omitempty"`
}

// revertPlanItemDTO is one line of a batched plan: its number, what
// happened to it, and the signed line as an object.
type revertPlanItemDTO struct {
	Line     int           `json:"line"`
	Outcome  string        `json:"outcome"`
	Batch    *int          `json:"batch,omitempty"`
	Conflict string        `json:"conflict,omitempty"`
	SQLState string        `json:"sqlState,omitempty"`
	Plan     revertLineDTO `json:"plan"`
}

func revertPlanFromDomain(p RevertPlan) revertPlanResult {
	r := p.Revert
	out := revertPlanResult{
		RevertID: r.ID.String(), Status: r.Status, Scope: r.Scope, ScopeID: r.ScopeID.String(),
		Lines: r.Rows + r.Skipped, Restored: r.Progress.Restored, Skipped: r.Progress.Skipped, Pending: r.Progress.Pending,
		ExpiresAt: timeText(r.ExpiresAt), MaxBatch: revert.MaxBatch,
		Items: make([]revertPlanItemDTO, 0, len(p.Page.Items)), NextCursor: p.Page.NextCursor,
		RevertURL: p.RevertURL, PersonMessage: p.PersonMessage,
	}
	if r.ApplyBy != nil {
		out.ApplyBy = timeText(*r.ApplyBy)
	}
	for _, l := range p.Page.Items {
		out.Items = append(out.Items, revertPlanItemDTO{
			Line: l.No, Outcome: l.Outcome, Batch: l.Batch, Conflict: l.Conflict, SQLState: l.SQLState,
			Plan: revertLineFromDomain(l.Plan),
		})
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
	RevertID string            `json:"revertId"`
	Batch    int               `json:"batch"`
	Status   string            `json:"status"`
	Restored int               `json:"restored"`
	Skipped  int               `json:"skipped"`
	Pending  int               `json:"pending"`
	Items    []guard.BatchItem `json:"items"`
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
	}, nil
}
