package storeproof_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/approval/approvaltest"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
)

// schemaTable is a name in Postgres's schema.table form.
var schemaTable = regexp.MustCompile(`^[a-z_]+\.[a-z_]+$`)

// sqlState is a code in the form of a SQLSTATE: five digits or capitals.
var sqlState = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// The requests of the flow, in the store's language: JSON filters, with
// spacing and key order a re-encoding would not keep, so a service that
// rewrote one would be seen.
const (
	findPro     = "{ \"filter\" : {\"plan\": {\"$param\": 0}},\n  \"find\": \"shop/customers\" }"
	upgradeOne  = "{\"update\":\"shop/customers\",  \"filter\":{\"_id\":\"c01\"},\"set\":{\"plan\":\"pro\",\"email\":\"c01.new@corp.ee\"}}"
	upgradeMany = "{\"set\": {\"plan\": \"pro\"}, \"update\": \"shop/customers\", \"filter\": {\"plan\": {\"$param\": 0}}}"
	upgradeTwo  = "{\"update\":\"shop/customers\",\"filter\":{\"_id\":\"c02\"},\"set\":{\"plan\":\"team\"}}"
	closeBatch  = "{\"update\":\"shop/orders\",\"filter\":{\"batch\":{\"$param\":0}},\"set\":{\"status\":\"closed\"}}"
)

// The binding gap: core/approval.ParseBinding reads only request.kind SQL,
// so every service step that parses a held write's binding refuses a
// held request of another family, before the store is asked.
const bindingGap = `binding request kind "DOCUMENT"`

// flow is what the cross-domain flow saw, for the assertions after it.
type flow struct {
	run, bulkRun    agent.RunInfo
	overview        agent.Overview
	held            action.Approval
	heldError       *toolresult.ToolError
	differentWrite  *toolresult.ToolError
	pending         map[string]any
	preview         map[string]any
	revertBinding   revert.Binding
	revertLines     []string
	bulkBinding     revert.Binding
	stepsSeen       []any
	revertPlanItems []map[string]any
}

// One store, every domain: the agent reads, writes and has a write held;
// the person sees the held write and its rows; list_pending lists it; the
// agent reverts its run, and a batched plan of more than a thousand lines;
// all through the services and their ports. Each flexibility assertion is
// its own subtest after the flow.
func TestOneMemoryStoreRunsEveryDomain(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	f := runFlow(t, h)

	t.Run("the request text is a JSON filter that reaches the store byte for byte", func(t *testing.T) {
		require.Equal(t, []string{findPro}, h.store.texts["Read"])
		require.Equal(t, []string{findPro}, h.store.texts["RecordRead"], "the ledger records the agent's own text")
		require.Equal(t, upgradeOne, h.store.texts["Write"][0])
		require.Equal(t, upgradeMany, h.store.texts["Write"][1], "the write the store held")
		require.Equal(t, []string{upgradeMany}, h.store.texts["Preview"])
		require.Equal(t, []string{upgradeMany}, h.store.texts["Hold"])
		require.Equal(t, upgradeMany, f.held.Request.Text)
		require.Equal(t, memRequestKind, f.held.Request.Kind)
		var b struct {
			Request approval.HeldRequest `json:"request"`
		}
		require.NoError(t, json.Unmarshal([]byte(f.held.BindingText), &b))
		require.Equal(t, upgradeMany, b.Request.Statement, "the person signs the agent's own text")
		item := items(t, f.pending)[0]["request"].(map[string]any)
		require.Equal(t, upgradeMany, item["statement"], "list_pending hands back the agent's own text")
		// No service parsed a request: every text the store got, it got as
		// the agent sent it, and only its language read one.
		for port, texts := range h.store.texts {
			for _, text := range texts {
				require.Contains(t, []string{findPro, upgradeOne, upgradeMany, upgradeTwo, closeBatch}, text, port)
			}
		}
		require.NotEmpty(t, h.store.texts["Check"])
	})

	t.Run("the store kind is MEMORY, never POSTGRES", func(t *testing.T) {
		require.Equal(t, string(memKind), f.overview.Store.Kind)
		var b struct {
			Store approval.BindingStore `json:"store"`
		}
		require.NoError(t, json.Unmarshal([]byte(f.held.BindingText), &b))
		require.Equal(t, approval.BindingStore{Kind: string(memKind), Name: memDatabase}, b.Store)
		require.NotContains(t, f.held.BindingText, "POSTGRES")
		for _, text := range f.held.Lines {
			l, err := approval.ParseLine(text)
			require.NoError(t, err)
			require.Equal(t, approval.LineStore{Kind: string(memKind), Verb: memVerbUpdate}, l.Store)
		}
		require.Equal(t, string(memKind), f.revertBinding.Store.Kind)
		require.Equal(t, string(memKind), f.bulkBinding.Store.Kind)
		for _, text := range f.revertLines {
			l, err := revert.ParseLine(text)
			require.NoError(t, err)
			require.Equal(t, string(memKind), l.Store.Kind)
		}
	})

	t.Run("resource names are the store's, not schema.table", func(t *testing.T) {
		names := []string{f.overview.Resources[0].Resource}
		for _, r := range h.store.reads {
			names = append(names, r.Tables...)
		}
		for _, text := range f.held.Lines {
			l, err := approval.ParseLine(text)
			require.NoError(t, err)
			names = append(names, l.Resource)
		}
		for _, it := range items(t, f.preview) {
			require.NotContains(t, it, "table")
			names = append(names, it["resource"].(string))
		}
		names = append(names, f.revertBinding.Select.Resources...)
		for _, it := range f.revertPlanItems {
			require.NotContains(t, it["plan"], "table")
			names = append(names, it["plan"].(map[string]any)["resource"].(string))
		}
		for _, n := range names {
			require.NotRegexp(t, schemaTable, n)
			require.Regexp(t, memResourceName, n)
		}
	})

	t.Run("next steps name the family's argument q, never sql", func(t *testing.T) {
		require.Equal(t, guidance.ReasonDifferentWrite, f.differentWrite.Reason)
		step := f.differentWrite.NextSteps[0]
		require.Equal(t, guidance.ToolWrite, step.Tool)
		require.Equal(t, upgradeMany, step.Arguments[argQuery])
		require.Equal(t, []any{"trial"}, step.Arguments["params"])
		require.NotEmpty(t, f.stepsSeen)
		for _, steps := range append(f.stepsSeen, f.differentWrite.NextSteps, f.heldError.NextSteps) {
			requireNoSQLArgument(t, steps)
		}
	})
}

// runFlow drives every domain through the flow, asserting each answer as
// the agent or the person gets it.
func runFlow(t *testing.T, h *harness) flow {
	t.Helper()
	ctx := context.Background()
	var f flow
	var err error

	f.overview, err = h.agent.DescribeOverview(ctx)
	require.NoError(t, err)
	f.run, err = h.agent.StartRun(ctx, "move trial customers to pro", uuid.Nil)
	require.NoError(t, err)

	// Read: the agent's JSON filter, run by the store. The values of
	// IDENTIFIER fields reach the dictionary before the rows leave, a JSON
	// string as its text.
	got, err := h.agent.Query(ctx, agent.QueryParams{Request: agentstore.Request{Text: findPro, Params: []any{"pro"}}, RunID: f.run.RunID})
	require.NoError(t, err)
	require.Len(t, got.Rows, 1)
	require.Equal(t, "c00", got.Rows[0]["_id"])
	require.Equal(t, []string{colCustomers}, h.store.reads[0].Tables)
	require.True(t, h.hasEmail("c00@example.com"))
	require.True(t, h.hasEmail("c00.alias@example.com"), "a JSON string reaches the dictionary unquoted")
	require.False(t, h.hasEmail(`"c00.alias@example.com"`))

	// Write: applied at once. The store hands the returned documents to
	// the observer before it keeps the write.
	w, err := h.agent.Write(ctx, agent.WriteParams{Request: agentstore.Request{Text: upgradeOne}, Intent: "upgrade c01", RunID: f.run.RunID})
	require.NoError(t, err)
	require.Equal(t, 1, w.Rows)
	require.Equal(t, action.OpUpdate, w.Op)
	require.True(t, h.hasEmail("c01.new@corp.ee"), "a returned value reaches the dictionary")

	// A write over the store's limit: held for the person.
	many := agentstore.Request{Text: upgradeMany, Params: []any{"trial"}}
	_, err = h.agent.Write(ctx, agent.WriteParams{Request: many, Intent: "upgrade every trial", RunID: f.run.RunID})
	f.heldError = h.agent.Failure(guidance.ToolWrite, nil, err)
	require.Equal(t, guidance.CodeApprovalRequired, f.heldError.Code, "%+v", f.heldError)
	require.Equal(t, guidance.ReasonHeld, f.heldError.Reason)
	id := uuid.MustParse(f.heldError.Approval.ApprovalID)
	f.held, err = h.store.FindApproval(ctx, id)
	require.NoError(t, err)
	require.Equal(t, memHeldOver+1, f.held.Rows)
	require.Equal(t, approval.RowsHash(f.held.Lines), bindingRowsHash(t, f.held.BindingText))

	// The agent sends another write with the approval: refused, with the
	// held write's own request as the family's tools take it.
	_, err = h.agent.Write(ctx, agent.WriteParams{
		Request: agentstore.Request{Text: upgradeTwo}, Intent: "upgrade every trial", RunID: f.run.RunID, ApprovalID: id,
	})
	f.differentWrite = h.agent.Failure(guidance.ToolWrite, nil, err)

	// list_pending: the held write, with what the agent hands the person.
	f.pending = h.mustCall(guidance.ToolListPending, map[string]any{})
	listed := items(t, f.pending)
	require.Len(t, listed, 1)
	require.Equal(t, id.String(), listed[0]["approvalId"])
	require.Equal(t, memRequestKind, listed[0]["request"].(map[string]any)["kind"])
	f.stepsSeen = append(f.stepsSeen, listed[0]["nextSteps"])

	// The person's page reads the request: the binding and lines the
	// store wrote, in its kind and names.
	_, secret := pageID(t, f.heldError.Approval.ApprovalURL)
	req, err := h.approval.ApprovalRequest(ctx, id)
	require.NoError(t, err)
	require.Equal(t, f.held.Lines, req.Lines)

	// Store-neutrality gap: the page's check, the reveal, the receipt and
	// the apply each parse the binding, and ParseBinding refuses a held
	// request that is not SQL. Until the request families reach
	// core/approval, the person cannot sign it and the agent cannot apply
	// it. These assertions pin where the flow stops.
	_, err = req.Check()
	require.ErrorContains(t, err, bindingGap, "the page's check")

	revealSecret := base64.RawURLEncoding.EncodeToString([]byte("sixteen bytes!!!"))
	_, err = h.approval.RevealApproval(ctx, id, secret, linksvc.RevealRequest{RevealSecret: revealSecret})
	require.ErrorContains(t, err, bindingGap, "the reveal reads the held write from the binding")
	require.Zero(t, h.store.calledTimes("RevealHeld"), "the reveal never reached the store")

	_, err = h.approval.RelayApproval(ctx, approvaltest.NewResponse(id, personAssertion(req.Binding)))
	require.ErrorContains(t, err, bindingGap, "the receipt reads the binding")
	approved, err := h.store.FindApproval(ctx, id)
	require.NoError(t, err)
	require.Equal(t, action.ApprovalApproved, approved.Status, "the store checked the person's signature itself and accepted it")

	_, err = h.agent.Write(ctx, agent.WriteParams{Request: many, Intent: "upgrade every trial", RunID: f.run.RunID, ApprovalID: id})
	require.ErrorContains(t, err, bindingGap, "the apply's receipt reads the binding")
	require.Empty(t, h.store.texts["WriteApproved"], "nothing was applied")

	// The agent reverts the run's applied write: preview, request, the
	// person's signature, the outcome.
	scope := map[string]any{"runId": f.run.RunID.String(), "resources": []string{colCustomers}}
	f.preview = h.mustCall(guidance.ToolPreviewRevert, scope)
	require.EqualValues(t, 1, f.preview["rows"])
	f.stepsSeen = append(f.stepsSeen, f.preview["nextSteps"])
	requested := h.mustCall(guidance.ToolRequestRevert, map[string]any{
		"runId": f.run.RunID.String(), "resources": []string{colCustomers}, "intent": "the upgrade was a mistake",
	})
	require.Equal(t, action.RevertPending, requested["status"])
	require.Equal(t, []time.Duration{memPrepareLimit}, h.store.prepareLimits, "the store gets its own time limit")
	f.stepsSeen = append(f.stepsSeen, requested["nextSteps"])
	revReq, b, applied, err := h.personSignsRevert(requested["revertUrl"].(string))
	require.NoError(t, err)
	f.revertBinding, f.revertLines = b, revReq.Lines
	require.Equal(t, []string{colCustomers}, b.Select.Resources)
	require.Equal(t, 1, applied.Rows)
	done := h.mustCall(guidance.ToolRequestRevert, map[string]any{"revertId": requested["revertId"], "waitForSignature": 0})
	require.Equal(t, action.RevertApplied, done["status"])
	require.Equal(t, "trial", h.store.doc(colCustomers, "c01")["plan"])
	require.Equal(t, "c01@example.com", h.store.doc(colCustomers, "c01")["email"])

	f.bulkRun, f.bulkBinding, f.revertPlanItems, f.stepsSeen = runBatchedRevert(t, h, f.stepsSeen)
	return f
}

// bulkOrders is how many orders the bulk run closes: a plan of more than
// revert.MaxLines lines, applied in batches.
const bulkOrders = 1100

// runBatchedRevert closes every order in batches of ten (none is held),
// then reverts the run: the plan is batched, the person signs its sample,
// and the agent applies it batch by batch, following the engine's steps.
func runBatchedRevert(t *testing.T, h *harness, seen []any) (agent.RunInfo, revert.Binding, []map[string]any, []any) {
	t.Helper()
	ctx := context.Background()
	for i := range bulkOrders {
		h.store.seed(colOrders, map[string]any{"_id": fmt.Sprintf("o%04d", i), "status": "open", "batch": float64(i / memHeldOver)})
	}
	run, err := h.agent.StartRun(ctx, "close every order", uuid.Nil)
	require.NoError(t, err)
	for b := range bulkOrders / memHeldOver {
		w, err := h.agent.Write(ctx, agent.WriteParams{
			Request: agentstore.Request{Text: closeBatch, Params: []any{float64(b)}}, Intent: "close a batch of orders", RunID: run.RunID,
		})
		require.NoError(t, err)
		require.Equal(t, memHeldOver, w.Rows)
	}
	// A person reopened one order after the agent: its line is skipped.
	h.store.personWrite(colOrders, "o0500", map[string]any{"_id": "o0500", "status": "reopened", "batch": float64(50)})

	requested := h.mustCall(guidance.ToolRequestRevert, map[string]any{"runId": run.RunID.String(), "intent": "the orders were closed by mistake"})
	require.Equal(t, true, requested["batched"])
	require.EqualValues(t, bulkOrders-1, requested["rows"])
	require.EqualValues(t, 1, requested["skipped"])
	req, b, applied, err := h.personSignsRevert(requested["revertUrl"].(string))
	require.NoError(t, err)
	require.True(t, b.Batched)
	require.Len(t, req.Lines, revert.MaxLines)
	require.Equal(t, approval.RowsHash(req.Lines), b.SampleHash)
	require.Equal(t, bulkOrders, applied.Pending)

	answer := h.mustCall(guidance.ToolRequestRevert, map[string]any{"revertId": requested["revertId"], "waitForSignature": 0})
	require.Equal(t, action.RevertApplying, answer["status"])
	var planItems, batched []map[string]any
	for step := callStep(answer); step != nil; step = callStep(answer) {
		require.Less(t, len(seen), 40, "the plan ends")
		seen = append(seen, answer["nextSteps"])
		answer = h.mustCall(step["tool"].(string), step["arguments"].(map[string]any))
		switch step["tool"] {
		case guidance.ToolRevertPlan:
			planItems = append(planItems, items(t, answer)...)
		case guidance.ToolApplyRevertBatch:
			batched = append(batched, items(t, answer)...)
		}
	}
	require.Equal(t, action.RevertApplied, answer["status"])
	require.Len(t, batched, bulkOrders)
	require.EqualValues(t, bulkOrders-1, answer["restored"])
	require.EqualValues(t, 1, answer["skipped"])
	require.Equal(t, "open", h.store.doc(colOrders, "o0000")["status"])
	require.Equal(t, "reopened", h.store.doc(colOrders, "o0500")["status"], "people win")
	return run, b, planItems, seen
}

// bindingRowsHash is a binding text's rowsHash.
func bindingRowsHash(t *testing.T, binding string) string {
	t.Helper()
	var b struct {
		RowsHash string `json:"rowsHash"`
	}
	require.NoError(t, json.Unmarshal([]byte(binding), &b))
	return b.RowsHash
}

// requireNoSQLArgument fails when any step's arguments name sql, at any
// depth.
func requireNoSQLArgument(t *testing.T, steps any) {
	t.Helper()
	raw, err := json.Marshal(steps)
	require.NoError(t, err)
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	var walkArgs func(any)
	walkArgs = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if args, ok := x["arguments"].(map[string]any); ok {
				require.NotContains(t, args, "sql", "a step names the SQL family's argument: %v", x)
			}
			for _, e := range x {
				walkArgs(e)
			}
		case []any:
			for _, e := range x {
				walkArgs(e)
			}
		}
	}
	walkArgs(v)
}

// refusalCase is one refusal of the store: how the agent or the person
// runs into it, and the store's own text and code for it next to
// Postgres's.
type refusalCase struct {
	name string
	// own and pg are the text the answer's message shows, the memory
	// store's and the Postgres adapter's ("" when the message shows none);
	// code and pgCode the store codes.
	own, pg      string
	code, pgCode string
	run          func(h *harness) *toolresult.ToolError
}

func refusalCases() []refusalCase {
	startRun := func(h *harness) uuid.UUID {
		run, err := h.agent.StartRun(context.Background(), "undo it", uuid.Nil)
		require.NoError(h.t, err)
		return run.RunID
	}
	revertCall := func(tool string, args func(h *harness) map[string]any) func(h *harness) *toolresult.ToolError {
		return func(h *harness) *toolresult.ToolError {
			a := args(h)
			if tool == guidance.ToolRequestRevert {
				a["intent"] = "undo it"
			}
			_, te := h.call(tool, a)
			return te
		}
	}
	return []refusalCase{
		{
			name: "query: the store's time limit", code: codeDeadline, pgCode: postgresTimeout.StoreCode,
			own: "the find ran past the store's deadline", pg: postgresTimeout.Message,
			run: func(h *harness) *toolresult.ToolError {
				h.store.mu.Lock()
				h.store.slowReads = true
				h.store.mu.Unlock()
				run := startRun(h)
				_, err := h.agent.Query(context.Background(), agent.QueryParams{Request: agentstore.Request{Text: findPro, Params: []any{"pro"}}, RunID: run})
				return h.agent.Failure(guidance.ToolQuery, nil, err)
			},
		},
		{
			name: "request_revert: a resource name the store cannot use",
			own:  memFilterNameDetail, pg: postgresRefusalOf(action.RevertFilterName).detail,
			run: revertCall(guidance.ToolRequestRevert, func(h *harness) map[string]any {
				return map[string]any{"runId": writtenRun(h).String(), "resources": []string{"public.customers"}}
			}),
		},
		{
			name: "preview_revert: a resource the agent did not write",
			own:  "shop/orders has no change of yours in this run", pg: postgresRefusalOf(action.RevertFilter).detail,
			run: revertCall(guidance.ToolPreviewRevert, func(h *harness) map[string]any {
				return map[string]any{"runId": writtenRun(h).String(), "resources": []string{colOrders}}
			}),
		},
		{
			name: "request_revert: a run with no change of the agent's",
			run: revertCall(guidance.ToolRequestRevert, func(h *harness) map[string]any {
				return map[string]any{"runId": startRun(h).String()}
			}),
		},
		{
			name: "request_revert: the store's time limit", code: codeDeadline, pgCode: "57014",
			run: revertCall(guidance.ToolRequestRevert, func(h *harness) map[string]any {
				require.NoError(h.t, h.store.StartRun(context.Background(), action.Intent{RunID: slowRun, Text: "slow"}))
				return map[string]any{"runId": slowRun.String()}
			}),
		},
		{
			name: "the person's approval: a signature the store does not accept", code: codeSignature, pgCode: postgresBadSignature.StoreCode,
			own: "the passkey's signature does not match the held write", pg: postgresBadSignature.Message,
			run: func(h *harness) *toolresult.ToolError {
				id := heldWrite(h)
				_, err := h.approval.RelayApproval(context.Background(), approvaltest.NewResponse(id, personAssertion("another binding")))
				return h.delivery.PageFailure(err)
			},
		},
	}
}

// withoutIDs is te with the ids of the runs and held writes the harness
// made replaced by their kind, so two harnesses' answers compare.
func (h *harness) withoutIDs(te *toolresult.ToolError) *toolresult.ToolError {
	h.t.Helper()
	if te == nil {
		return nil
	}
	raw, err := json.Marshal(te)
	require.NoError(h.t, err)
	text := string(raw)
	h.store.mu.Lock()
	for id := range h.store.runs {
		text = strings.ReplaceAll(text, id.String(), "RUN")
	}
	for id := range h.store.approvals {
		text = strings.ReplaceAll(text, id.String(), "APPROVAL")
	}
	h.store.mu.Unlock()
	var out toolresult.ToolError
	require.NoError(h.t, json.Unmarshal([]byte(text), &out))
	return &out
}

// writtenRun is a run in which the agent changed one customer.
func writtenRun(h *harness) uuid.UUID {
	ctx := context.Background()
	run, err := h.agent.StartRun(ctx, "upgrade c01", uuid.Nil)
	require.NoError(h.t, err)
	_, err = h.agent.Write(ctx, agent.WriteParams{Request: agentstore.Request{Text: upgradeOne}, Intent: "upgrade c01", RunID: run.RunID})
	require.NoError(h.t, err)
	return run.RunID
}

// heldWrite is a write the store held for the person.
func heldWrite(h *harness) uuid.UUID {
	ctx := context.Background()
	run, err := h.agent.StartRun(ctx, "upgrade every trial", uuid.Nil)
	require.NoError(h.t, err)
	_, err = h.agent.Write(ctx, agent.WriteParams{Request: agentstore.Request{Text: upgradeMany, Params: []any{"trial"}}, Intent: "upgrade every trial", RunID: run.RunID})
	te := h.agent.Failure(guidance.ToolWrite, nil, err)
	require.Equal(h.t, guidance.CodeApprovalRequired, te.Code)
	return uuid.MustParse(te.Approval.ApprovalID)
}

// Each refusal of the memory store gives the agent and the person the
// answer the same refusal of the Postgres store gives: the same code,
// reason, steps and person's message, with the store's own text where the
// message shows it and the store's own code, never a SQLSTATE.
func TestMemoryStoreRefusalsGiveThePostgresAnswers(t *testing.T) {
	t.Parallel()
	for _, c := range refusalCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			mem := newHarness(t)
			got := mem.withoutIDs(c.run(mem))
			require.NotNil(t, got, "the store refused")
			pg := newHarness(t, func(s *memStore) { s.asPostgres = true })
			want := pg.withoutIDs(c.run(pg))
			require.NotNil(t, want)

			require.NotEqual(t, guidance.CodeInternal, got.Code, "a refusal, not an engine error: %+v", got)
			require.Equal(t, want.Code, got.Code)
			require.Equal(t, want.Reason, got.Reason)
			require.Equal(t, want.PersonMessage, got.PersonMessage)
			require.Equal(t, want.NextSteps, got.NextSteps)
			wantMessage := want.Message
			if c.own != "" {
				require.Contains(t, want.Message, c.pg)
				require.Contains(t, got.Message, c.own, "the store's own text, verbatim")
				wantMessage = strings.ReplaceAll(want.Message, c.pg, c.own)
			}
			require.Equal(t, wantMessage, got.Message)
			require.Equal(t, c.pgCode, want.StoreCode)
			require.Equal(t, c.code, got.StoreCode, "the store's own code, passed on as it is")
			if got.StoreCode != "" {
				require.NotRegexp(t, sqlState, got.StoreCode, "a store code is the store's word, not a SQLSTATE")
			}
			requireNoSQLArgument(t, got.NextSteps)
		})
	}
}
