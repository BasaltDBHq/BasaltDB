package agent_test

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// This file drives the agent service through its ports only, over a
// document store that is not SQL: requests are JSON filters, resources are
// collections named "namespace/name", and fields are refs the store makes
// up. If the service read a request's text, parsed a resource name or
// assumed a catalog of tables, these tests would fail.

const (
	docFamily    agentstore.Family = "DOCUMENT"
	docStoreKind action.StoreKind  = "DOCSTORE"
	// docHeldOver is the most items a write changes without a hold.
	docHeldOver = 10
)

// docRequest is the document store's language: one JSON object. Find reads,
// update sets fields. A filter value {"$param": n} is the request's n-th
// parameter.
type docRequest struct {
	Find   string         `json:"find,omitempty"`
	Update string         `json:"update,omitempty"`
	Filter map[string]any `json:"filter"`
	Set    map[string]any `json:"set,omitempty"`
}

// docLanguage checks and names requests of the document store.
type docLanguage struct{}

var errDocWrongTool = &action.RefusalError{Reason: action.ReasonWrongTool, Detail: "a find runs with query, an update with write"}

func parseDoc(req agentstore.Request) (docRequest, error) {
	var r docRequest
	if err := json.Unmarshal([]byte(req.Text), &r); err != nil {
		return docRequest{}, &action.RefusalError{Reason: action.ReasonParseError, Detail: "not a JSON request"}
	}
	return r, nil
}

func (docLanguage) Check(req agentstore.Request, tool action.Tool) (action.Statement, error) {
	r, err := parseDoc(req)
	if err != nil {
		return action.Statement{}, err
	}
	switch {
	case r.Find != "" && tool == action.ToolQuery:
		return action.Statement{Op: action.OpSelect, Tables: []string{r.Find}, Handle: r}, nil
	case r.Update != "" && tool == action.ToolWrite:
		return action.Statement{Op: action.OpUpdate, Tables: []string{r.Update}, Handle: r}, nil
	}
	return action.Statement{}, errDocWrongTool
}

func (docLanguage) RefusalText(string) (string, bool) { return "", false }
func (docLanguage) LimitText(string) string           { return "narrow the filter" }

func (docLanguage) ReadRow(target string, key map[string]any) agentstore.Request {
	raw, err := json.Marshal(docRequest{Find: target, Filter: key})
	if err != nil {
		return agentstore.Request{}
	}
	return agentstore.Request{Text: string(raw)}
}

func (docLanguage) StaleTarget(string) (string, map[string]any, error) {
	return "", nil, errors.New("the document store reports no stale reads")
}
func (docLanguage) DeniedTarget(string) (string, bool) { return "", false }
func (docLanguage) NoKeyTarget(string) (string, bool)  { return "", false }

func (docLanguage) ParseName(s string) (string, string, error) {
	ns, name, ok := strings.Cut(s, "/")
	if !ok || ns == "" || name == "" {
		return "", "", errors.New("must be namespace/collection")
	}
	return ns, name, nil
}

func (docLanguage) PrintName(namespace, name string) string { return namespace + "/" + name }

// docStore is the documents, the catalog, the ledger and the PII classes of
// one document store, in memory.
type docStore struct {
	mu          sync.Mutex
	collections map[string][]map[string]any
	runs        map[uuid.UUID]action.Run
	reads       []action.Read
	refusals    []action.Refusal
	classes     map[agentstore.FieldRef]pii.Class
	// shortClasses makes Resolve drop the last class.
	shortClasses bool
	// flags are added to the detail's flags.
	flags map[string]any
	// ssnDisplay is the display of the SECRET field ssn.
	ssnDisplay any
}

// docOption edits the document store before the service is built on it.
type docOption func(*docStore)

func newDocStore() *docStore {
	s := &docStore{
		collections: map[string][]map[string]any{},
		runs:        map[uuid.UUID]action.Run{},
		classes: map[agentstore.FieldRef]pii.Class{
			"customers#ssn":   {Class: guardmodel.ClassSecret},
			"customers#email": {Class: guardmodel.ClassIdentifier, EntityType: "EMAIL"},
		},
	}
	for i := range docHeldOver + 3 { // one pro, one upgraded alone, eleven held
		s.collections["customers"] = append(s.collections["customers"], map[string]any{
			"_id": fmt.Sprintf("c%02d", i), "email": fmt.Sprintf("c%02d@example.com", i), "plan": "trial", "ssn": "000-00-0000",
		})
	}
	s.collections["customers"][0]["plan"] = "pro"
	return s
}

func (s *docStore) match(r docRequest, params []any) []map[string]any {
	var out []map[string]any
	for _, doc := range s.collections[cmp.Or(r.Find, r.Update)] {
		ok := true
		for k, want := range r.Filter {
			if p, isParam := want.(map[string]any); isParam {
				want = params[int(p["$param"].(float64))]
			}
			ok = ok && doc[k] == want
		}
		if ok {
			out = append(out, doc)
		}
	}
	return out
}

// Data

func (s *docStore) Read(_ context.Context, req agentstore.Request, stmt action.Statement) (action.ReadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	docs := s.match(stmt.Handle.(docRequest), req.Params)
	res := action.ReadResult{Columns: []action.Column{{Name: "_id"}, {Name: "plan"}}}
	for _, d := range docs {
		res.Rows = append(res.Rows, map[string]any{"_id": d["_id"], "plan": d["plan"]})
	}
	return res, nil
}

func (s *docStore) Write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement) (action.WriteResult, error) {
	return s.write(req, stmt, false)
}

func (s *docStore) WriteApproved(_ context.Context, _ action.Intent, _ uuid.UUID, req agentstore.Request, stmt action.Statement) (action.WriteResult, error) {
	return s.write(req, stmt, true)
}

func (s *docStore) write(req agentstore.Request, stmt action.Statement, approved bool) (action.WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := stmt.Handle.(docRequest)
	docs := s.match(r, req.Params)
	if len(docs) > docHeldOver && !approved {
		return action.WriteResult{}, action.ErrApprovalRequired
	}
	for _, d := range docs {
		maps.Copy(d, r.Set)
	}
	return action.WriteResult{ChangeID: uuid.Must(uuid.NewV7()), Rows: len(docs)}, nil
}

func (s *docStore) Limits() action.Limits {
	return action.Limits{StatementTimeout: 5 * time.Second, ReadRowLimit: 100}
}

// Catalog: one collection, customers, in namespace shop.

func (s *docStore) customers() agentstore.Resource {
	n := int64(len(s.collections["customers"]))
	return agentstore.Resource{
		Ref: "customers", Namespace: "shop", Name: "customers", Kind: "COLLECTION", Estimate: &n,
		Actions: []action.Op{action.OpSelect, action.OpUpdate},
	}
}

func (s *docStore) Resources(context.Context) ([]agentstore.Resource, int, error) {
	return []agentstore.Resource{s.customers()}, 0, nil
}

func (s *docStore) Find(_ context.Context, namespace, name string) (agentstore.Resource, bool, error) {
	if namespace != "shop" || name != "customers" {
		return agentstore.Resource{}, false, nil
	}
	return s.customers(), true, nil
}

// docIndex is an index as the document store shows it.
type docIndex struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

func (s *docStore) Describe(_ context.Context, ref agentstore.ResourceRef) (agentstore.Detail, error) {
	if ref != "customers" {
		return agentstore.Detail{}, action.ErrNotFound
	}
	field := func(name string) agentstore.Field {
		return agentstore.Field{Ref: agentstore.FieldRef("customers#" + name), Name: name, Type: "string", Readable: true}
	}
	f := func(name string) agentstore.FieldRef { return agentstore.FieldRef("customers#" + name) }
	ssn := field("ssn")
	ssn.Display = s.ssnDisplay
	flags := map[string]any{"sharded": false}
	maps.Copy(flags, s.flags)
	return agentstore.Detail{
		Resource: s.customers(),
		Fields:   []agentstore.Field{field("_id"), field("email"), field("plan"), ssn},
		Identity: []agentstore.FieldRef{f("_id")},
		Groups:   []string{"searchIndexes"},
		Features: []agentstore.Feature{
			{Group: "searchIndexes", Touches: []agentstore.FieldRef{f("email")}, Visible: true, Display: docIndex{Name: "by_email", Fields: []string{"email"}}},
			{Group: "searchIndexes", Touches: []agentstore.FieldRef{f("plan"), f("ssn")}, Visible: true, Display: docIndex{Name: "by_plan_ssn", Fields: []string{"plan", "ssn"}}},
		},
		Flags: flags,
	}, nil
}

func (s *docStore) Guarded(context.Context, agentstore.ResourceRef) (bool, error) { return true, nil }

func (s *docStore) Search(context.Context, string, []agentstore.FieldRef, *agentstore.Cursor, int) ([]agentstore.Match, error) {
	return []agentstore.Match{{Resource: s.customers(), Matched: "table"}}, nil
}

func (s *docStore) Structure(context.Context) ([]string, error) {
	return []string{"shop/customers _id email plan"}, nil
}

func (s *docStore) Database() string { return "shop" }
func (s *docStore) Host() string     { return "docs.example.com" }

// Ledger

func (s *docStore) FindRun(_ context.Context, id uuid.UUID) (action.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return action.Run{}, action.ErrRunNotFound
	}
	return r, nil
}

func (s *docStore) StartRun(_ context.Context, in action.Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[in.RunID] = action.Run{ID: in.RunID, TaskID: in.TaskID, Intent: in.Text}
	return nil
}

func (s *docStore) RecordRead(_ context.Context, r action.Read) (uuid.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, r)
	return uuid.Must(uuid.NewV7()), nil
}

func (s *docStore) RecordRefusal(_ context.Context, r action.Refusal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusals = append(s.refusals, r)
	return nil
}

func (s *docStore) ListRuns(context.Context, action.RunListParams) (pagination.Page[action.RunSummary], error) {
	return pagination.Page[action.RunSummary]{}, nil
}

// docClasses are the store's PII classes: a separate type, as Resolve and
// the catalog's Describe would clash on one.
type docClasses struct{ s *docStore }

func (c docClasses) Resolve(_ context.Context, refs []agentstore.FieldRef) ([]pii.Class, error) {
	out := make([]pii.Class, 0, len(refs))
	for _, r := range refs {
		out = append(out, c.s.classes[r])
	}
	if c.s.shortClasses {
		out = out[:len(out)-1]
	}
	return out, nil
}

func (c docClasses) Secrets(context.Context) ([]agentstore.FieldRef, error) {
	var out []agentstore.FieldRef
	for r, cl := range c.s.classes {
		if cl.Class == guardmodel.ClassSecret {
			out = append(out, r)
		}
	}
	return out, nil
}

func (docClasses) CatalogFingerprint(context.Context) (string, error) { return "docs-pii-1", nil }

// docApprovals holds writes and plays the person who signs them: AwaitWhile
// approves the held write and lets the service read it again.
type docApprovals struct {
	mu        sync.Mutex
	approvals map[uuid.UUID]action.Approval
	notified  []linksvc.HeldNotice
	preview   func(req agentstore.Request) []string
}

var errNoApproval = errors.New("no such approval")

func (a *docApprovals) ApprovalNotice(_ context.Context, id, _ uuid.UUID, req linksvc.SizedRequest, expires time.Time, _ bool) (linksvc.HeldAnswer, error) {
	return linksvc.HeldAnswer{
		ApprovalNotice: toolresult.ApprovalNotice{
			ApprovalID: id.String(), ExpiresAt: expires.UTC().Format(time.RFC3339), Rows: len(req.Lines),
			Headline: "update customers", ApprovalURL: "https://approve.example/" + id.String(), PersonMessage: "Approve it.",
		},
		LongURL: "https://approve.example/" + id.String(), Reason: guidance.ReasonHeld,
	}, nil
}

func (a *docApprovals) HoldColumns(context.Context, agentstore.Request) ([]string, error) {
	return nil, nil
}

func (a *docApprovals) Preview(_ context.Context, _ action.Intent, req agentstore.Request, _ []string) ([]string, error) {
	return a.preview(req), nil
}

func (a *docApprovals) Hold(_ context.Context, in action.Intent, r action.HoldRequest) (action.Held, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	params, err := json.Marshal(r.Params)
	if err != nil {
		return action.Held{}, err
	}
	id := uuid.Must(uuid.NewV7())
	expires := time.Now().Add(time.Hour)
	a.approvals[id] = action.Approval{
		ID: id, RunID: in.RunID, Intent: in.Text, Statement: r.Statement, Params: params, Rows: len(r.Lines),
		Status: action.ApprovalPending, ExpiresAt: expires, Lines: r.Lines, BindingText: "binding",
	}
	return action.Held{ApprovalID: id, BindingText: "binding", ExpiresAt: expires}, nil
}

func (a *docApprovals) FindApproval(_ context.Context, id uuid.UUID) (action.Approval, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ap, ok := a.approvals[id]
	if !ok {
		return action.Approval{}, errNoApproval
	}
	return ap, nil
}

func (a *docApprovals) NotFound() error { return errNoApproval }

func (a *docApprovals) HoldTooLargeSteps(*guidance.Steps, *toolresult.ToolError) string { return "" }

func (a *docApprovals) ApprovalRequiredSteps(*guidance.Steps, *toolresult.ToolError) string {
	return ""
}

// Delivery: the person signs every held write the moment the service waits.

func (a *docApprovals) ApprovalReceiptOf(ap action.Approval) (linksvc.Receipt, error) {
	return linksvc.Receipt{Token: "receipt-" + ap.ID.String()}, nil
}

func (a *docApprovals) AwaitWhile(ctx context.Context, _ time.Duration, pending func() bool, refresh func(context.Context) error) error {
	a.mu.Lock()
	for id, ap := range a.approvals {
		if ap.Status == action.ApprovalPending {
			ap.Status = action.ApprovalApproved
			a.approvals[id] = ap
		}
	}
	a.mu.Unlock()
	if err := refresh(ctx); err != nil {
		return err
	}
	if pending() {
		return errors.New("still pending after the person signed")
	}
	return nil
}

func (a *docApprovals) DeliverHeld(uuid.UUID, time.Time, error) {}

func (a *docApprovals) NotifyHeldTo(_ context.Context, n linksvc.HeldNotice) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.notified = append(a.notified, n)
	return nil
}

// The upgrade warnings, the approval link and the UNAVAILABLE steps, which
// these tests never reach but the service is given.

func (a *docApprovals) UpgradeWarnings(context.Context) []toolresult.Warning { return nil }

func (a *docApprovals) ApprovalLinkError(te *toolresult.ToolError, _ linksvc.HeldAnswer) *toolresult.ToolError {
	return te
}

func (a *docApprovals) UnavailableSteps(*guidance.Steps, *toolresult.ToolError, guidance.Failure) string {
	return ""
}

// newDocService is the agent service over the document store, built with
// its ports only.
func newDocService(t *testing.T, opts ...docOption) (*agent.Service, *docStore, *docApprovals) {
	t.Helper()
	store := newDocStore()
	for _, opt := range opts {
		opt(store)
	}
	approvals := &docApprovals{approvals: map[uuid.UUID]action.Approval{}}
	approvals.preview = func(req agentstore.Request) []string {
		r, err := parseDoc(req)
		require.NoError(t, err)
		store.mu.Lock()
		defer store.mu.Unlock()
		docs := store.match(r, req.Params)
		lines := make([]string, 0, len(docs))
		for _, d := range docs {
			lines = append(lines, fmt.Sprintf("customers %v: plan %v -> %v", d["_id"], d["plan"], r.Set["plan"]))
		}
		return lines
	}
	svc := agent.New(
		agent.Core{Name: "docbot", Log: slog.New(slog.DiscardHandler), Now: time.Now},
		agent.StoreSet{
			Kind: docStoreKind, Family: docFamily, Language: docLanguage{},
			Data: store, Catalog: store, Ledger: store, Classes: docClasses{store},
		},
		nil, func() *guidance.UpdateInfo { return nil },
	)
	svc.SetPorts(approvals, approvals, approvals, approvals, approvals)
	return svc, store, approvals
}

func TestDocumentStoreRunsTheAgentThroughThePorts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, store, approvals := newDocService(t)
	require.Equal(t, docFamily, svc.Family())
	require.Equal(t, 5*time.Second, svc.StatementTimeout())

	run, err := svc.StartRun(ctx, "move trial customers to pro", uuid.Nil)
	require.NoError(t, err)

	// query: a find, recorded with its text and parameters as given.
	find := agentstore.Request{Text: `{"find":"customers","filter":{"plan":{"$param":0}}}`, Params: []any{"pro"}}
	got, err := svc.Query(ctx, agent.QueryParams{Request: find, RunID: run.RunID})
	require.NoError(t, err)
	require.Equal(t, []map[string]any{{"_id": "c00", "plan": "pro"}}, got.Rows)
	require.Len(t, store.reads, 1)
	require.Equal(t, find.Text, store.reads[0].Statement)
	require.Equal(t, find.Params, store.reads[0].Params)
	require.Equal(t, []string{"customers"}, store.reads[0].Tables)

	// A find sent to write is the language's refusal, recorded.
	_, err = svc.Write(ctx, agent.WriteParams{Request: find, Intent: "wrong tool", RunID: run.RunID})
	require.ErrorIs(t, err, errDocWrongTool)
	require.Len(t, store.refusals, 1)
	require.Equal(t, find.Text, store.refusals[0].Statement)

	// write: one item, applied at once.
	one := agentstore.Request{Text: `{"update":"customers","filter":{"_id":"c01"},"set":{"plan":"pro"}}`}
	w, err := svc.Write(ctx, agent.WriteParams{Request: one, Intent: "upgrade c01", RunID: run.RunID})
	require.NoError(t, err)
	require.Equal(t, 1, w.Rows)
	require.Equal(t, action.OpUpdate, w.Op)
	require.Equal(t, uuid.Nil, w.ApprovalID)

	// A held write: eleven items, held, signed while the call waits, then
	// applied under the approval with its receipt.
	many := agentstore.Request{Text: `{"update":"customers","filter":{"plan":{"$param":0}},"set":{"plan":"pro"}}`, Params: []any{"trial"}}
	w, err = svc.Write(ctx, agent.WriteParams{Request: many, Intent: "upgrade every trial", RunID: run.RunID, Wait: time.Second})
	require.NoError(t, err)
	require.Equal(t, docHeldOver+1, w.Rows)
	require.NotEqual(t, uuid.Nil, w.ApprovalID)
	require.NotNil(t, w.Receipt)
	require.Equal(t, "receipt-"+w.ApprovalID.String(), w.Receipt.Token)
	require.Len(t, approvals.notified, 1)
	require.Equal(t, many.Text, approvals.notified[0].Statement)
	require.Equal(t, docHeldOver+1, approvals.notified[0].Rows)
	held := approvals.approvals[w.ApprovalID]
	require.Equal(t, many.Text, held.Statement)
	require.JSONEq(t, `["trial"]`, string(held.Params))

	docs := store.match(docRequest{Find: "customers", Filter: map[string]any{"plan": "trial"}}, nil)
	require.Empty(t, docs, "the approved write changed every trial customer")
}

func TestDocumentStoreDescribeHidesAFeatureOnAHiddenField(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, _, _ := newDocService(t)

	o, err := svc.DescribeOverview(ctx)
	require.NoError(t, err)
	require.Equal(t, string(docStoreKind), o.Store.Kind)
	require.Equal(t, agent.Counts{Namespaces: 1, Resources: 1}, o.Counts)
	require.Equal(t, "shop/customers", o.Resources[0].Resource)

	r, err := svc.DescribeResource(ctx, "shop/customers", "")
	require.NoError(t, err)
	raw, err := json.Marshal(r)
	require.NoError(t, err)
	for _, hidden := range []string{"ssn", "by_plan_ssn", "000-00-0000"} {
		require.NotContains(t, string(raw), hidden, "describe never names a SECRET field or a feature on it")
	}
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	require.Equal(t, "shop/customers", m["resource"])
	require.EqualValues(t, 1, m["hiddenFields"])
	require.Equal(t, []any{map[string]any{"name": "by_email", "fields": []any{"email"}}}, m["searchIndexes"])
	require.EqualValues(t, 1, m["hiddenSearchIndexes"])
	fields := m["fields"].([]any)
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.(map[string]any)["name"].(string))
	}
	require.Equal(t, []string{"_id", "email", "plan"}, names)

	again, err := svc.DescribeResource(ctx, "shop/customers", r.Fingerprint)
	require.NoError(t, err)
	require.True(t, again.Unchanged)

	_, err = svc.DescribeResource(ctx, "shop.customers", "")
	var argErr *guidance.ArgumentError
	require.ErrorAs(t, err, &argErr, "the store's language reads the name, not the service")
}

// TestDocumentStoreDescribeFailsClosedOnShortClasses: classes that do not
// cover every field are an engine error, never fields taken as not SECRET.
func TestDocumentStoreDescribeFailsClosedOnShortClasses(t *testing.T) {
	t.Parallel()
	svc, _, _ := newDocService(t, func(s *docStore) { s.shortClasses = true })
	r, err := svc.DescribeResource(context.Background(), "shop/customers", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "classes")
	require.Nil(t, r.Detail)
	requireInternal(t, svc, err, "ssn")
}

// requireInternal: err answers the agent INTERNAL with the engine's text
// only, never a store key or field name of the cause.
func requireInternal(t *testing.T, svc *agent.Service, err error, names ...string) {
	t.Helper()
	te := guidance.ErrorMap{}.ToolError(svc.DescribeError(err))
	require.Equal(t, guidance.CodeInternal, te.Code)
	for _, n := range names {
		require.NotContains(t, te.Message, n)
	}
}

// TestDocumentStoreDescribeRefusesAFlagOnAnAnswerKey: a store flag named as
// one of describe's own keys is an engine error, never a second key.
func TestDocumentStoreDescribeRefusesAFlagOnAnAnswerKey(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"fields", "kind", "actions", "stats", "searchIndexes", "hiddenSearchIndexes"} {
		svc, _, _ := newDocService(t, func(s *docStore) { s.flags = map[string]any{key: true} })
		r, err := svc.DescribeResource(context.Background(), "shop/customers", "")
		require.Error(t, err, key)
		require.Contains(t, err.Error(), fmt.Sprintf("%q", key))
		require.Nil(t, r.Detail, key)
		requireInternal(t, svc, err, key)
	}
}

// TestDocumentStoreDescribeRefusesADisplayOnAFieldKey: a display member
// named as one of a field's own keys is an engine error, also on a field
// describe hides, and the answer never names that field.
func TestDocumentStoreDescribeRefusesADisplayOnAFieldKey(t *testing.T) {
	t.Parallel()
	svc, _, _ := newDocService(t, func(s *docStore) { s.ssnDisplay = map[string]any{"pii": "none"} })
	r, err := svc.DescribeResource(context.Background(), "shop/customers", "")
	require.Error(t, err)
	require.Nil(t, r.Detail)
	requireInternal(t, svc, err, "ssn", "pii")
}
