package storeproof_test

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	postgres "github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// This package proves that every store-neutral domain runs on a store that
// is not Postgres: one in-memory document store implements the ports of
// the agent, approval, revert and PII domains, and the tests drive the
// services through those ports only. The store's words are its own: its
// kind is MEMORY, its requests are JSON filters (the DOCUMENT family), its
// resources are namespace/collection names, its fields are refs in its own
// path syntax (customers#contact.email) and its error codes are not
// SQLSTATEs. Where a service still needs Postgres-shaped data, the test
// pins the refusal and says so.

const (
	// memKind is the store's kind, a label only.
	memKind action.StoreKind = "MEMORY"
	// memFamily is the family of the store's requests.
	memFamily agentstore.Family = "DOCUMENT"
	// memRequestKind is the held request's kind, by family.
	memRequestKind = "DOCUMENT"
	// memAgent is the agent the store serves.
	memAgent = "docbot"
	// memDatabase is the name the store gives what the agent is bound to.
	memDatabase = "shop"
	// memHeldOver is the most documents a write changes before the store
	// holds it for the person.
	memHeldOver = 10
	// memVerbUpdate is the store's own word for an update.
	memVerbUpdate = "updateMany"
)

// The store's own error codes, in its own words.
const (
	codeDeadline  = "E_DEADLINE"
	codeSignature = "E_SIGNATURE"
)

// The store's collections, by the name the agent writes.
const (
	colCustomers = "shop/customers"
	colOrders    = "shop/orders"
	colArchive   = "shop/archive"
	colEvents    = "shop/events"
)

// memRequest is one request in the store's language: a JSON filter that
// finds documents of a collection, or updates them.
type memRequest struct {
	Find   string         `json:"find,omitempty"`
	Update string         `json:"update,omitempty"`
	Filter map[string]any `json:"filter"`
	Set    map[string]any `json:"set,omitempty"`
}

func (r memRequest) collection() string { return cmp.Or(r.Find, r.Update) }

// errWrongTool is the store's refusal of a find sent to write or an update
// sent to query.
var errWrongTool = &action.RefusalError{Reason: action.ReasonWrongTool, Detail: "a find runs with query, an update with write"}

func parseRequest(text string) (memRequest, error) {
	var r memRequest
	if err := json.Unmarshal([]byte(text), &r); err != nil {
		return memRequest{}, &action.RefusalError{Reason: action.ReasonParseError, Detail: "not a JSON request"}
	}
	return r, nil
}

// memLanguage is the store's language: the only reader of a request's text.
// It notes every text it is given, byte for byte.
type memLanguage struct{ s *memStore }

func (l memLanguage) Check(req agentstore.Request, tool action.Tool) (action.Statement, error) {
	l.s.saw("Check", req.Text)
	r, err := parseRequest(req.Text)
	if err != nil {
		return action.Statement{}, err
	}
	switch {
	case r.Find != "" && tool == action.ToolQuery:
		return action.Statement{Op: action.OpRead, Tables: []string{r.Find}, Handle: r}, nil
	case r.Update != "" && tool == action.ToolWrite:
		return action.Statement{Op: action.OpUpdate, Tables: []string{r.Update}, Target: r.Update, Handle: r}, nil
	}
	return action.Statement{}, errWrongTool
}

func (memLanguage) RefusalText(string) (string, bool) { return "", false }
func (memLanguage) LimitText(string) string           { return "narrow the filter" }

func (memLanguage) ReadRow(target string, key map[string]any) agentstore.Request {
	raw, err := json.Marshal(memRequest{Find: target, Filter: key})
	if err != nil {
		return agentstore.Request{}
	}
	return agentstore.Request{Text: string(raw)}
}

// argQuery is the DOCUMENT family's argument for a request's text.
const argQuery = "q"

func (memLanguage) Args(req agentstore.Request) map[string]any {
	args := map[string]any{argQuery: req.Text}
	if len(req.Params) > 0 {
		args["params"] = req.Params
	}
	return args
}

func (memLanguage) StaleTarget(string) (string, map[string]any, error) {
	return "", nil, errors.New("the memory store reports no stale reads")
}
func (memLanguage) DeniedTarget(string) (string, bool) { return "", false }
func (memLanguage) RLSRefusal(string) (string, bool)   { return "", false }
func (memLanguage) NoKeyTarget(string) (string, bool)  { return "", false }

func (memLanguage) HeldFrom(_ context.Context, held, sent agentstore.Request) (bool, error) {
	return held.Text == sent.Text, nil
}

func (memLanguage) ParseName(s string) (string, string, error) {
	ns, name, ok := strings.Cut(s, "/")
	if !ok || ns == "" || name == "" {
		return "", "", errors.New("must be namespace/collection")
	}
	return ns, name, nil
}

func (memLanguage) PrintName(namespace, name string) string { return namespace + "/" + name }

// change is one recorded change of a document: who made it, in which run,
// and the document before and after.
type change struct {
	id, run       uuid.UUID
	agent         string
	resource, key string
	before, after map[string]any
	// version is the document's version this change made.
	version int
}

// document is one stored document and its version, which every write
// moves on.
type document struct {
	doc     map[string]any
	version int
}

// memStore is the one store every domain runs on, in memory.
type memStore struct {
	mu sync.Mutex
	// docs are the documents by collection and _id.
	docs map[string]map[string]*document
	// order is each collection's _ids in insertion order.
	order   map[string][]string
	runs    map[uuid.UUID]action.Run
	reads   []action.Read
	refuses []action.Refusal
	changes []change
	// texts are the request texts each port was given, by port.
	texts map[string][]string
	// calls counts the store's calls by name.
	calls map[string]int
	ids   int

	approvals map[uuid.UUID]*memApproval
	reverts   map[uuid.UUID]*memRevert
	// prepareLimits are the time limits the revert service gave each
	// prepare.
	prepareLimits []time.Duration

	pii memPII
	// slowReads makes every read run into the store's time limit.
	slowReads bool
	// asPostgres makes every refusal the one the Postgres adapter maps the
	// guard's answer to: same reason, Postgres's text and SQLSTATE.
	asPostgres bool
}

func newMemStore() *memStore {
	s := &memStore{
		docs: map[string]map[string]*document{}, order: map[string][]string{}, runs: map[uuid.UUID]action.Run{},
		texts: map[string][]string{}, calls: map[string]int{},
		approvals: map[uuid.UUID]*memApproval{}, reverts: map[uuid.UUID]*memRevert{},
	}
	s.pii = newMemPII()
	return s
}

// saw notes text as given to port.
func (s *memStore) saw(port, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.texts[port] = append(s.texts[port], text)
}

func (s *memStore) count(name string) { s.calls[name]++ }

// calledTimes is how often the store's call name ran.
func (s *memStore) calledTimes(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[name]
}

// nextID is a fixed sequence of UUIDv7-shaped ids.
func (s *memStore) nextID() uuid.UUID {
	s.ids++
	return uuid.MustParse(fmt.Sprintf("0193a4c2-7d1e-7c3a-9f00-%012d", 1000+s.ids))
}

// put sets a document (nil deletes it) and moves its version on.
func (s *memStore) put(resource, key string, doc map[string]any) (before map[string]any, version int) {
	if s.docs[resource] == nil {
		s.docs[resource] = map[string]*document{}
	}
	d := s.docs[resource][key]
	if d == nil {
		d = &document{}
		s.docs[resource][key] = d
		s.order[resource] = append(s.order[resource], key)
	}
	before = d.doc
	d.doc, d.version = maps.Clone(doc), d.version+1
	return before, d.version
}

// seed puts documents in place as a person did, recorded as no agent's.
func (s *memStore) seed(resource string, docs ...map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range docs {
		s.put(resource, d["_id"].(string), d)
	}
}

// personWrite is a change by a person, which a revert never overwrites.
func (s *memStore) personWrite(resource, key string, doc map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.put(resource, key, doc)
}

func (s *memStore) doc(resource, key string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.docs[resource][key]; d != nil {
		return d.doc
	}
	return nil
}

// match is the documents of r's collection its filter matches, in
// insertion order. A filter value {"$param": n} is the request's n-th
// parameter.
func (s *memStore) match(r memRequest, params []any) []map[string]any {
	var out []map[string]any
	for _, key := range s.order[r.collection()] {
		d := s.docs[r.collection()][key]
		if d.doc != nil && matches(d.doc, r.Filter, params) {
			out = append(out, d.doc)
		}
	}
	return out
}

func matches(doc, filter map[string]any, params []any) bool {
	for k, want := range filter {
		if p, isParam := want.(map[string]any); isParam {
			n, ok := p["$param"].(float64)
			if !ok || int(n) >= len(params) {
				return false
			}
			want = params[int(n)]
		}
		if doc[k] != want {
			return false
		}
	}
	return true
}

// The fields a read returns, in order, with the field each comes from.
var readFields = []string{"_id", "email", "plan", "alias"}

// fieldRef is the store's ref of a field of a collection: the collection
// without its namespace, then # and the field's path.
func fieldRef(collection, path string) agentstore.FieldRef {
	_, name, _ := strings.Cut(collection, "/")
	return agentstore.FieldRef(name + "#" + path)
}

// result is docs as the store returns them: each field's value as the
// read path hands it (a JSON value stays json.RawMessage).
func result(collection string, docs []map[string]any) ([]action.Column, []map[string]any) {
	cols := make([]action.Column, 0, len(readFields))
	for _, f := range readFields {
		cols = append(cols, action.Column{Name: f, Type: "string", Ref: fieldRef(collection, f)})
	}
	rows := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		row := map[string]any{}
		for _, f := range readFields {
			row[f] = d[f]
		}
		rows = append(rows, row)
	}
	return cols, rows
}

// postgresTimeout is the refusal the Postgres adapter maps a read the
// statement timeout canceled to, made by the adapter's own mapping.
func postgresTimeout() *action.StoreError {
	return postgresAnswer(&pgconn.PgError{Code: "57014", Message: "canceling statement due to statement timeout"})
}

// postgresAnswer is the Postgres guard's answer pe as the Postgres
// adapter maps it.
func postgresAnswer(pe *pgconn.PgError) *action.StoreError {
	var se *action.StoreError
	if !errors.As(postgres.MapError(pe), &se) {
		panic("the Postgres adapter did not map " + pe.Code)
	}
	return se
}

// Data.

func (s *memStore) Read(_ context.Context, req agentstore.Request, stmt action.Statement) (action.ReadResult, error) {
	s.saw("Read", req.Text)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("Read")
	if s.slowReads {
		if s.asPostgres {
			return action.ReadResult{}, postgresTimeout()
		}
		msg := "the find ran past the store's deadline"
		return action.ReadResult{}, &action.StoreError{
			Code: action.CodeQueryTimeout, Reason: action.ReasonTimeLimit, StoreCode: codeDeadline, Message: msg, Err: errors.New(msg),
		}
	}
	r := stmt.Handle.(memRequest)
	cols, rows := result(r.Find, s.match(r, req.Params))
	return action.ReadResult{Columns: cols, Rows: rows}, nil
}

func (s *memStore) Write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement, returned agent.Returned) (action.WriteResult, error) {
	s.saw("Write", req.Text)
	return s.write(ctx, in, req, stmt, returned, false)
}

func (s *memStore) WriteApproved(ctx context.Context, in action.Intent, _ uuid.UUID, req agentstore.Request, stmt action.Statement, returned agent.Returned) (action.WriteResult, error) {
	s.saw("WriteApproved", req.Text)
	return s.write(ctx, in, req, stmt, returned, true)
}

// write applies an update, recording each document's change in the
// agent's run, and hands the returned documents to returned, the agent's
// PII port, before it commits; a write of more than memHeldOver documents
// is held unless approved.
func (s *memStore) write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement, returned agent.Returned, approved bool) (action.WriteResult, error) {
	s.mu.Lock()
	r := stmt.Handle.(memRequest)
	docs := s.match(r, req.Params)
	if len(docs) > memHeldOver && !approved {
		s.mu.Unlock()
		return action.WriteResult{}, action.ErrApprovalRequired
	}
	after := make([]map[string]any, 0, len(docs))
	for _, d := range docs {
		next := maps.Clone(d)
		maps.Copy(next, r.Set)
		after = append(after, next)
	}
	cols, rows := result(r.Update, after)
	s.mu.Unlock()
	// The port reads the class map alone, as inside the write's own
	// transaction (Shared false), before the write is kept.
	if len(rows) > 0 {
		if err := returned(ctx, txClasses{s}, cols, rows); err != nil {
			return action.WriteResult{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, next := range after {
		key := next["_id"].(string)
		before, version := s.put(r.Update, key, next)
		s.changes = append(s.changes, change{
			id: s.nextID(), run: in.RunID, agent: memAgent, resource: r.Update, key: key,
			before: before, after: maps.Clone(next), version: version,
		})
	}
	return action.WriteResult{ChangeID: s.nextID(), Rows: len(after), Columns: cols, Returning: rows}, nil
}

func (s *memStore) Limits() action.Limits {
	return action.Limits{StatementTimeout: 5 * time.Second, ReadRowLimit: 100}
}

// Ledger.

func (s *memStore) FindRun(_ context.Context, id uuid.UUID) (action.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if !ok {
		return action.Run{}, action.ErrRunNotFound
	}
	return r, nil
}

func (s *memStore) CheckRun(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return nil
	}
	_, err := s.FindRun(ctx, id)
	return err
}

func (s *memStore) StartRun(_ context.Context, in action.Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[in.RunID] = action.Run{ID: in.RunID, TaskID: in.TaskID, Intent: in.Text}
	return nil
}

func (s *memStore) RecordRead(_ context.Context, r action.Read) (uuid.UUID, error) {
	s.saw("RecordRead", r.Statement)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, r)
	return s.nextID(), nil
}

func (s *memStore) RecordRefusal(_ context.Context, r action.Refusal) error {
	s.saw("RecordRefusal", r.Statement)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuses = append(s.refuses, r)
	return nil
}

func (s *memStore) ListRuns(context.Context, action.RunListParams) (pagination.Page[action.RunListItem], error) {
	return pagination.Page[action.RunListItem]{}, nil
}

// Catalog.

func (s *memStore) customers() agentstore.Resource {
	s.mu.Lock()
	n := int64(len(s.order[colCustomers]))
	s.mu.Unlock()
	return agentstore.Resource{
		Ref: "customers", Namespace: "shop", Name: "customers", Kind: "COLLECTION", Estimate: &n,
		Actions: []action.Op{action.OpRead, action.OpUpdate},
	}
}

func (s *memStore) Resources(context.Context) ([]agentstore.Resource, agentstore.NotGranted, error) {
	return []agentstore.Resource{s.customers()}, agentstore.NotGranted{}, nil
}

func (s *memStore) Find(_ context.Context, namespace, name string) (agentstore.Resource, bool, error) {
	if namespace+"/"+name != colCustomers {
		return agentstore.Resource{}, false, nil
	}
	return s.customers(), true, nil
}

// customerFields are the customers' fields describe lists, before the
// service hides any.
var customerFields = []string{"_id", "email", "plan", "alias", "ssn"}

func (s *memStore) Describe(_ context.Context, ref agentstore.ResourceRef) (agentstore.Detail, error) {
	if ref != "customers" {
		return agentstore.Detail{}, action.ErrNotFound
	}
	fields := make([]agentstore.Field, 0, len(customerFields))
	for _, f := range customerFields {
		fields = append(fields, agentstore.Field{Ref: fieldRef(colCustomers, f), Name: f, Type: "string", Readable: true})
	}
	return agentstore.Detail{
		Resource: s.customers(), Fields: fields, Identity: []agentstore.FieldRef{fieldRef(colCustomers, "_id")},
	}, nil
}

func (s *memStore) Guarded(context.Context, agentstore.ResourceRef) (bool, error) { return true, nil }

// Search matches a collection by the name of a field the agent may see:
// a field in exclude is never matched.
func (s *memStore) Search(_ context.Context, q string, exclude []agentstore.FieldRef, _ *agentstore.Cursor, _ int) ([]agentstore.Match, error) {
	s.mu.Lock()
	s.pii.excluded = append(s.pii.excluded, exclude...)
	s.mu.Unlock()
	for _, f := range customerFields {
		if f == q && !slices.Contains(exclude, fieldRef(colCustomers, f)) {
			return []agentstore.Match{{Resource: s.customers(), Matched: "field"}}, nil
		}
	}
	return nil, nil
}

func (s *memStore) Structure(context.Context) ([]string, error) {
	return []string{colCustomers + " " + strings.Join(customerFields, " ")}, nil
}

func (s *memStore) Database() string { return memDatabase }
func (s *memStore) Host() string     { return "memory.example.com" }

// MapError is the PII class reads' error mapping: the store's errors are
// already its own.
func (s *memStore) MapError(err error) error { return err }

// txClasses is the store's classes read inside a write's own transaction:
// alone, never sharing a load.
type txClasses struct{ *memStore }

func (txClasses) Shared() bool { return false }

// rawJSON is v as a JSON value, nil for nil.
func rawJSON(v map[string]any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
