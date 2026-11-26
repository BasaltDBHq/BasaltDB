package storeproof_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent"
	approvalsvc "github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/approval/in/approvalmcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/pii/out/dictfile"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/revert/in/revertmcp"
)

// The wiring's error sentinels for this store: none is a Postgres
// adapter's.
var (
	errMemParams       = errors.New("memory store: invalid parameters")
	errMemIntent       = errors.New("memory store: invalid intent")
	errMemNotConnected = errors.New("no Vault connected")
)

// memPrepareLimit is the store's own time limit on a revert's prepare.
const memPrepareLimit = 42 * time.Second

// memSort whitelists the approval list's sort.
var memSort = pagination.SortSpec{Default: "-id", Allowed: map[string]struct{}{"id": {}, "-id": {}}}

// harness is every store-neutral use case over one memory store, wired
// as the app wires them, with the PII map, observer and dictionary.
type harness struct {
	t        *testing.T
	store    *memStore
	agent    *agent.Service
	approval *approvalsvc.Service
	revert   *revertsvc.Service
	delivery *linksvc.Service
	errors   guidance.ErrorMap
	tools    map[string]func(context.Context, json.RawMessage) (any, error)

	classes  *pii.Map
	observer *pii.Observer
	dict     *corepii.FuseDictionary
	keys     *corepii.Keys
	log      *logBuffer
	logger   *slog.Logger
}

// The app's glue the use cases ask for, which no store answers.
type (
	admitted   struct{}
	noUpgrade  struct{}
	linkErrors struct{}
	noSteps    struct{}
)

func (admitted) Admit(context.Context) error                           { return nil }
func (noUpgrade) UpgradeWarnings(context.Context) []toolresult.Warning { return nil }
func (noSteps) UnavailableSteps(*guidance.Steps, *toolresult.ToolError, guidance.Failure) string {
	return ""
}

// approvalReads is what delivery reads of the approval records, from the
// store; the pages show the rows' field order, as without a column order.
type approvalReads struct{ approvalsvc.Records }

func (approvalReads) HasColumns() bool { return false }

func (approvalReads) ColumnOrder(context.Context, []string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

// statementLimit is the store's statement timeout, which a revert's answer
// names.
type statementLimit time.Duration

func (l statementLimit) StatementTimeout() time.Duration { return time.Duration(l) }

func (linkErrors) ApprovalLinkError(te *toolresult.ToolError, _ linksvc.HeldAnswer) *toolresult.ToolError {
	return te
}

// agentPII is the observer as the agent's PII port, as internal/app wires
// it: each column's field ref, and its key in the rows; a read's classes
// through the store, a write's through the classes the write hands it.
type agentPII struct {
	o       *pii.Observer
	classes pii.Classes
}

func (a agentPII) Observe(ctx context.Context, cols []action.Column, rows []map[string]any) error {
	return a.o.Observe(ctx, a.classes, resultFields(cols), rows)
}

func (a agentPII) ObserveReturned(ctx context.Context, classes pii.Classes, cols []action.Column, rows []map[string]any) error {
	return a.o.Observe(ctx, classes, resultFields(cols), rows)
}

func resultFields(cols []action.Column) []piistore.ResultField {
	out := make([]piistore.ResultField, len(cols))
	for i, c := range cols {
		out[i] = piistore.ResultField{Ref: c.Ref, Key: c.Name}
	}
	return out
}

// newDictionary is an empty PII dictionary and its keys, in a temporary
// directory.
func newDictionary(t *testing.T) (*corepii.FuseDictionary, *corepii.Keys) {
	t.Helper()
	dir := t.TempDir()
	keys, err := dictfile.LoadKeys(dir+"/"+corepii.KeyFileName, rand.Reader)
	require.NoError(t, err)
	dict, err := dictfile.Open(dir, keys, corepii.DefaultDictionaryOptions(time.Now))
	require.NoError(t, err)
	t.Cleanup(func() { _ = dict.Close() })
	return dict, keys
}

func newHarness(t *testing.T, opts ...func(*memStore)) *harness {
	t.Helper()
	store := newMemStore()
	seedCustomers(store)
	for _, opt := range opts {
		opt(store)
	}
	logger, buf := newLog()
	errs := guidance.ErrorMap{
		InvalidParams: errMemParams, InvalidIntent: errMemIntent,
		RowTooLarge: func(error) (string, bool) { return "", false },
	}
	cmds := guidance.NewCommands(memAgent, "", "/etc/basalt/config.toml", "linux", guidance.ServiceManager{
		StartCommand: func(string) string { return "basalt start" }, RestartArgs: func(string) []string { return []string{"restart"} },
	})
	keys, err := channel.GenerateEngineKeys(time.Now)
	require.NoError(t, err)
	dict, dictKeys := newDictionary(t)
	classes := pii.NewMap(logger)
	observer := pii.NewObserver(classes, dict)

	// Wired as the app wires them: delivery reads the approval records from
	// the store, revert reads the statement timeout from the store's limits,
	// and each use case takes the others it asks in its constructor.
	delivery := linksvc.New(
		linksvc.Core{Name: memAgent, Log: logger, Now: time.Now, Commands: cmds, Errors: errs, PagesBase: links.DefaultLocal, PagesOrigin: links.DefaultLocal},
		&linksvc.Deps{
			Notifier: linksvc.NoNotifier{}, Links: links.NewSecrets(time.Now, rand.Reader), Poll: time.Millisecond,
			Relay: linksvc.NoRelay{NotConnected: errMemNotConnected}, VaultConflict: func(error) bool { return false },
			ErrVaultNotConnected: errMemNotConnected, Receipts: keys,
		},
		approvalReads{store},
		func(_ string, _ map[string]any, err error) *toolresult.ToolError { return errs.ToolError(err) },
	)
	rev := revertsvc.New(
		revertsvc.Core{Name: memAgent, Log: logger, Now: time.Now, Commands: cmds, Errors: errs, PagesBase: links.DefaultLocal, LinkBudget: links.DefaultBudget},
		revertsvc.StoreSet{Limits: revertsvc.Limits{Prepare: memPrepareLimit}, Records: store, Undo: store, Proofs: store},
		&revertsvc.Deps{
			AfterAnswer:   func(context.Context, func()) bool { return false },
			RotateSession: func(context.Context, channel.LinkToken) bool { return false },
		},
		store, delivery, statementLimit(store.Limits().StatementTimeout), admitted{},
	)
	approval := approvalsvc.New(
		approvalsvc.Core{
			Name: memAgent, Log: logger, Now: time.Now, Commands: cmds, Errors: errs,
			PagesBase: links.DefaultLocal, LinkBudget: links.DefaultBudget,
		},
		approvalsvc.StoreSet{Records: store, Holds: store, Proofs: store},
		&approvalsvc.Deps{SortSpec: memSort}, delivery, rev, store, admitted{},
	)
	svc := agent.New(
		agent.Core{Name: memAgent, Log: logger, Now: time.Now, Commands: cmds, Errors: errs},
		agent.StoreSet{
			Kind: memKind, Family: memFamily, Language: memLanguage{store},
			Data: store, Catalog: store, Ledger: store,
			Classes: pii.StoreClasses{BoundMap: classes.On(store), Store: store},
		},
		agentPII{o: observer, classes: store}, func() *guidance.UpdateInfo { return nil },
		delivery, approval, noUpgrade{}, linkErrors{}, noSteps{},
	)

	h := &harness{
		t: t, store: store, agent: svc, approval: approval, revert: rev, delivery: delivery, errors: errs,
		tools: map[string]func(context.Context, json.RawMessage) (any, error){}, classes: classes, observer: observer,
		dict: dict, keys: dictKeys, log: buf, logger: logger,
	}
	mount := func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool {
		h.tools[name] = call
		return mcpserver.Tool{}
	}
	revertmcp.Tools(rev, mount)
	approvalmcp.Tools(approval, mount)
	return h
}

// seedCustomers puts the customers a person entered before the agent came:
// thirteen trial customers, one of them pro.
func seedCustomers(s *memStore) {
	for i := range memHeldOver + 3 {
		id := fmt.Sprintf("c%02d", i)
		s.seed(colCustomers, map[string]any{
			"_id": id, "email": id + "@example.com", "plan": "trial", "ssn": "000-00-0000",
			"alias":   json.RawMessage(`"` + id + `.alias@example.com"`),
			"contact": map[string]any{"email": id + ".home@example.com"},
			"login":   id + ".login@example.com", "note": "called twice",
			"tags": []any{"vip", float64(i), true}[i%3],
		})
	}
	s.docs[colCustomers]["c00"].doc["plan"] = "pro"
}

// call is the agent's tool call: its answer as the agent reads it, or the
// error the wiring maps it to.
func (h *harness) call(name string, args map[string]any) (map[string]any, *toolresult.ToolError) {
	h.t.Helper()
	raw, err := json.Marshal(args)
	require.NoError(h.t, err)
	tool, ok := h.tools[name]
	require.True(h.t, ok, name)
	out, err := tool(context.Background(), raw)
	if err != nil {
		return nil, h.agent.Failure(name, args, err)
	}
	b, err := json.Marshal(out)
	require.NoError(h.t, err)
	var m map[string]any
	require.NoError(h.t, json.Unmarshal(b, &m))
	return m, nil
}

// mustCall is a tool call that must succeed.
func (h *harness) mustCall(name string, args map[string]any) map[string]any {
	h.t.Helper()
	out, te := h.call(name, args)
	require.Nil(h.t, te, "%s answered %+v", name, te)
	return out
}

// pageID is the item id and secret of a short link to a page.
func pageID(t *testing.T, link string) (uuid.UUID, string) {
	t.Helper()
	u, err := url.Parse(link)
	require.NoError(t, err)
	id, err := uuid.Parse(path.Base(u.Path))
	require.NoError(t, err)
	secret, ok := strings.CutPrefix(u.Fragment, "s=")
	require.True(t, ok, "a short link carries its secret: %s", link)
	return id, secret
}

// personSignsRevert is the person on the revert page the agent's link
// opens: the page reads the request, checks it against the binding, and
// posts the signed response.
func (h *harness) personSignsRevert(link string) (revert.Request, revert.Binding, revertstore.AppliedRevert, error) {
	h.t.Helper()
	id, secret := pageID(h.t, link)
	req, err := h.revert.RevertRequest(context.Background(), id, secret)
	require.NoError(h.t, err)
	b, err := req.Check()
	require.NoError(h.t, err, "the page checks the request before asking for a signature")
	applied, _, err := h.revert.RelayRevert(context.Background(), reverttest.NewResponse(id, personAssertion(req.Binding)))
	return req, b, applied, err
}

// items are the answer's items as the agent reads them.
func items(t *testing.T, answer map[string]any) []map[string]any {
	t.Helper()
	raw, ok := answer["items"].([]any)
	require.True(t, ok, "answer has items: %v", answer)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		out = append(out, it.(map[string]any))
	}
	return out
}

// callStep is the answer's CALL_TOOL step, nil when it has none.
func callStep(answer map[string]any) map[string]any {
	steps, _ := answer["nextSteps"].([]any)
	for _, s := range steps {
		if step := s.(map[string]any); step["action"] == toolresult.ActionCallTool {
			return step
		}
	}
	return nil
}

// hasEmail reports whether the dictionary holds v as an email.
func (h *harness) hasEmail(v string) bool {
	return h.dict.Contains(corepii.EntityEmail, h.keys.TypedHash(corepii.EntityEmail, v, ""))
}

// logBuffer is a logger's output a test reads.
type logBuffer struct {
	mu  chan struct{}
	buf strings.Builder
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu <- struct{}{}
	defer func() { <-b.mu }()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu <- struct{}{}
	defer func() { <-b.mu }()
	return b.buf.String()
}

func newLog() (*slog.Logger, *logBuffer) {
	b := &logBuffer{mu: make(chan struct{}, 1)}
	return slog.New(slog.NewTextHandler(b, nil)), b
}
