package agent_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// writeTxClasses stands in for the classes a store reads inside a write's
// own transaction.
type writeTxClasses struct{ pii.Classes }

func (*writeTxClasses) Shared() bool { return false }

// returningData is the document store returning the documents a write
// changed. An honest one hands them to the agent's Returned before it
// answers, with its transaction's classes; a bypassing one does not.
type returningData struct {
	*docStore
	honest  bool
	classes *writeTxClasses
}

var returnedCols = []action.Column{{Name: "_id", Ref: "customers/_id"}}

func (d returningData) Write(ctx context.Context, in action.Intent, req agentstore.Request, stmt action.Statement, returned agent.Returned) (action.WriteResult, error) {
	res, err := d.docStore.Write(ctx, in, req, stmt, returned)
	return d.returning(ctx, res, err, returned)
}

func (d returningData) WriteApproved(ctx context.Context, in action.Intent, id uuid.UUID, req agentstore.Request, stmt action.Statement, returned agent.Returned) (action.WriteResult, error) {
	res, err := d.docStore.WriteApproved(ctx, in, id, req, stmt, returned)
	return d.returning(ctx, res, err, returned)
}

func (d returningData) returning(ctx context.Context, res action.WriteResult, err error, returned agent.Returned) (action.WriteResult, error) {
	if err != nil {
		return res, err
	}
	rows := make([]map[string]any, res.Rows)
	for i := range rows {
		rows[i] = map[string]any{"_id": fmt.Sprintf("r%02d", i)}
	}
	if d.honest {
		if err := returned(ctx, d.classes, returnedCols, rows); err != nil {
			return action.WriteResult{}, err
		}
	}
	res.Columns, res.Returning = returnedCols, rows
	return res, nil
}

// returnedPort is the agent's PII port, recording the returned rows and
// the classes it was handed; err fails every one.
type returnedPort struct {
	classes []pii.Classes
	rows    [][]map[string]any
	err     error
}

func (*returnedPort) Observe(context.Context, []action.Column, []map[string]any) error { return nil }

func (p *returnedPort) ObserveReturned(_ context.Context, classes pii.Classes, _ []action.Column, rows []map[string]any) error {
	p.classes = append(p.classes, classes)
	p.rows = append(p.rows, rows)
	return p.err
}

// newReturningService is newDocService over returningData, with port as the
// agent's PII port.
func newReturningService(t *testing.T, data returningData, port agent.PIIObserver) *agent.Service {
	t.Helper()
	store := data.docStore
	approvals := &docApprovals{approvals: map[uuid.UUID]action.Approval{}}
	approvals.preview = func(req agentstore.Request) []string {
		r, err := parseDoc(req)
		require.NoError(t, err)
		store.mu.Lock()
		defer store.mu.Unlock()
		return []string{fmt.Sprintf("customers: %d", len(store.match(r, req.Params)))}
	}
	return agent.New(
		agent.Core{Name: "docbot", Log: slog.New(slog.DiscardHandler), Now: time.Now},
		agent.StoreSet{
			Kind: docStoreKind, Family: docFamily, Language: docLanguage{},
			Data: data, Catalog: store, Ledger: store, Classes: docClasses{store},
		},
		port, func() *guidance.UpdateInfo { return nil },
		approvals, approvals, approvals, approvals, approvals,
	)
}

var (
	returnOne  = agentstore.Request{Text: `{"update":"customers","filter":{"_id":"c01"},"set":{"plan":"pro"}}`}
	returnMany = agentstore.Request{Text: `{"update":"customers","filter":{"plan":{"$param":0}},"set":{"plan":"pro"}}`, Params: []any{"trial"}}
)

// A write's returned rows reach the agent's PII port, with the classes the
// store read in the write's own transaction, on both the write and the
// write applied under an approval.
func TestWriteHandsReturnedRowsToThePIIPort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	data := returningData{docStore: newDocStore(), honest: true, classes: &writeTxClasses{}}
	port := &returnedPort{}
	svc := newReturningService(t, data, port)

	w, err := svc.Write(ctx, agent.WriteParams{Request: returnOne, Intent: "upgrade c01"})
	require.NoError(t, err)
	require.Len(t, w.Returning, 1)
	require.Len(t, port.rows, 1)
	require.Equal(t, w.Returning, port.rows[0])
	require.Same(t, data.classes, port.classes[0], "the port reads the classes of the write's transaction")

	w, err = svc.Write(ctx, agent.WriteParams{Request: returnMany, Intent: "upgrade every trial", Wait: time.Second})
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, w.ApprovalID)
	require.Len(t, port.rows, 2, "the approved write's rows went through the port")
	require.Equal(t, w.Returning, port.rows[1])
	require.Same(t, data.classes, port.classes[1])
}

// The port's error is the write's, as is: the store rolls the write back
// on it.
func TestWriteReturnsThePIIPortsError(t *testing.T) {
	t.Parallel()
	full := errors.New("dictionary full")
	data := returningData{docStore: newDocStore(), honest: true, classes: &writeTxClasses{}}
	svc := newReturningService(t, data, &returnedPort{err: full})
	_, err := svc.Write(context.Background(), agent.WriteParams{Request: returnOne, Intent: "upgrade c01"})
	require.ErrorIs(t, err, full)
}

// A store that returns rows without handing them to the PII port does not
// get them to the agent: the write fails closed as an engine defect.
func TestWriteWithholdsReturnedRowsThatBypassThePIIPort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	data := returningData{docStore: newDocStore()}
	port := &returnedPort{}
	svc := newReturningService(t, data, port)

	w, err := svc.Write(ctx, agent.WriteParams{Request: returnOne, Intent: "upgrade c01"})
	requireEngineDefect(t, err)
	require.Empty(t, w.Returning)

	w, err = svc.Write(ctx, agent.WriteParams{Request: returnMany, Intent: "upgrade every trial", Wait: time.Second})
	requireEngineDefect(t, err)
	require.Empty(t, w.Returning)
	require.Empty(t, port.rows)
}

func requireEngineDefect(t *testing.T, err error) {
	t.Helper()
	var te *toolresult.ToolError
	require.ErrorAs(t, err, &te)
	require.Equal(t, guidance.CodeInternal, te.Code)
}
