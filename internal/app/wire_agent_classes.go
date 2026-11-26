package app

import (
	"context"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgquerier"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/sqlport"
)

// resultFields names the fields of a Postgres result for the PII observer:
// each column's field ref, and none for a computed column (oid 0). The
// agent's action.Column still carries the oid and attribute number.
func resultFields(cols []action.Column) []piistore.ResultField {
	out := make([]piistore.ResultField, len(cols))
	for i, c := range cols {
		out[i] = piistore.ResultField{Ref: c.Ref, Key: c.Name}
	}
	return out
}

// agentPII is the observer as the agent's PIIObserver: a read's rows,
// with the classes read through the agent's pool, and a write's returned
// rows, with the classes read through the write's own transaction.
type agentPII struct {
	o       *pii.Observer
	classes pii.Classes
}

// NewAgentPII is obs reading the map through classes for the agent's query
// rows, and through the write's transaction for its returned rows.
func NewAgentPII(obs *pii.Observer, classes pii.Classes) agentsvc.PIIObserver {
	return agentPII{o: obs, classes: classes}
}

func (a agentPII) Observe(ctx context.Context, cols []action.Column, rows []map[string]any) error {
	return a.o.Observe(ctx, a.classes, resultFields(cols), rows)
}

// ObserveReturned adds a write's RETURNING values inside its transaction,
// before COMMIT, reading the map through classes, that transaction's own
// class store. An error rolls the write back.
func (a agentPII) ObserveReturned(ctx context.Context, classes pii.Classes, cols []action.Column, rows []map[string]any) error {
	return a.o.Observe(ctx, classes, resultFields(cols), rows)
}

// txReturned is the agent's Returned as the Postgres store calls it: the
// classes the agent's PII port reads are the class store on the write's
// own transaction, so they are the ones in force in it.
func txReturned(returned agentsvc.Returned) txRows {
	if returned == nil {
		return nil
	}
	return func(ctx context.Context, tx sqlport.Port, cols []action.Column, rows []map[string]any) error {
		return returned(ctx, pgpii.ClassesInTx(pgquerier.Unwrap(tx)), cols, rows)
	}
}
