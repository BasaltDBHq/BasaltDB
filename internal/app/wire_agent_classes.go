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

// agentPII is the observer as the agent's PIIObserver: query rows, read
// through the agent's pool.
type agentPII struct{ o pii.BoundObserver }

// NewAgentPII is obs reading the map through classes, for the agent's
// query rows.
func NewAgentPII(obs *pii.Observer, classes pii.Classes) agentsvc.PIIObserver {
	return agentPII{o: obs.On(classes)}
}

func (a agentPII) Observe(ctx context.Context, cols []action.Column, rows []map[string]any) error {
	return a.o.Observe(ctx, resultFields(cols), rows)
}

// returnedPII is obs as the Postgres store's returned-rows hook: a write's
// RETURNING values, added inside its transaction before COMMIT, reading the
// map on that transaction's connection. An error rolls the write back.
func returnedPII(obs *pii.Observer) func(ctx context.Context, tx sqlport.Port, cols []action.Column, rows []map[string]any) error {
	return func(ctx context.Context, tx sqlport.Port, cols []action.Column, rows []map[string]any) error {
		return obs.Observe(ctx, pgpii.ClassesInTx(pgquerier.Unwrap(tx)), resultFields(cols), rows)
	}
}
