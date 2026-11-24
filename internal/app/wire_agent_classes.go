package app

import (
	"context"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/agentcatalog"
)

// pgClasses are the agent's PII classes by column (pii.StoreClasses).
type pgClasses interface {
	Resolve(ctx context.Context, refs []pii.ColumnRef) ([]pii.Class, error)
	Secrets(ctx context.Context) ([]pii.ColumnRef, error)
	CatalogFingerprint(ctx context.Context) (string, error)
}

// agentClasses are the PII classes as the agent reads them, by field ref.
// The refs are the Postgres catalog adapter's (agentcatalog); this only
// converts its columns to and from pii's.
type agentClasses struct{ pg pgClasses }

// NewAgentClasses are the PII classes c as the agent reads them.
func NewAgentClasses(c pgClasses) agentsvc.ClassResolver { return agentClasses{pg: c} }

func (c agentClasses) Resolve(ctx context.Context, refs []agentstore.FieldRef) ([]pii.Class, error) {
	cols := make([]pii.ColumnRef, len(refs))
	for i, ref := range refs {
		col, err := agentcatalog.ParseFieldRef(ref)
		if err != nil {
			return nil, err
		}
		cols[i] = pii.ColumnRef{TableOID: col.OID, Attnum: col.Attnum}
	}
	return c.pg.Resolve(ctx, cols)
}

func (c agentClasses) Secrets(ctx context.Context) ([]agentstore.FieldRef, error) {
	cols, err := c.pg.Secrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]agentstore.FieldRef, len(cols))
	for i, col := range cols {
		out[i] = agentcatalog.FieldRef(col.TableOID, col.Attnum)
	}
	return out, nil
}

func (c agentClasses) CatalogFingerprint(ctx context.Context) (string, error) {
	return c.pg.CatalogFingerprint(ctx)
}
