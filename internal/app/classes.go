package app

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// storeClasses is the agent's PII classification read on its credential
// (pii.BoundMap), with its errors mapped like the store's
// (postgres.MapError), so the service sees contract errors.
type storeClasses struct {
	pii.BoundMap
}

func (m storeClasses) Resolve(ctx context.Context, refs []pii.ColumnRef) ([]pii.Class, error) {
	c, err := m.BoundMap.Resolve(ctx, refs)
	return c, store.MapError(err)
}

func (m storeClasses) Secrets(ctx context.Context) ([]pii.ColumnRef, error) {
	s, err := m.BoundMap.Secrets(ctx)
	return s, store.MapError(err)
}

func (m storeClasses) CatalogFingerprint(ctx context.Context) (string, error) {
	f, err := m.BoundMap.CatalogFingerprint(ctx)
	return f, store.MapError(err)
}
