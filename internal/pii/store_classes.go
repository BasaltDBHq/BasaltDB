package pii

import "context"

// Store maps the store's errors to contract errors.
type Store interface {
	MapError(err error) error
}

// StoreClasses is the agent's PII classification read on its credential
// (BoundMap), with its errors mapped like the store's, so the agent
// service sees contract errors.
type StoreClasses struct {
	BoundMap
	Store Store
}

// Resolve is the classes of refs.
func (m StoreClasses) Resolve(ctx context.Context, refs []ColumnRef) ([]Class, error) {
	c, err := m.BoundMap.Resolve(ctx, refs)
	return c, m.Store.MapError(err)
}

// Secrets is the columns classed secret.
func (m StoreClasses) Secrets(ctx context.Context) ([]ColumnRef, error) {
	s, err := m.BoundMap.Secrets(ctx)
	return s, m.Store.MapError(err)
}

// CatalogFingerprint is the fingerprint of the classified catalog.
func (m StoreClasses) CatalogFingerprint(ctx context.Context) (string, error) {
	f, err := m.BoundMap.CatalogFingerprint(ctx)
	return f, m.Store.MapError(err)
}
