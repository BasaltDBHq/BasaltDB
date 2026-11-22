package piidict

import (
	"context"
	"encoding/hex"
	"sort"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
)

// Secrets returns the SECRET columns of the map, ordered by table oid and
// attribute number, loading it first when nothing is loaded. describe hides
// them and search never matches them (CONTRACT.md, describe).
func (m *Map) Secrets(ctx context.Context, db guard.Querier) ([]ColumnRef, error) {
	s, err := m.current(ctx, db, nil)
	if err != nil {
		return nil, err
	}
	var out []ColumnRef
	for ref, c := range s.cols {
		if c.Class == guard.ClassSecret {
			out = append(out, ref)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TableOID != out[j].TableOID {
			return out[i].TableOID < out[j].TableOID
		}
		return out[i].Attnum < out[j].Attnum
	})
	return out, nil
}

// CatalogFingerprint returns the agent's PII catalog fingerprint
// (agent_pii_catalog.fingerprint) the map was loaded with, as hex: empty
// before the first basalt classify. It loads the map first when nothing is
// loaded.
func (m *Map) CatalogFingerprint(ctx context.Context, db guard.Querier) (string, error) {
	s, err := m.current(ctx, db, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(s.marks.catalogPrint), nil
}

// On is the map reading through db (the agent's pool), as describe calls
// it (agent.ClassResolver).
func (m *Map) On(db guard.Querier) BoundMap {
	return BoundMap{m: m, db: db}
}

// BoundMap is a Map with its database.
type BoundMap struct {
	m  *Map
	db guard.Querier
}

// Resolve is Map.Resolve through the bound database.
func (b BoundMap) Resolve(ctx context.Context, refs []ColumnRef) ([]Class, error) {
	return b.m.Resolve(ctx, b.db, refs)
}

// Secrets is Map.Secrets through the bound database.
func (b BoundMap) Secrets(ctx context.Context) ([]ColumnRef, error) {
	return b.m.Secrets(ctx, b.db)
}

// CatalogFingerprint is Map.CatalogFingerprint through the bound database.
func (b BoundMap) CatalogFingerprint(ctx context.Context) (string, error) {
	return b.m.CatalogFingerprint(ctx, b.db)
}
