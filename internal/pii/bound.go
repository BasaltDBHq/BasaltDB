package pii

import (
	"context"
	"encoding/hex"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// Secrets returns the SECRET fields of the map, in the store's order,
// loading it first when nothing is loaded. describe hides them and search
// never matches them (CONTRACT.md, describe).
func (m *Map) Secrets(ctx context.Context, c Classes) ([]agentstore.FieldRef, error) {
	s, err := m.current(ctx, c, nil)
	if err != nil {
		return nil, err
	}
	var out []agentstore.FieldRef
	for _, f := range s.fields {
		if f.class.Class == guardmodel.ClassSecret {
			out = append(out, f.ref)
		}
	}
	return out, nil
}

// CatalogFingerprint returns the fingerprint of the agent's last classify
// the map was loaded with (Marks.CatalogPrint), as hex: empty before the
// first basalt classify. It loads the map first when nothing is
// loaded.
func (m *Map) CatalogFingerprint(ctx context.Context, c Classes) (string, error) {
	s, err := m.current(ctx, c, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(s.marks.CatalogPrint), nil
}

// On is the map reading through c (the agent's pool), as describe calls it
// (agent.ClassResolver).
func (m *Map) On(c Classes) BoundMap {
	return BoundMap{m: m, c: c}
}

// BoundMap is a Map with its class store.
type BoundMap struct {
	m *Map
	c Classes
}

// Resolve is Map.Resolve through the bound class store.
func (b BoundMap) Resolve(ctx context.Context, refs []agentstore.FieldRef) ([]Class, error) {
	return b.m.Resolve(ctx, b.c, refs)
}

// Secrets is Map.Secrets through the bound class store.
func (b BoundMap) Secrets(ctx context.Context) ([]agentstore.FieldRef, error) {
	return b.m.Secrets(ctx, b.c)
}

// CatalogFingerprint is Map.CatalogFingerprint through the bound class
// store.
func (b BoundMap) CatalogFingerprint(ctx context.Context) (string, error) {
	return b.m.CatalogFingerprint(ctx, b.c)
}
