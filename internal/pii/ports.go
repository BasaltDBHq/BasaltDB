package pii

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
)

// Classes is the store's classification of one agent's fields, read on the
// agent's credential.
type Classes interface {
	// Snapshot reads the marks and the classes in one consistent read,
	// begun after the call: the marks first, then the classes.
	Snapshot(ctx context.Context) (piistore.Snapshot, error)
	// Marks reads the marks alone.
	Marks(ctx context.Context) (piistore.Marks, error)
	// Unclassified lists the fields the agent can read that need a person.
	Unclassified(ctx context.Context) ([]piistore.Unclassified, error)
	// ResourceOf is the resource that holds ref, for a ref the map does not
	// know. ref is never empty.
	ResourceOf(ref action.FieldRef) action.ResourceRef
	// Shared is true for a source others may share a load with (a pool),
	// false inside a caller's transaction (a write's RETURNING), which
	// reads alone, on its own connection.
	Shared() bool
}

// Adder takes values into the dictionary's delta (corepii.FuseDictionary).
type Adder interface {
	Add(t corepii.EntityType, value, phoneRegion string) error
}

// Builder is the dictionary the scan rebuilds (corepii.FuseDictionary).
type Builder interface {
	StartBuild() (*corepii.DictionaryBuild, error)
	RebuildNeeded() <-chan struct{}
}

// Fields reads the values of one agent's fields for the dictionary scan,
// with the agent's own credential (decision M51-2) and statement timeout
// (the store's adapter: pgpii.Fields).
type Fields interface {
	// Read pages through t's fields, pageRows rows at a time. value gets
	// each non-null value of t.Fields[field] as the read path hands it: a
	// JSON value as json.RawMessage, any other as its text (string). A
	// json.RawMessage's bytes are the adapter's and valid only during the
	// call: value must copy what it keeps, never the bytes themselves. page
	// gets each page's row count, after that page's read has let go of its
	// connection, so the rate limit's sleep never holds one. An error of
	// value or page is returned as is. A resource the scan should skip
	// fails with piistore.ErrUnreadable or piistore.ErrTooSlow, wrapping
	// the store's error.
	Read(ctx context.Context, t piistore.ScanTarget, pageRows int, value func(field int, v any) error, page func(rows int) error) error
}

// Store maps the store's errors to contract errors.
type Store interface {
	MapError(err error) error
}
