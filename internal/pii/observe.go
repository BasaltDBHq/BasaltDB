package pii

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
)

// Adder takes values into the dictionary's delta (corepii.FuseDictionary).
type Adder interface {
	Add(t corepii.EntityType, value, phoneRegion string) error
}

// Observer adds the values of IDENTIFIER columns the agent is about to get
// (query rows, write RETURNING rows) to the dictionary, with the column's
// entity type and phone region (M5.1 plan, section 6, "Values the agent
// reads go in first").
type Observer struct {
	classes *Map
	dict    Adder
}

// NewObserver returns an observer resolving columns in classes and adding
// to dict. It panics on a nil dependency.
func NewObserver(classes *Map, dict Adder) *Observer {
	if classes == nil || dict == nil {
		panic("piidict: classes and dictionary required")
	}
	return &Observer{classes: classes, dict: dict}
}

// Observe adds every non-null value of rows in a column that maps to an
// IDENTIFIER column. db reloads the map when needed. A computed column has
// no source and is not added (rule 2 refuses those on PII columns from
// M5.2). An error means a value could not be added or a column not
// classified, and the caller must not return the rows. Errors name no value.
func (o *Observer) Observe(ctx context.Context, db PiidictQuerier, cols []action.Column, rows []map[string]any) error {
	if len(rows) == 0 || len(cols) == 0 {
		return nil
	}
	if err := o.observe(ctx, db, cols, rows); err != nil {
		return &DictionaryError{err: err}
	}
	return nil
}

// DictionaryError is a failure to classify or add the values of a result:
// an engine failure, not the agent's SQL, so the tool answers INTERNAL even
// when a Postgres error (a map reload) caused it. It does not unwrap, so the
// tool's error mapping never sees that Postgres error; errors.Is still finds
// the cause (corepii.ErrDeltaFull).
type DictionaryError struct{ err error }

func (e *DictionaryError) Error() string { return "pii dictionary: " + e.err.Error() }

// Is reports whether the cause is target.
func (e *DictionaryError) Is(target error) bool { return errors.Is(e.err, target) }

func (o *Observer) observe(ctx context.Context, db PiidictQuerier, cols []action.Column, rows []map[string]any) error {
	refs := make([]ColumnRef, len(cols))
	for i, c := range cols {
		refs[i] = ColumnRef{TableOID: c.TableOID, Attnum: c.Attnum}
	}
	classes, err := o.classes.Resolve(ctx, db, refs)
	if err != nil {
		return err
	}
	for i, c := range classes {
		if c.Class != guardmodel.ClassIdentifier {
			continue
		}
		if err := o.addColumn(c, cols[i].Name, rows); err != nil {
			return err
		}
	}
	return nil
}

func (o *Observer) addColumn(c Class, key string, rows []map[string]any) error {
	t := corepii.EntityType(c.EntityType)
	for _, row := range rows {
		v, ok := valueText(row[key])
		if !ok {
			continue
		}
		if err := o.dict.Add(t, v, c.PhoneRegion); err != nil {
			return fmt.Errorf("add a value of %s (%s): %w", c.Name(), c.EntityType, err)
		}
	}
	return nil
}

// valueText is a row value as the dictionary takes it: the text Postgres
// printed, a JSON string unquoted. NULL, an empty value and a boolean are
// skipped.
func valueText(v any) (string, bool) {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case json.Number:
		s = x.String()
	case json.RawMessage:
		s = string(x)
		var str string
		if json.Unmarshal(x, &str) == nil {
			s = str
		}
	default: // nil, bool: no PII
		return "", false
	}
	return s, s != ""
}

// On is the observer reading the map through db (the agent's pool), as the
// query tool calls it.
func (o *Observer) On(db PiidictQuerier) BoundObserver {
	return BoundObserver{o: o, db: db}
}

// Returned adds a write's RETURNING values inside its transaction, before
// COMMIT (the store's ReturnedFunc): an error rolls the write back.
func (o *Observer) Returned(ctx context.Context, tx pgx.Tx, cols []action.Column, rows []map[string]any) error {
	return o.Observe(ctx, tx, cols, rows)
}

// BoundObserver is an Observer with its database (agent.PIIObserver).
type BoundObserver struct {
	o  *Observer
	db PiidictQuerier
}

// Observe is Observer.Observe through the bound database.
func (b BoundObserver) Observe(ctx context.Context, cols []action.Column, rows []map[string]any) error {
	return b.o.Observe(ctx, b.db, cols, rows)
}
