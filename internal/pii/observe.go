package pii

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	corepii "github.com/basaltdbhq/basaltdb/internal/core/pii"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
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

// Observe adds every non-null value of rows in a field that maps to an
// IDENTIFIER field. c reloads the map when needed. A computed value (an
// empty ref) has no source and is not added (rule 2 refuses those on PII
// columns from M5.2). An error means a value could not be added or a field
// not classified, and the caller must not return the rows. Errors name no
// value.
func (o *Observer) Observe(ctx context.Context, c Classes, fields []piistore.ResultField, rows []map[string]any) error {
	if len(rows) == 0 || len(fields) == 0 {
		return nil
	}
	if err := o.observe(ctx, c, fields, rows); err != nil {
		return &DictionaryError{err: err}
	}
	return nil
}

// DictionaryError is a failure to classify or add the values of a result:
// an engine failure, not the agent's SQL, so the tool answers INTERNAL even
// when a store error (a map reload) caused it. It does not unwrap, so the
// tool's error mapping never sees that store error; errors.Is still finds
// the cause (corepii.ErrDeltaFull).
type DictionaryError struct{ err error }

func (e *DictionaryError) Error() string { return "pii dictionary: " + e.err.Error() }

// Is reports whether the cause is target.
func (e *DictionaryError) Is(target error) bool { return errors.Is(e.err, target) }

func (o *Observer) observe(ctx context.Context, c Classes, fields []piistore.ResultField, rows []map[string]any) error {
	refs := make([]agentstore.FieldRef, len(fields))
	for i, f := range fields {
		refs[i] = f.Ref
	}
	classes, err := o.classes.Resolve(ctx, c, refs)
	if err != nil {
		return err
	}
	for i, cl := range classes {
		if cl.Class != guardmodel.ClassIdentifier {
			continue
		}
		if err := o.addColumn(cl, fields[i].Key, rows); err != nil {
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

// valueText is a row value as the dictionary takes it: the text the store
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

// On is the observer reading the map through c (the agent's pool), as the
// query tool calls it.
func (o *Observer) On(c Classes) BoundObserver {
	return BoundObserver{o: o, c: c}
}

// BoundObserver is an Observer with its class store.
type BoundObserver struct {
	o *Observer
	c Classes
}

// Observe is Observer.Observe through the bound class store.
func (b BoundObserver) Observe(ctx context.Context, fields []piistore.ResultField, rows []map[string]any) error {
	return b.o.Observe(ctx, b.c, fields, rows)
}
