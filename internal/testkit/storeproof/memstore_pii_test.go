package storeproof_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// The PII domain's ports: the class store (pii.Classes), the dictionary
// scan's reader (pii.Fields) and the classifier's sampler, over documents
// with nested fields. A field is named by its ref in the store's own path
// syntax: customers#contact.email.

// memPII is the store's classification of the agent's fields.
type memPII struct {
	classes []piistore.FieldClass
	// unclassified are the fields the agent can read that need a person.
	unclassified []piistore.Unclassified
	// generation moves the fingerprint on with every change of the classes.
	generation int
	// snapshots counts the class map's loads.
	snapshots int
	// gone and slow are collections the scan's reader cannot read: gone,
	// or too slow to read in one pass.
	gone, slow map[agentstore.ResourceRef]bool
	// broken fails the scan's read of a collection with an error that is
	// neither.
	broken map[agentstore.ResourceRef]bool
	// excluded are the fields describe's search was told never to match.
	excluded []agentstore.FieldRef
	// sampled are the fields the classifier sampled, by printed name.
	sampled []string
}

// identifier is an IDENTIFIER EMAIL field of collection at path.
func identifier(collection, path string) piistore.FieldClass {
	return fieldClass(collection, path, guardmodel.ClassIdentifier, guardmodel.EntityEmail)
}

func fieldClass(collection, path, class, entity string) piistore.FieldClass {
	ns, name, _ := strings.Cut(collection, "/")
	return piistore.FieldClass{
		Ref: fieldRef(collection, path), Resource: agentstore.ResourceRef(name),
		Namespace: ns, ResourceName: name, Field: path, Class: class, EntityType: entity,
	}
}

func newMemPII() memPII {
	return memPII{
		classes: []piistore.FieldClass{
			fieldClass(colCustomers, "_id", guardmodel.ClassPublic, ""),
			identifier(colCustomers, "email"),
			fieldClass(colCustomers, "plan", guardmodel.ClassPublic, ""),
			// alias holds JSON strings: the read path hands them over as
			// json.RawMessage.
			identifier(colCustomers, "alias"),
			// A nested field: the scan's reader walks the store's path; the
			// observer reads top-level values only (a known limit).
			identifier(colCustomers, "contact.email"),
			fieldClass(colCustomers, "ssn", guardmodel.ClassSecret, ""),
			identifier(colArchive, "email"),
			identifier(colEvents, "email"),
		},
		unclassified: []piistore.Unclassified{{Name: "shop.customers.note", DataType: "string"}},
		gone:         map[agentstore.ResourceRef]bool{}, slow: map[agentstore.ResourceRef]bool{}, broken: map[agentstore.ResourceRef]bool{},
	}
}

// marks are the classes' fingerprint: it moves with the generation.
func (p *memPII) marks() piistore.Marks {
	sum := sha256.Sum256(fmt.Appendf(nil, "classes %d", p.generation))
	return piistore.Marks{Fingerprint: sum[:], CatalogPrint: sum[:]}
}

// classify puts a field's class in the store, as a person's labels do.
func (s *memStore) classify(f piistore.FieldClass) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pii.classes = append(s.pii.classes, f)
	s.pii.generation++
}

func (s *memStore) snapshots() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pii.snapshots
}

// pii.Classes.

func (s *memStore) Snapshot(context.Context) (piistore.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pii.snapshots++
	return piistore.Snapshot{Marks: s.pii.marks(), Fields: slices.Clone(s.pii.classes)}, nil
}

func (s *memStore) Marks(context.Context) (piistore.Marks, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pii.marks(), nil
}

func (s *memStore) Unclassified(context.Context) ([]piistore.Unclassified, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.pii.unclassified), nil
}

// ResourceOf is the collection of a field: its ref before #.
func (*memStore) ResourceOf(ref agentstore.FieldRef) agentstore.ResourceRef {
	name, _, _ := strings.Cut(string(ref), "#")
	return agentstore.ResourceRef(name)
}

func (*memStore) Shared() bool { return true }

// pii.Fields.

// errBroken is a read of a collection that failed for a reason that skips
// nothing: the scan must fail and keep the previous dictionary.
var errBroken = errors.New("the memory store lost its index of the collection")

// collectionOf is the collection the agent names for the resource ref.
func collectionOf(ns string, ref agentstore.ResourceRef) string { return ns + "/" + string(ref) }

// Read pages through t's documents and hands each non-null value of each
// field to value, walking the field's path in the document: a JSON value as
// json.RawMessage, any other as its text.
// memFields is the store's reader for the dictionary scan.
type memFields struct{ s *memStore }

func (m memFields) Read(_ context.Context, t piistore.ScanTarget, pageRows int, value func(int, any) error, page func(int) error) error {
	m.s.mu.Lock()
	switch {
	case m.s.pii.gone[t.Resource]:
		m.s.mu.Unlock()
		return fmt.Errorf("collection %s was dropped: %w", t.Name, piistore.ErrUnreadable)
	case m.s.pii.slow[t.Resource]:
		m.s.mu.Unlock()
		return fmt.Errorf("collection %s ran past the deadline: %w", t.Name, piistore.ErrTooSlow)
	case m.s.pii.broken[t.Resource]:
		m.s.mu.Unlock()
		return errBroken
	}
	collection := collectionOf(t.Namespace, t.Resource)
	var docs []map[string]any
	for _, key := range m.s.order[collection] {
		if d := m.s.docs[collection][key].doc; d != nil {
			docs = append(docs, d)
		}
	}
	m.s.mu.Unlock()
	for len(docs) > 0 {
		n := min(pageRows, len(docs))
		for _, d := range docs[:n] {
			for i, f := range t.Fields {
				_, path, _ := strings.Cut(string(f.Ref), "#")
				if v, ok := walk(d, path); ok {
					if err := value(i, v); err != nil {
						return err
					}
				}
			}
		}
		if err := page(n); err != nil {
			return err
		}
		docs = docs[n:]
	}
	return nil
}

// walk is the value at a dotted path in doc, false when there is none.
func walk(doc map[string]any, path string) (any, bool) {
	var v any = doc
	for part := range strings.SplitSeq(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[part]; !ok || v == nil {
			return nil, false
		}
	}
	return v, true
}

// The classifier's side: the fields setup lists and the sampler.

// columns are the customers' fields as the classifier sees them: each
// field's kind is the store's mapping of the types its values hold, and a
// field whose values hold more than one type is text ("uncertain means
// text"), so it is sampled.
func (s *memStore) columns() []pii.Column {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := map[string]bool{}
	for _, key := range s.order[colCustomers] {
		for f := range s.docs[colCustomers][key].doc {
			names[f] = true
		}
	}
	out := make([]pii.Column, 0, len(names))
	for _, f := range slices.Sorted(maps.Keys(names)) {
		kind, dataType := s.kindOf(f)
		out = append(out, pii.Column{Namespace: "shop", Resource: "customers", Name: f, Kind: kind, DataType: dataType, Key: f == "_id"})
	}
	return out
}

// kindOf maps the types a customers field holds to a kind.
func (s *memStore) kindOf(field string) (piistore.Kind, string) {
	types := map[string]bool{}
	for _, key := range s.order[colCustomers] {
		switch s.docs[colCustomers][key].doc[field].(type) {
		case nil:
		case string, json.RawMessage:
			types["string"] = true
		case float64, int:
			types["number"] = true
		case bool:
			types["bool"] = true
		default:
			types["object"] = true
		}
	}
	switch {
	case len(types) > 1:
		return piistore.KindText, "mixed"
	case types["number"]:
		return piistore.KindNumeric, "number"
	case types["bool"]:
		return piistore.KindBool, "bool"
	case types["object"]:
		return piistore.KindOther, "object"
	}
	return piistore.KindText, "string"
}

// sample reads up to pii.SampleRows non-null values of a field as text.
func (s *memStore) sample(_ context.Context, col pii.Column) (pii.Sample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pii.sampled = append(s.pii.sampled, col.FullName())
	collection := col.Namespace + "/" + col.Resource
	var out pii.Sample
	for _, key := range s.order[collection] {
		v := s.docs[collection][key].doc[col.Name]
		if v == nil || len(out.Values) == pii.SampleRows {
			continue
		}
		if raw, ok := v.(json.RawMessage); ok {
			out.Values = append(out.Values, string(raw))
			continue
		}
		out.Values = append(out.Values, fmt.Sprint(v))
	}
	return out, nil
}
