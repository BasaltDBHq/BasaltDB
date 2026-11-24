package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/pii"
)

// DescribeResource returns one resource as the agent may see it, or only
// its name and fingerprint when ifFingerprint is still current. A resource
// that does not exist and one the agent cannot read are the same NOT_FOUND.
func (ds *Service) DescribeResource(ctx context.Context, resource, ifFingerprint string) (Resource, error) {
	namespace, name, err := ds.core.Language.ParseName(resource)
	if err != nil {
		return Resource{}, &guidance.ArgumentError{Message: "invalid arguments: resource " + err.Error()}
	}
	res, ok, err := ds.describe.Catalog.Find(ctx, namespace, name)
	if err != nil {
		return Resource{}, err
	}
	if !ok {
		return Resource{}, describeNotFound(resource)
	}
	d, err := ds.describe.Catalog.Describe(ctx, res.Ref)
	if errors.Is(err, action.ErrNotFound) { // dropped since Find
		return Resource{}, describeNotFound(resource)
	}
	if err != nil {
		return Resource{}, err
	}
	refs := make([]agentstore.FieldRef, len(d.Fields))
	for i, f := range d.Fields {
		refs[i] = f.Ref
	}
	classes, err := ds.describe.Classes.Resolve(ctx, refs)
	if err != nil {
		return Resource{}, err
	}
	pii, err := ds.describe.Classes.CatalogFingerprint(ctx)
	if err != nil {
		return Resource{}, err
	}
	detail, err := hideFields(d, classes)
	if err != nil {
		return Resource{}, err
	}
	if slices.ContainsFunc(detail.Actions, func(a action.Op) bool { return a != action.OpSelect }) {
		guarded, err := ds.describe.Catalog.Guarded(ctx, d.Ref)
		if err != nil {
			return Resource{}, err
		}
		if guarded {
			p := writePolicy
			detail.Policy = &p
		}
	}
	out := Resource{Resource: ds.core.Language.PrintName(d.Namespace, d.Name), Detail: &detail}
	out.Fingerprint, err = resourceFingerprint(out, pii)
	if err != nil {
		return Resource{}, err
	}
	if ifFingerprint != "" && ifFingerprint == out.Fingerprint {
		return Resource{Resource: out.Resource, Fingerprint: out.Fingerprint, Unchanged: true}, nil
	}
	detail.Stats = d.Stats
	return out, nil
}

// hideFields is the visibility rule (CONTRACT.md, describe, Hidden tables
// and columns): a field the agent cannot read or classed SECRET is not
// listed, and every identity, feature and expression that touches one is
// left out whole and counted, as is a feature that is not Visible. classes
// are the fields' classes, in field order. The store's content (displays,
// stats, flags) passes through as it is.
func hideFields(d agentstore.Detail, classes []pii.Class) (ResourceDetail, error) {
	hidden := map[agentstore.FieldRef]bool{}
	names := map[agentstore.FieldRef]string{}
	for i, f := range d.Fields {
		names[f.Ref] = f.Name
		if !f.Readable || (i < len(classes) && classes[i].Class == guardmodel.ClassSecret) {
			hidden[f.Ref] = true
		}
	}
	touches := func(refs []agentstore.FieldRef) bool {
		return slices.ContainsFunc(refs, func(r agentstore.FieldRef) bool { return hidden[r] })
	}
	out := ResourceDetail{
		Kind: d.Kind, Comment: trimComment(d.Comment, resourceCommentMax), Flags: d.Flags,
		Fields: []Field{}, Actions: []action.Op{},
	}
	for i, f := range d.Fields {
		if hidden[f.Ref] {
			out.HiddenFields++
			continue
		}
		out.Fields = append(out.Fields, visibleField(f, classAt(classes, i), touches(f.ReadsFrom)))
	}
	switch {
	case touches(d.Identity):
		out.HiddenKeys++
	case len(d.Identity) > 0:
		for _, r := range d.Identity {
			out.PrimaryKey = append(out.PrimaryKey, names[r])
		}
	}
	groups, err := featureGroups(d)
	if err != nil {
		return ResourceDetail{}, err
	}
	for _, x := range d.Features {
		g := groups[x.Group]
		if !x.Visible || touches(x.Touches) {
			g.Hidden++
			continue
		}
		stable := x.Stable
		if stable == nil {
			stable = x.Display
		}
		g.Items = append(g.Items, x.Display)
		g.stable = append(g.stable, stable)
	}
	for _, key := range featureOrder(d) {
		out.Features = append(out.Features, *groups[key])
	}
	if d.Actions != nil {
		out.Actions = d.Actions
	}
	return out, nil
}

// featureGroups is an empty group for every group the store lists and
// every group a feature names.
func featureGroups(d agentstore.Detail) (map[string]*FeatureGroup, error) {
	groups := map[string]*FeatureGroup{}
	for _, key := range featureOrder(d) {
		if key == "" {
			return nil, errUnnamedGroup
		}
		groups[key] = &FeatureGroup{Key: key, Items: []any{}, stable: []any{}}
	}
	return groups, nil
}

var errUnnamedGroup = errors.New("describe: a store feature has no group")

// featureOrder is the store's groups in its order, then any group only a
// feature names, in the order first named: no feature is dropped.
func featureOrder(d agentstore.Detail) []string {
	order := slices.Clone(d.Groups)
	for _, x := range d.Features {
		if !slices.Contains(order, x.Group) {
			order = append(order, x.Group)
		}
	}
	return order
}

func classAt(classes []pii.Class, i int) pii.Class {
	if i < len(classes) && classes[i].Class != "" {
		return classes[i]
	}
	return pii.Unclassified
}

// visibleField is f as the agent sees it: with the store's masked display
// when its expression reads a hidden field.
func visibleField(f agentstore.Field, class pii.Class, expressionHidden bool) Field {
	out := Field{
		Name: f.Name, Type: f.Type, Nullable: f.Nullable, Display: f.Display,
		Comment: trimComment(f.Comment, resourceCommentMax), PII: FieldPII{Class: class.Class, EntityType: class.EntityType},
	}
	if expressionHidden {
		out.ExpressionHidden = true
		out.Display = f.Masked
	}
	return out
}

// resourceFingerprint is the sha256 of the canonical JSON of the answer
// without stats, the parts of features that change with use (index sizes
// and scans), and fingerprint, followed by the PII catalog fingerprint: it
// moves on any structural change the agent can see and on a
// reclassification, never on row counts, sizes or scans.
func resourceFingerprint(r Resource, pii string) (string, error) {
	canon := r
	canon.Form, canon.Fingerprint = "", ""
	if r.Detail != nil {
		d := *r.Detail
		d.Stats = nil
		d.Features = make([]FeatureGroup, len(r.Detail.Features))
		for i, g := range r.Detail.Features {
			g.Items = g.stable
			d.Features[i] = g
		}
		canon.Detail = &d
	}
	raw, err := json.Marshal(canon)
	if err != nil {
		return "", fmt.Errorf("fingerprint %s: %w", r.Resource, err)
	}
	sum := sha256.Sum256(append(raw, pii...))
	return hex.EncodeToString(sum[:]), nil
}

// catalogFingerprint is the sha256 of the catalog's structure lines (every
// relation, visible column, constraint and index the agent can see),
// notGranted and the PII catalog fingerprint: it moves on a structural
// change or a grant, never on rows.
func catalogFingerprint(lines []string, notGranted int, pii string) string {
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	h.Write([]byte("notGranted:" + strconv.Itoa(notGranted) + "\npii:" + pii))
	return hex.EncodeToString(h.Sum(nil))
}

// trimComment trims a user's comment and caps it at most characters.
func trimComment(s string, most int) string {
	return firstRunes(strings.TrimSpace(s), most)
}

// firstRunes is s cut to at most n characters.
func firstRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// DescribeError keeps a describe failure within the codes describe declares
// (INVALID_ARGUMENT, NOT_FOUND, QUERY_TIMEOUT, UNAVAILABLE, INTERNAL): any
// other, such as a Postgres error reading the catalog, is the engine's
// failure, INTERNAL, logged with its cause and never shown to the agent.
func (ds *Service) DescribeError(err error) error {
	switch ds.core.Errors.ToolError(err).Code {
	case guidance.CodeInvalidArgument, guidance.CodeNotFound, guidance.CodeQueryTimeout, guidance.CodeUnavailable, guidance.CodeInternal:
		return err
	}
	return &describeFailureError{err: err}
}

// describeFailureError is an error ToolError cannot map to a contract code
// (it does not unwrap), so it answers INTERNAL; its text is only logged.
type describeFailureError struct{ err error }

func (e *describeFailureError) Error() string { return "describe: " + e.err.Error() }
