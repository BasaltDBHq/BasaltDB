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
	namespace, name, err := parseResource(resource)
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
	out := Resource{Resource: printedName(d.Namespace, d.Name), Detail: &detail}
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

// parseResource reads schema.table as Postgres prints it: each part bare
// (folded to lower case, as Postgres folds it) or double-quoted, with ""
// for a quote inside.
func parseResource(s string) (schema, name string, err error) {
	parts := make([]string, 0, 2)
	rest := s
	for {
		part, tail, err := parseIdent(rest)
		if err != nil {
			return "", "", err
		}
		parts = append(parts, part)
		if tail == "" {
			break
		}
		if tail[0] != '.' {
			return "", "", errors.New("must be schema.table")
		}
		rest = tail[1:]
	}
	if len(parts) != 2 {
		return "", "", errors.New("must be schema.table, with the schema")
	}
	return parts[0], parts[1], nil
}

// parseIdent reads one identifier from the front of s: a quoted one as
// written, an unquoted one folded as Postgres folds it (foldASCII).
func parseIdent(s string) (ident, rest string, err error) {
	if strings.HasPrefix(s, `"`) {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] != '"' {
				b.WriteByte(s[i])
				continue
			}
			if i+1 < len(s) && s[i+1] == '"' {
				b.WriteByte('"')
				i++
				continue
			}
			if b.Len() == 0 {
				return "", "", errors.New("has an empty quoted name")
			}
			return b.String(), s[i+1:], nil
		}
		return "", "", errors.New("has an unclosed quote")
	}
	end := strings.IndexByte(s, '.')
	if end < 0 {
		end = len(s)
	}
	ident = s[:end]
	if ident == "" || strings.ContainsAny(ident, "\" \t\r\n") {
		return "", "", errors.New("must be schema.table, each part a name or a double-quoted name")
	}
	return foldASCII(ident), s[end:], nil
}

// foldASCII lower-cases A to Z only, as Postgres folds an unquoted
// identifier; other letters keep their case.
func foldASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// PrintedName is schema.name as Postgres prints it (quote_ident), for the
// store wiring that renders a foreign key's other table.
func PrintedName(schema, name string) string { return printedName(schema, name) }

// printedName is schema.name as Postgres prints it (quote_ident).
func printedName(schema, name string) string {
	return quoteIdent(schema) + "." + quoteIdent(name)
}

// quoteIdent quotes an identifier exactly when Postgres's quote_ident does:
// anything but lower-case letters, digits, _ and $ (not leading), or a
// keyword that is not unreserved.
func quoteIdent(s string) string {
	plain := s != "" && !quotedKeywords[s]
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case (r >= '0' && r <= '9') || r == '$':
			plain = plain && i > 0
		default:
			plain = false
		}
	}
	if plain {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// quotedKeywords are Postgres's reserved, type/function-name and
// column-name keywords (kwlist.h, up to version 17): quote_ident quotes
// them. A word quoted here that an older server leaves bare is still a
// valid name.
var quotedKeywords = func() map[string]bool {
	//nolint:misspell // analyse is a Postgres keyword
	words := strings.Fields(`all analyse analyze and any array as asc asymmetric both case cast check collate
		column constraint create current_catalog current_date current_role current_time current_timestamp
		current_user default deferrable desc distinct do else end except false fetch for foreign from grant
		group having in initially intersect into lateral leading limit localtime localtimestamp not null
		offset on only or order placing primary references returning select session_user some symmetric
		system_user table then to trailing true union unique user using variadic when where window with
		authorization binary collation concurrently cross current_schema freeze full ilike inner is isnull
		join left like natural notnull outer overlaps right similar tablesample verbose
		between bigint bit boolean char character coalesce dec decimal exists extract float greatest grouping
		inout int integer interval json json_array json_arrayagg json_object json_objectagg json_scalar
		json_serialize least national nchar none normalize numeric out overlay position precision real row
		setof smallint substring time timestamp treat trim values varchar xmlattributes xmlconcat xmlelement
		xmlexists xmlforest xmlnamespaces xmlparse xmlpi xmlroot xmlserialize xmltable
		json_exists json_query json_table json_value merge_action`)
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}()

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
