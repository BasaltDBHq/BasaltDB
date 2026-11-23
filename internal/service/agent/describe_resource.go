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
	"time"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/service/piidict"
)

// DescribeResource returns one table as the agent may see it, or only its
// name and fingerprint when ifFingerprint is still current. A table that
// does not exist and one the agent cannot read are the same NOT_FOUND.
func (ds *describeCase) DescribeResource(ctx context.Context, resource, ifFingerprint string) (Resource, error) {
	schema, name, err := parseResource(resource)
	if err != nil {
		return Resource{}, &guidance.ArgumentError{Message: "invalid arguments: resource " + err.Error()}
	}
	rel, ok, err := ds.deps.Catalog.Find(ctx, schema, name)
	if err != nil {
		return Resource{}, err
	}
	if !ok {
		return Resource{}, describeNotFound(resource)
	}
	d, err := ds.deps.Catalog.Describe(ctx, rel.OID)
	if errors.Is(err, action.ErrNotFound) { // dropped since Find
		return Resource{}, describeNotFound(resource)
	}
	if err != nil {
		return Resource{}, err
	}
	refs := make([]piidict.ColumnRef, len(d.Columns))
	for i, c := range d.Columns {
		refs[i] = piidict.ColumnRef{TableOID: d.OID, Attnum: c.Attnum}
	}
	classes, err := ds.deps.Classes.Resolve(ctx, refs)
	if err != nil {
		return Resource{}, err
	}
	pii, err := ds.deps.Classes.CatalogFingerprint(ctx)
	if err != nil {
		return Resource{}, err
	}
	detail := hideColumns(d, classes)
	if slices.ContainsFunc(detail.Actions, func(a string) bool { return a != privSelect }) {
		guarded, err := ds.deps.Catalog.Guarded(ctx, d.OID)
		if err != nil {
			return Resource{}, err
		}
		if guarded {
			p := writePolicy
			detail.Policy = &p
		}
	}
	out := Resource{Resource: printedName(d.Schema, d.Name), ResourceDetail: &detail}
	out.Fingerprint, err = resourceFingerprint(out, pii)
	if err != nil {
		return Resource{}, err
	}
	if ifFingerprint != "" && ifFingerprint == out.Fingerprint {
		return Resource{Resource: out.Resource, Fingerprint: out.Fingerprint, Unchanged: true}, nil
	}
	detail.Stats = resourceStats(d)
	return out, nil
}

// hideColumns is the visibility rule (CONTRACT.md, describe, Hidden tables
// and columns): a column the agent cannot SELECT or classed SECRET is not
// listed, and every index, key and expression that touches one is left out
// whole and counted. classes are the columns' classes, in column order.
func hideColumns(d CatalogDetail, classes []piidict.Class) ResourceDetail {
	hidden := map[int16]bool{}
	names := map[int16]string{}
	for i, c := range d.Columns {
		names[c.Attnum] = c.Name
		if !c.Selectable || (i < len(classes) && classes[i].Class == guardmodel.ClassSecret) {
			hidden[c.Attnum] = true
		}
	}
	touches := func(attnums []int16) bool {
		return slices.ContainsFunc(attnums, func(n int16) bool { return hidden[n] })
	}
	out := ResourceDetail{
		Kind: d.Kind, Comment: trimComment(d.Comment, resourceCommentMax), RLS: d.RLS,
		Fields: []Field{}, Indexes: []IndexInfo{}, ForeignKeys: []ForeignKeyInfo{}, Actions: []string{},
		CascadesIntoHidden: d.CascadesIntoHidden,
	}
	for i, c := range d.Columns {
		if hidden[c.Attnum] {
			out.HiddenFields++
			continue
		}
		out.Fields = append(out.Fields, visibleField(c, classAt(classes, i), touches(c.DefaultAttnums)))
	}
	switch {
	case touches(d.PrimaryKey):
		out.HiddenKeys++
	case len(d.PrimaryKey) > 0:
		for _, n := range d.PrimaryKey {
			out.PrimaryKey = append(out.PrimaryKey, names[n])
		}
	}
	for _, x := range d.Indexes {
		if touches(x.Attnums) {
			out.HiddenIndexes++
			continue
		}
		out.Indexes = append(out.Indexes, IndexInfo{
			Name: x.Name, Definition: x.Definition, Unique: x.Unique, Partial: x.Partial, SizeBytes: x.SizeBytes, Scans: x.Scans,
		})
	}
	for _, k := range d.Keys {
		if !k.OtherReadable || touches(k.Attnums) {
			out.HiddenForeignKeys++
			continue
		}
		out.ForeignKeys = append(out.ForeignKeys, foreignKey(k, names))
	}
	if d.Privileges != nil {
		out.Actions = d.Privileges
	}
	return out
}

func classAt(classes []piidict.Class, i int) piidict.Class {
	if i < len(classes) && classes[i].Class != "" {
		return classes[i]
	}
	return piidict.Unclassified
}

func visibleField(c CatalogColumn, class piidict.Class, expressionHidden bool) Field {
	f := Field{
		Name: c.Name, Type: c.Type, Nullable: c.Nullable, Generated: c.Generated,
		Comment: trimComment(c.Comment, resourceCommentMax), PII: FieldPII{Class: class.Class, EntityType: class.EntityType},
	}
	switch {
	case expressionHidden:
		f.ExpressionHidden = true
	case c.Default != "":
		def := c.Default
		f.Default = &def
	}
	return f
}

func foreignKey(k CatalogKey, names map[int16]string) ForeignKeyInfo {
	fk := ForeignKeyInfo{
		Direction: "INCOMING", Columns: make([]string, 0, len(k.Attnums)), Table: printedName(k.OtherSchema, k.OtherTable),
		OnDelete: fkAction(k.OnDelete), OnUpdate: fkAction(k.OnUpdate),
	}
	if k.Outgoing {
		fk.Direction = "OUTGOING"
	}
	for _, n := range k.Attnums {
		fk.Columns = append(fk.Columns, names[n])
	}
	return fk
}

// fkAction is a catalog action (SET NULL) as the contract spells it.
func fkAction(a string) string { return strings.ReplaceAll(a, " ", "_") }

func resourceStats(d CatalogDetail) *ResourceStats {
	st := &ResourceStats{
		EstimatedRows: d.EstimatedRows, TableBytes: d.Stats.TableBytes, TotalBytes: d.Stats.TotalBytes,
		SeqScans: d.Stats.SeqScans, IndexScans: d.Stats.IndexScans,
	}
	if d.Stats.LastAnalyzed != nil {
		at := d.Stats.LastAnalyzed.UTC().Format(time.RFC3339)
		st.LastAnalyzed = &at
	}
	return st
}

// resourceFingerprint is the sha256 of the canonical JSON of the answer
// without stats, index sizes and scans, and fingerprint, followed by the PII catalog fingerprint:
// it moves on any structural change the agent can see and on a
// reclassification, never on row counts, sizes or scans.
func resourceFingerprint(r Resource, pii string) (string, error) {
	canon := r
	canon.Fingerprint = ""
	if r.ResourceDetail != nil {
		d := *r.ResourceDetail
		d.Stats = nil
		// Index sizes and scan counters change with use, like stats.
		d.Indexes = make([]IndexInfo, len(r.Indexes))
		for i, x := range r.Indexes {
			x.SizeBytes, x.Scans = 0, 0
			d.Indexes[i] = x
		}
		canon.ResourceDetail = &d
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

// describeError keeps a describe failure within the codes describe declares
// (INVALID_ARGUMENT, NOT_FOUND, QUERY_TIMEOUT, UNAVAILABLE, INTERNAL): any
// other, such as a Postgres error reading the catalog, is the engine's
// failure, INTERNAL, logged with its cause and never shown to the agent.
func (ds *describeCase) describeError(err error) error {
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
