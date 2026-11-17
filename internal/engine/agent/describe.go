package agent

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine/piidict"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// Catalog reads the structure of the database the agent can see, on the
// agent's own credential (CONTRACT.md, describe). The Postgres adapter
// implements it; it mirrors internal/pgcatalog.
type Catalog interface {
	// Relations lists the readable relations by schema and name, and counts
	// the ones in user schemas the agent cannot read.
	Relations(ctx context.Context) ([]pgcatalog.Relation, int, error)
	// Find returns schema.name, or false when it is absent or unreadable.
	Find(ctx context.Context, schema, name string) (pgcatalog.Relation, bool, error)
	// Describe reads one relation Find or Relations returned.
	Describe(ctx context.Context, oid uint32) (pgcatalog.Detail, error)
	// Guarded reports whether basalt init guards the relation, so its
	// writes run under the write policy; false where the guard predates
	// the record of it.
	Guarded(ctx context.Context, oid uint32) (bool, error)
	// Search finds readable relations by name, column or comment; exclude
	// lists columns never matched or named.
	Search(ctx context.Context, q string, exclude []pgcatalog.ColumnKey, after *pgcatalog.SearchCursor, limit int) ([]pgcatalog.Match, error)
	// Structure is the sorted structure lines the catalog fingerprint hashes.
	Structure(ctx context.Context) ([]string, error)
	// Database is the database the credential connects to.
	Database() string
	// Limits are the read limits the agent's statements run within.
	Limits() sqlguard.Limits
}

// ClassResolver is the agent's PII classification (piidict.BoundMap).
type ClassResolver interface {
	Resolve(ctx context.Context, refs []piidict.ColumnRef) ([]piidict.Class, error)
	// Secrets lists the SECRET columns: describe never lists, matches or
	// names them.
	Secrets(ctx context.Context) ([]piidict.ColumnRef, error)
	// CatalogFingerprint is agent_pii_catalog.fingerprint as hex, empty
	// before the first basalt classify.
	CatalogFingerprint(ctx context.Context) (string, error)
}

// noCatalog serves a service built without a catalog: every describe call
// is an engine defect (INTERNAL).
type noCatalog struct{}

var errNoCatalog = errors.New("describe: no catalog configured")

func (noCatalog) Relations(context.Context) ([]pgcatalog.Relation, int, error) {
	return nil, 0, errNoCatalog
}

func (noCatalog) Find(context.Context, string, string) (pgcatalog.Relation, bool, error) {
	return pgcatalog.Relation{}, false, errNoCatalog
}

func (noCatalog) Describe(context.Context, uint32) (pgcatalog.Detail, error) {
	return pgcatalog.Detail{}, errNoCatalog
}

func (noCatalog) Guarded(context.Context, uint32) (bool, error) { return false, errNoCatalog }

func (noCatalog) Search(context.Context, string, []pgcatalog.ColumnKey, *pgcatalog.SearchCursor, int) ([]pgcatalog.Match, error) {
	return nil, errNoCatalog
}

func (noCatalog) Structure(context.Context) ([]string, error) { return nil, errNoCatalog }
func (noCatalog) Database() string                            { return "" }
func (noCatalog) Limits() sqlguard.Limits                     { return sqlguard.DefaultLimits() }

// noClasses serves a service built without PII classes: it cannot tell a
// SECRET column, so every describe call fails closed (INTERNAL).
type noClasses struct{}

var errNoClasses = errors.New("describe: no pii classes configured")

func (noClasses) Resolve(context.Context, []piidict.ColumnRef) ([]piidict.Class, error) {
	return nil, errNoClasses
}

func (noClasses) Secrets(context.Context) ([]piidict.ColumnRef, error) { return nil, errNoClasses }
func (noClasses) CatalogFingerprint(context.Context) (string, error)   { return "", errNoClasses }

const (
	// overviewInlineMax is the most visible tables the overview lists
	// inline; above it lists schemas and points to search.
	overviewInlineMax = 50
	// overviewSchemasMax is the most schemas the large overview lists (D-3):
	// the ones with the most visible tables; the rest are counted.
	overviewSchemasMax = 50
	// resourceCommentMax and searchCommentMax cap comments, in characters
	// (D-4): the full form and a search item.
	resourceCommentMax = 500
	searchCommentMax   = 120
	// describeQueryMax is the longest search query, in characters.
	describeQueryMax = 100
	// policyAllowedUpTo is the most rows a write is allowed without a hold;
	// up to MaxRetryRows it is held for approval, over it refused.
	policyAllowedUpTo = 10

	storePostgres = "POSTGRES"
	formOverview  = "OVERVIEW"
	formSearch    = "SEARCH"
	formResource  = "RESOURCE"
	privSelect    = "SELECT"
)

// WritePolicy is the guard's write policy (CONTRACT.md, Approvals).
type WritePolicy struct {
	AllowedUpTo         int  `json:"allowedUpTo"`
	HeldUpTo            int  `json:"heldUpTo"`
	RefusedOver         int  `json:"refusedOver"`
	DeleteHeld          bool `json:"deleteHeld"`
	CascadedRowsCounted bool `json:"cascadedRowsCounted"`
}

// writePolicy is the one policy every guarded table has today.
var writePolicy = WritePolicy{
	AllowedUpTo: policyAllowedUpTo, HeldUpTo: MaxRetryRows, RefusedOver: MaxRetryRows,
	DeleteHeld: true, CascadedRowsCounted: true,
}

// SearchItem is one table in the overview or a search page.
type SearchItem struct {
	Resource      string   `json:"resource"`
	Kind          string   `json:"kind"`
	EstimatedRows *int64   `json:"estimatedRows"`
	Matched       string   `json:"matched,omitempty"`
	Access        []string `json:"access"`
	Comment       string   `json:"comment,omitempty"`
}

// StoreInfo names the store the agent is pointed at.
type StoreInfo struct {
	Kind     string `json:"kind"`
	Database string `json:"database"`
}

// Counts are the overview's counts.
type Counts struct {
	Schemas    int `json:"schemas"`
	Tables     int `json:"tables"`
	NotGranted int `json:"notGranted"`
}

// OverviewLimits are the read limits and the write policy.
type OverviewLimits struct {
	ReadRowLimit       int         `json:"readRowLimit"`
	StatementTimeoutMs int64       `json:"statementTimeoutMs"`
	WritePolicy        WritePolicy `json:"writePolicy"`
}

// SchemaCount is one schema of a large overview.
type SchemaCount struct {
	Schema string `json:"schema"`
	Tables int    `json:"tables"`
}

// OtherSchemas counts the schemas a large overview leaves out, and the
// visible tables in them.
type OtherSchemas struct {
	Schemas int `json:"schemas"`
	Tables  int `json:"tables"`
}

// Overview is describe's first form.
type Overview struct {
	Store         StoreInfo      `json:"store"`
	Fingerprint   string         `json:"fingerprint"`
	Counts        Counts         `json:"counts"`
	Limits        OverviewLimits `json:"limits"`
	Resources     []SearchItem   `json:"resources,omitzero"`
	Schemas       []SchemaCount  `json:"schemas,omitzero"`
	OtherSchemas  *OtherSchemas  `json:"otherSchemas,omitempty"`
	PersonMessage string         `json:"personMessage,omitempty"`
	NextSteps     []mcp.NextStep `json:"nextSteps,omitempty"`
	Update        *UpdateInfo    `json:"update,omitempty"`
}

// DescribeSearchParams are a search's validated arguments.
type DescribeSearchParams struct {
	pagination.Params
	Query string
}

// FieldPII is a field's PII class.
type FieldPII struct {
	Class      string `json:"class"`
	EntityType string `json:"entityType,omitempty"`
}

// Field is one visible column.
type Field struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	// Default is null when there is none or it names a hidden column.
	Default          *string  `json:"default"`
	Generated        bool     `json:"generated,omitempty"`
	ExpressionHidden bool     `json:"expressionHidden,omitempty"`
	Comment          string   `json:"comment,omitempty"`
	PII              FieldPII `json:"pii"`
}

// IndexInfo is one visible index.
type IndexInfo struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Unique     bool   `json:"unique"`
	Partial    bool   `json:"partial"`
	SizeBytes  int64  `json:"sizeBytes"`
	Scans      int64  `json:"scans"`
}

// ForeignKeyInfo is one visible foreign key.
type ForeignKeyInfo struct {
	Direction string   `json:"direction"`
	Columns   []string `json:"columns"`
	Table     string   `json:"table"`
	OnDelete  string   `json:"onDelete"`
	OnUpdate  string   `json:"onUpdate"`
}

// ResourceStats are left out of the resource fingerprint.
type ResourceStats struct {
	EstimatedRows *int64  `json:"estimatedRows"`
	TableBytes    int64   `json:"tableBytes"`
	TotalBytes    int64   `json:"totalBytes"`
	SeqScans      int64   `json:"seqScans"`
	IndexScans    int64   `json:"indexScans"`
	LastAnalyzed  *string `json:"lastAnalyzed"`
}

// ResourceDetail is what the agent may see of one table: hidden columns,
// and the indexes, keys and expressions that touch them, only counted.
type ResourceDetail struct {
	Kind               string           `json:"kind"`
	Comment            string           `json:"comment,omitempty"`
	Fields             []Field          `json:"fields"`
	HiddenFields       int              `json:"hiddenFields"`
	PrimaryKey         []string         `json:"primaryKey,omitempty"`
	HiddenKeys         int              `json:"hiddenKeys"`
	Indexes            []IndexInfo      `json:"indexes"`
	HiddenIndexes      int              `json:"hiddenIndexes"`
	ForeignKeys        []ForeignKeyInfo `json:"foreignKeys"`
	HiddenForeignKeys  int              `json:"hiddenForeignKeys"`
	CascadesIntoHidden int              `json:"cascadesIntoHidden"`
	Stats              *ResourceStats   `json:"stats,omitempty"`
	RLS                bool             `json:"rls"`
	Actions            []string         `json:"actions"`
	// Policy is the write policy on a guarded table the agent can write;
	// null otherwise.
	Policy *WritePolicy `json:"policy"`
}

// Resource is describe's resource form: the detail, or only the name and
// fingerprint with Unchanged when ifFingerprint is current.
type Resource struct {
	Resource    string `json:"resource"`
	Fingerprint string `json:"fingerprint"`
	Unchanged   bool   `json:"unchanged,omitempty"`
	*ResourceDetail
}

// DescribeOverview counts what the agent can see, lists it (up to 50
// tables) or its schemas, and tells the person how to see what it cannot.
func (s *Service) DescribeOverview(ctx context.Context) (Overview, error) {
	visible, notGranted, err := s.Catalog.Relations(ctx)
	if err != nil {
		return Overview{}, err
	}
	lines, err := s.Catalog.Structure(ctx)
	if err != nil {
		return Overview{}, err
	}
	pii, err := s.Classes.CatalogFingerprint(ctx)
	if err != nil {
		return Overview{}, err
	}
	limits := s.Catalog.Limits()
	o := Overview{
		Store:       StoreInfo{Kind: storePostgres, Database: s.Catalog.Database()},
		Fingerprint: catalogFingerprint(lines, notGranted, pii),
		Counts:      Counts{Tables: len(visible), NotGranted: notGranted},
		Update:      s.updateInfo(),
		Limits: OverviewLimits{
			ReadRowLimit: limits.ReadRowLimit, StatementTimeoutMs: limits.StatementTimeout.Milliseconds(), WritePolicy: writePolicy,
		},
	}
	schemas := schemaCounts(visible)
	o.Counts.Schemas = len(schemas)
	b := NewSteps()
	switch {
	case len(visible) > overviewInlineMax:
		o.Schemas, o.OtherSchemas = capSchemas(schemas)
		overviewLargeSteps(b, o.Schemas)
	default:
		o.Resources = make([]SearchItem, 0, len(visible))
		for _, r := range visible {
			o.Resources = append(o.Resources, searchItem(r, ""))
		}
	}
	if notGranted > 0 {
		o.PersonMessage = s.notGrantedSteps(b, notGranted)
	}
	if o.Schemas == nil && notGranted == 0 {
		return o, nil
	}
	if o.NextSteps, err = b.Build(); err != nil {
		return Overview{}, err
	}
	return o, nil
}

// schemaCounts counts the visible tables of each schema, by schema name.
func schemaCounts(visible []pgcatalog.Relation) []SchemaCount {
	var out []SchemaCount
	for _, r := range visible {
		if n := len(out); n > 0 && out[n-1].Schema == r.Schema {
			out[n-1].Tables++
			continue
		}
		out = append(out, SchemaCount{Schema: r.Schema, Tables: 1})
	}
	return out
}

// capSchemas keeps the overviewSchemasMax schemas with the most visible
// tables, most first (ties by schema name), and counts the rest. nil when
// nothing was left out.
func capSchemas(schemas []SchemaCount) ([]SchemaCount, *OtherSchemas) {
	sorted := slices.Clone(schemas)
	slices.SortFunc(sorted, func(a, b SchemaCount) int {
		return cmp.Or(cmp.Compare(b.Tables, a.Tables), cmp.Compare(a.Schema, b.Schema))
	})
	if len(sorted) <= overviewSchemasMax {
		return sorted, nil
	}
	other := &OtherSchemas{Schemas: len(sorted) - overviewSchemasMax}
	for _, sc := range sorted[overviewSchemasMax:] {
		other.Tables += sc.Tables
	}
	return sorted[:overviewSchemasMax], other
}

// overviewLargeSteps (OVERVIEW_LARGE): search instead of listing. The
// arguments list the largest schema, a complete call the agent can make as
// it is.
func overviewLargeSteps(b *Steps, schemas []SchemaCount) {
	largest := schemas[0]
	for _, sc := range schemas[1:] {
		if sc.Tables > largest.Tables {
			largest = sc
		}
	}
	b.CallTool(toolDescribe, map[string]any{argQuery: firstRunes(largest.Schema, describeQueryMax)},
		"Find tables with describe and a query: a word of a table, column or schema name. These arguments list the largest schema.")
}

// notGrantedSteps (NOT_GRANTED): the person may look at what the agent
// cannot read, with basalt access, always a PERSON step: its output names
// the tables the agent must not read (D-1, D-7). No ASK_PERSON: platform
// schemas are ungranted on every Supabase project.
func (s *Service) notGrantedSteps(b *Steps, notGranted int) string {
	command := s.Commands.Access()
	b.RunCommand(command, "Run this to list the tables the agent cannot read, with the basalt init flag that would grant each.")
	b.TellAgent("Tell the agent when you grant it a table it needs.")
	return fitMessage(fmt.Sprintf("%d %s in this database %s not granted to the agent, so it cannot see %s. "+
		"To list the tables the agent cannot read, run: %s",
		notGranted, plural(notGranted, "table", "tables"), plural(notGranted, "is", "are"), plural(notGranted, "it", "them"), command), command)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// describeNotFound is NOT_FOUND for a resource that does not exist and for
// one the agent cannot read: the same answer, so names cannot be probed.
func describeNotFound(resource string) error {
	return &mcp.ToolError{Code: CodeNotFound, Message: fmt.Sprintf(
		"%q is not a table this agent can read: it does not exist, or the agent has no access to it", firstRunes(resource, maxTableChars))}
}

// describeNotFoundSteps are NOT_FOUND's steps for describe, all of them on
// every answer: search, ask, and the person's basalt access.
func (s *Service) describeNotFoundSteps(b *Steps, f failure) string {
	b.CallTool(toolDescribe, map[string]any{argQuery: searchTerm(f.arg(argResource))},
		"Search for the table by name: it may be spelled differently or sit in another schema.")
	b.AskPerson("Tell the person the table was not found or is not granted to you, and ask whether you should have it.")
	command := s.Commands.Access()
	b.RunCommand(command, "Run this to list the tables the agent cannot read, with the basalt init flag that would grant each.")
	b.TellAgent("Tell the agent when it has the access, or which table to use instead.")
	return fitMessage("The agent asked for a table it cannot see: it does not exist, or the agent may not read it. "+
		"To list the tables the agent cannot read, run: "+command, command)
}

// searchTerm is the search for a resource not found: its table name.
func searchTerm(resource string) string {
	term := resource
	if _, name, err := parseResource(resource); err == nil {
		term = name
	}
	term = firstRunes(strings.TrimSpace(term), describeQueryMax)
	if term == "" {
		return resource
	}
	return term
}

// DescribeSearch returns one page of the relations matching p.Query, never
// matching or naming a SECRET column.
func (s *Service) DescribeSearch(ctx context.Context, p DescribeSearchParams) (pagination.Page[SearchItem], error) {
	var after *pgcatalog.SearchCursor
	if p.Cursor != "" {
		c, err := decodeSearchCursor(p.Cursor)
		if err != nil {
			return pagination.Page[SearchItem]{}, err
		}
		after = &c
	}
	secrets, err := s.Classes.Secrets(ctx)
	if err != nil {
		return pagination.Page[SearchItem]{}, err
	}
	exclude := make([]pgcatalog.ColumnKey, 0, len(secrets))
	for _, r := range secrets {
		exclude = append(exclude, pgcatalog.ColumnKey{OID: r.TableOID, Attnum: r.Attnum})
	}
	matches, err := s.Catalog.Search(ctx, p.Query, exclude, after, p.Limit+1)
	if err != nil {
		return pagination.Page[SearchItem]{}, err
	}
	var page pagination.Page[SearchItem]
	if len(matches) > p.Limit {
		matches = matches[:p.Limit]
		last := matches[len(matches)-1]
		page.NextCursor = encodeSearchCursor(pgcatalog.SearchCursor{Rank: last.Rank, Schema: last.Schema, Name: last.Name})
	}
	page.Items = make([]SearchItem, 0, len(matches))
	for _, m := range matches {
		page.Items = append(page.Items, searchItem(m.Relation, m.Matched))
	}
	return page, nil
}

func searchItem(r pgcatalog.Relation, matched string) SearchItem {
	access := r.Privileges
	if access == nil {
		access = []string{}
	}
	return SearchItem{
		Resource: printedName(r.Schema, r.Name), Kind: r.Kind, EstimatedRows: r.EstimatedRows,
		Matched: matched, Access: access, Comment: trimComment(r.Comment, searchCommentMax),
	}
}

// searchCursorKey is a search page's cursor: the last match's rank and name.
type searchCursorKey struct {
	Rank   int    `json:"r"`
	Schema string `json:"s"`
	Name   string `json:"n"`
}

// searchRanks is how many ranks Search has (exact table name to comment).
const searchRanks = 6

func encodeSearchCursor(c pgcatalog.SearchCursor) string {
	raw, err := json.Marshal(searchCursorKey(c))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeSearchCursor reads a cursor describe returned for a search.
func decodeSearchCursor(cursor string) (pgcatalog.SearchCursor, error) {
	stale := &ArgumentError{Message: "invalid arguments: the cursor is not one describe returned for a search", Reason: ReasonStaleCursor}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return pgcatalog.SearchCursor{}, stale
	}
	var k searchCursorKey
	if json.Unmarshal(raw, &k) != nil || k.Rank < 0 || k.Rank >= searchRanks || k.Schema == "" || k.Name == "" {
		return pgcatalog.SearchCursor{}, stale
	}
	return pgcatalog.SearchCursor(k), nil
}

// DescribeResource returns one table as the agent may see it, or only its
// name and fingerprint when ifFingerprint is still current. A table that
// does not exist and one the agent cannot read are the same NOT_FOUND.
func (s *Service) DescribeResource(ctx context.Context, resource, ifFingerprint string) (Resource, error) {
	schema, name, err := parseResource(resource)
	if err != nil {
		return Resource{}, &ArgumentError{Message: "invalid arguments: resource " + err.Error()}
	}
	rel, ok, err := s.Catalog.Find(ctx, schema, name)
	if err != nil {
		return Resource{}, err
	}
	if !ok {
		return Resource{}, describeNotFound(resource)
	}
	d, err := s.Catalog.Describe(ctx, rel.OID)
	if errors.Is(err, pgx.ErrNoRows) { // dropped since Find
		return Resource{}, describeNotFound(resource)
	}
	if err != nil {
		return Resource{}, err
	}
	refs := make([]piidict.ColumnRef, len(d.Columns))
	for i, c := range d.Columns {
		refs[i] = piidict.ColumnRef{TableOID: d.OID, Attnum: c.Attnum}
	}
	classes, err := s.Classes.Resolve(ctx, refs)
	if err != nil {
		return Resource{}, err
	}
	pii, err := s.Classes.CatalogFingerprint(ctx)
	if err != nil {
		return Resource{}, err
	}
	detail := hideColumns(d, classes)
	if slices.ContainsFunc(detail.Actions, func(a string) bool { return a != privSelect }) {
		guarded, err := s.Catalog.Guarded(ctx, d.OID)
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
func hideColumns(d pgcatalog.Detail, classes []piidict.Class) ResourceDetail {
	hidden := map[int16]bool{}
	names := map[int16]string{}
	for i, c := range d.Columns {
		names[c.Attnum] = c.Name
		if !c.Selectable || (i < len(classes) && classes[i].Class == guard.ClassSecret) {
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

func visibleField(c pgcatalog.Column, class piidict.Class, expressionHidden bool) Field {
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

func foreignKey(k pgcatalog.Key, names map[int16]string) ForeignKeyInfo {
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

func resourceStats(d pgcatalog.Detail) *ResourceStats {
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
func describeError(err error) error {
	switch ToolError(err).Code {
	case CodeInvalidArgument, CodeNotFound, CodeQueryTimeout, CodeUnavailable, CodeInternal:
		return err
	}
	return &describeFailureError{err: err}
}

// describeFailureError is an error ToolError cannot map to a contract code
// (it does not unwrap), so it answers INTERNAL; its text is only logged.
type describeFailureError struct{ err error }

func (e *describeFailureError) Error() string { return "describe: " + e.err.Error() }
