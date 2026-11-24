package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgcatalog"
)

// The Postgres catalog as the agent reads it. The agent's describe is
// written in core/agentstore's types; this wiring renders pgcatalog's
// answers into them (refs from OIDs and attribute numbers, the index,
// foreign key, default and stats content the agent sees) and reads the refs
// back. pgcatalog itself does not know the agent.

// Postgres's feature groups and flags in describe's answer.
const (
	pgGroupIndexes     = "indexes"
	pgGroupForeignKeys = "foreignKeys"
	pgFlagCascades     = "cascadesIntoHidden"
	pgFlagRLS          = "rls"
)

// pgCatalog is the store's catalog in pgcatalog's types (*postgres.Catalog).
type pgCatalog interface {
	Relations(ctx context.Context) ([]pgcatalog.Relation, int, error)
	Find(ctx context.Context, schema, name string) (pgcatalog.Relation, bool, error)
	Describe(ctx context.Context, oid uint32) (pgcatalog.Detail, error)
	Guarded(ctx context.Context, oid uint32) (bool, error)
	Search(ctx context.Context, q string, exclude []pgcatalog.ColumnKey, after *pgcatalog.SearchCursor, limit int) ([]pgcatalog.Match, error)
	Structure(ctx context.Context) ([]string, error)
	Database() string
	Host() string
	Limits() action.Limits
}

// agentCatalog is the store's catalog as the agent reads it.
type agentCatalog struct{ pg pgCatalog }

func (c agentCatalog) Resources(ctx context.Context) ([]agentstore.Resource, int, error) {
	rs, n, err := c.pg.Relations(ctx)
	if err != nil {
		return nil, 0, err
	}
	out := make([]agentstore.Resource, len(rs))
	for i, r := range rs {
		out[i] = pgResource(r)
	}
	return out, n, nil
}

func (c agentCatalog) Find(ctx context.Context, namespace, name string) (agentstore.Resource, bool, error) {
	r, ok, err := c.pg.Find(ctx, namespace, name)
	if err != nil || !ok {
		return agentstore.Resource{}, false, err
	}
	return pgResource(r), true, nil
}

func (c agentCatalog) Describe(ctx context.Context, ref agentstore.ResourceRef) (agentstore.Detail, error) {
	oid, err := pgOID(ref)
	if err != nil {
		return agentstore.Detail{}, err
	}
	d, err := c.pg.Describe(ctx, oid)
	if err != nil {
		return agentstore.Detail{}, err
	}
	return pgDetail(d), nil
}

func (c agentCatalog) Guarded(ctx context.Context, ref agentstore.ResourceRef) (bool, error) {
	oid, err := pgOID(ref)
	if err != nil {
		return false, err
	}
	return c.pg.Guarded(ctx, oid)
}

func (c agentCatalog) Search(ctx context.Context, q string, exclude []agentstore.FieldRef, after *agentstore.Cursor, limit int) ([]agentstore.Match, error) {
	ex := make([]pgcatalog.ColumnKey, len(exclude))
	for i, ref := range exclude {
		col, err := pgColumn(ref)
		if err != nil {
			return nil, err
		}
		ex[i] = pgcatalog.ColumnKey{OID: col.TableOID, Attnum: col.Attnum}
	}
	var cur *pgcatalog.SearchCursor
	if after != nil {
		cur = &pgcatalog.SearchCursor{Rank: after.Rank, Schema: after.Namespace, Name: after.Name}
	}
	ms, err := c.pg.Search(ctx, q, ex, cur, limit)
	if err != nil {
		return nil, err
	}
	out := make([]agentstore.Match, len(ms))
	for i, m := range ms {
		out[i] = agentstore.Match{Resource: pgResource(m.Relation), Rank: m.Rank, Matched: m.Matched}
	}
	return out, nil
}

func (c agentCatalog) Structure(ctx context.Context) ([]string, error) { return c.pg.Structure(ctx) }

func (c agentCatalog) Database() string { return c.pg.Database() }

func (c agentCatalog) Host() string { return c.pg.Host() }

func (c agentCatalog) Limits() action.Limits { return c.pg.Limits() }

// pgResourceRef is a table's ref: its OID.
func pgResourceRef(oid uint32) agentstore.ResourceRef {
	return agentstore.ResourceRef(strconv.FormatUint(uint64(oid), 10))
}

// pgFieldRef is a column's ref: its table's OID and its attribute number.
func pgFieldRef(oid uint32, attnum int16) agentstore.FieldRef {
	return agentstore.FieldRef(strconv.FormatUint(uint64(oid), 10) + "/" + strconv.Itoa(int(attnum)))
}

func pgFieldRefs(oid uint32, attnums []int16) []agentstore.FieldRef {
	if attnums == nil {
		return nil
	}
	out := make([]agentstore.FieldRef, len(attnums))
	for i, n := range attnums {
		out[i] = pgFieldRef(oid, n)
	}
	return out
}

// pgOID reads a resource ref back. A ref this wiring did not write is an
// engine defect, never a guess.
func pgOID(ref agentstore.ResourceRef) (uint32, error) {
	oid, err := strconv.ParseUint(string(ref), 10, 32)
	if err != nil || pgResourceRef(uint32(oid)) != ref {
		return 0, fmt.Errorf("describe: %q is not a Postgres resource ref", ref)
	}
	return uint32(oid), nil
}

// pgColumn reads a field ref back, as the column ref the PII classes use. A
// ref this wiring did not write is an engine defect, never a guess.
func pgColumn(ref agentstore.FieldRef) (pii.ColumnRef, error) {
	bad := fmt.Errorf("describe: %q is not a Postgres field ref", ref)
	table, col, ok := strings.Cut(string(ref), "/")
	if !ok {
		return pii.ColumnRef{}, bad
	}
	oid, err := strconv.ParseUint(table, 10, 32)
	if err != nil {
		return pii.ColumnRef{}, bad
	}
	attnum, err := strconv.ParseInt(col, 10, 16)
	if err != nil || pgFieldRef(uint32(oid), int16(attnum)) != ref {
		return pii.ColumnRef{}, bad
	}
	return pii.ColumnRef{TableOID: uint32(oid), Attnum: int16(attnum)}, nil
}

func pgResource(r pgcatalog.Relation) agentstore.Resource {
	var actions []action.Op
	if r.Privileges != nil {
		actions = make([]action.Op, len(r.Privileges))
		for i, p := range r.Privileges {
			actions[i] = action.Op(p)
		}
	}
	return agentstore.Resource{
		Ref: pgResourceRef(r.OID), Namespace: r.Schema, Name: r.Name, Kind: r.Kind,
		Estimate: r.EstimatedRows, Comment: r.Comment, Actions: actions,
	}
}

// pgFieldDisplay is what describe shows of a column beyond its name, type
// and nullability. Default is null when there is none, or when it reads a
// hidden column (the masked form).
type pgFieldDisplay struct {
	Default   *string `json:"default"`
	Generated bool    `json:"generated,omitempty"`
}

// pgIndexDisplay is one index as describe shows it.
type pgIndexDisplay struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Unique     bool   `json:"unique"`
	Partial    bool   `json:"partial"`
	SizeBytes  int64  `json:"sizeBytes"`
	Scans      int64  `json:"scans"`
}

// pgForeignKeyDisplay is one foreign key as describe shows it.
type pgForeignKeyDisplay struct {
	Direction string   `json:"direction"`
	Columns   []string `json:"columns"`
	Table     string   `json:"table"`
	OnDelete  string   `json:"onDelete"`
	OnUpdate  string   `json:"onUpdate"`
}

// pgStatsDisplay is a table's size and scan activity as describe shows it.
type pgStatsDisplay struct {
	EstimatedRows *int64  `json:"estimatedRows"`
	TableBytes    int64   `json:"tableBytes"`
	TotalBytes    int64   `json:"totalBytes"`
	SeqScans      int64   `json:"seqScans"`
	IndexScans    int64   `json:"indexScans"`
	LastAnalyzed  *string `json:"lastAnalyzed"`
}

// pgDetail is one relation in the agent's types. Every column an index, key
// or default names is in its Touches or ReadsFrom: the attribute numbers
// pgcatalog reads for it.
func pgDetail(d pgcatalog.Detail) agentstore.Detail {
	out := agentstore.Detail{
		Resource: pgResource(d.Relation),
		Identity: pgFieldRefs(d.OID, d.PrimaryKey),
		Groups:   []string{pgGroupIndexes, pgGroupForeignKeys},
		Stats:    pgStats(d),
		Flags:    map[string]any{pgFlagCascades: d.CascadesIntoHidden, pgFlagRLS: d.RLS},
	}
	names := map[int16]string{}
	for _, c := range d.Columns {
		names[c.Attnum] = c.Name
		out.Fields = append(out.Fields, pgField(d.OID, c))
	}
	for _, x := range d.Indexes {
		shown := pgIndexDisplay{Name: x.Name, Definition: x.Definition, Unique: x.Unique, Partial: x.Partial, SizeBytes: x.SizeBytes, Scans: x.Scans}
		stable := shown
		stable.SizeBytes, stable.Scans = 0, 0
		out.Features = append(out.Features, agentstore.Feature{
			Group: pgGroupIndexes, Touches: pgFieldRefs(d.OID, x.Attnums), Visible: true, Display: shown, Stable: stable,
		})
	}
	for _, k := range d.Keys {
		f := agentstore.Feature{Group: pgGroupForeignKeys, Touches: pgFieldRefs(d.OID, k.Attnums), Visible: k.OtherReadable}
		if k.OtherReadable {
			f.Display = pgForeignKey(k, names)
		}
		out.Features = append(out.Features, f)
	}
	return out
}

func pgField(oid uint32, c pgcatalog.Column) agentstore.Field {
	shown := pgFieldDisplay{Generated: c.Generated}
	if c.Default != "" {
		def := c.Default
		shown.Default = &def
	}
	return agentstore.Field{
		Ref: pgFieldRef(oid, c.Attnum), Name: c.Name, Type: c.Type, Nullable: c.Nullable, Comment: c.Comment,
		Readable: c.Selectable, ReadsFrom: pgFieldRefs(oid, c.DefaultAttnums),
		Display: shown, Masked: pgFieldDisplay{Generated: c.Generated},
	}
}

func pgForeignKey(k pgcatalog.Key, names map[int16]string) pgForeignKeyDisplay {
	fk := pgForeignKeyDisplay{
		Direction: "INCOMING", Columns: make([]string, 0, len(k.Attnums)), Table: agentsvc.PrintedName(k.OtherSchema, k.OtherTable),
		OnDelete: pgFKAction(k.OnDelete), OnUpdate: pgFKAction(k.OnUpdate),
	}
	if k.Outgoing {
		fk.Direction = "OUTGOING"
	}
	for _, n := range k.Attnums {
		fk.Columns = append(fk.Columns, names[n])
	}
	return fk
}

// pgFKAction is a catalog action (SET NULL) as the contract spells it.
func pgFKAction(a string) string { return strings.ReplaceAll(a, " ", "_") }

func pgStats(d pgcatalog.Detail) pgStatsDisplay {
	st := pgStatsDisplay{
		EstimatedRows: d.EstimatedRows, TableBytes: d.Stats.TableBytes, TotalBytes: d.Stats.TotalBytes,
		SeqScans: d.Stats.SeqScans, IndexScans: d.Stats.IndexScans,
	}
	if d.Stats.LastAnalyzed != nil {
		at := d.Stats.LastAnalyzed.UTC().Format(time.RFC3339)
		st.LastAnalyzed = &at
	}
	return st
}

// pgClasses are the agent's PII classes by column (pii.StoreClasses).
type pgClasses interface {
	Resolve(ctx context.Context, refs []pii.ColumnRef) ([]pii.Class, error)
	Secrets(ctx context.Context) ([]pii.ColumnRef, error)
	CatalogFingerprint(ctx context.Context) (string, error)
}

// agentClasses are the PII classes as the agent reads them, by field ref.
type agentClasses struct{ pg pgClasses }

// NewAgentClasses are the PII classes c as the agent reads them.
func NewAgentClasses(c pgClasses) agentsvc.ClassResolver { return agentClasses{pg: c} }

func (c agentClasses) Resolve(ctx context.Context, refs []agentstore.FieldRef) ([]pii.Class, error) {
	cols := make([]pii.ColumnRef, len(refs))
	for i, ref := range refs {
		col, err := pgColumn(ref)
		if err != nil {
			return nil, err
		}
		cols[i] = col
	}
	return c.pg.Resolve(ctx, cols)
}

func (c agentClasses) Secrets(ctx context.Context) ([]agentstore.FieldRef, error) {
	cols, err := c.pg.Secrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]agentstore.FieldRef, len(cols))
	for i, col := range cols {
		out[i] = pgFieldRef(col.TableOID, col.Attnum)
	}
	return out, nil
}

func (c agentClasses) CatalogFingerprint(ctx context.Context) (string, error) {
	return c.pg.CatalogFingerprint(ctx)
}
