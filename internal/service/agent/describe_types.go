package agent

import (
	"context"
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	"github.com/basaltdbhq/basaltdb/internal/service/piidict"
)

// Catalog reads the structure of the database the agent can see, on the
// agent's own credential (CONTRACT.md, describe). The Postgres adapter
// implements it; it mirrors internal/adapter/outbound/postgres/pgcatalog.
type Catalog interface {
	// Relations lists the readable relations by schema and name, and counts
	// the ones in user schemas the agent cannot read.
	Relations(ctx context.Context) ([]CatalogRelation, int, error)
	// Find returns schema.name, or false when it is absent or unreadable.
	Find(ctx context.Context, schema, name string) (CatalogRelation, bool, error)
	// Describe reads one relation Find or Relations returned.
	Describe(ctx context.Context, oid uint32) (CatalogDetail, error)
	// Guarded reports whether basalt init guards the relation, so its
	// writes run under the write policy; false where the guard predates
	// the record of it.
	Guarded(ctx context.Context, oid uint32) (bool, error)
	// Search finds readable relations by name, column or comment; exclude
	// lists columns never matched or named.
	Search(ctx context.Context, q string, exclude []CatalogColumnKey, after *CatalogSearchCursor, limit int) ([]CatalogMatch, error)
	// Structure is the sorted structure lines the catalog fingerprint hashes.
	Structure(ctx context.Context) ([]string, error)
	// Database is the database the credential connects to.
	Database() string
	// Host is the host that database is on (name and host only, never a
	// user, port or credential).
	Host() string
	// Limits are the read limits the agent's statements run within.
	Limits() action.Limits
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

func (noCatalog) Relations(context.Context) ([]CatalogRelation, int, error) {
	return nil, 0, errNoCatalog
}

func (noCatalog) Find(context.Context, string, string) (CatalogRelation, bool, error) {
	return CatalogRelation{}, false, errNoCatalog
}

func (noCatalog) Describe(context.Context, uint32) (CatalogDetail, error) {
	return CatalogDetail{}, errNoCatalog
}

func (noCatalog) Guarded(context.Context, uint32) (bool, error) { return false, errNoCatalog }

func (noCatalog) Search(context.Context, string, []CatalogColumnKey, *CatalogSearchCursor, int) ([]CatalogMatch, error) {
	return nil, errNoCatalog
}

func (noCatalog) Structure(context.Context) ([]string, error) { return nil, errNoCatalog }

func (noCatalog) Database() string { return "" }

func (noCatalog) Host() string { return "" }

func (noCatalog) Limits() action.Limits { return action.Limits{} }

// noClasses serves a service built without PII classes: it cannot tell a
// SECRET column, so every describe call fails closed (INTERNAL).
type noClasses struct{}

var errNoClasses = errors.New("describe: no pii classes configured")

func (noClasses) Resolve(context.Context, []piidict.ColumnRef) ([]piidict.Class, error) {
	return nil, errNoClasses
}

func (noClasses) Secrets(context.Context) ([]piidict.ColumnRef, error) { return nil, errNoClasses }

func (noClasses) CatalogFingerprint(context.Context) (string, error) { return "", errNoClasses }

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

	formOverview = "OVERVIEW"
	formSearch   = "SEARCH"
	formResource = "RESOURCE"
	privSelect   = "SELECT"
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
	Host     string `json:"host"`
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
	Store         StoreInfo             `json:"store"`
	Fingerprint   string                `json:"fingerprint"`
	Counts        Counts                `json:"counts"`
	Limits        OverviewLimits        `json:"limits"`
	Resources     []SearchItem          `json:"resources,omitzero"`
	Schemas       []SchemaCount         `json:"schemas,omitzero"`
	OtherSchemas  *OtherSchemas         `json:"otherSchemas,omitempty"`
	PersonMessage string                `json:"personMessage,omitempty"`
	NextSteps     []toolresult.NextStep `json:"nextSteps,omitempty"`
	Update        *UpdateInfo           `json:"update,omitempty"`
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
